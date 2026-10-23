"""
AMSA watcher (final, VM edition)  --  runs INSIDE the VMware guest.

Static + remote-intelligence triage of files dropped into a watched folder:
  1. YARA pattern matching   (local rules: rules.yar plus a folder of signature packs)
  2. PE heuristics           (local: entropy / imports / entry point)
  3. VirusTotal hash lookup  (through the host's /vt proxy, direct, or off)
The results are combined by calculate_risk() and POSTed to the host dashboard.

This tool does NOT execute samples. It performs no behavioural/dynamic analysis.

Examples
--------
Interactive (s = start, x = stop, q = quit):
    python watcher-final.py

Unattended (what a vmrun-driven runner would use):
    python watcher-final.py --autostart --scan-existing --log C:\\Sandbox\\watcher.log

Settings (CLI flag > environment variable > default):
    --server      SANDBOX_SERVER      http://192.168.45.1:5000  (the host's VMnet1 IP)
    --folder      SANDBOX_FOLDER      C:\\Sandbox\\Watch
    --yara-rules  SANDBOX_YARA_RULES  C:\\Sandbox\\rules.yar;C:\\Sandbox\\Rules
                                      (semicolon-separated .yar/.yara files and/or folders)
    --vt-mode     SANDBOX_VT_MODE     proxy | direct | off   (default: proxy)
    --vt-upload   SANDBOX_VT_UPLOAD=1 upload files VirusTotal has never seen.
                                      Off by default: uploading shares the file itself
                                      with a third party, otherwise only the SHA-256 is sent.
    VT_API_KEY                        direct mode only. In proxy mode the key stays on the
                                      host and the guest never sees it.
"""

import argparse
import glob
import hashlib
import math
import os
import threading
import time
from datetime import datetime

import pefile
import requests

try:
    import yara
except ImportError:  # keep the tool running; YARA layer becomes N/A
    yara = None

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# --------------------------------------------------------------------------
# Configuration (defaults; main() applies CLI flags on top)
# --------------------------------------------------------------------------

SERVER_URL = os.environ.get("SANDBOX_SERVER", "http://192.168.45.1:5000")
FOLDER_TO_WATCH = os.environ.get("SANDBOX_FOLDER", r"C:\Sandbox\Watch")
YARA_RULES_PATH = os.environ.get("SANDBOX_YARA_RULES", r"C:\Sandbox\rules.yar;C:\Sandbox\Rules")
VT_MODE = os.environ.get("SANDBOX_VT_MODE", "proxy")
VT_UPLOAD_UNKNOWN = (os.environ.get("SANDBOX_VT_UPLOAD")
                     or os.environ.get("VT_UPLOAD_UNKNOWN")) == "1"
LOG_PATH = None

VT_DIRECT_BASE = "https://www.virustotal.com/api/v3"
VT_POLL_INTERVAL = 15      # seconds; the free VT tier allows ~4 requests/minute
VT_POLL_ATTEMPTS = 20      # 20 x 15 s = 5 minutes

PE_EXTENSIONS = (".exe", ".dll", ".scr", ".sys", ".ocx")

# PE import heuristics are split in two on purpose. Ordinary software (runtime
# libraries, installers, copy protection) calls the "common" APIs all the time,
# so they only add a little; the "injection" APIs are rarely needed outside
# debuggers and security tools, so they add a lot.
INJECTION_IMPORTS = {
    b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread",
    b"NtUnmapViewOfSection",
}
INJECTION_TRIO = {b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread"}
COMMON_IMPORTS = {
    b"VirtualAlloc", b"VirtualProtect",
    b"IsDebuggerPresent", b"CheckRemoteDebuggerPresent",
    b"WinExec", b"URLDownloadToFileA", b"URLDownloadToFileW",
    b"SetWindowsHookExA", b"SetWindowsHookExW",
}

# Verdict limits for the PE layer (see calculate_risk):
PE_ONLY_MAX_SCORE = 59        # heuristics alone can reach MEDIUM, never HIGH
VT_CLEAN_MIN_ENGINES = 50     # "VirusTotal knows this file" = at least this many engines
PE_VT_CLEAN_SCORE = 25        # a PE-only finding on a VT-known-clean file becomes LOW

running = False
watcher_thread = None

# Set every time watching starts ('s' or --autostart). It is just the start
# time, so it doubles as a human-readable label on the dashboard.
current_session_id = None

# Compiled once at startup so every scan doesn't re-parse the ruleset.
YARA_RULES = None

_log_lock = threading.Lock()


def log(message):
    """Timestamped line to the console and, if --log was given, to a file."""
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {message}"
    with _log_lock:
        print(line, flush=True)
        if LOG_PATH:
            try:
                with open(LOG_PATH, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except OSError:
                pass


# Third-party rule packs (e.g. signature-base) expect these external variables.
# They are declared at compile time and filled in per file at match time.
YARA_EXTERNALS = {"filename": "", "filepath": "", "extension": "", "filetype": "", "owner": ""}


def _collect_rule_files(spec):
    """Expand a ';'-separated list of files / folders into .yar/.yara files."""
    files = []
    for part in [p.strip() for p in spec.split(";") if p.strip()]:
        if not os.path.exists(part):
            alt = os.path.join(SCRIPT_DIR, os.path.basename(part))
            if os.path.exists(alt):          # convenience outside the VM
                log(f"[YARA] {part} not found; using {alt} instead")
                part = alt
            else:
                log(f"[YARA] Not found: {part}")
                continue
        if os.path.isdir(part):
            files += sorted(glob.glob(os.path.join(part, "*.yar")) +
                            glob.glob(os.path.join(part, "*.yara")))
        else:
            files.append(part)
    return files


def load_yara_rules(path):
    """
    Compile rules from every .yar/.yara file named by `path` (files and/or
    folders, ';'-separated). A rule file that fails to compile is skipped and
    logged, so one bad file cannot disable the whole YARA layer.
    """
    global YARA_RULES
    YARA_RULES = None

    if yara is None:
        log("[YARA] 'yara-python' is not installed; YARA layer will show N/A. "
            "Install with: pip install yara-python")
        return

    rule_files = _collect_rule_files(path)
    if not rule_files:
        log("[YARA] No rule files found; YARA layer will show N/A.")
        return

    good = {}
    skipped = 0
    for i, rule_file in enumerate(rule_files):
        try:
            yara.compile(filepath=rule_file, externals=YARA_EXTERNALS)
            good[f"r{i}"] = rule_file              # unique namespace per file
        except (yara.Error, OSError) as e:
            skipped += 1
            log(f"[YARA] Skipping {os.path.basename(rule_file)}: {e}")

    if not good:
        log("[YARA] No rule file compiled successfully; YARA layer will show N/A.")
        return

    try:
        YARA_RULES = yara.compile(filepaths=good, externals=YARA_EXTERNALS)
        log(f"[YARA] Compiled {len(good)}/{len(rule_files)} rule file(s)"
            + (f", {skipped} skipped" if skipped else ""))
    except (yara.Error, OSError) as e:
        log(f"[YARA] Rule compilation failed ({e}); YARA layer will show N/A.")


# --------------------------------------------------------------------------
# Hashing
# --------------------------------------------------------------------------

def get_file_hash(filepath):
    """SHA-256, read in chunks so large files don't need to fit in memory."""
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


# --------------------------------------------------------------------------
# Layer 1: PE heuristics
# --------------------------------------------------------------------------

def get_pe_info(filepath):
    """Basic PE header facts, or None if the file is not a parseable PE."""
    try:
        pe = pefile.PE(filepath)
        info = {
            "machine_type": hex(pe.FILE_HEADER.Machine),
            "num_sections": pe.FILE_HEADER.NumberOfSections,
        }
        pe.close()
        return info
    except Exception:
        return None


def _section_entropy(data):
    """Shannon entropy in bits per byte (0-8). Packed/encrypted data is near 8."""
    if not data:
        return 0.0
    occurrences = [0] * 256
    for byte in data:
        occurrences[byte] += 1
    entropy = 0.0
    length = len(data)
    for count in occurrences:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def calculate_pe_score(filepath, extension):
    """
    Heuristic PE score (0-100) plus a human-readable detail string and a list
    of plain-English notes explaining how much weight each finding deserves.
    Returns (None, detail, []) when the file isn't a PE at all, so the
    dashboard shows 'N/A' (inconclusive) rather than a false 'clean'.
    """
    if extension.lower() not in PE_EXTENSIONS:
        return None, "not a PE extension", []

    try:
        pe = pefile.PE(filepath)
    except Exception:
        return None, "not a valid PE file", []

    try:
        score = 0
        reasons = []
        notes = []

        # 1. High-entropy sections suggest packed or encrypted code - but
        #    installers and archives are compressed too, so it is a weak signal.
        max_entropy = 0.0
        for section in pe.sections:
            max_entropy = max(max_entropy, _section_entropy(section.get_data()))
        if max_entropy >= 7.4:
            score += 35
            reasons.append(f"high entropy section ({max_entropy:.2f})")
        elif max_entropy >= 6.8:
            score += 15
            reasons.append(f"elevated entropy ({max_entropy:.2f})")
        if max_entropy >= 6.8:
            notes.append("High entropy means compressed or encrypted data. Packed malware looks "
                         "like this, but so do installers and archives, so it is a weak signal on its own.")

        # 2. Imports, in two tiers (see INJECTION_IMPORTS / COMMON_IMPORTS).
        found = set()
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        found.add(imp.name)

        strong = found & INJECTION_IMPORTS
        if strong:
            import_score = 20 * len(strong)
            if INJECTION_TRIO <= found:
                import_score += 20
                notes.append("Importing VirtualAllocEx, WriteProcessMemory and CreateRemoteThread "
                             "together is the classic code-injection pattern.")
            else:
                notes.append("These APIs change another process's memory or threads. Debuggers and "
                             "security tools use them legitimately, but ordinary programs rarely do.")
            score += min(70, import_score)
            reasons.append("process-injection imports: "
                           + ", ".join(sorted(n.decode(errors="ignore") for n in strong)))

        weak = found & COMMON_IMPORTS
        if weak:
            score += min(10, 5 * len(weak))
            reasons.append("common APIs (weak signal): "
                           + ", ".join(sorted(n.decode(errors="ignore") for n in weak)))
            notes.append("APIs like VirtualAlloc and IsDebuggerPresent are used by ordinary software "
                         "(runtime libraries, installers, copy protection), so they add only a little.")

        # 3. Entry point outside every declared section.
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        if not any(section.contains_rva(ep) for section in pe.sections):
            score += 20
            reasons.append("entry point outside declared sections")

        # 4. Very few imports often means APIs are resolved at runtime (packed).
        total_imports = sum(
            len(entry.imports) for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
        )
        if total_imports and total_imports < 5:
            score += 10
            reasons.append(f"unusually small import table ({total_imports})")
    except Exception as e:
        return None, f"PE analysis error: {e}", []
    finally:
        pe.close()

    score = min(score, 100)
    return score, ("; ".join(reasons) if reasons else "no heuristic flags"), notes


# --------------------------------------------------------------------------
# Layer 2: YARA
# --------------------------------------------------------------------------

_TEXT_SEVERITY = {"low": 20, "medium": 40, "high": 70, "critical": 90}


def _severity(meta):
    """
    Numeric severity from rule metadata: 'severity' (AMSA rules), else 'score'
    (signature-base style), else 20. Either may be a number or low/medium/high/critical.
    """
    raw = meta.get("severity", meta.get("score", 20))
    try:
        return int(raw)
    except (TypeError, ValueError):
        return _TEXT_SEVERITY.get(str(raw).strip().lower(), 20)


def _matched_strings(match, limit=4):
    """Readable list of the strings a rule actually found in the file."""
    found = []
    for item in match.strings:
        if hasattr(item, "instances"):            # yara-python >= 4.3
            datas = [inst.matched_data for inst in item.instances]
        else:                                     # older tuple format
            datas = [item[2]]
        for data in datas:
            text = data.decode("latin-1", errors="replace")
            text = "".join(c if c.isprintable() else "." for c in text)[:40]
            if text not in found:
                found.append(text)
    return found[:limit]


def calculate_yara_score(filepath):
    """
    Runs the compiled ruleset against the file.
    Returns (score, detail, reasons). score is None (not 0) when the ruleset
    isn't available. reasons is a list of plain-English lines for the dashboard.
    """
    if YARA_RULES is None:
        return None, "ruleset not loaded", []

    try:
        name = os.path.basename(filepath)
        ext = os.path.splitext(name)[1]
        matches = YARA_RULES.match(filepath, timeout=30, externals={
            "filename": name,
            "filepath": filepath,
            "extension": ext,
            "filetype": ext.lstrip(".").upper(),
            "owner": "",
        })
    except yara.Error as e:
        return None, f"yara error: {e}", []

    if not matches:
        return 0, "no rule matches", []

    score = 0
    names = []
    reasons = []
    for match in matches:
        severity = _severity(match.meta)
        score += severity
        names.append(match.rule)

        description = match.meta.get("description", "no description provided")
        line = f"YARA rule {match.rule} (+{severity}): {description}."
        found = _matched_strings(match)
        if found:
            line += " Found: " + ", ".join(f"'{f}'" for f in found) + "."
        reasons.append(line)

    return min(score, 100), "matched: " + ", ".join(names), reasons


# --------------------------------------------------------------------------
# Layer 3: VirusTotal
# --------------------------------------------------------------------------

def _vt_stats_result(stats):
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values())
    return f"VT: {malicious}/{total} malicious, {suspicious} suspicious", malicious, total


def vt_endpoint():
    """
    (base_url, headers) for the selected VT mode.
    None = VT disabled, "KEYMISSING" = direct mode without VT_API_KEY.
    proxy: the host's /vt route adds the API key, so the guest never holds it.
    """
    if VT_MODE == "off":
        return None
    if VT_MODE == "direct":
        api_key = os.environ.get("VT_API_KEY")
        if not api_key:
            return "KEYMISSING"
        return VT_DIRECT_BASE, {"x-apikey": api_key}
    return f"{SERVER_URL}/vt", {}


def _vt_proxy_problem(status):
    """Plain-English text for the setup mistakes specific to proxy mode."""
    if VT_MODE == "proxy":
        if status == 403:
            return "VT: host refused the request (is this VM inside SANDBOX_GUEST_NET?)"
        if status == 503:
            return "VT: host has no VT_API_KEY set"
    return None


def check_virustotal(file_hash, filepath):
    """
    Returns (summary, malicious, total). total == 0 means "no VT signal"
    (disabled, unknown hash, no key, offline, rate-limited) - NOT "clean".
    """
    endpoint = vt_endpoint()
    if endpoint is None:
        return "VT: disabled", 0, 0
    if endpoint == "KEYMISSING":
        return "VT: API key not set (direct mode)", 0, 0

    base, headers = endpoint

    try:
        response = requests.get(f"{base}/files/{file_hash}", headers=headers, timeout=30)
    except requests.RequestException as e:
        return f"VT: connection error ({e})", 0, 0

    if response.status_code == 200:
        try:
            stats = response.json()["data"]["attributes"].get("last_analysis_stats", {})
        except (ValueError, KeyError, TypeError):
            return "VT: unexpected response", 0, 0
        return _vt_stats_result(stats)

    if response.status_code == 429:
        return "VT: rate limit reached (free tier: 4 requests/min)", 0, 0

    if response.status_code != 404:
        return (_vt_proxy_problem(response.status_code)
                or f"VT: lookup error {response.status_code}"), 0, 0

    # 404 = VirusTotal has never seen this hash.
    if not VT_UPLOAD_UNKNOWN:
        return "VT: hash not found (file not uploaded)", 0, 0

    log("[VT] Hash not found. Upload enabled, sending file for analysis...")
    try:
        with open(filepath, "rb") as f:
            upload = requests.post(
                f"{base}/files",                    # limit: 32 MB
                headers=headers,
                files={"file": (os.path.basename(filepath), f)},
                timeout=120,
            )
    except (OSError, requests.RequestException) as e:
        return f"VT: upload error ({e})", 0, 0

    if upload.status_code not in (200, 201):
        return (_vt_proxy_problem(upload.status_code)
                or f"VT: upload error {upload.status_code}"), 0, 0

    try:
        analysis_id = upload.json()["data"]["id"]
    except (ValueError, KeyError, TypeError):
        return "VT: unexpected upload response", 0, 0
    log(f"[VT] Analysis submitted: {analysis_id}")

    for attempt in range(VT_POLL_ATTEMPTS):
        time.sleep(VT_POLL_INTERVAL)
        try:
            poll = requests.get(f"{base}/analyses/{analysis_id}", headers=headers, timeout=30)
        except requests.RequestException as e:
            return f"VT: analysis connection error ({e})", 0, 0

        if poll.status_code == 429:
            log("[VT] Rate limited, waiting...")
            continue
        if poll.status_code != 200:
            return f"VT: analysis error {poll.status_code}", 0, 0

        try:
            attributes = poll.json()["data"]["attributes"]
        except (ValueError, KeyError, TypeError):
            return "VT: unexpected analysis response", 0, 0
        if attributes.get("status") == "completed":
            return _vt_stats_result(attributes.get("stats", {}))

        log(f"[VT] Analysis status: {attributes.get('status')} ({attempt + 1}/{VT_POLL_ATTEMPTS})")

    return "VT: analysis timed out", 0, 0


# --------------------------------------------------------------------------
# Combining the layers
# --------------------------------------------------------------------------

_LABEL_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _label_for(score):
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def _vt_candidate(vt_malicious, vt_total):
    """(score, label) from VirusTotal consensus, or None if VT flagged nothing."""
    if vt_total <= 0 or vt_malicious <= 0:
        return None
    ratio = vt_malicious / vt_total
    if ratio >= 0.5:
        return 95, "HIGH"
    if ratio >= 0.15:
        return 60, "MEDIUM"
    return 30, "LOW"


def calculate_risk(vt_malicious, vt_total, extension, pe_info, yara_score=None, pe_score=None):
    """
    Takes the strongest signal from any layer (not an average):
      - VirusTotal consensus, YARA and PE heuristics each propose a score.
      - The highest one wins, so VirusTotal can raise the verdict but a weak VT
        result (e.g. 1/57) can no longer pull down a strong YARA match.
      - PE heuristics are weaker evidence than a signature, so on their own:
          * they can never produce HIGH (capped at MEDIUM), and
          * if VirusTotal knows the file and no engine flags it, they are
            downgraded to LOW. YARA matches are never downgraded this way.
      - If nothing flagged the file, a small extension / section-count fallback.
    Returns (score, label, basis, adjustments). `adjustments` lists any caps or
    downgrades that were applied, for the explanation text.
    """
    adjustments = []
    candidates = []                                   # (score, label, basis)

    vt = _vt_candidate(vt_malicious, vt_total)
    if vt:
        candidates.append((vt[0], vt[1], "VirusTotal"))
    if yara_score:
        candidates.append((yara_score, _label_for(yara_score), "YARA"))

    if pe_score:
        pe_effective = pe_score
        vt_known_clean = vt_total >= VT_CLEAN_MIN_ENGINES and vt_malicious == 0
        if vt_known_clean and pe_score > PE_VT_CLEAN_SCORE:
            pe_effective = PE_VT_CLEAN_SCORE
            adjustments.append(
                f"VirusTotal knows this file and 0 of {vt_total} engines flag it, so the PE "
                "heuristic finding was downgraded to LOW. (YARA matches are never downgraded this way.)")
        elif pe_score > PE_ONLY_MAX_SCORE:
            pe_effective = PE_ONLY_MAX_SCORE
            adjustments.append(
                f"PE heuristics alone cannot rate a file HIGH, so the PE score of {pe_score} was "
                "capped at MEDIUM. HIGH needs a strong YARA match (score 60+) or VirusTotal detections.")
        candidates.append((pe_effective, _label_for(pe_effective), "PE heuristics"))

    if candidates:
        score, label, basis = max(candidates, key=lambda c: (c[0], _LABEL_RANK[c[1]]))
        if basis != "PE heuristics":
            adjustments = []          # the PE adjustment didn't decide the verdict
        return score, label, basis, adjustments

    score = 0
    if extension.lower() in (".exe", ".dll", ".scr", ".bat"):
        score += 10
    if pe_info and pe_info.get("num_sections", 0) > 8:
        score += 20

    if score >= 20:
        return score, "LOW", "file-type fallback", []
    return 0, "CLEAN", "no layer flagged this file", []


def build_explanation(yara_reasons, pe_score, pe_detail, vt_malicious, vt_total,
                      risk_score, risk_label, basis, extension, vt_summary="",
                      pe_notes=(), adjustments=()):
    """Plain-English 'why was this flagged?' text, one finding per line."""
    lines = list(yara_reasons)

    if pe_score:
        lines.append(f"PE heuristics (score {pe_score}): {pe_detail}.")
        lines.extend(pe_notes)

    if vt_total > 0 and vt_malicious > 0:
        lines.append(f"VirusTotal: {vt_malicious} of {vt_total} engines flagged this file as malicious.")
    elif vt_total > 0:
        lines.append(f"VirusTotal: 0 of {vt_total} engines flagged this file.")
    else:
        reason = vt_summary.replace("VT: ", "", 1) or "no data"
        lines.append(f"VirusTotal returned no result: {reason}. This is not the same as clean.")

    lines.extend(adjustments)

    if risk_label == "CLEAN":
        lines.insert(0, "No detection layer flagged this file.")
    elif basis == "file-type fallback":
        lines.append(f"Only a weak hint: {extension} files can run code, but nothing specific was found.")
    else:
        lines.append(f"Final verdict {risk_label} ({risk_score}/100) comes from the strongest signal: {basis}.")

    return "\n".join(lines)


def layer_display(score):
    return "N/A" if score is None else str(score)


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def send_to_server(filename, filesize, extension, sha256, yara_score, yara_detail,
                   pe_score, pe_detail, vt_malicious, vt_total, risk_score, risk_label,
                   session_id=None, explanation=None):
    payload = {
        "filename": filename,
        "filesize": filesize,
        "extension": extension,
        "sha256": sha256,
        "yara_score": yara_score,
        "yara_detail": yara_detail,
        "pe_score": pe_score,
        "pe_detail": pe_detail,
        "vt_malicious": vt_malicious,
        "vt_total": vt_total,
        "risk_score": risk_score,
        "risk_label": risk_label,
        "session_id": session_id,
        "explanation": explanation,
    }

    for attempt in range(1, 4):
        try:
            response = requests.post(f"{SERVER_URL}/report", json=payload, timeout=10)
            if response.status_code == 200:
                log(f"[SENT] {filename} -> {SERVER_URL}")
                return True
            log(f"[ERROR] Server rejected {filename}: HTTP {response.status_code} {response.text[:200]}")
            if 400 <= response.status_code < 500:
                return False        # retrying a refused/invalid request won't help
        except requests.RequestException as e:
            log(f"[ERROR] Could not reach {SERVER_URL} (try {attempt}/3): {e}")
        time.sleep(2)

    log(f"[ERROR] Giving up on {filename}: is the server running and is the host firewall "
        f"open for port {SERVER_URL.rsplit(':', 1)[-1]}?")
    return False


def check_server():
    """One-time connectivity check at startup so network mistakes show up early."""
    try:
        response = requests.get(f"{SERVER_URL}/", timeout=5)
    except requests.RequestException as e:
        log(f"[NET] WARNING: cannot reach server at {SERVER_URL} ({e}). "
            "Results will fail to send until it is reachable.")
        return False
    if response.status_code == 403:
        log(f"[NET] WARNING: {SERVER_URL} refused this machine (HTTP 403). "
            "Check SANDBOX_GUEST_NET on the host.")
        return False
    log(f"[NET] Server reachable at {SERVER_URL} (HTTP {response.status_code})")
    return True


# --------------------------------------------------------------------------
# Per-file analysis and folder watching
# --------------------------------------------------------------------------

def wait_until_file_is_ready(filepath, attempts=10, delay=1):
    """OneDrive/Windows can expose a new file before it is fully written."""
    previous_size = None
    for _ in range(attempts):
        try:
            current_size = os.path.getsize(filepath)
            with open(filepath, "rb") as f:
                f.read(1)
            if current_size == previous_size:
                return True
            previous_size = current_size
        except (OSError, PermissionError):
            pass
        time.sleep(delay)
    return False


def analyze_file(filepath, filename):
    if not wait_until_file_is_ready(filepath):
        log(f"[ERROR] File is not ready/accessible: {filename}")
        return

    file_hash = get_file_hash(filepath)
    file_size = os.path.getsize(filepath)
    extension = os.path.splitext(filename)[1]

    output = f"[NEW FILE] {filename} | size: {file_size} bytes | ext: {extension} | sha256: {file_hash}"

    pe_info = get_pe_info(filepath) if extension.lower() in PE_EXTENSIONS else None
    if extension.lower() in PE_EXTENSIONS:
        if pe_info:
            output += f" | PE: sections={pe_info['num_sections']}, machine={pe_info['machine_type']}"
        else:
            output += " | PE: invalid/unparseable"

    yara_score, yara_detail, yara_reasons = calculate_yara_score(filepath)
    output += f" | YARA: {layer_display(yara_score)} ({yara_detail})"

    pe_score, pe_detail, pe_notes = calculate_pe_score(filepath, extension)
    output += f" | PE-score: {layer_display(pe_score)} ({pe_detail})"

    vt_summary, vt_malicious, vt_total = check_virustotal(file_hash, filepath)
    output += f" | {vt_summary}"

    risk_score, risk_label, risk_basis, risk_adjustments = calculate_risk(
        vt_malicious, vt_total, extension, pe_info,
        yara_score=yara_score, pe_score=pe_score,
    )
    output += f" | RISK: {risk_label} ({risk_score})"

    explanation = build_explanation(
        yara_reasons, pe_score, pe_detail, vt_malicious, vt_total,
        risk_score, risk_label, risk_basis, extension, vt_summary=vt_summary,
        pe_notes=pe_notes, adjustments=risk_adjustments,
    )

    log(output)

    send_to_server(
        filename, file_size, extension, file_hash,
        yara_score, yara_detail, pe_score, pe_detail,
        vt_malicious, vt_total, risk_score, risk_label,
        session_id=current_session_id, explanation=explanation,
    )


def list_files():
    return {
        name for name in os.listdir(FOLDER_TO_WATCH)
        if os.path.isfile(os.path.join(FOLDER_TO_WATCH, name))
    }


def watch_folder(scan_existing=False):
    os.makedirs(FOLDER_TO_WATCH, exist_ok=True)
    known_files = set() if scan_existing else list_files()

    log(f"[WATCHING] {FOLDER_TO_WATCH}")
    if scan_existing:
        log("[BASELINE] Files already in the folder will be scanned too.")
    else:
        log(f"[BASELINE] {len(known_files)} existing file(s) will not be scanned.")

    while running:
        try:
            current_files = list_files()
        except OSError as e:
            log(f"[ERROR] Cannot read {FOLDER_TO_WATCH}: {e}")
            time.sleep(2)
            continue

        for filename in sorted(current_files - known_files):
            filepath = os.path.join(FOLDER_TO_WATCH, filename)
            try:
                analyze_file(filepath, filename)
            except Exception as e:
                log(f"[ERROR] Could not process {filename}: {e}")

        known_files = current_files
        time.sleep(2)


def start_watching(scan_existing=False):
    """Begin a new watcher session (used by both 's' and --autostart)."""
    global running, watcher_thread, current_session_id
    running = True
    current_session_id = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log(f"[SESSION] New session started at {current_session_id}")
    watcher_thread = threading.Thread(target=watch_folder, args=(scan_existing,), daemon=True)
    watcher_thread.start()


def listen_for_commands(scan_existing):
    global running
    print("Commands: 's' = start, 'x' = stop, 'q' = quit")

    while True:
        try:
            command = input().strip().lower()
        except EOFError:
            log("[ERROR] No console input available. Use --autostart for unattended runs.")
            break

        if command == "s":
            if watcher_thread is not None and watcher_thread.is_alive():
                print("Already watching (if you just stopped it, wait ~2 s and try again).")
                continue
            start_watching(scan_existing)
        elif command == "x":
            running = False
            log("Stopped watching.")
        elif command == "q":
            running = False
            log("Exiting.")
            break


def main():
    global SERVER_URL, FOLDER_TO_WATCH, YARA_RULES_PATH, VT_MODE, VT_UPLOAD_UNKNOWN, LOG_PATH

    parser = argparse.ArgumentParser(description="AMSA watcher (guest side)")
    parser.add_argument("--server", default=SERVER_URL,
                        help="host dashboard URL, e.g. http://192.168.45.1:5000")
    parser.add_argument("--folder", default=FOLDER_TO_WATCH,
                        help="folder inside the guest to watch")
    parser.add_argument("--yara-rules", default=YARA_RULES_PATH,
                        help="semicolon-separated .yar/.yara files and/or folders (e.g. rules.yar;Rules)")
    parser.add_argument("--vt-mode", choices=["proxy", "direct", "off"], default=VT_MODE,
                        help="proxy = via the host (key stays on host); direct = this VM calls VT; off")
    parser.add_argument("--vt-upload", action="store_true", default=VT_UPLOAD_UNKNOWN,
                        help="upload files VirusTotal has never seen (shares the file with a third party)")
    parser.add_argument("--fuzzy-corpus", default=None, help=argparse.SUPPRESS)  # accepted, unused
    parser.add_argument("--autostart", action="store_true",
                        help="start watching immediately, no keyboard input (for vmrun)")
    parser.add_argument("--scan-existing", action="store_true",
                        help="also analyse files already in the folder at startup")
    parser.add_argument("--log", default=None, help="append log lines to this file")
    args = parser.parse_args()

    SERVER_URL = args.server.rstrip("/")
    if SERVER_URL.endswith("/report"):           # tolerate the old full-endpoint style
        SERVER_URL = SERVER_URL[: -len("/report")]
    FOLDER_TO_WATCH = args.folder
    YARA_RULES_PATH = args.yara_rules
    VT_MODE = args.vt_mode
    VT_UPLOAD_UNKNOWN = args.vt_upload
    LOG_PATH = args.log

    os.makedirs(FOLDER_TO_WATCH, exist_ok=True)
    log(f"[CONFIG] server={SERVER_URL} folder={FOLDER_TO_WATCH} vt={VT_MODE} "
        f"vt_upload={'on' if VT_UPLOAD_UNKNOWN else 'off'} yara_rules={YARA_RULES_PATH}")
    if args.fuzzy_corpus:
        log("[WARN] --fuzzy-corpus is ignored: this build has no SSDEEP layer.")
    if VT_MODE == "direct" and not os.environ.get("VT_API_KEY"):
        log("[WARN] --vt-mode direct but VT_API_KEY is not set; VirusTotal layer will be skipped.")

    load_yara_rules(YARA_RULES_PATH)
    check_server()

    if args.autostart:
        start_watching(args.scan_existing)
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            pass
    else:
        listen_for_commands(args.scan_existing)


if __name__ == "__main__":
    main()
