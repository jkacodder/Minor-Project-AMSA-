# AMSA – Automated Malware Sandbox Analyzer

AMSA is a self-hosted, static triage framework for suspicious files. Files dropped into a watched folder inside an isolated **VMware** guest are analysed by three independent layers (**YARA**, **PE heuristics** and **VirusTotal**). The results are fused into one risk verdict and sent to a live dashboard on the host, where every verdict comes with a plain-English explanation.

> **AMSA never executes a sample.** It performs static and reputation analysis only. There is no behavioural or dynamic analysis.

---

## Table of contents

- [Features](#features)
- [Architecture](#architecture)
- [How the verdict is calculated](#how-the-verdict-is-calculated)
- [Repository structure](#repository-structure)
- [Requirements](#requirements)
- [Setup](#setup)
- [Usage](#usage)
- [Configuration reference](#configuration-reference)
- [Dashboard and API](#dashboard-and-api)
- [Security design](#security-design)
- [Limitations](#limitations)
- [Future work](#future-work)
- [Team](#team)

---

## Features

- **Three detection layers**
  - **YARA** pattern matching with your own `rules.yar` plus folders of third-party rule packs (e.g. signature-base).
  - **PE heuristics**: section entropy, process-injection imports, entry point outside declared sections and import table size.
  - **VirusTotal** hash reputation, with optional upload of files VirusTotal has never seen.
- **Strongest-signal fusion** instead of averaging, with explicit false-positive guards.
- **Explainable verdicts**: every scan page answers "Why was this flagged?" in plain English.
- **Live dashboard** (Flask + HTMX) that refreshes every 5 seconds, groups scans by watcher session and supports filename search.
- **API key stays on the host.** The guest reaches VirusTotal through a restricted proxy and never sees the key.
- **Network-restricted server.** Only the isolated VMnet1 subnet can reach it.
- **Resilient by design.** A broken rule file is skipped rather than disabling YARA. Missing layers show as `N/A` (inconclusive), never as a false "clean".
- **Unattended mode** for runners that drive the guest with `vmrun`.

---

## Architecture

```
┌──────────────────────── VMware guest (isolated) ────────────────────────┐
│                                                                         │
│   C:\Sandbox\Watch  ──►  watcher-final-pe-v2.py                         │
│    (dropped files)        ├─ 1. SHA-256                                 │
│                           ├─ 2. YARA        (rules.yar + Rules\)        │
│                           ├─ 3. PE heuristics                           │
│                           ├─ 4. VirusTotal lookup ─────────┐            │
│                           └─ 5. calculate_risk() + explanation          │
│                                      │                     │            │
└──────────────────────────────────────┼─────────────────────┼────────────┘
                                       │ POST /report        │ GET/POST /vt/...
                         VMnet1 (192.168.45.0/24, host-only) │
┌──────────────────────────────────────▼─────────────────────▼────────────┐
│  Host: server_final.py (Flask)                                          │
│   ├─ /report      validate and store results in SQLite (scans.db)       │
│   ├─ /vt/*        allow-listed VirusTotal proxy (adds the API key)  ──► VirusTotal
│   ├─ /scans       live dashboard      /scan/<id>   detail + explanation │
│   └─ /api/scan/<sha256>   JSON result lookup                            │
└─────────────────────────────────────────────────────────────────────────┘
```

| Component | File | Runs on |
|---|---|---|
| Watcher (analysis engine) | `watcher-final-pe-v2.py` | VMware guest |
| Server (dashboard, storage, VT proxy) | `server_final.py` | Host |
| Detection rules | `rules.yar`, `Rules.zip` | Guest |

---

## How the verdict is calculated

Each layer proposes a score from 0 to 100. **The highest proposal wins**, so a weak VirusTotal result such as 1/57 cannot pull down a strong YARA match.

| Layer | How it scores |
|---|---|
| **YARA** | Sum of matched rule severities (rule `severity` or `score` metadata, either numeric or `low`/`medium`/`high`/`critical`), capped at 100 |
| **PE heuristics** | High entropy (+35 at ≥ 7.4, +15 at ≥ 6.8), injection imports (+20 each, +20 more for the classic `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` trio, capped at 70), common APIs (+5 each, capped at 10), entry point outside sections (+20), very small import table (+10) |
| **VirusTotal** | ≥ 50% of engines flag it → 95 (HIGH); ≥ 15% → 60 (MEDIUM); any detection → 30 (LOW) |

**Labels:** `HIGH` ≥ 60, `MEDIUM` ≥ 30, otherwise `LOW`. `CLEAN` means no layer flagged the file.

**False-positive guards**

- PE heuristics alone can **never** produce HIGH. The score is capped at 59.
- If VirusTotal knows the file (≥ 50 engines analysed) and none flag it, a PE-only finding is downgraded to 25 (LOW).
- YARA matches are **never** downgraded this way.
- If no layer flags a file, a small fallback applies (`.exe`/`.dll`/`.scr`/`.bat` extension, or more than 8 PE sections), and the result is at most LOW.
- A missing VirusTotal result (offline, rate-limited, unknown hash, disabled) is reported as *"no result, not the same as clean"*.

---

## Repository structure

```
Minor-Project-AMSA-/
├── server_final.py            # Host: Flask dashboard, SQLite storage, VirusTotal proxy
├── watcher-final-pe-v2.py     # Guest: folder watcher + YARA / PE / VT analysis
├── rules.yar                  # AMSA's own YARA rules
├── Rules.zip                  # Additional YARA rule packs (extract into the guest's Rules folder)
└── README.md
```

---

## Requirements

- **VMware Workstation or Player**, with a Windows guest on a **host-only (VMnet1)** network
- **Python 3.9+** on both the host and the guest
- A **VirusTotal API key** (the free tier works, at about 4 requests per minute)

| Where | Python packages |
|---|---|
| Host | `flask`, `requests` |
| Guest | `pefile`, `requests`, `yara-python` |

`yara-python` is optional. Without it the YARA layer shows `N/A` and the other layers keep working.

---

## Setup

### 1. Network

Put the guest on a host-only network. The defaults in the code assume:

| Machine | Address |
|---|---|
| Host (VMnet1) | `192.168.45.1` |
| Guest | `192.168.45.10` |
| Subnet | `192.168.45.0/24` |

If your VMnet1 uses a different subnet, set `SANDBOX_GUEST_NET` on the host. Allow inbound TCP port `5000` from that subnet in the host firewall.

### 2. Host

```powershell
pip install flask requests

$env:VT_API_KEY = "your-virustotal-api-key"
python server_final.py
```

Open the dashboard at **`http://192.168.45.1:5000/scans`**. `localhost` is deliberately blocked, so use the VMnet1 address.

### 3. Guest

```powershell
pip install pefile requests yara-python
```

1. Copy `watcher-final-pe-v2.py` and `rules.yar` to `C:\Sandbox\`.
2. Extract `Rules.zip` to `C:\Sandbox\Rules\`.
3. Create `C:\Sandbox\Watch\`, the folder that will be monitored.

---

## Usage

**Interactive** (`s` = start, `x` = stop, `q` = quit):

```powershell
python watcher-final-pe-v2.py
```

**Unattended** (for a `vmrun`-driven runner):

```powershell
python watcher-final-pe-v2.py --autostart --scan-existing --log C:\Sandbox\watcher.log
```

Drop a file into `C:\Sandbox\Watch` and it appears on the dashboard within seconds. VirusTotal lookups on the free tier can take longer.

**Options** (CLI flag > environment variable > default):

| Flag | Environment variable | Default |
|---|---|---|
| `--server` | `SANDBOX_SERVER` | `http://192.168.45.1:5000` |
| `--folder` | `SANDBOX_FOLDER` | `C:\Sandbox\Watch` |
| `--yara-rules` | `SANDBOX_YARA_RULES` | `C:\Sandbox\rules.yar;C:\Sandbox\Rules` |
| `--vt-mode` | `SANDBOX_VT_MODE` | `proxy` (`proxy` \| `direct` \| `off`) |
| `--vt-upload` | `SANDBOX_VT_UPLOAD=1` | off |
| `--autostart` | – | start watching immediately |
| `--scan-existing` | – | also scan files already in the folder |
| `--log` | – | also write the log to a file |

**VirusTotal modes**

- `proxy` (default): the guest calls the host's `/vt` route, which adds the API key.
- `direct`: the guest calls VirusTotal itself and needs `VT_API_KEY` in its own environment.
- `off`: no VirusTotal lookups.

> **Privacy:** by default only the file's **SHA-256** is sent to VirusTotal. Enabling `--vt-upload` sends files VirusTotal has never seen to a third party, so keep it off for anything sensitive.

---

## Configuration reference

### Server (host) environment variables

| Variable | Default | Purpose |
|---|---|---|
| `VT_API_KEY` | – | VirusTotal key. Required for proxy mode. |
| `SANDBOX_BIND` | `0.0.0.0` | Address to bind. Set to `192.168.45.1` to bind only to VMnet1. |
| `SANDBOX_PORT` | `5000` | Port. |
| `SANDBOX_GUEST_NET` | `192.168.45.0/24` | Comma-separated networks allowed to reach the server. |
| `VT_ALLOW_UPLOAD` | `1` | Set to `0` to refuse sample uploads through the proxy. |

Scans are kept in `scans.db` (SQLite) and **purged after 7 days**.

---

## Dashboard and API

| Route | Description |
|---|---|
| `GET /scans` | Live scan history with stats, session grouping and filename filter |
| `GET /scan/<id>` | Detail page: per-layer scores, VirusTotal result and the "Why was this flagged?" explanation |
| `POST /report` | Watcher submits a result (validated before storage) |
| `GET /api/scan/<sha256>` | Latest stored result as JSON, or `404 {"status": "pending"}` |
| `/vt/<path>` | Allow-listed VirusTotal proxy: hash lookup, upload and analysis polling only |

---

## Security design

- **Isolated network.** Every route, including the dashboard, accepts connections only from the configured VMnet1 subnet. Everything else gets `403`.
- **The guest is treated as untrusted.** `/report` validates types, lengths and the SHA-256 format before anything reaches the database, and the dashboard HTML-escapes all stored values.
- **Key isolation.** The VirusTotal API key exists only on the host. The proxy forwards only three request patterns: hash lookup, file upload (under 32 MB) and analysis polling.
- **No debugger.** The server runs with `debug=False`, because Werkzeug's debugger allows code execution and must never be reachable from a network that malware can touch.
- **No execution.** Samples are read and hashed, never run.

Run AMSA only inside an isolated lab VM. Take a snapshot of the guest before use and do not give it internet access except through the host proxy.

---

## Limitations

- Static analysis only. Heavily obfuscated or novel malware with no signature, no suspicious imports and no VirusTotal history can be missed.
- PE heuristics apply to `.exe`, `.dll`, `.scr`, `.sys` and `.ocx` files. Other file types rely on YARA and VirusTotal.
- Thresholds and weights are hand-tuned, not learned from a labelled dataset.
- The free VirusTotal tier is rate-limited, so large batches may get `N/A` for VirusTotal.
- The dashboard loads HTMX from a CDN (`unpkg.com`), so the browser opening it needs internet access.

---

## Future work

- A labelled benchmark with precision, recall and F1 per layer and for the fused verdict
- Dynamic behavioural analysis (process, file, registry and network monitoring) with snapshot revert after each run
- Calibrating thresholds and weights from data, possibly with a learned classifier
- Fuzzy hashing and file-type-specific analysers for scripts and documents
- Mapping findings to MITRE ATT&CK techniques and exporting reports in standard formats

---

## Team

Developed as the *Advanced Programming with Project-I / Minor Project* at the **College of Technology, Silver Oak University**.

- **Ansh Bhavsar** – Enrollment No. 2301030700006
- **Darshan Kumavat** – Enrollment No. 2301030700026

**Internal guide:** Mr. Sunny Mesuriya, Department of Computer Science and Engineering

---

## Disclaimer

AMSA is an academic project intended for use in isolated lab environments. It is a triage aid, not a replacement for a full antivirus or EDR product. A `CLEAN` verdict means that none of the three static layers flagged the file, not that the file is safe.
