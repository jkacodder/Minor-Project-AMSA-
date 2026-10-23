from flask import Flask, request, jsonify, render_template_string, Response, abort
from datetime import datetime, timedelta
import ipaddress
import os
import re
import sqlite3
import html

import requests

app = Flask(__name__)

# -----------------------------
# VM-sandbox configuration
# -----------------------------
# All of these can be overridden with environment variables.

# Address to bind. 0.0.0.0 = every adapter. To be stricter, set
# SANDBOX_BIND=192.168.45.1 (the host's VMnet1 address) and browse the
# dashboard at http://192.168.45.1:5000 instead.
BIND_HOST = os.environ.get("SANDBOX_BIND", "0.0.0.0")
BIND_PORT = int(os.environ.get("SANDBOX_PORT", "5000"))

# Only these networks may reach the server at all (the VMnet1 subnet).
GUEST_NETS = [
    ipaddress.ip_network(n.strip())
    for n in os.environ.get("SANDBOX_GUEST_NET", "192.168.45.0/24").split(",")
    if n.strip()
]
print(f"[CONFIG] Subnet(s) allowed to reach this server: {[str(n) for n in GUEST_NETS]}")

# VirusTotal key lives ONLY on the host; the guest never sees it.
VT_BASE = "https://www.virustotal.com/api/v3/"
VT_ALLOW_UPLOAD = os.environ.get("VT_ALLOW_UPLOAD", "1") == "1"
VT_ALLOWED = [
    ("GET", re.compile(r"^files/[A-Fa-f0-9]{64}$")),             # hash lookup
    ("POST", re.compile(r"^files$")),                             # upload (<32 MB)
    ("GET", re.compile(r"^analyses/[A-Za-z0-9=_\-]{1,200}$")),    # poll analysis
]

app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024  # VT direct-upload limit

SHA256_RE = re.compile(r"^[A-Fa-f0-9]{64}$")


@app.before_request
def restrict_access():
    """
    Every route, dashboard included, is only reachable from the isolated
    VMnet1 subnet (covers both the host's own 192.168.45.1 and the guest's
    192.168.45.10). 127.0.0.1/localhost is deliberately NOT allowed, so the
    dashboard must be opened via the VMnet1 IP, not localhost.
    """
    try:
        addr = ipaddress.ip_address(request.remote_addr)
    except ValueError:
        abort(403)

    if any(addr in net for net in GUEST_NETS):
        return None

    abort(403)


DB_PATH = "scans.db"
PURGE_DAYS = 7


# -----------------------------
# Database
# -----------------------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            filesize INTEGER,
            extension TEXT,
            sha256 TEXT,
            yara_score INTEGER,
            yara_detail TEXT,
            pe_score INTEGER,
            pe_detail TEXT,
            vt_malicious INTEGER,
            vt_total INTEGER,
            risk_score INTEGER,
            risk_label TEXT,
            session_id TEXT,
            explanation TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()

    # Lightweight migration: if scans.db already existed from before YARA/PE
    # columns were added, ALTER it in place instead of requiring a fresh DB.
    existing_cols = {row["name"] for row in conn.execute("PRAGMA table_info(scans)")}
    for col, coltype in [
        ("yara_score", "INTEGER"),
        ("yara_detail", "TEXT"),
        ("pe_score", "INTEGER"),
        ("pe_detail", "TEXT"),
        ("session_id", "TEXT"),
        ("explanation", "TEXT"),
    ]:
        if col not in existing_cols:
            conn.execute(f"ALTER TABLE scans ADD COLUMN {col} {coltype}")
    conn.commit()
    conn.close()


def purge_old_scans(days=PURGE_DAYS):
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db()
    conn.execute("DELETE FROM scans WHERE timestamp < ?", (cutoff,))
    conn.commit()
    conn.close()


# -----------------------------
# Helpers
# -----------------------------

def format_size(size):
    if size is None:
        return "—"

    size = float(size)

    if size < 1024:
        return f"{int(size)} B"
    if size < 1024 ** 2:
        return f"{size / 1024:.1f} KB"
    if size < 1024 ** 3:
        return f"{size / (1024 ** 2):.1f} MB"

    return f"{size / (1024 ** 3):.1f} GB"


def risk_class(label):
    return {
        "HIGH": "risk-high",
        "MEDIUM": "risk-medium",
        "LOW": "risk-low",
        "CLEAN": "risk-clean"
    }.get(str(label).upper(), "risk-unknown")


def verdict_class(malicious):
    return "danger" if malicious and malicious > 0 else "safe"


def layer_class(score):
    """
    Same bucketing as risk_class, but for a single layer's raw 0-100 score.
    score=None means the layer was inconclusive/unavailable (no yara ruleset,
    non-PE file, etc.) rather than "clean" — kept visually distinct.
    """
    if score is None:
        return "layer-na"
    score = int(score)
    if score >= 80:
        return "layer-high"
    if score >= 50:
        return "layer-medium"
    if score >= 20:
        return "layer-low"
    return "layer-clean"


def layer_label(score):
    return "N/A" if score is None else str(int(score))


def get_scan_rows():
    purge_old_scans()

    conn = get_db()
    rows = conn.execute("""
        SELECT *
        FROM scans
        ORDER BY timestamp ASC, id ASC
    """).fetchall()
    conn.close()

    return rows


# -----------------------------
# Routes
# -----------------------------

@app.route("/")
def home():
    return "Sandbox server is running."


@app.route("/report", methods=["POST"])
def report():
    data = request.get_json(force=True, silent=True)
    if not isinstance(data, dict):
        return jsonify({"status": "error", "message": "JSON object expected"}), 400
    local_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[REPORT] Received scan: {data.get('filename', '<no filename>')}")

    # Core fields are required. YARA/PE fields are optional so that older
    # watcher versions (which don't send them) still work; they are stored
    # as NULL and shown as N/A on the dashboard.
    required = [
        "filename",
        "filesize",
        "extension",
        "sha256",
        "vt_malicious",
        "vt_total",
        "risk_score",
        "risk_label"
    ]

    missing = [key for key in required if key not in data]
    if missing:
        return jsonify({
            "status": "error",
            "missing": missing
        }), 400

    # The guest is untrusted: validate everything before it reaches the database
    # (a malformed value here would otherwise break the dashboard for everyone).
    if not SHA256_RE.match(str(data["sha256"])):
        return jsonify({"status": "error", "message": "invalid sha256"}), 400
    data["sha256"] = str(data["sha256"]).lower()
    data["filename"] = str(data["filename"])[:255]
    data["extension"] = str(data["extension"])[:16]
    data["risk_label"] = str(data["risk_label"])[:16]
    for key in ("filesize", "vt_malicious", "vt_total", "risk_score"):
        try:
            data[key] = int(data[key])
        except (TypeError, ValueError):
            return jsonify({"status": "error", "message": f"{key} must be an integer"}), 400
    for key in ("yara_score", "pe_score"):          # optional: None means N/A
        if data.get(key) is not None:
            try:
                data[key] = int(data[key])
            except (TypeError, ValueError):
                return jsonify({"status": "error", "message": f"{key} must be an integer"}), 400
    for key, max_len in (("yara_detail", 500), ("pe_detail", 500),
                         ("session_id", 32), ("explanation", 4000)):
        if data.get(key) is not None:
            data[key] = str(data[key])[:max_len]

    conn = get_db()

    conn.execute("""
        INSERT INTO scans (
            filename,
            filesize,
            extension,
            sha256,
            yara_score,
            yara_detail,
            pe_score,
            pe_detail,
            vt_malicious,
            vt_total,
            risk_score,
            risk_label,
            session_id,
            explanation,
            timestamp
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data["filename"],
        data["filesize"],
        data["extension"],
        data["sha256"],
        data.get("yara_score"),
        data.get("yara_detail"),
        data.get("pe_score"),
        data.get("pe_detail"),
        data["vt_malicious"],
        data["vt_total"],
        data["risk_score"],
        data["risk_label"],
        data.get("session_id"),
        data.get("explanation"),
        local_time
    ))

    conn.commit()
    conn.close()

    return jsonify({"status": "saved"}), 200


@app.route("/scans/table")
def scans_table_fragment():
    rows = get_scan_rows()

    if not rows:
        return """
        <tr>
            <td colspan="10">
                <div class="empty-state">
                    <div class="empty-icon">✓</div>
                    <div class="empty-title">No scans yet</div>
                    <div class="empty-text">Submitted scans will appear here automatically.</div>
                </div>
            </td>
        </tr>
        """

    table_rows = []
    session_numbers = {}          # session_id -> "Session N" (order of first appearance)
    session_counts = {}
    for row in rows:
        sid = row["session_id"]
        session_counts[sid] = session_counts.get(sid, 0) + 1
        if sid not in session_numbers:
            session_numbers[sid] = len(session_numbers) + 1
    current_session = object()    # sentinel so the first row always opens a group

    # IMPORTANT:
    # This is a DISPLAY NUMBER, not the SQLite primary key (which keeps
    # climbing after old rows are purged). Oldest scan is #1, newest is last.
    for display_id, row in enumerate(rows, start=1):
        sid = row["session_id"]
        if sid != current_session:
            current_session = sid
            n = session_counts[sid]
            scans_word = "scan" if n == 1 else "scans"
            if sid is None:
                title = "Earlier scans"
                sub = f"recorded before session tracking · {n} {scans_word}"
            else:
                title = f"Session {session_numbers[sid]}"
                sub = f"watcher started {html.escape(str(sid))} · {n} {scans_word}"
            table_rows.append(f"""
        <tr class="session-row">
            <td colspan="10">
                <span class="session-title">{title}</span>
                <span class="session-sub">{sub}</span>
            </td>
        </tr>
        """)

        filename = html.escape(str(row["filename"]))
        extension = html.escape(str(row["extension"] or "—"))
        sha256 = html.escape(str(row["sha256"] or ""))
        risk_label = html.escape(str(row["risk_label"] or "UNKNOWN"))

        malicious = int(row["vt_malicious"] or 0)
        total = int(row["vt_total"] or 0)
        risk_score = int(row["risk_score"] or 0)

        actual_id = int(row["id"])

        vt_class = "vt-danger" if malicious > 0 else "vt-safe"
        risk_cls = risk_class(risk_label)

        yara_score = row["yara_score"]
        yara_score = int(yara_score) if yara_score is not None else None
        yara_detail = html.escape(str(row["yara_detail"] or "—"))
        yara_cls = layer_class(yara_score)

        pe_score = row["pe_score"]
        pe_score = int(pe_score) if pe_score is not None else None
        pe_detail = html.escape(str(row["pe_detail"] or "—"))
        pe_cls = layer_class(pe_score)

        table_rows.append(f"""
        <tr class="scan-row" data-filename="{filename.lower()}">
            <td>
                <span class="scan-number">{display_id}</span>
            </td>

            <td>
                <a class="filename-link" href="/scan/{actual_id}">
                    <span class="file-icon">◈</span>
                    <span class="filename-text">{filename}</span>
                </a>
            </td>

            <td class="muted">{format_size(row["filesize"])}</td>

            <td>
                <span class="extension">{extension}</span>
            </td>

            <td>
                <span class="hash">{sha256[:16]}…</span>
            </td>

            <td>
                <span class="layer-badge {yara_cls}" title="{yara_detail}">
                    YARA <strong>{layer_label(yara_score)}</strong>
                </span>
            </td>

            <td>
                <span class="layer-badge {pe_cls}" title="{pe_detail}">
                    PE <strong>{layer_label(pe_score)}</strong>
                </span>
            </td>

            <td>
                <span class="vt-badge {vt_class}">
                    <span class="status-dot"></span>
                    {malicious}/{total}
                </span>
            </td>

            <td>
                <span class="risk-badge {risk_cls}">
                    {risk_label}
                    <strong>{risk_score}</strong>
                </span>
            </td>

            <td class="timestamp">
                {html.escape(str(row["timestamp"]))}
            </td>
        </tr>
        """)

    return "".join(table_rows)


@app.route("/scans")
def view_scans():
    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Malware Sandbox — Scan History</title>

    <script src="https://unpkg.com/htmx.org@1.9.10"></script>

    <style>
        :root {
            --bg: #f4f7fb;
            --surface: #ffffff;
            --surface-2: #f8fafc;
            --border: #e5eaf0;
            --text: #172033;
            --muted: #718096;
            --blue: #2563eb;
            --blue-soft: #eff6ff;
            --green: #059669;
            --green-soft: #ecfdf5;
            --red: #dc2626;
            --red-soft: #fef2f2;
            --yellow: #d97706;
            --yellow-soft: #fffbeb;
            --shadow: 0 12px 35px rgba(15, 23, 42, 0.07);
        }

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            background:
                radial-gradient(circle at top left, rgba(37, 99, 235, 0.07), transparent 30%),
                var(--bg);
            color: var(--text);
            font-family:
                Inter,
                ui-sans-serif,
                system-ui,
                -apple-system,
                BlinkMacSystemFont,
                "Segoe UI",
                sans-serif;
        }

        .page {
            max-width: 1400px;
            margin: 0 auto;
            padding: 38px 28px 60px;
        }

        /* Header */
        .topbar {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 24px;
            margin-bottom: 28px;
        }

        .eyebrow {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            font-size: 12px;
            font-weight: 800;
            letter-spacing: .12em;
            text-transform: uppercase;
            color: var(--blue);
            margin-bottom: 8px;
        }

        .live-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: #22c55e;
            box-shadow: 0 0 0 4px rgba(34, 197, 94, .12);
        }

        h1 {
            margin: 0;
            font-size: 32px;
            line-height: 1.1;
            letter-spacing: -0.035em;
        }

        .subtitle {
            margin: 9px 0 0;
            color: var(--muted);
            font-size: 14px;
        }

        .live-status {
            display: flex;
            align-items: center;
            gap: 9px;
            padding: 10px 14px;
            border: 1px solid var(--border);
            border-radius: 12px;
            background: rgba(255,255,255,.85);
            font-size: 13px;
            color: #475569;
            box-shadow: 0 4px 16px rgba(15, 23, 42, .04);
        }

        /* Stats */
        .stats {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 16px;
            margin-bottom: 22px;
        }

        .stat-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 19px;
            box-shadow: var(--shadow);
        }

        .stat-label {
            color: var(--muted);
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: .07em;
        }

        .stat-value {
            margin-top: 7px;
            font-size: 27px;
            font-weight: 800;
            letter-spacing: -0.025em;
        }

        .stat-note {
            margin-top: 5px;
            color: #94a3b8;
            font-size: 12px;
        }

        .stat-value.green { color: var(--green); }
        .stat-value.red { color: var(--red); }
        .stat-value.yellow { color: var(--yellow); }

        /* Main panel */
        .panel {
            overflow: hidden;
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 18px;
            box-shadow: var(--shadow);
        }

        .panel-head {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 20px;
            padding: 20px 22px;
            border-bottom: 1px solid var(--border);
        }

        .panel-title {
            margin: 0;
            font-size: 16px;
            font-weight: 800;
        }

        .panel-subtitle {
            margin-top: 4px;
            font-size: 12px;
            color: var(--muted);
        }

        .search-wrap {
            position: relative;
            width: min(330px, 100%);
        }

        .search-icon {
            position: absolute;
            left: 13px;
            top: 50%;
            transform: translateY(-50%);
            color: #94a3b8;
            font-size: 15px;
        }

        #search {
            width: 100%;
            border: 1px solid var(--border);
            border-radius: 11px;
            padding: 10px 13px 10px 36px;
            outline: none;
            background: var(--surface-2);
            color: var(--text);
            font-size: 13px;
            transition: .18s ease;
        }

        #search:focus {
            background: white;
            border-color: #93c5fd;
            box-shadow: 0 0 0 3px rgba(37, 99, 235, .09);
        }

        .table-wrap {
            overflow-x: auto;
        }

        table {
            width: 100%;
            min-width: 1280px;
            border-collapse: collapse;
        }

        thead {
            background: #f8fafc;
        }

        th {
            padding: 12px 18px;
            text-align: left;
            color: #64748b;
            font-size: 10px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: .09em;
            white-space: nowrap;
        }

        td {
            padding: 15px 18px;
            border-top: 1px solid #edf1f5;
            font-size: 13px;
            vertical-align: middle;
        }

        .session-row td {
            background: #eef2ff;
            padding: 10px 20px;
            border-top: 2px solid #c7d2fe;
            border-bottom: 1px solid #c7d2fe;
        }
        .session-title {
            font-weight: 700;
            color: #3730a3;
            margin-right: 12px;
        }
        .session-sub {
            font-size: 12px;
            color: #6366f1;
        }

        .scan-row {
            transition: background .15s ease;
        }

        .scan-row:hover {
            background: #f8fbff;
        }

        .scan-number {
            display: inline-flex;
            width: 30px;
            height: 30px;
            align-items: center;
            justify-content: center;
            border-radius: 9px;
            background: #f1f5f9;
            color: #475569;
            font-weight: 800;
            font-size: 12px;
        }

        .filename-link {
            display: inline-flex;
            align-items: center;
            gap: 10px;
            color: var(--text);
            text-decoration: none;
            font-weight: 700;
            max-width: 280px;
        }

        .filename-link:hover {
            color: var(--blue);
        }

        .file-icon {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 32px;
            height: 32px;
            border-radius: 9px;
            background: var(--blue-soft);
            color: var(--blue);
            flex: 0 0 auto;
        }

        .filename-text {
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .muted {
            color: var(--muted);
        }

        .extension {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 7px;
            background: #f1f5f9;
            color: #475569;
            font-size: 11px;
            font-weight: 700;
        }

        .hash {
            font-family: "SFMono-Regular", Consolas, monospace;
            color: #64748b;
            font-size: 11px;
        }

        .vt-badge,
        .risk-badge,
        .layer-badge {
            display: inline-flex;
            align-items: center;
            gap: 7px;
            padding: 6px 9px;
            border-radius: 999px;
            font-size: 11px;
            font-weight: 800;
            white-space: nowrap;
        }

        .layer-badge strong {
            opacity: .75;
        }

        .layer-high {
            background: var(--red-soft);
            color: var(--red);
        }

        .layer-medium {
            background: var(--yellow-soft);
            color: var(--yellow);
        }

        .layer-low {
            background: var(--blue-soft);
            color: var(--blue);
        }

        .layer-clean {
            background: var(--green-soft);
            color: var(--green);
        }

        .layer-na {
            background: #f1f5f9;
            color: #94a3b8;
        }

        .vt-safe {
            background: var(--green-soft);
            color: var(--green);
        }

        .vt-danger {
            background: var(--red-soft);
            color: var(--red);
        }

        .status-dot {
            width: 6px;
            height: 6px;
            border-radius: 50%;
            background: currentColor;
        }

        .risk-high {
            background: var(--red-soft);
            color: var(--red);
        }

        .risk-medium {
            background: var(--yellow-soft);
            color: var(--yellow);
        }

        .risk-low {
            background: var(--blue-soft);
            color: var(--blue);
        }

        .risk-clean {
            background: var(--green-soft);
            color: var(--green);
        }

        .risk-unknown {
            background: #f1f5f9;
            color: #64748b;
        }

        .risk-badge strong {
            opacity: .7;
        }

        .timestamp {
            color: #64748b;
            white-space: nowrap;
            font-size: 12px;
        }

        /* Empty state */
        .empty-state {
            padding: 65px 20px;
            text-align: center;
        }

        .empty-icon {
            width: 48px;
            height: 48px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            border-radius: 14px;
            background: var(--green-soft);
            color: var(--green);
            font-size: 22px;
            font-weight: 900;
        }

        .empty-title {
            margin-top: 14px;
            font-weight: 800;
        }

        .empty-text {
            margin-top: 5px;
            color: var(--muted);
            font-size: 13px;
        }

        /* Detail page */
        .detail-shell {
            max-width: 850px;
            margin: 0 auto;
        }

        .back-link {
            display: inline-block;
            margin-bottom: 18px;
            color: var(--blue);
            text-decoration: none;
            font-size: 13px;
            font-weight: 700;
        }

        .detail-card {
            background: white;
            border: 1px solid var(--border);
            border-radius: 18px;
            box-shadow: var(--shadow);
            overflow: hidden;
        }

        .detail-header {
            padding: 28px;
            border-bottom: 1px solid var(--border);
        }

        .detail-title {
            margin: 0;
            font-size: 26px;
            letter-spacing: -.03em;
            word-break: break-word;
        }

        .verdict {
            display: inline-flex;
            margin-top: 12px;
            padding: 7px 10px;
            border-radius: 999px;
            font-size: 11px;
            font-weight: 900;
            letter-spacing: .04em;
        }

        .verdict.safe {
            background: var(--green-soft);
            color: var(--green);
        }

        .verdict.danger {
            background: var(--red-soft);
            color: var(--red);
        }

        .detail-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
        }

        .detail-item {
            padding: 20px 28px;
            border-bottom: 1px solid var(--border);
        }

        .detail-item:nth-child(odd) {
            border-right: 1px solid var(--border);
        }

        .detail-label {
            display: block;
            margin-bottom: 7px;
            color: var(--muted);
            font-size: 10px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: .09em;
        }

        .detail-value {
            color: var(--text);
            font-size: 14px;
            font-weight: 650;
            word-break: break-word;
        }

        .detail-hash {
            font-family: "SFMono-Regular", Consolas, monospace;
            font-size: 12px;
        }

        @media (max-width: 900px) {
            .stats {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }

            .topbar,
            .panel-head {
                flex-direction: column;
                align-items: stretch;
            }

            .search-wrap {
                width: 100%;
            }
        }

        @media (max-width: 600px) {
            .page {
                padding: 24px 14px 40px;
            }

            h1 {
                font-size: 26px;
            }

            .stats {
                grid-template-columns: 1fr 1fr;
                gap: 10px;
            }

            .stat-card {
                padding: 15px;
            }

            .detail-grid {
                grid-template-columns: 1fr;
            }

            .detail-item:nth-child(odd) {
                border-right: 0;
            }
        }
    </style>
</head>

<body>
<div class="page">

    <div class="topbar">
        <div>
            <div class="eyebrow">
                <span class="live-dot"></span>
                Malware Analysis
            </div>
            <h1>Scan History</h1>
            <p class="subtitle">
                Recent sandbox submissions, VirusTotal results and risk assessments.
            </p>
        </div>

        <div class="live-status">
            <span class="live-dot"></span>
            Live — refreshes every 5 seconds
        </div>
    </div>

    <div class="stats" id="stats">
        <div class="stat-card">
            <div class="stat-label">Visible scans</div>
            <div class="stat-value" id="stat-total">—</div>
            <div class="stat-note">Last 7 days</div>
        </div>

        <div class="stat-card">
            <div class="stat-label">Clean</div>
            <div class="stat-value green" id="stat-clean">—</div>
            <div class="stat-note">No VT engines flagged</div>
        </div>

        <div class="stat-card">
            <div class="stat-label">Flagged</div>
            <div class="stat-value red" id="stat-flagged">—</div>
            <div class="stat-note">One or more VT detections</div>
        </div>

        <div class="stat-card">
            <div class="stat-label">High risk</div>
            <div class="stat-value yellow" id="stat-high">—</div>
            <div class="stat-note">Risk assessment</div>
        </div>
    </div>

    <div class="panel">

        <div class="panel-head">
            <div>
                <div class="panel-title">Recent scans</div>
                <div class="panel-subtitle">
                    Grouped by watcher session, oldest first.
                </div>
            </div>

            <div class="search-wrap">
                <span class="search-icon">⌕</span>
                <input
                    id="search"
                    type="text"
                    placeholder="Filter by filename..."
                    autocomplete="off"
                >
            </div>
        </div>

        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Filename</th>
                        <th>Size</th>
                        <th>Type</th>
                        <th>SHA-256</th>
                        <th>YARA</th>
                        <th>PE</th>
                        <th>VirusTotal</th>
                        <th>Risk</th>
                        <th>Timestamp</th>
                    </tr>
                </thead>

                <tbody
                    id="scan-table-body"
                    hx-get="/scans/table"
                    hx-trigger="load, every 5s"
                    hx-swap="innerHTML"
                ></tbody>
            </table>
        </div>
    </div>
</div>

<script>
    const search = document.getElementById("search");

    function applyFilter() {
        const query = search.value.toLowerCase().trim();

        let header = null;
        let visibleInGroup = 0;
        const finishGroup = () => {
            if (header) header.style.display = visibleInGroup > 0 ? "" : "none";
        };

        document.querySelectorAll("#scan-table-body tr").forEach(row => {
            if (row.classList.contains("session-row")) {
                finishGroup();
                header = row;
                visibleInGroup = 0;
            } else if (row.classList.contains("scan-row")) {
                const filename = row.dataset.filename || "";
                const match = filename.includes(query);
                row.style.display = match ? "" : "none";
                if (match) visibleInGroup++;
            }
        });
        finishGroup();
    }

    search.addEventListener("input", applyFilter);

    document.body.addEventListener("htmx:afterSwap", function(event) {
        if (event.detail.target.id === "scan-table-body") {
            applyFilter();
            updateStats();
        }
    });

    function updateStats() {
        const rows = [...document.querySelectorAll(".scan-row")];

        let clean = 0;
        let flagged = 0;
        let high = 0;

        rows.forEach(row => {
            const vt = row.children[7]?.textContent.trim() || "";
            const risk = row.children[8]?.textContent.trim() || "";

            if (vt.startsWith("0/")) {
                clean++;
            } else {
                flagged++;
            }

            if (risk.startsWith("HIGH")) {
                high++;
            }
        });

        document.getElementById("stat-total").textContent = rows.length;
        document.getElementById("stat-clean").textContent = clean;
        document.getElementById("stat-flagged").textContent = flagged;
        document.getElementById("stat-high").textContent = high;
    }

    // Initial stats once the first HTMX request completes.
    document.body.addEventListener("htmx:afterRequest", function(event) {
        if (event.detail.pathInfo?.requestPath === "/scans/table") {
            updateStats();
        }
    });
</script>

</body>
</html>
""")


@app.route("/scan/<int:scan_id>")
def scan_detail(scan_id):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM scans WHERE id = ?",
        (scan_id,)
    ).fetchone()
    conn.close()

    if not row:
        return "<h1>Scan not found</h1>", 404

    # Verdict comes from the final risk label (VT + YARA + PE combined), so a
    # file flagged only by local layers is not shown as "CLEAN".
    label = str(row["risk_label"] or "").upper()
    verdict = {
        "HIGH": "HIGH RISK",
        "MEDIUM": "MEDIUM RISK",
        "LOW": "LOW RISK",
        "CLEAN": "CLEAN",
    }.get(label, "UNKNOWN")
    verdict_cls = "safe" if label == "CLEAN" else "danger"

    return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ row["filename"] }} — Scan Details</title>

    <style>
        :root {
            --bg: #f4f7fb;
            --surface: #ffffff;
            --border: #e5eaf0;
            --text: #172033;
            --muted: #718096;
            --blue: #2563eb;
            --green: #059669;
            --green-soft: #ecfdf5;
            --red: #dc2626;
            --red-soft: #fef2f2;
            --shadow: 0 12px 35px rgba(15, 23, 42, 0.07);
        }

        * { box-sizing: border-box; }

        body {
            margin: 0;
            padding: 40px 20px 60px;
            background:
                radial-gradient(circle at top left, rgba(37, 99, 235, .07), transparent 30%),
                var(--bg);
            color: var(--text);
            font-family: Inter, ui-sans-serif, system-ui, sans-serif;
        }

        .shell {
            max-width: 850px;
            margin: auto;
        }

        .back {
            display: inline-block;
            margin-bottom: 18px;
            color: var(--blue);
            text-decoration: none;
            font-size: 13px;
            font-weight: 750;
        }

        .card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 18px;
            box-shadow: var(--shadow);
            overflow: hidden;
        }

        .header {
            padding: 28px;
            border-bottom: 1px solid var(--border);
        }

        h1 {
            margin: 0;
            font-size: 27px;
            letter-spacing: -.035em;
            word-break: break-word;
        }

        .verdict {
            display: inline-flex;
            margin-top: 13px;
            padding: 7px 11px;
            border-radius: 999px;
            font-size: 11px;
            font-weight: 900;
            letter-spacing: .05em;
        }

        .safe {
            color: var(--green);
            background: var(--green-soft);
        }

        .danger {
            color: var(--red);
            background: var(--red-soft);
        }

        .why {
            padding: 22px 28px 26px;
            border-top: 1px solid #e5e7eb;
        }
        .why ul {
            margin: 10px 0 0;
            padding-left: 20px;
            line-height: 1.6;
            color: #1f2937;
        }
        .why li { margin-bottom: 6px; }
        .session-note {
            font-size: 12px;
            color: #6b7280;
            margin-top: 4px;
        }

        .grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
        }

        .item {
            padding: 20px 28px;
            border-bottom: 1px solid var(--border);
        }

        .item:nth-child(odd) {
            border-right: 1px solid var(--border);
        }

        .label {
            display: block;
            margin-bottom: 7px;
            color: var(--muted);
            font-size: 10px;
            font-weight: 850;
            text-transform: uppercase;
            letter-spacing: .09em;
        }

        .value {
            font-size: 14px;
            font-weight: 650;
            word-break: break-word;
        }

        .hash {
            font-family: "SFMono-Regular", Consolas, monospace;
            font-size: 12px;
        }

        @media (max-width: 650px) {
            .grid {
                grid-template-columns: 1fr;
            }

            .item:nth-child(odd) {
                border-right: 0;
            }
        }
    </style>
</head>

<body>
<div class="shell">
    <a class="back" href="/scans">← Back to Scan History</a>

    <div class="card">
        <div class="header">
            <h1>{{ row["filename"] }}</h1>
            <span class="verdict {{ verdict_cls }}">{{ verdict }}</span>
        </div>

        <div class="grid">
            <div class="item">
                <span class="label">File Size</span>
                <div class="value">{{ row["filesize"] }} bytes</div>
            </div>

            <div class="item">
                <span class="label">Extension</span>
                <div class="value">{{ row["extension"] }}</div>
            </div>

            <div class="item">
                <span class="label">SHA-256</span>
                <div class="value hash">{{ row["sha256"] }}</div>
            </div>

            <div class="item">
                <span class="label">YARA</span>
                <div class="value">
                    {% if row["yara_score"] is not none %}
                        score {{ row["yara_score"] }}/100 — {{ row["yara_detail"] or "no detail" }}
                    {% else %}
                        inconclusive{% if row["yara_detail"] %} — {{ row["yara_detail"] }}{% endif %}
                    {% endif %}
                </div>
            </div>

            <div class="item">
                <span class="label">PE Heuristics</span>
                <div class="value">
                    {% if row["pe_score"] is not none %}
                        score {{ row["pe_score"] }}/100 — {{ row["pe_detail"] or "no detail" }}
                    {% else %}
                        inconclusive{% if row["pe_detail"] %} — {{ row["pe_detail"] }}{% endif %}
                    {% endif %}
                </div>
            </div>

            <div class="item">
                <span class="label">VirusTotal</span>
                <div class="value">
                    {{ row["vt_malicious"] }} / {{ row["vt_total"] }} engines flagged malicious
                </div>
            </div>

            <div class="item">
                <span class="label">Risk Assessment</span>
                <div class="value">
                    {{ row["risk_label"] }} — score {{ row["risk_score"] }}/100
                </div>
            </div>

            <div class="item">
                <span class="label">Scanned At</span>
                <div class="value">{{ row["timestamp"] }}</div>
                <div class="session-note">
                    {% if row["session_id"] %}Session started {{ row["session_id"] }}{% else %}Recorded before session tracking{% endif %}
                </div>
            </div>
        </div>

        <div class="why">
            <span class="label">Why was this flagged?</span>
            {% if row["explanation"] %}
            <ul>
                {% for line in row["explanation"].split("\n") %}
                <li>{{ line }}</li>
                {% endfor %}
            </ul>
            {% else %}
            <div class="value">No explanation recorded (scanned by an older watcher version).</div>
            {% endif %}
        </div>
    </div>
</div>
</body>
</html>
""", row=row, verdict=verdict, verdict_cls=verdict_cls)


# -----------------------------
# VirusTotal proxy (guest -> host -> VirusTotal)
# -----------------------------

@app.route("/vt/<path:subpath>", methods=["GET", "POST"])
def vt_proxy(subpath):
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        return jsonify({"error": "VT_API_KEY is not set on the host"}), 503

    if not any(m == request.method and rx.match(subpath) for m, rx in VT_ALLOWED):
        abort(404)

    headers = {"x-apikey": api_key}

    try:
        if request.method == "GET":
            upstream = requests.get(VT_BASE + subpath, headers=headers, timeout=30)
        else:
            if not VT_ALLOW_UPLOAD:
                return jsonify({"error": "sample upload is disabled on the host"}), 403
            upload = request.files.get("file")
            if upload is None:
                return jsonify({"error": "multipart field 'file' required"}), 400
            name = os.path.basename(upload.filename or "sample.bin")
            upstream = requests.post(
                VT_BASE + subpath,
                headers=headers,
                files={"file": (name, upload.stream)},
                timeout=120,
            )
    except requests.RequestException as exc:
        return jsonify({"error": f"upstream failure: {exc}"}), 502

    return Response(
        upstream.content,
        status=upstream.status_code,
        content_type=upstream.headers.get("Content-Type", "application/json"),
    )


# -----------------------------
# Host-side API (e.g. for a sandbox runner polling for a result)
# -----------------------------

@app.route("/api/scan/<sha256>")
def api_scan(sha256):
    if not SHA256_RE.match(sha256):
        return jsonify({"status": "error", "message": "invalid sha256"}), 400

    conn = get_db()
    row = conn.execute(
        "SELECT * FROM scans WHERE sha256 = ? ORDER BY id DESC LIMIT 1",
        (sha256.lower(),),
    ).fetchone()
    conn.close()

    if not row:
        return jsonify({"status": "pending"}), 404
    return jsonify(dict(row))


if __name__ == "__main__":
    init_db()
    # debug=False on purpose: Werkzeug's debugger allows code execution and
    # must never be reachable from a network that malware can touch.
    app.run(host=BIND_HOST, port=BIND_PORT, debug=False, threaded=True)