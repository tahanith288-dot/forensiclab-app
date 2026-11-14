from __future__ import annotations

import csv
import hashlib
import io
import json
import mimetypes
import os
import re
import secrets
import sqlite3
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Flask, abort, flash, redirect, render_template, request, send_file, url_for
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
REPORT_DIR = BASE_DIR / "reports"
DB_PATH = BASE_DIR / "forensics.db"
MAX_UPLOAD_BYTES = 20 * 1024 * 1024
ALLOWED_EXTENSIONS = {
    ".txt", ".log", ".csv", ".json", ".xml", ".md", ".eml",
    ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".docx", ".xlsx",
    ".zip", ".evtx", ".pcap", ".pcapng"
}

app = Flask(__name__)
app.secret_key = os.environ.get("CFL_SECRET_KEY") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=os.environ.get("RENDER", "") == "true")
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES

def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")

def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db() -> None:
    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_ref TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            priority TEXT NOT NULL,
            status TEXT NOT NULL,
            investigator TEXT NOT NULL,
            description TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            mime_type TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            evidence_type TEXT NOT NULL,
            notes TEXT DEFAULT '',
            acquired_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            evidence_id INTEGER REFERENCES evidence(id) ON DELETE SET NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            details TEXT NOT NULL,
            source TEXT NOT NULL,
            event_time TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE,
            action TEXT NOT NULL,
            details TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """)

def log_activity(case_id: int | None, action: str, details: str) -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO activity(case_id, action, details, created_at) VALUES(?,?,?,?)",
            (case_id, action, details, now_iso())
        )

def allowed_file(filename: str) -> bool:
    return Path(filename).suffix.lower() in ALLOWED_EXTENSIONS

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def classify_file(path: Path, original_name: str) -> tuple[str, str]:
    ext = Path(original_name).suffix.lower()
    mime = mimetypes.guess_type(original_name)[0] or "application/octet-stream"
    labels = {
        ".log": "System log", ".txt": "Text document", ".csv": "CSV dataset",
        ".json": "JSON data", ".xml": "XML data", ".eml": "Email message",
        ".pcap": "Network capture", ".pcapng": "Network capture",
        ".evtx": "Windows event log", ".pdf": "PDF document",
        ".png": "Image", ".jpg": "Image", ".jpeg": "Image", ".gif": "Image",
        ".zip": "Archive", ".docx": "Office document", ".xlsx": "Office spreadsheet"
    }
    return labels.get(ext, "Other file"), mime

def safe_text(path: Path, limit: int = 2_000_000) -> str | None:
    try:
        if path.stat().st_size > limit:
            return None
        raw = path.read_bytes()
        if b"\x00" in raw[:4096]:
            return None
        return raw.decode("utf-8-sig", errors="replace")
    except OSError:
        return None

SUSPICIOUS_PATTERNS = [
    ("Critical", "Possible credential dumping command", re.compile(r"\b(procdump|sekurlsa|lsass\.dmp|comsvcs\.dll)\b", re.I)),
    ("High", "PowerShell encoded command indicator", re.compile(r"powershell(?:\.exe)?[^\r\n]{0,160}-(?:enc|encodedcommand)\b", re.I)),
    ("High", "Potential persistence through scheduled task", re.compile(r"\bschtasks(?:\.exe)?\s+/create\b", re.I)),
    ("High", "Suspicious account or privilege change", re.compile(r"\b(net\s+user|net\s+localgroup)\b[^\r\n]{0,120}(?:/add|administrators)", re.I)),
    ("Medium", "Repeated authentication failure indicator", re.compile(r"(failed password|authentication failure|login failed|invalid password)", re.I)),
    ("Medium", "Port scanning indicator", re.compile(r"(nmap|masscan|syn scan|port scan)", re.I)),
    ("Medium", "Potential encoded or obfuscated content", re.compile(r"\b(base64|frombase64string)\b", re.I)),
]

def analyze_text(content: str) -> list[dict[str, str]]:
    findings = []
    lines = content.splitlines()
    for line_no, line in enumerate(lines, 1):
        for severity, title, pattern in SUSPICIOUS_PATTERNS:
            if pattern.search(line):
                findings.append({
                    "severity": severity,
                    "title": title,
                    "details": f"Matched rule on line {line_no}: {line[:500]}",
                    "source": f"Line {line_no}",
                    "event_time": now_iso()
                })
                break
    return findings[:500]

def extract_metadata(path: Path, original_name: str, size: int, mime: str) -> dict[str, Any]:
    stat = path.stat()
    return {
        "original_filename": original_name,
        "extension": Path(original_name).suffix.lower() or "(none)",
        "size_bytes": size,
        "mime_type": mime,
        "sha256": sha256_file(path),
        "modified_utc": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(timespec="seconds"),
        "analysis_scope": "Basic file metadata only; no execution or modification performed."
    }

def get_case(case_id: int):
    with db() as conn:
        row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    if row is None:
        abort(404)
    return row

@app.errorhandler(413)
def too_large(_error):
    flash("File exceeds the 20 MB upload limit.", "error")
    return redirect(request.referrer or url_for("dashboard"))

@app.route("/")
def dashboard():
    with db() as conn:
        stats = {
            "cases": conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0],
            "active": conn.execute("SELECT COUNT(*) FROM cases WHERE status='Open'").fetchone()[0],
            "evidence": conn.execute("SELECT COUNT(*) FROM evidence").fetchone()[0],
            "findings": conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
        }
        recent_cases = conn.execute("SELECT * FROM cases ORDER BY id DESC LIMIT 6").fetchall()
        recent_findings = conn.execute("""
            SELECT f.*, c.case_ref FROM findings f
            JOIN cases c ON c.id=f.case_id ORDER BY f.id DESC LIMIT 8
        """).fetchall()
        activity = conn.execute("SELECT * FROM activity ORDER BY id DESC LIMIT 8").fetchall()
    return render_template("dashboard.html", stats=stats, cases=recent_cases,
                           findings=recent_findings, activity=activity)

@app.route("/cases")
def cases():
    with db() as conn:
        rows = conn.execute("SELECT * FROM cases ORDER BY id DESC").fetchall()
    return render_template("cases.html", cases=rows)

@app.route("/cases/new", methods=["GET", "POST"])
def new_case():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        investigator = request.form.get("investigator", "").strip()
        if not title or not investigator:
            flash("Case title and investigator are required.", "error")
            return redirect(url_for("new_case"))
        ref = "CFL-" + datetime.now().strftime("%y%m%d") + "-" + secrets.token_hex(2).upper()
        with db() as conn:
            cur = conn.execute("""
                INSERT INTO cases(case_ref,title,category,priority,status,investigator,description,created_at)
                VALUES(?,?,?,?,?,?,?,?)
            """, (ref, title, request.form.get("category", "General"),
                  request.form.get("priority", "Medium"), "Open", investigator,
                  request.form.get("description", "").strip(), now_iso()))
            case_id = cur.lastrowid
        log_activity(case_id, "Case created", f"{ref} — {title}")
        flash(f"Case {ref} created.", "success")
        return redirect(url_for("case_detail", case_id=case_id))
    return render_template("case_new.html")

@app.route("/cases/<int:case_id>")
def case_detail(case_id):
    case = get_case(case_id)
    with db() as conn:
        evidence = conn.execute("SELECT * FROM evidence WHERE case_id=? ORDER BY id DESC", (case_id,)).fetchall()
        findings = conn.execute("SELECT * FROM findings WHERE case_id=? ORDER BY id DESC", (case_id,)).fetchall()
        activity = conn.execute("SELECT * FROM activity WHERE case_id=? ORDER BY id DESC LIMIT 15", (case_id,)).fetchall()
    return render_template("case_detail.html", case=case, evidence=evidence,
                           findings=findings, activity=activity)

@app.route("/cases/<int:case_id>/status", methods=["POST"])
def update_status(case_id):
    case = get_case(case_id)
    status = request.form.get("status", "")
    if status not in {"Open", "In Review", "Closed"}:
        abort(400)
    with db() as conn:
        conn.execute("UPDATE cases SET status=? WHERE id=?", (status, case_id))
    log_activity(case_id, "Status updated", f"{case['status']} → {status}")
    flash("Case status updated.", "success")
    return redirect(url_for("case_detail", case_id=case_id))

@app.route("/cases/<int:case_id>/upload", methods=["POST"])
def upload_evidence(case_id):
    case = get_case(case_id)
    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        flash("Choose a file to upload.", "error")
        return redirect(url_for("case_detail", case_id=case_id))
    original = secure_filename(uploaded.filename)
    if not original or not allowed_file(original):
        flash("This file type is not in the supported allowlist.", "error")
        return redirect(url_for("case_detail", case_id=case_id))
    data = uploaded.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        flash("File exceeds the 20 MB upload limit.", "error")
        return redirect(url_for("case_detail", case_id=case_id))
    stored = secrets.token_hex(12) + Path(original).suffix.lower()
    destination = UPLOAD_DIR / stored
    destination.write_bytes(data)
    digest = sha256_file(destination)
    evidence_type, mime = classify_file(destination, original)
    with db() as conn:
        cur = conn.execute("""
            INSERT INTO evidence(case_id,original_name,stored_name,file_size,mime_type,sha256,evidence_type,notes,acquired_at)
            VALUES(?,?,?,?,?,?,?,?,?)
        """, (case_id, original, stored, len(data), mime, digest, evidence_type,
              request.form.get("notes", "").strip(), now_iso()))
        evidence_id = cur.lastrowid
    log_activity(case_id, "Evidence acquired", f"{original} · SHA-256 {digest[:16]}…")
    flash("Evidence stored and SHA-256 calculated.", "success")
    return redirect(url_for("evidence_detail", evidence_id=evidence_id))

@app.route("/evidence/<int:evidence_id>")
def evidence_detail(evidence_id):
    with db() as conn:
        evidence = conn.execute("""
            SELECT e.*, c.case_ref, c.title AS case_title
            FROM evidence e JOIN cases c ON c.id=e.case_id WHERE e.id=?
        """, (evidence_id,)).fetchone()
    if evidence is None:
        abort(404)
    path = UPLOAD_DIR / evidence["stored_name"]
    metadata = extract_metadata(path, evidence["original_name"], evidence["file_size"], evidence["mime_type"])
    return render_template("evidence_detail.html", evidence=evidence, metadata=metadata)

@app.route("/evidence/<int:evidence_id>/analyze", methods=["POST"])
def analyze_evidence(evidence_id):
    with db() as conn:
        evidence = conn.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
    if evidence is None:
        abort(404)
    path = UPLOAD_DIR / evidence["stored_name"]
    text = safe_text(path)
    if text is None:
        flash("This file is not a supported readable text/log format. Integrity metadata is still available.", "warning")
        return redirect(url_for("evidence_detail", evidence_id=evidence_id))
    findings = analyze_text(text)
    with db() as conn:
        for item in findings:
            conn.execute("""
                INSERT INTO findings(case_id,evidence_id,severity,title,details,source,event_time,created_at)
                VALUES(?,?,?,?,?,?,?,?)
            """, (evidence["case_id"], evidence_id, item["severity"], item["title"],
                  item["details"], item["source"], item["event_time"], now_iso()))
    log_activity(evidence["case_id"], "Evidence analyzed",
                 f"{evidence['original_name']} · {len(findings)} rule matches")
    flash(f"Analysis complete: {len(findings)} potential indicator(s) found.", "success")
    return redirect(url_for("case_detail", case_id=evidence["case_id"]))

@app.route("/findings")
def findings_page():
    severity = request.args.get("severity", "")
    query = """
        SELECT f.*, c.case_ref, e.original_name
        FROM findings f JOIN cases c ON c.id=f.case_id
        LEFT JOIN evidence e ON e.id=f.evidence_id
    """
    params = ()
    if severity in {"Critical", "High", "Medium", "Low"}:
        query += " WHERE f.severity=?"
        params = (severity,)
    query += " ORDER BY f.id DESC"
    with db() as conn:
        rows = conn.execute(query, params).fetchall()
    return render_template("findings.html", findings=rows, selected=severity)

@app.route("/timeline")
def timeline():
    with db() as conn:
        rows = conn.execute("""
            SELECT f.event_time, f.severity, f.title, f.details, f.source, c.case_ref
            FROM findings f JOIN cases c ON c.id=f.case_id
            ORDER BY f.id DESC LIMIT 100
        """).fetchall()
    return render_template("timeline.html", events=rows)

@app.route("/reports/<int:case_id>.pdf")
def report_pdf(case_id):
    case = get_case(case_id)
    with db() as conn:
        evidence = conn.execute(
            "SELECT * FROM evidence WHERE case_id=? ORDER BY id", (case_id,)
        ).fetchall()
        findings = conn.execute(
            "SELECT * FROM findings WHERE case_id=? ORDER BY id", (case_id,)
        ).fetchall()

    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT, TA_CENTER
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            KeepTogether, HRFlowable
        )
        from xml.sax.saxutils import escape
    except ImportError:
        flash("Install reportlab with: pip install -r requirements.txt", "error")
        return redirect(url_for("case_detail", case_id=case_id))

    navy = colors.HexColor("#102944")
    deep_navy = colors.HexColor("#071426")
    blue = colors.HexColor("#315F94")
    pale_blue = colors.HexColor("#EAF1F8")
    light = colors.HexColor("#F4F7FB")
    ink = colors.HexColor("#1E293B")
    muted = colors.HexColor("#64748B")
    border = colors.HexColor("#D8E1EB")
    red = colors.HexColor("#A94452")
    amber = colors.HexColor("#98752E")
    green = colors.HexColor("#34745F")

    def safe(value, fallback="—"):
        value = "" if value is None else str(value).strip()
        return escape(value) if value else fallback

    def severity_color(value):
        value = str(value or "").lower()
        if value == "critical":
            return red
        if value == "high":
            return red
        if value == "medium":
            return amber
        return green

    output = io.BytesIO()
    doc = SimpleDocTemplate(
        output, pagesize=A4,
        rightMargin=17 * mm, leftMargin=17 * mm,
        topMargin=22 * mm, bottomMargin=19 * mm,
        title=f"Digital Investigation Report - {case['case_ref']}",
        author="Cyber Forensics Lab",
        subject="Digital forensic case report"
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="CoverBrand", parent=styles["Title"], fontName="Helvetica-Bold",
        fontSize=19, leading=23, textColor=navy, alignment=TA_LEFT,
        spaceAfter=3
    ))
    styles.add(ParagraphStyle(
        name="CoverSub", parent=styles["Normal"], fontSize=10,
        leading=14, textColor=muted, spaceAfter=14
    ))
    styles.add(ParagraphStyle(
        name="CaseTitle", parent=styles["Heading1"], fontName="Helvetica-Bold",
        fontSize=21, leading=25, textColor=deep_navy, spaceBefore=4,
        spaceAfter=7
    ))
    styles.add(ParagraphStyle(
        name="SectionTitle", parent=styles["Heading2"],
        fontName="Helvetica-Bold", fontSize=12, leading=15,
        textColor=navy, spaceBefore=13, spaceAfter=7
    ))
    styles.add(ParagraphStyle(
        name="BodyClean", parent=styles["BodyText"], fontSize=9,
        leading=13, textColor=ink, spaceAfter=4
    ))
    styles.add(ParagraphStyle(
        name="SmallClean", parent=styles["BodyText"], fontSize=7.3,
        leading=9.5, textColor=ink, wordWrap="CJK"
    ))
    styles.add(ParagraphStyle(
        name="MutedSmall", parent=styles["BodyText"], fontSize=7.5,
        leading=10, textColor=muted
    ))
    styles.add(ParagraphStyle(
        name="FindingTitle", parent=styles["BodyText"], fontSize=9,
        leading=12, textColor=ink
    ))
    styles.add(ParagraphStyle(
        name="ScopeNote", parent=styles["BodyText"], fontSize=8,
        leading=11, textColor=muted, leftIndent=7, rightIndent=7
    ))

    story = [
        Paragraph("CYBER FORENSICS LAB", styles["CoverBrand"]),
        Paragraph("DIGITAL EVIDENCE WORKSTATION  /  INVESTIGATION REPORT",
                  styles["CoverSub"]),
        HRFlowable(width="100%", thickness=1.2, color=blue, spaceAfter=13),
        Paragraph("DIGITAL INVESTIGATION REPORT", styles["MutedSmall"]),
        Paragraph(safe(case["title"]), styles["CaseTitle"]),
        Paragraph(
            f"<b>Case reference:</b> {safe(case['case_ref'])}"
            f" &nbsp;&nbsp; <b>Category:</b> {safe(case['category'])}",
            styles["BodyClean"]
        ),
        Spacer(1, 8),
    ]

    description = safe(case["description"], "No case description provided.")
    description_box = Table(
        [[Paragraph("<b>CASE DESCRIPTION</b><br/><br/>" + description,
                    styles["BodyClean"])]],
        colWidths=[176 * mm]
    )
    description_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), pale_blue),
        ("BOX", (0, 0), (-1, -1), 0.6, border),
        ("LINEBEFORE", (0, 0), (0, -1), 2.5, blue),
        ("LEFTPADDING", (0, 0), (-1, -1), 11),
        ("RIGHTPADDING", (0, 0), (-1, -1), 11),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.extend([description_box, Spacer(1, 12)])

    meta_data = [
        [
            Paragraph("<b>INVESTIGATOR</b><br/>" + safe(case["investigator"]),
                      styles["BodyClean"]),
            Paragraph("<b>PRIORITY</b><br/>" + safe(case["priority"]),
                      styles["BodyClean"]),
            Paragraph("<b>STATUS</b><br/>" + safe(case["status"]),
                      styles["BodyClean"]),
            Paragraph("<b>CREATED</b><br/>" + safe(case["created_at"]),
                      styles["BodyClean"]),
        ]
    ]
    meta_table = Table(meta_data, colWidths=[48 * mm, 34 * mm, 34 * mm, 60 * mm])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), light),
        ("BOX", (0, 0), (-1, -1), 0.6, border),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, border),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.extend([
        meta_table,
        Paragraph("01  /  EVIDENCE REGISTER", styles["SectionTitle"]),
        Paragraph(
            "Files acquired and recorded for this investigation. "
            "SHA-256 values are integrity fingerprints calculated by the application.",
            styles["MutedSmall"]
        ),
        Spacer(1, 6)
    ])

    evidence_data = [[
        Paragraph("<b>FILE</b>", styles["SmallClean"]),
        Paragraph("<b>TYPE</b>", styles["SmallClean"]),
        Paragraph("<b>SIZE</b>", styles["SmallClean"]),
        Paragraph("<b>SHA-256</b>", styles["SmallClean"])
    ]]
    for item in evidence:
        evidence_data.append([
            Paragraph(safe(item["original_name"]), styles["SmallClean"]),
            Paragraph(safe(item["evidence_type"]), styles["SmallClean"]),
            Paragraph(f"{int(item['file_size']):,} bytes", styles["SmallClean"]),
            Paragraph(safe(item["sha256"]), styles["SmallClean"])
        ])
    if len(evidence_data) == 1:
        evidence_data.append([
            Paragraph("No evidence registered for this case.", styles["SmallClean"]),
            "", "", ""
        ])

    evidence_table = Table(
        evidence_data, colWidths=[48 * mm, 34 * mm, 27 * mm, 67 * mm],
        repeatRows=1, hAlign="LEFT"
    )
    evidence_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), navy),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.45, border),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, light]),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.extend([evidence_table, Paragraph(
        "02  /  ANALYSIS FINDINGS", styles["SectionTitle"]
    )])

    if findings:
        for item in findings:
            severity = safe(item["severity"])
            finding_table = Table([[
                Paragraph(
                    f"<b>{severity.upper()}</b>",
                    ParagraphStyle(
                        name=f"Severity{item['id']}", parent=styles["SmallClean"],
                        textColor=colors.white, alignment=TA_CENTER,
                        fontName="Helvetica-Bold"
                    )
                ),
                Paragraph(
                    f"<b>{safe(item['title'])}</b><br/>{safe(item['details'])}",
                    styles["FindingTitle"]
                )
            ]], colWidths=[23 * mm, 153 * mm])
            finding_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (0, 0), severity_color(item["severity"])),
                ("BACKGROUND", (1, 0), (1, 0), light),
                ("BOX", (0, 0), (-1, -1), 0.5, border),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]))
            story.extend([KeepTogether([finding_table, Spacer(1, 6)])])
    else:
        story.append(Paragraph(
            "No rule-based findings recorded for this investigation.",
            styles["BodyClean"]
        ))

    story.extend([
        Spacer(1, 9),
        Paragraph("03  /  SCOPE AND HANDLING NOTE", styles["SectionTitle"]),
        Paragraph(
            "This report documents results produced by this application. "
            "Findings are indicators for human review and are not, by themselves, "
            "proof of malicious activity. Original evidence should be preserved "
            "and handled under an approved chain-of-custody process.",
            styles["ScopeNote"]
        )
    ])

    def draw_page(canvas, document):
        canvas.saveState()
        width, height = A4
        canvas.setStrokeColor(border)
        canvas.setLineWidth(0.5)
        canvas.line(17 * mm, height - 14 * mm, width - 17 * mm, height - 14 * mm)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(muted)
        canvas.drawString(17 * mm, height - 11 * mm, "CYBER FORENSICS LAB")
        canvas.drawRightString(width - 17 * mm, height - 11 * mm, "CONFIDENTIAL  /  CASE RECORD")
        canvas.line(17 * mm, 13 * mm, width - 17 * mm, 13 * mm)
        canvas.drawString(17 * mm, 8 * mm, safe(case["case_ref"]).replace("&amp;", "&"))
        canvas.drawRightString(width - 17 * mm, 8 * mm, f"Page {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=draw_page, onLaterPages=draw_page)
    output.seek(0)
    return send_file(
        output, mimetype="application/pdf", as_attachment=True,
        download_name=f"{case['case_ref']}-investigation-report.pdf"
    )

@app.route("/api/ingest", methods=["POST"])
def api_ingest():
    token = os.environ.get("CFL_API_TOKEN")
    if token and request.headers.get("Authorization") != f"Bearer {token}":
        return {"error": "Unauthorized"}, 401
    payload = request.get_json(silent=True) or {}
    required = ["case_ref", "message"]
    if any(not isinstance(payload.get(k), str) or not payload[k].strip() for k in required):
        return {"error": "case_ref and message are required strings"}, 400
    with db() as conn:
        case = conn.execute("SELECT * FROM cases WHERE case_ref=?", (payload["case_ref"],)).fetchone()
    if case is None:
        return {"error": "Case not found"}, 404
    message = payload["message"][:4000]
    matches = analyze_text(message)
    with db() as conn:
        for item in matches:
            conn.execute("""
                INSERT INTO findings(case_id,evidence_id,severity,title,details,source,event_time,created_at)
                VALUES(?,NULL,?,?,?,?,?,?)
            """, (case["id"], item["severity"], item["title"], item["details"],
                  "API event", payload.get("timestamp", now_iso()), now_iso()))
    log_activity(case["id"], "API event received", message[:180])
    return {"accepted": True, "findings_created": len(matches)}, 202

@app.route("/settings")
def settings():
    return render_template("settings.html", max_mb=MAX_UPLOAD_BYTES // (1024*1024),
                           allowed=", ".join(sorted(ALLOWED_EXTENSIONS)))

@app.route("/health")
def health():
    return {"status": "ok", "application": "Cyber Forensics Lab", "time": now_iso()}

@app.cli.command("seed-demo")
def seed_demo():
    """Create the synthetic demo case if the database is empty."""
    with db() as conn:
        exists = conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
    if exists:
        print("Database already contains cases; demo seed skipped.")
        return
    ensure_demo_environment()
    print("Demo case created.")

def ensure_demo_environment() -> None:
    """Initialize an isolated synthetic demo instance for hosted previews."""
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    init_db()
    with db() as conn:
        count = conn.execute("SELECT COUNT(*) FROM cases").fetchone()[0]
        if count == 0:
            cur = conn.execute(
                """INSERT INTO cases(case_ref,title,category,priority,status,investigator,description,created_at)
                   VALUES(?,?,?,?,?,?,?,?)""",
                ("CFL-DEMO-001", "Suspicious Authentication Activity", "Account Compromise",
                 "High", "Open", "Demo Investigator",
                 "Synthetic training case for demonstrating the digital evidence workflow. No real personal data is used.", now_iso())
            )
            case_id = cur.lastrowid
            demo_findings = [
                ("High", "PowerShell encoded command indicator", "Matched rule on line 4: powershell.exe -EncodedCommand SQBFAFgA", "Line 4"),
                ("Medium", "Repeated authentication failure indicator", "Matched rule on line 8: Failed password for demo_user", "Line 8")
            ]
            for severity, title, details, source in demo_findings:
                conn.execute(
                    """INSERT INTO findings(case_id,evidence_id,severity,title,details,source,event_time,created_at)
                       VALUES(?,NULL,?,?,?,?,?,?)""",
                    (case_id, severity, title, details, source, now_iso(), now_iso())
                )
            conn.execute(
                "INSERT INTO activity(case_id,action,details,created_at) VALUES(?,?,?,?)",
                (case_id, "Demo case initialized", "Synthetic demonstration records created", now_iso())
            )

# Initialize when imported by Gunicorn as well as when run locally.
ensure_demo_environment()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
