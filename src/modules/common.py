"""Shared helpers for collector modules: HTTP session, CSV and PDF writers, result shape."""
import csv
import os
from dataclasses import dataclass, field

import requests

import logger_config

log = logger_config.get_logger(__name__)


@dataclass
class Result:
    """What every collector module returns to main.py."""
    name: str                      # short id, e.g. "sonarqube"
    title: str                     # heading used in the Word document
    status: str = "PASS"           # PASS / WARN / FAIL / ERROR
    summary: dict = field(default_factory=dict)    # key -> value shown as a table
    findings: list = field(default_factory=list)   # list of dicts (rows)
    files: list = field(default_factory=list)      # generated report paths
    notes: str = ""
    explanations: list = field(default_factory=list)   # known CVEs: cve, severity, packages, definition, justification


def session(verify=True, auth=None, token=None, timeout=60):
    s = requests.Session()
    s.verify = verify
    if auth:
        s.auth = auth
    if token:
        s.headers["Authorization"] = f"Bearer {token}"
    s.headers["Accept"] = "application/json"
    s.request_timeout = timeout
    return s


def get(s, url, **kw):
    r = s.get(url, timeout=getattr(s, "request_timeout", 60), **kw)
    r.raise_for_status()
    return r


def verify_flag(insecure, ca_bundle=None):
    if insecure:
        log.warning("TLS verification is disabled (lab use only)")
        requests.packages.urllib3.disable_warnings()
        return False
    return ca_bundle or True


def write_csv(path, rows, columns=None):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    columns = columns or (list(rows[0].keys()) if rows else ["info"])
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        w.writeheader()
        for row in rows or []:
            w.writerow(row)
    return path


def write_pdf(path, title, summary, rows, columns, max_rows=500):
    """Simple landscape PDF: title, summary table, findings table."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    styles = getSampleStyleSheet()
    cell = styles["BodyText"].clone("cell", fontSize=7, leading=9)
    doc = SimpleDocTemplate(path, pagesize=landscape(A4), leftMargin=24, rightMargin=24,
                            topMargin=24, bottomMargin=24)
    story = [Paragraph(title, styles["Title"]), Spacer(1, 8)]

    if summary:
        t = Table([[k, str(v)] for k, v in summary.items()], colWidths=[180, 400])
        t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                               ("BACKGROUND", (0, 0), (0, -1), colors.whitesmoke),
                               ("FONTSIZE", (0, 0), (-1, -1), 8)]))
        story += [t, Spacer(1, 12)]

    if rows:
        shown = rows[:max_rows]
        data = [[Paragraph(f"<b>{c}</b>", cell) for c in columns]]
        data += [[Paragraph(_esc(_clip(r.get(c, ""))), cell) for c in columns] for r in shown]
        width = (landscape(A4)[0] - 48) / len(columns)
        t = Table(data, colWidths=[width] * len(columns), repeatRows=1)
        t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
                               ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                               ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story.append(t)
        if len(rows) > max_rows:
            story.append(Paragraph(f"{len(rows) - max_rows} more rows in the CSV report.", styles["Italic"]))
    else:
        story.append(Paragraph("No findings.", styles["BodyText"]))
    doc.build(story)
    return path


def export(outdir, name, title, summary, rows, columns, formats):
    files = []
    if "csv" in formats:
        files.append(write_csv(os.path.join(outdir, f"{name}.csv"), rows, columns))
    if "pdf" in formats:
        files.append(write_pdf(os.path.join(outdir, f"{name}.pdf"), title, summary, rows, columns))
    log.debug("Exported %d rows to %s", len(rows), ", ".join(files) or "no files")
    return files


def _clip(v, limit=600):
    """A table row can't span PDF pages, so very long text would otherwise fail the PDF build."""
    v = str(v)
    return v if len(v) <= limit else v[:limit] + "... [shortened: full text in the CSV and Word draft]"


def _esc(v):
    return str(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def env(name, default=None):
    v = os.environ.get(name)
    return v if v not in (None, "") else default
