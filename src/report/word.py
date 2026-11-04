"""Writes the change request draft as a Word document."""
import datetime as dt
import os

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Pt, RGBColor

import logger_config

from .justification import business_justification, overall_status, risk_level, risk_mitigations

log = logger_config.get_logger(__name__)

STATUS_COLOUR = {"PASS": "C6EFCE", "WARN": "FFEB9C", "FAIL": "FFC7CE", "ERROR": "D9D9D9"}
IDENTIFIERS = {"Project", "Branch", "Image", "Digest", "Log source", "Dashboard"}   # not shown in summary table
MAX_ROWS_IN_DOC = 25      # top findings shown per section; the rest are in the attachments


def _shade(cell, hex_colour):
    tc = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_colour)
    tc.append(shd)


def _kv_table(doc, rows):
    t = doc.add_table(rows=0, cols=2, style="Table Grid")
    for k, v in rows:
        c = t.add_row().cells
        c[0].text, c[1].text = str(k), str(v)
        c[0].paragraphs[0].runs[0].bold = True
        _shade(c[0], "F2F2F2")
    return t


def _grid(doc, rows, columns):
    t = doc.add_table(rows=1, cols=len(columns), style="Table Grid")
    for i, c in enumerate(columns):
        t.rows[0].cells[i].text = c.replace("_", " ").title()
        t.rows[0].cells[i].paragraphs[0].runs[0].bold = True
        _shade(t.rows[0].cells[i], "D9E1F2")
    for r in rows:
        cells = t.add_row().cells
        for i, c in enumerate(columns):
            cells[i].text = str(r.get(c, ""))[:300]
    for row in t.rows:
        for cell in row.cells:
            for p in cell.paragraphs:
                for run in p.runs:
                    run.font.size = Pt(8)
    return t


def write(a, results, outdir):
    log.debug("Writing change request: status=%s, risk=%s, sections=%d",
              overall_status(results), risk_level(results), len(results))
    doc = Document()
    doc.styles["Normal"].font.name = "Calibri"
    doc.styles["Normal"].font.size = Pt(10)

    doc.add_heading(a.cr_title or f"Deploy {a.application} {a.release_version or ''}".strip(), 0)
    p = doc.add_paragraph(f"Draft generated {dt.datetime.now():%d %b %Y %H:%M} - review before submission.")
    p.runs[0].italic = True
    p.runs[0].font.color.rgb = RGBColor(0x80, 0x80, 0x80)
    if a.mock:
        p = doc.add_paragraph("MOCK DATA - this draft uses sample data, not real scan results. Do not submit it.")
        p.runs[0].bold = True
        p.runs[0].font.color.rgb = RGBColor(0xC0, 0x00, 0x00)

    doc.add_heading("1. Change details", 1)
    _kv_table(doc, [
        ("Change reference", a.cr_id or "TBC"), ("Application / service", a.application),
        ("Release version", a.release_version or "-"), ("Target environment", a.environment),
        ("Change type", a.change_type), ("Proposed window", a.change_window or "TBC"),
        ("Requested by", a.requester or "-"), ("Overall assurance status", overall_status(results)),
        ("Risk rating", risk_level(results)),
    ])

    doc.add_heading("2. Description of change", 1)
    doc.add_paragraph(a.cr_description or "Deployment of the release listed above via the standard pipeline.")

    doc.add_heading("3. Business justification", 1)
    for para in business_justification(a, results):
        doc.add_paragraph(para)

    doc.add_heading("4. Assurance summary", 1)
    t = doc.add_table(rows=1, cols=3, style="Table Grid")
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, h in enumerate(["Check", "Result", "Key points"]):
        t.rows[0].cells[i].text = h
        t.rows[0].cells[i].paragraphs[0].runs[0].bold = True
        _shade(t.rows[0].cells[i], "D9E1F2")
    for r in results:
        c = t.add_row().cells
        c[0].text, c[1].text = r.title, r.status
        _shade(c[1], STATUS_COLOUR.get(r.status, "FFFFFF"))
        key = [(k, v) for k, v in r.summary.items() if k not in IDENTIFIERS][:4]
        c[2].text = "; ".join(f"{k}: {v}" for k, v in key) or r.notes

    for n, r in enumerate(results, start=5):
        doc.add_heading(f"{n}. {r.title}", 1)
        if r.summary:
            _kv_table(doc, r.summary.items())
        if r.notes:
            doc.add_paragraph(r.notes).runs[0].italic = True
        if r.findings:
            cols = [c for c in r.findings[0].keys() if c not in ("url", "key", "sample_urls")][:6]
            doc.add_paragraph(f"Top {min(len(r.findings), MAX_ROWS_IN_DOC)} of {len(r.findings)} findings:")
            _grid(doc, r.findings[:MAX_ROWS_IN_DOC], cols)

    n = len(results) + 5
    doc.add_heading(f"{n}. Risk and mitigation", 1)
    for m in risk_mitigations(results):
        doc.add_paragraph(m, style="List Bullet")

    doc.add_heading(f"{n + 1}. Implementation and rollback", 1)
    doc.add_paragraph(a.implementation_plan or
                      "Deploy via the CI/CD pipeline; verify health checks, smoke tests and monitoring dashboards.")
    doc.add_paragraph("Rollback: " + (a.rollback_plan or
                      "Redeploy the previous known-good image tag and confirm service health."))

    doc.add_heading(f"{n + 2}. Attachments", 1)
    for r in results:
        for f in r.files:
            doc.add_paragraph(os.path.basename(f), style="List Bullet")

    doc.add_heading(f"{n + 3}. Approvals", 1)
    _kv_table(doc, [("Technical approver", ""), ("Security approver", ""), ("Service owner", ""),
                    ("CAB decision / date", "")])

    path = os.path.join(outdir, f"change_request_{(a.cr_id or a.application).replace(' ', '_')}.docx")
    doc.save(path)
    return path
