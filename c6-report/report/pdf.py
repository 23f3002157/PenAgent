"""Component 6: renders an AuditReport as a PDF. This is the actual service
output (GET /v1/audits/{audit}/report.pdf), not an out-of-band script --
anyone who can read the JSON report can get the same content as a document.

Pure function of an already-built AuditReport; no network, no extra queries.
Deterministic, same redaction guarantees as the JSON report (request_summary
entries are already public_result()-shaped -- hashes and booleans only).
"""
import io

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from penagent_common.models import AuditReport

NAVY = colors.HexColor("#163a5f")
LIGHT_BLUE = colors.HexColor("#eaf1f8")
SEV_COLORS = {
    "critical": colors.HexColor("#9f1a1a"), "high": colors.HexColor("#c0392b"),
    "medium": colors.HexColor("#b7791f"), "low": colors.HexColor("#4b7a3f"),
}

_styles = getSampleStyleSheet()
_styles.add(ParagraphStyle("RTitle", parent=_styles["Title"], fontSize=22, textColor=NAVY))
_styles.add(ParagraphStyle("RH1", parent=_styles["Heading1"], fontSize=14, textColor=NAVY, spaceBefore=14, spaceAfter=6))
_styles.add(ParagraphStyle("RBody", parent=_styles["Normal"], fontSize=9.5, leading=13.5, spaceAfter=4))
_styles.add(ParagraphStyle("RSmall", parent=_styles["Normal"], fontSize=8.3, leading=11, textColor=colors.HexColor("#555555")))
_styles.add(ParagraphStyle("RCell", parent=_styles["Normal"], fontSize=8.5, leading=11))
_styles.add(ParagraphStyle("RHead", parent=_styles["Normal"], fontSize=8.7, leading=10.5, textColor=colors.white, fontName="Helvetica-Bold"))
_styles.add(ParagraphStyle("RFindTitle", parent=_styles["Normal"], fontSize=11, leading=14, fontName="Helvetica-Bold", textColor=NAVY))


def _cell(text):
    return Paragraph(str(text), _styles["RCell"])


def _head(text):
    return Paragraph(str(text), _styles["RHead"])


def _table(header, rows, widths):
    data = [[_head(h) for h in header]] + [[_cell(c) for c in r] for r in rows]
    t = Table(data, colWidths=widths, repeatRows=1)
    style = [("BACKGROUND", (0, 0), (-1, 0), NAVY), ("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
             ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
             ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5)]
    for i in range(1, len(data)):
        if i % 2 == 0:
            style.append(("BACKGROUND", (0, i), (-1, i), LIGHT_BLUE))
    t.setStyle(TableStyle(style))
    return t


def _finding_block(finding):
    sev_color = SEV_COLORS.get(finding.severity, colors.grey)
    bar = Table([[""]], colWidths=[6.3 * inch], rowHeights=[4])
    bar.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), sev_color)]))
    header = Table([[Paragraph(finding.title, _styles["RFindTitle"]),
                      Paragraph(f"{finding.severity.upper()} · CVSS {finding.cvss_score}", _styles["RSmall"])]],
                    colWidths=[4.6 * inch, 1.7 * inch])
    header.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("ALIGN", (1, 0), (1, 0), "RIGHT")]))
    rows = [
        bar, Spacer(1, 4), header,
        Paragraph(f"<b>Classification:</b> {finding.classification.value} (confidence {finding.confidence:.0%}) "
                  f"&nbsp;&nbsp;<b>CVSS vector:</b> {finding.cvss_vector}", _styles["RBody"]),
        Paragraph(f"<b>Reproduction chain:</b> {' → '.join(finding.probe_chain) or '(single probe)'}", _styles["RBody"]),
        Paragraph(f"<b>Evidence:</b> {finding.explanation}", _styles["RBody"]),
        Paragraph(f"<b>Remediation:</b> {finding.remediation}", _styles["RBody"]),
        Spacer(1, 10),
    ]
    return rows


def build_pdf(report: AuditReport) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.7 * inch, bottomMargin=0.7 * inch,
                             leftMargin=0.8 * inch, rightMargin=0.8 * inch,
                             title=f"PenAgent Audit Report — {report.audit_id}")
    story = []

    story.append(Paragraph("PenAgent Audit Report", _styles["RTitle"]))
    story.append(Paragraph(f"Audit <b>{report.audit_id}</b> against target <b>{report.target_id}</b>", _styles["RBody"]))
    import datetime
    generated = datetime.datetime.fromtimestamp(report.generated_at, tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    story.append(Paragraph(f"Generated {generated} · {report.probes_executed} probe(s) executed", _styles["RSmall"]))
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", thickness=0.6, color=colors.HexColor("#bbbbbb")))

    story.append(Paragraph("Summary", _styles["RH1"]))
    if report.summary:
        story.append(_table(["Classification", "Count"], [[k, v] for k, v in report.summary.items()], [3.8 * inch, 1.5 * inch]))
    else:
        story.append(Paragraph("No interpreted probes yet.", _styles["RBody"]))

    story.append(Paragraph(f"Findings ({len(report.findings)})", _styles["RH1"]))
    if report.findings:
        for finding in sorted(report.findings, key=lambda f: f.cvss_score, reverse=True):
            story.extend(_finding_block(finding))
    else:
        story.append(Paragraph("No CONFIRMED_VULNERABILITY or STRONG_SIGNAL findings.", _styles["RBody"]))

    if report.observations:
        story.append(Paragraph(f"Observations — WEAK_SIGNAL ({len(report.observations)})", _styles["RH1"]))
        rows = [[o.get("method", ""), o.get("path", ""), o.get("owasp_category", ""), (o.get("reasoning_summary") or "")[:90]] for o in report.observations]
        story.append(_table(["Method", "Path", "OWASP category", "Reasoning"], rows, [0.6 * inch, 1.6 * inch, 1.5 * inch, 2.6 * inch]))

    if report.operational_issues:
        story.append(Paragraph(f"Operational issues — ERROR_CRASH ({len(report.operational_issues)})", _styles["RH1"]))
        story.append(Paragraph("A 5xx or transport failure: a potential logic/availability bug, never proof of a vulnerability.", _styles["RSmall"]))
        rows = [[o.get("method", ""), o.get("path", ""), (o.get("reasoning_summary") or "")[:110]] for o in report.operational_issues]
        story.append(_table(["Method", "Path", "Reasoning"], rows, [0.6 * inch, 1.8 * inch, 3.9 * inch]))

    story.append(Spacer(1, 16))
    story.append(HRFlowable(width="100%", thickness=0.4, color=colors.HexColor("#dddddd")))
    story.append(Paragraph("Generated by PenAgent Component 6. CVSS v3.1 scores are deterministic (no LLM), derived only "
                            "from operator-configured policy and probe metadata -- never from raw response content.", _styles["RSmall"]))

    doc.build(story)
    return buffer.getvalue()
