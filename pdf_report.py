# pdf_report.py
# ZeroThreat v3.0 PDF Report Generator (reportlab)
#
# Output: PDF bytes (for /api/report/pdf)
#
# Requires:
#   python -m pip install reportlab

from __future__ import annotations

from io import BytesIO
from datetime import datetime
from typing import Any, Dict, List, Tuple

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether
)


def _safe(s: Any) -> str:
    if s is None:
        return ""
    return str(s).replace("\r", " ").replace("\n", " ").strip()


def _pick(result: Dict[str, Any], *keys: str, default=None):
    for k in keys:
        if k in result and result[k] not in (None, ""):
            return result[k]
    return default


def _severity_rank(sev: str) -> int:
    s = (sev or "").lower()
    if "critical" in s:
        return 0
    if "high" in s:
        return 1
    if "medium" in s:
        return 2
    if "low" in s:
        return 3
    return 4


def _collect_findings(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Tries to support different result shapes:
      - result["findings"]
      - result["web_findings"], result["network_findings"]
      - result["vulnerabilities"]
    """
    findings: List[Dict[str, Any]] = []

    for key in ("findings", "vulnerabilities", "network_findings", "web_findings"):
        v = result.get(key)
        if isinstance(v, list):
            for f in v:
                if isinstance(f, dict):
                    findings.append(f)

    # de-dup (best-effort)
    seen = set()
    out = []
    for f in findings:
        title = _safe(_pick(f, "title", "name", "issue", default="Finding"))
        sev = _safe(_pick(f, "severity", "level", default=""))
        fp = (title.lower(), sev.lower())
        if fp in seen:
            continue
        seen.add(fp)
        out.append(f)

    out.sort(key=lambda x: (_severity_rank(_pick(x, "severity", "level", default="")), _safe(_pick(x, "title", "name", default=""))))
    return out


def _collect_ports(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Supports:
      - result["open_ports"]
      - result["ports"]
      - result["port_findings"]
    """
    for key in ("open_ports", "ports", "port_findings"):
        v = result.get(key)
        if isinstance(v, list) and v and isinstance(v[0], dict):
            return v
    return []


def _collect_crawl(result: Dict[str, Any]) -> Dict[str, Any]:
    # could be "crawl", "crawl_result", "crawler"
    for key in ("crawl", "crawl_result", "crawler"):
        v = result.get(key)
        if isinstance(v, dict):
            return v
    return {}


def _collect_passive(result: Dict[str, Any]) -> Dict[str, Any]:
    for key in ("passive", "passive_info", "recon", "recon_result"):
        v = result.get(key)
        if isinstance(v, dict):
            return v
    return {}


def generate_pdf(result: Dict[str, Any]) -> bytes:
    """
    Input: result dict (as stored in job['result'] or history DB)
    Output: PDF bytes
    """
    buf = BytesIO()

    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=1.8 * cm,
        bottomMargin=1.6 * cm,
        title="ZeroThreat VAPT Report"
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ZTTitle",
        parent=styles["Title"],
        fontSize=20,
        spaceAfter=10
    ))
    styles.add(ParagraphStyle(
        name="ZTSub",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.grey,
        spaceAfter=6
    ))
    styles.add(ParagraphStyle(
        name="ZTSection",
        parent=styles["Heading2"],
        fontSize=13,
        spaceBefore=12,
        spaceAfter=6
    ))
    styles.add(ParagraphStyle(
        name="ZTMono",
        parent=styles["Code"],
        fontName="Courier",
        fontSize=8,
        leading=10
    ))

    target = _safe(result.get("target", ""))
    scan_type = _safe(_pick(result, "scan_type", "type", default="both"))
    profile = _safe(_pick(result, "profile_name", "profile", default="normal"))
    started_at = _safe(_pick(result, "started_at", "timestamp", "time", default=""))
    risk_score = _pick(result, "risk_score", "score", default=None)
    risk_label = _safe(_pick(result, "risk_label", "label", default=""))
    stack = _safe(_pick(result, "stack", "tech_stack", default=""))

    # Title Page
    story: List[Any] = []
    story.append(Paragraph("ZeroThreat VAPT Report", styles["ZTTitle"]))
    story.append(Paragraph(f"Target: <b>{target}</b>", styles["Normal"]))
    story.append(Paragraph(f"Scan type: <b>{scan_type}</b> &nbsp;&nbsp; Profile: <b>{profile}</b>", styles["Normal"]))
    if started_at:
        story.append(Paragraph(f"Started: {started_at}", styles["ZTSub"]))
    story.append(Spacer(1, 10))

    # Summary box
    findings = _collect_findings(result)
    ports = _collect_ports(result)
    crawl = _collect_crawl(result)
    passive = _collect_passive(result)

    # count severities
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        sev = _safe(_pick(f, "severity", "level", default="")).lower()
        if "critical" in sev:
            sev_counts["Critical"] += 1
        elif "high" in sev:
            sev_counts["High"] += 1
        elif "medium" in sev:
            sev_counts["Medium"] += 1
        elif "low" in sev:
            sev_counts["Low"] += 1

    summary_rows = [
        ["Overall Risk", f"{risk_score}/10 ({risk_label})" if risk_score is not None else risk_label],
        ["Findings", f"{len(findings)}  (C:{sev_counts['Critical']}  H:{sev_counts['High']}  M:{sev_counts['Medium']}  L:{sev_counts['Low']})"],
        ["Open Ports", str(len(ports))],
        ["Crawl", f"URLs: {len(crawl.get('urls', []) or [])}   Forms: {len(crawl.get('forms', []) or [])}   Params: {len(crawl.get('params', []) or [])}"],
        ["Tech/Stack", stack if stack else "—"],
    ]

    t = Table(summary_rows, colWidths=[3.2 * cm, 12.8 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#CBD5E1")),
        ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#94A3B8")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 1), (0, -1), colors.HexColor("#F1F5F9")),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t)
    story.append(Spacer(1, 8))

    story.append(Paragraph(
        "Disclaimer: Use this tool only on targets you own or have explicit permission to test.",
        styles["ZTSub"]
    ))

    story.append(PageBreak())

    # Findings section
    story.append(Paragraph("Findings", styles["ZTSection"]))
    if not findings:
        story.append(Paragraph("No findings recorded.", styles["Normal"]))
    else:
        for i, f in enumerate(findings, 1):
            title = _safe(_pick(f, "title", "name", "issue", default=f"Finding {i}"))
            sev = _safe(_pick(f, "severity", "level", default=""))
            score = _safe(_pick(f, "score", "cvss", "adjusted_score", default=""))
            affected = _safe(_pick(f, "affected", "endpoint", "port", "path", default=""))
            desc = _safe(_pick(f, "description", "details", default=""))
            rec = _safe(_pick(f, "recommendation", "fix", "remediation", default=""))
            evidence = f.get("evidence") or f.get("request_snippet") or f.get("response_snippet") or ""

            header = f"<b>{i}. [{sev}]</b> {title}"
            if score:
                header += f"  <font color='#64748B'>(score: {score})</font>"
            story.append(Paragraph(header, styles["Normal"]))
            if affected:
                story.append(Paragraph(f"<b>Affected:</b> {affected}", styles["Normal"]))
            if desc:
                story.append(Paragraph(f"<b>Description:</b> {desc}", styles["Normal"]))
            if evidence:
                story.append(Paragraph("<b>Evidence:</b>", styles["Normal"]))
                story.append(Paragraph(_safe(evidence), styles["ZTMono"]))
            if rec:
                story.append(Paragraph(f"<b>Recommendation:</b> {rec}", styles["Normal"]))
            story.append(Spacer(1, 8))

    story.append(PageBreak())

    # Ports section
    story.append(Paragraph("Open Ports & Services", styles["ZTSection"]))
    if not ports:
        story.append(Paragraph("No open ports recorded.", styles["Normal"]))
    else:
        rows = [["Port", "Proto", "Service", "Confidence", "Version", "Banner (short)"]]
        for pinfo in ports[:200]:
            port = _safe(_pick(pinfo, "port", default=""))
            proto = _safe(_pick(pinfo, "proto", "protocol", default="TCP"))
            service = _safe(_pick(pinfo, "service", "name", default=""))
            conf = _safe(_pick(pinfo, "confidence", "conf", default=""))
            version = _safe(_pick(pinfo, "version", default=""))
            banner = _safe(_pick(pinfo, "banner", default=""))
            if len(banner) > 80:
                banner = banner[:80] + "…"
            rows.append([port, proto, service, conf, version, banner])

        tbl = Table(rows, repeatRows=1, colWidths=[1.3*cm, 1.5*cm, 3.0*cm, 2.2*cm, 2.5*cm, 6.5*cm])
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 9),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#CBD5E1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(tbl)

    story.append(PageBreak())

    # Recon/Crawl
    story.append(Paragraph("Recon & Crawl", styles["ZTSection"]))

    # Passive
    if passive:
        story.append(Paragraph("<b>Passive Recon</b>", styles["Normal"]))
        # Try common fields
        dns = passive.get("dns") or passive.get("dns_records") or {}
        headers = passive.get("headers") or passive.get("http_headers") or {}
        tls = passive.get("tls") or passive.get("tls_cert") or {}

        if tls:
            story.append(Paragraph(f"TLS: {_safe(tls)}", styles["Normal"]))
        if dns:
            story.append(Paragraph(f"DNS: {_safe(dns)}", styles["Normal"]))
        if headers:
            story.append(Paragraph(f"HTTP Headers: {_safe(headers)}", styles["Normal"]))
        story.append(Spacer(1, 6))

    # Crawl
    if crawl:
        urls = crawl.get("urls") or []
        forms = crawl.get("forms") or []
        params = crawl.get("params") or crawl.get("parameters") or []
        emails = crawl.get("emails") or []

        story.append(Paragraph("<b>Crawl Summary</b>", styles["Normal"]))
        story.append(Paragraph(f"URLs discovered: {len(urls)}", styles["Normal"]))
        story.append(Paragraph(f"Forms discovered: {len(forms)}", styles["Normal"]))
        story.append(Paragraph(f"Params discovered: {len(params)}", styles["Normal"]))
        if emails:
            story.append(Paragraph(f"Emails found: {', '.join([_safe(e) for e in emails[:10]])}", styles["Normal"]))
        story.append(Spacer(1, 6))

        if urls:
            story.append(Paragraph("<b>Top URLs</b>", styles["Normal"]))
            story.append(Paragraph("<br/>".join(_safe(u) for u in urls[:40]), styles["ZTMono"]))
            story.append(Spacer(1, 6))

        if forms:
            story.append(Paragraph("<b>Forms</b>", styles["Normal"]))
            lines = []
            for f in forms[:20]:
                if isinstance(f, dict):
                    method = _safe(f.get("method", ""))
                    action = _safe(f.get("action", f.get("url", "")))
                    fields = f.get("fields") or f.get("inputs") or []
                    if isinstance(fields, list):
                        fields = ", ".join(_safe(x) for x in fields[:20])
                    lines.append(f"{method} {action} | fields: {fields}")
                else:
                    lines.append(_safe(f))
            story.append(Paragraph("<br/>".join(lines), styles["ZTMono"]))
            story.append(Spacer(1, 6))

    # AI analysis (if present)
    ai = _pick(result, "ai_analysis", "analysis", "ai_summary", default="")
    if ai:
        story.append(Spacer(1, 8))
        story.append(Paragraph("AI Risk Assessment", styles["ZTSection"]))
        story.append(Paragraph(_safe(ai).replace("\n", "<br/>"), styles["Normal"]))

    # Footer/header
    def _on_page(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.grey)
        canvas.drawString(2 * cm, 1.0 * cm, f"ZeroThreat v3.0 • {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        canvas.drawRightString(A4[0] - 2 * cm, 1.0 * cm, f"Page {doc.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
    return buf.getvalue()