from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, Image
)
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.legends import Legend
from reportlab.pdfgen import canvas as canvas_module
from datetime import datetime
import os
import io

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "reports")

C_DARK   = colors.HexColor("#0D1B2A")
C_ACCENT = colors.HexColor("#E63946")
C_MID    = colors.HexColor("#1D3557")
C_LIGHT  = colors.HexColor("#F1FAEE")
C_GRAY   = colors.HexColor("#8D99AE")

SEV_BG = {"Critical":colors.HexColor("#E63946"),"High":colors.HexColor("#F4831F"),
          "Medium":colors.HexColor("#F4D03F"),"Low":colors.HexColor("#2ECC71"),
          "Info":colors.HexColor("#3498DB")}
SEV_FG = {"Critical":colors.white,"High":colors.white,
          "Medium":colors.HexColor("#1a1a1a"),"Low":colors.white,"Info":colors.white}

SEV_ORDER = ["Critical","High","Medium","Low","Info"]

PAGE_W, PAGE_H = A4


# ----------------------------------------------------------------------
# Custom canvas: draws accurate "Page X of Y" in a second pass
# ----------------------------------------------------------------------
class NumberedCanvas(canvas_module.Canvas):
    def __init__(self, *args, **kwargs):
        canvas_module.Canvas.__init__(self, *args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total_pages = len(self._saved_page_states)
        for i, state in enumerate(self._saved_page_states, 1):
            self.__dict__.update(state)
            self._draw_page_number(i, total_pages)
            canvas_module.Canvas.showPage(self)
        canvas_module.Canvas.save(self)

    def _draw_page_number(self, page_num, total_pages):
        self.setFillColor(C_GRAY)
        self.setFont("Helvetica", 7.5)
        self.drawRightString(PAGE_W - 1.2 * cm, 0.32 * cm,
                              f"Page {page_num} of {total_pages}")


def get_styles():
    def ps(name, **kw): return ParagraphStyle(name, **kw)
    return {
        "section": ps("sec", fontSize=13, textColor=C_DARK, fontName="Helvetica-Bold",
                       spaceBefore=12, spaceAfter=5),
        # tracked headings -> picked up for the Table of Contents / PDF bookmarks
        "sec_toc": ps("sec_toc", fontSize=13, textColor=C_DARK, fontName="Helvetica-Bold",
                       spaceBefore=12, spaceAfter=5),
        # invisible marker placed before each finding title so it can be
        # tracked for the TOC/bookmarks without affecting the visible layout
        "finding_toc": ps("finding_toc", fontSize=1, leading=1,
                       textColor=colors.white, spaceBefore=0, spaceAfter=0),
        "body":    ps("body", fontSize=10, textColor=C_DARK, fontName="Helvetica",
                       spaceAfter=4, leading=15),
        "code":    ps("code", fontSize=9, textColor=colors.HexColor("#2C3E50"),
                       fontName="Courier", backColor=colors.HexColor("#F4F6F7"),
                       borderPad=6, spaceAfter=4, leading=13),
    }


def page_template(target_url, scan_date):
    def draw(canvas_obj, doc):
        canvas_obj.saveState()
        canvas_obj.setFillColor(C_DARK)
        canvas_obj.rect(0, PAGE_H-1.1*cm, PAGE_W, 1.1*cm, fill=1, stroke=0)
        canvas_obj.setFillColor(C_LIGHT)
        canvas_obj.setFont("Helvetica-Bold", 9)
        canvas_obj.drawString(1.2*cm, PAGE_H-0.75*cm, "CYBER SUDARSHAN")
        canvas_obj.setFillColor(C_GRAY)
        canvas_obj.setFont("Helvetica", 8)
        canvas_obj.drawRightString(PAGE_W-1.2*cm, PAGE_H-0.75*cm, "CONFIDENTIAL SECURITY REPORT")
        canvas_obj.setFillColor(C_DARK)
        canvas_obj.rect(0, 0, PAGE_W, 0.9*cm, fill=1, stroke=0)
        canvas_obj.setFillColor(C_GRAY)
        canvas_obj.setFont("Helvetica", 7.5)
        canvas_obj.drawString(1.2*cm, 0.32*cm, f"Target: {target_url[:60]}")
        canvas_obj.drawCentredString(PAGE_W/2, 0.32*cm, f"Scan Date: {scan_date}")
        # "Page X of Y" is drawn by NumberedCanvas.save() in a second pass
        canvas_obj.restoreState()
    return draw


def compute_risk_score(counts):
    """0 (worst) - 100 (best) overall security score."""
    penalty = counts["Critical"]*25 + counts["High"]*12 + counts["Medium"]*5 + counts["Low"]*2
    return max(0, 100 - penalty)


def build_risk_gauge(score):
    d = Drawing(400, 50)
    bar_w, bar_h = 360, 22
    x0, y0 = 20, 12
    d.add(Rect(x0, y0, bar_w, bar_h, fillColor=colors.HexColor("#27384D"),
               strokeColor=None, rx=11, ry=11))
    fill_w = max(8, bar_w * score / 100)
    if score >= 70:
        bar_color = colors.HexColor("#2ECC71")
    elif score >= 40:
        bar_color = colors.HexColor("#F4D03F")
    else:
        bar_color = C_ACCENT
    d.add(Rect(x0, y0, fill_w, bar_h, fillColor=bar_color, strokeColor=None, rx=11, ry=11))
    d.add(String(x0 + bar_w/2, y0 + bar_h + 9, f"Security Score: {score} / 100",
                 fontName="Helvetica-Bold", fontSize=11, fillColor=C_DARK,
                 textAnchor="middle"))
    return d


def build_severity_chart(counts):
    filtered = [(s, counts[s]) for s in SEV_ORDER if counts[s] > 0]
    if not filtered:
        return None
    d = Drawing(420, 150)
    pie = Pie()
    pie.x, pie.y = 30, 10
    pie.width, pie.height = 130, 130
    pie.data = [v for _, v in filtered]
    pie.labels = [str(v) for _, v in filtered]
    pie.simpleLabels = 1
    pie.slices.strokeWidth = 0.75
    pie.slices.strokeColor = colors.white
    pie.slices.fontName = "Helvetica-Bold"
    pie.slices.fontColor = colors.white
    pie.slices.fontSize = 9
    for i, (s, _) in enumerate(filtered):
        pie.slices[i].fillColor = SEV_BG[s]
    d.add(pie)

    legend = Legend()
    legend.x, legend.y = 200, 110
    legend.dx, legend.dy = 8, 8
    legend.fontName = "Helvetica"
    legend.fontSize = 9
    legend.boxAnchor = "w"
    legend.columnMaximum = 5
    legend.alignment = "left"
    legend.colorNamePairs = [(SEV_BG[s], f"{s}  ({v})") for s, v in filtered]
    d.add(legend)
    return d


def build_cover(st, target_url, scan_date, counts):
    e = []
    e.append(Spacer(1, 2*cm))
    e.append(Paragraph("CYBER SUDARSHAN", ParagraphStyle("br", fontSize=32, leading=38,
        textColor=C_ACCENT, fontName="Helvetica-Bold", alignment=TA_CENTER, spaceAfter=10)))
    e.append(Paragraph("Web Vulnerability Assessment Report", ParagraphStyle("rt",
        fontSize=16, leading=20, textColor=C_MID, fontName="Helvetica", alignment=TA_CENTER, spaceAfter=8)))
    e.append(HRFlowable(width="100%", thickness=2, color=C_ACCENT))
    e.append(Spacer(1, 0.5*cm))
    e.append(Paragraph(f"<b>Target:</b> {target_url}", ParagraphStyle("ci",
        fontSize=11, textColor=C_DARK, fontName="Helvetica", alignment=TA_CENTER, spaceAfter=4)))
    e.append(Paragraph(f"<b>Date:</b> {scan_date}", ParagraphStyle("ci2",
        fontSize=11, textColor=C_DARK, fontName="Helvetica", alignment=TA_CENTER, spaceAfter=4)))
    e.append(Paragraph("Tool: Cyber Sudarshan Scanner v1.0  |  APCSIP2026 Project",
        ParagraphStyle("ci3", fontSize=9, textColor=C_GRAY, fontName="Helvetica",
        alignment=TA_CENTER, spaceAfter=8)))
    e.append(Spacer(1, 0.8*cm))
    badge_row = [[Paragraph(f"<b>{counts[s]}</b><br/>{s}", ParagraphStyle(f"b{s}",
        fontSize=11, textColor=SEV_FG[s], fontName="Helvetica-Bold", alignment=TA_CENTER))
        for s in SEV_ORDER]]
    bt = Table(badge_row, colWidths=[3*cm]*5, rowHeights=[1.6*cm])
    bt.setStyle(TableStyle(
        [("BACKGROUND",(i,0),(i,0),SEV_BG[s]) for i,s in enumerate(SEV_ORDER)] +
        [("ALIGN",(0,0),(-1,-1),"CENTER"),("VALIGN",(0,0),(-1,-1),"MIDDLE")]
    ))
    e.append(bt)
    e.append(Spacer(1, 0.7*cm))
    score = compute_risk_score(counts)
    gauge = build_risk_gauge(score)
    gauge.hAlign = "CENTER"
    e.append(gauge)
    e.append(PageBreak())
    return e


def build_toc_page(st, entries, page_offset):
    e = []
    e.append(Paragraph("Table of Contents", st["section"]))
    e.append(HRFlowable(width="100%", thickness=2, color=C_ACCENT))
    e.append(Spacer(1, 0.4*cm))
    rows = []
    for ent in entries:
        page_num = ent["page"] + page_offset
        fsize = 9 if ent["level"] == 1 else 11
        if ent["level"] == 1:
            text = f'&nbsp;&nbsp;&nbsp;&nbsp;<a href="#{ent["bm"]}" color="#1D3557">{ent["text"]}</a>'
        else:
            text = f'<a href="#{ent["bm"]}" color="#1D3557"><b>{ent["text"]}</b></a>'
        rows.append([
            Paragraph(text, ParagraphStyle(f"toc_{ent['bm']}", fontSize=fsize,
                fontName="Helvetica", textColor=C_DARK, leading=fsize+5)),
            Paragraph(str(page_num), ParagraphStyle(f"tocp_{ent['bm']}", fontSize=fsize,
                fontName="Helvetica", textColor=C_GRAY, alignment=TA_RIGHT)),
        ])
    if rows:
        t = Table(rows, colWidths=[14.5*cm, 1.5*cm])
        t.setStyle(TableStyle([
            ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
            ("LINEBELOW",(0,0),(-1,-1),0.3,colors.HexColor("#E0E0E0")),
            ("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5),
        ]))
        e.append(t)
    e.append(PageBreak())
    return e


def build_summary(st, target_url, recon_data, findings, counts):
    if counts["Critical"] > 0:
        rl,rc = "CRITICAL RISK", C_ACCENT
        txt = (f"Target <b>{target_url}</b> has <b>{counts['Critical']} critical vulnerabilities</b>. "
               "An attacker could gain full DB or server control. Immediate action required.")
    elif counts["High"] > 0:
        rl,rc = "HIGH RISK", colors.HexColor("#F4831F")
        txt = f"<b>{counts['High']} high-severity issues</b> found. Fix within 7 days."
    elif counts["Medium"] > 0:
        rl,rc = "MEDIUM RISK", colors.HexColor("#F4D03F")
        txt = f"<b>{counts['Medium']} medium-severity issues</b> found. Address within 30 days."
    else:
        rl,rc = "LOW RISK", colors.HexColor("#2ECC71")
        txt = f"No critical or high vulnerabilities found on <b>{target_url}</b>."
    e = []
    e.append(Paragraph("Executive Summary", st["sec_toc"]))
    e.append(HRFlowable(width="100%", thickness=1, color=C_ACCENT))
    e.append(Spacer(1, 0.3*cm))
    e.append(Paragraph(f"Overall Risk: <b>{rl}</b>", ParagraphStyle("rl",
        fontSize=13, textColor=rc, fontName="Helvetica-Bold", spaceAfter=8)))
    e.append(Paragraph(txt, st["body"]))
    e.append(Spacer(1, 0.3*cm))

    chart = build_severity_chart(counts)
    if chart is not None:
        chart.hAlign = "CENTER"
        e.append(chart)
        e.append(Spacer(1, 0.2*cm))

    e.append(Paragraph("Reconnaissance Summary", st["section"]))
    tech = ", ".join(recon_data.get("tech_stack",[])) or "Not identified"
    waf  = ", ".join(recon_data.get("waf",[])) or "None"
    rows = [["Metric","Value"],
            ["Technology Stack", tech],
            ["WAF / Firewall", waf],
            ["Subdomains Found", str(len(recon_data.get("subdomains",[])))],
            ["Security Header Score",
             f"{recon_data.get('header_audit',{}).get('score',0)} / "
             f"{recon_data.get('header_audit',{}).get('max_score',9)}"],
            ["Server", recon_data.get("server","Unknown")],
            ["Total Findings", str(sum(counts.values()))]]
    t = Table(rows, colWidths=[6*cm,10*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(1,0),C_DARK),("TEXTCOLOR",(0,0),(1,0),C_LIGHT),
        ("FONTNAME",(0,0),(1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),9),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_LIGHT,colors.white]),
        ("GRID",(0,0),(-1,-1),0.3,C_GRAY),
        ("LEFTPADDING",(0,0),(-1,-1),8),("TOPPADDING",(0,0),(-1,-1),5),
        ("BOTTOMPADDING",(0,0),(-1,-1),5)]))
    e.append(t)
    e.append(PageBreak())
    return e


def build_table(st, findings):
    e = []
    e.append(Paragraph("Vulnerability Summary", st["sec_toc"]))
    e.append(HRFlowable(width="100%", thickness=1, color=C_ACCENT))
    e.append(Spacer(1, 0.3*cm))
    rows = [["#","Vulnerability","Severity","CVSS","URL"]]
    for i,f in enumerate(findings,1):
        sev = f.get("severity","Info")
        rows.append([str(i),
            Paragraph(f["type"], ParagraphStyle("t",fontSize=9,fontName="Helvetica")),
            Paragraph(f"<b>{sev}</b>", ParagraphStyle("s",fontSize=9,
                textColor=SEV_FG.get(sev,colors.black),fontName="Helvetica-Bold")),
            str(f.get("cvss_score","-")),
            Paragraph(f["url"][:55], ParagraphStyle("u",fontSize=8,
                fontName="Helvetica",textColor=C_MID))])
    ts = TableStyle([
        ("BACKGROUND",(0,0),(-1,0),C_DARK),("TEXTCOLOR",(0,0),(-1,0),C_LIGHT),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),9),
        ("ALIGN",(0,0),(0,-1),"CENTER"),("ALIGN",(3,0),(3,-1),"CENTER"),
        ("GRID",(0,0),(-1,-1),0.3,C_GRAY),("LEFTPADDING",(0,0),(-1,-1),6),
        ("TOPPADDING",(0,0),(-1,-1),5),("BOTTOMPADDING",(0,0),(-1,-1),5),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[C_LIGHT,colors.white])])
    for i,f in enumerate(findings,1):
        ts.add("BACKGROUND",(2,i),(2,i),SEV_BG.get(f.get("severity","Info"),C_GRAY))
    t = Table(rows, colWidths=[0.7*cm,5.2*cm,2.2*cm,1.3*cm,7.6*cm])
    t.setStyle(ts)
    e.append(t)
    e.append(PageBreak())
    return e


def build_detail(st, f, idx):
    sev = f.get("severity","Info")
    e   = []
    # invisible marker -> picked up by afterFlowable for TOC + PDF bookmarks
    e.append(Paragraph(f"Finding #{idx}: {f['type']}", st["finding_toc"]))
    hdr = Table([[
        Paragraph(f"Finding #{idx}: {f['type']}", ParagraphStyle("fh",fontSize=13,
            textColor=C_LIGHT,fontName="Helvetica-Bold")),
        Paragraph(f"{sev}  |  CVSS: {f.get('cvss_score','-')}", ParagraphStyle("fs",
            fontSize=11,textColor=SEV_FG.get(sev,colors.white),
            fontName="Helvetica-Bold",alignment=TA_RIGHT)),
    ]], colWidths=[11*cm,6*cm])
    hdr.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,-1),C_MID),("VALIGN",(0,0),(-1,-1),"MIDDLE"),
        ("LEFTPADDING",(0,0),(-1,-1),10),("RIGHTPADDING",(0,0),(-1,-1),10),
        ("TOPPADDING",(0,0),(-1,-1),8),("BOTTOMPADDING",(0,0),(-1,-1),8)]))
    e.append(hdr)
    e.append(Spacer(1,0.2*cm))
    det = Table([
        ["URL",      f.get("url","-")[:80]],
        ["Ease",     f.get("ease_of_exploit","-")],
        ["Impact",   f.get("impact","-")],
        ["Priority", f.get("remediation_priority","-")],
    ], colWidths=[4*cm,13*cm])
    det.setStyle(TableStyle([
        ("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),("FONTSIZE",(0,0),(-1,-1),9),
        ("TEXTCOLOR",(1,0),(1,-1),C_MID),
        ("ROWBACKGROUNDS",(0,0),(-1,-1),[C_LIGHT,colors.white]),
        ("GRID",(0,0),(-1,-1),0.3,C_GRAY),("LEFTPADDING",(0,0),(-1,-1),8),
        ("TOPPADDING",(0,0),(-1,-1),4),("BOTTOMPADDING",(0,0),(-1,-1),4)]))
    e.append(det)
    e.append(Spacer(1,0.3*cm))
    e.append(Paragraph("Description", st["section"]))
    e.append(Paragraph(f.get("description","-"), st["body"]))
    if f.get("proof"):
        e.append(Spacer(1,0.2*cm))
        e.append(Paragraph("Proof / Payload", st["section"]))
        e.append(Paragraph(f["proof"], st["code"]))
    if f.get("screenshot") and os.path.exists(f["screenshot"]):
        e.append(Spacer(1,0.2*cm))
        e.append(Paragraph("Screenshot Evidence", st["section"]))
        try:
            e.append(Image(f["screenshot"],width=15*cm,height=8*cm,kind="proportional"))
        except Exception:
            pass
    e.append(Spacer(1,0.2*cm))
    e.append(Paragraph("Recommended Fix", st["section"]))
    e.append(Paragraph(f.get("fixSnippet","No fix snippet available."), st["code"]))
    e.append(Spacer(1,0.4*cm))
    e.append(HRFlowable(width="100%",thickness=0.5,color=C_GRAY))
    return e


def build_body_story(st, target_url, recon_data, findings, counts):
    """Everything that comes after the cover + TOC pages."""
    body = []
    body += build_summary(st, target_url, recon_data, findings, counts)
    body += build_table(st, findings)
    body.append(Paragraph("Detailed Findings", st["sec_toc"]))
    body.append(HRFlowable(width="100%", thickness=2, color=C_ACCENT))
    body.append(Spacer(1, 0.4*cm))
    for i, f in enumerate(findings, 1):
        body += build_detail(st, f, i)
        if i % 3 == 0:
            body.append(PageBreak())
    body.append(PageBreak())
    body.append(Paragraph("Disclaimer", st["section"]))
    body.append(Paragraph(
        "This report was generated by Yatendra Dixit as part of a APCSIP2026 Internship. "
        "For authorized security testing only. Use only on targets with explicit written permission.",
        st["body"]))
    return body


def make_tracking_doc_template(base_cls, toc_entries):
    """Returns a DocTemplate subclass that records (text, page, bookmark)
    for every heading flagged with the 'sec_toc' / 'finding_toc' styles,
    and also registers real PDF bookmarks/outline entries for navigation."""
    class TrackingDocTemplate(base_cls):
        def afterFlowable(self, flowable):
            if isinstance(flowable, Paragraph):
                style_name = getattr(flowable.style, "name", "")
                if style_name in ("sec_toc", "finding_toc"):
                    text = flowable.getPlainText()
                    idx = len(toc_entries)
                    bm = f"bm_{idx}"
                    self.canv.bookmarkPage(bm)
                    level = 0 if style_name == "sec_toc" else 1
                    self.canv.addOutlineEntry(text, bm, level=level, closed=False)
                    toc_entries.append({"text": text, "page": self.page, "bm": bm, "level": level})
    return TrackingDocTemplate


def run(scan_id, target_url, findings, recon_data, emit):
    os.makedirs(REPORTS_DIR, exist_ok=True)
    scan_date   = datetime.now().strftime("%Y-%m-%d %H:%M UTC")
    report_path = os.path.join(REPORTS_DIR, f"report_{scan_id}.pdf")
    st          = get_styles()
    on_page     = page_template(target_url, scan_date)

    counts = {k: 0 for k in SEV_ORDER}
    for f in findings:
        counts[f.get("severity", "Info")] = counts.get(f.get("severity", "Info"), 0) + 1

    emit("Phase E: Reporting — Building PDF", 95)

    common_kwargs = dict(pagesize=A4, leftMargin=1.5*cm, rightMargin=1.5*cm,
                          topMargin=1.8*cm, bottomMargin=1.8*cm)

    # ---------- PASS 1 (dry run): figure out real page numbers for the TOC ----------
    dry_entries = []
    DryDoc = make_tracking_doc_template(SimpleDocTemplate, dry_entries)
    dry_buf = io.BytesIO()
    dry_doc = DryDoc(dry_buf, **common_kwargs)
    dry_story = build_body_story(st, target_url, recon_data, findings, counts)
    dry_doc.build(dry_story, onFirstPage=on_page, onLaterPages=on_page, canvasmaker=NumberedCanvas)

    toc_page_count = max(1, (len(dry_entries) // 32) + 1)
    page_offset = 1 + toc_page_count  # +1 cover page, +N TOC pages

    # ---------- PASS 2: real build with cover + TOC + accurate page numbers ----------
    real_entries = []
    RealDoc = make_tracking_doc_template(SimpleDocTemplate, real_entries)
    real_doc = RealDoc(report_path, title=f"Vuln Report — {target_url}",
                        author="Cyber Sudarshan Scanner", **common_kwargs)

    story = []
    story += build_cover(st, target_url, scan_date, counts)
    story += build_toc_page(st, dry_entries, page_offset)
    story += build_body_story(st, target_url, recon_data, findings, counts)

    emit("Phase E: Reporting — Writing PDF", 98)
    real_doc.build(story, onFirstPage=on_page, onLaterPages=on_page, canvasmaker=NumberedCanvas)
    emit(f"Phase E: Reporting — Saved: {report_path}", 99)
    return report_path