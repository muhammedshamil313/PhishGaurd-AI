"""
report_generator.py
===================
Generates a professional PDF security report from a PageReport object.
Uses ReportLab Platypus for clean, structured output.
"""

import math
import os
from datetime import datetime
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    HRFlowable,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus import KeepTogether
from reportlab.pdfgen import canvas as rl_canvas

from analyzer import PageReport, ContainerMetrics


# ── Brand palette ──────────────────────────────────────────────────────────────
C_BG        = colors.HexColor("#0a0b0f")
C_DARK      = colors.HexColor("#111318")
C_BORDER    = colors.HexColor("#1e2130")
C_BLUE      = colors.HexColor("#4f8fff")
C_BLUE_DARK = colors.HexColor("#2563eb")
C_LOW       = colors.HexColor("#3ddc84")
C_MED       = colors.HexColor("#ffb340")
C_HIGH      = colors.HexColor("#ff4757")
C_TEXT      = colors.HexColor("#1a1b2e")
C_MUTED     = colors.HexColor("#6b7280")
C_WHITE     = colors.white
C_LIGHT_BG  = colors.HexColor("#f8faff")
C_CARD_BG   = colors.HexColor("#f0f4ff")


def risk_color(risk: str) -> colors.Color:
    return {"HIGH": C_HIGH, "MEDIUM": C_MED, "LOW": C_LOW}.get(risk, C_MUTED)


def risk_emoji(risk: str) -> str:
    return {"HIGH": "HIGH RISK", "MEDIUM": "MEDIUM RISK", "LOW": "LOW RISK", "NONE": "NO LOGIN FORM"}.get(risk, risk)


# ── Page template with header/footer ─────────────────────────────────────────

class ReportCanvas(rl_canvas.Canvas):
    def __init__(self, *args, report_title="", **kwargs):
        super().__init__(*args, **kwargs)
        self._report_title = report_title
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self._draw_page(num_pages)
            super().showPage()
        super().save()

    def _draw_page(self, page_count):
        page_width, page_height = A4
        self.saveState()

        # Header bar
        self.setFillColor(C_BG)
        self.rect(0, page_height - 1.4*cm, page_width, 1.4*cm, fill=1, stroke=0)
        self.setFillColor(C_BLUE)
        self.rect(0, page_height - 1.4*cm, 0.4*cm, 1.4*cm, fill=1, stroke=0)
        self.setFillColor(C_WHITE)
        self.setFont("Helvetica-Bold", 7)
        self.drawString(0.8*cm, page_height - 0.85*cm, "SYMMETRY-BASED PHISHING GUARD")
        self.setFont("Helvetica", 7)
        self.setFillColor(colors.HexColor("#8899bb"))
        self.drawRightString(page_width - 0.8*cm, page_height - 0.85*cm, self._report_title[:80])

        # Footer
        self.setFillColor(C_LIGHT_BG)
        self.rect(0, 0, page_width, 0.9*cm, fill=1, stroke=0)
        self.setStrokeColor(C_BORDER)
        self.setLineWidth(0.5)
        self.line(0, 0.9*cm, page_width, 0.9*cm)
        self.setFillColor(C_MUTED)
        self.setFont("Helvetica", 7)
        self.drawString(0.8*cm, 0.35*cm, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  R = left_margin / right_margin  |  |R - 1| > 4% → HIGH RISK")
        self.drawRightString(page_width - 0.8*cm, 0.35*cm, f"Page {self._pageNumber} of {page_count}")

        self.restoreState()


# ── Style registry ─────────────────────────────────────────────────────────────

def build_styles():
    base = getSampleStyleSheet()
    styles = {}

    styles["title"] = ParagraphStyle(
        "title", fontName="Helvetica-Bold", fontSize=22,
        textColor=C_BG, leading=28, spaceAfter=4,
    )
    styles["subtitle"] = ParagraphStyle(
        "subtitle", fontName="Helvetica", fontSize=10,
        textColor=C_MUTED, leading=14, spaceAfter=2,
    )
    styles["section_head"] = ParagraphStyle(
        "section_head", fontName="Helvetica-Bold", fontSize=11,
        textColor=C_BG, leading=16, spaceBefore=14, spaceAfter=6,
        borderPad=0,
    )
    styles["body"] = ParagraphStyle(
        "body", fontName="Helvetica", fontSize=9,
        textColor=C_TEXT, leading=14, spaceAfter=4,
    )
    styles["mono"] = ParagraphStyle(
        "mono", fontName="Courier", fontSize=8,
        textColor=C_TEXT, leading=12, spaceAfter=2,
    )
    styles["mono_muted"] = ParagraphStyle(
        "mono_muted", fontName="Courier", fontSize=8,
        textColor=C_MUTED, leading=12,
    )
    styles["label"] = ParagraphStyle(
        "label", fontName="Helvetica-Bold", fontSize=8,
        textColor=C_MUTED, leading=12, spaceAfter=2,
    )
    styles["risk_tag"] = ParagraphStyle(
        "risk_tag", fontName="Helvetica-Bold", fontSize=13,
        textColor=C_WHITE, leading=18, alignment=TA_CENTER,
    )
    styles["score_big"] = ParagraphStyle(
        "score_big", fontName="Helvetica-Bold", fontSize=36,
        textColor=C_BG, leading=44, alignment=TA_CENTER,
    )
    styles["caption"] = ParagraphStyle(
        "caption", fontName="Helvetica", fontSize=8,
        textColor=C_MUTED, leading=11, alignment=TA_CENTER,
    )
    styles["verdict"] = ParagraphStyle(
        "verdict", fontName="Helvetica-Bold", fontSize=10,
        textColor=C_TEXT, leading=16, spaceAfter=4,
    )
    styles["formula"] = ParagraphStyle(
        "formula", fontName="Courier-Bold", fontSize=9,
        textColor=C_BLUE_DARK, leading=14, alignment=TA_CENTER,
    )

    return styles


# ── Section builders ──────────────────────────────────────────────────────────

def _hr(color=C_BORDER, thickness=0.5):
    return HRFlowable(width="100%", thickness=thickness, color=color, spaceAfter=6, spaceBefore=6)


def build_cover_section(report: PageReport, styles: dict) -> list:
    story = []

    # Risk badge table (colored header card)
    risk = report.overall_risk
    rc   = risk_color(risk)
    score = report.composite_score

    badge_data = [[
        Paragraph(risk_emoji(risk), styles["risk_tag"]),
    ]]
    badge_table = Table(badge_data, colWidths=[16.5*cm])
    badge_table.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (-1,-1), rc),
        ("TOPPADDING",  (0,0), (-1,-1), 10),
        ("BOTTOMPADDING",(0,0),(-1,-1), 10),
        ("ROUNDEDCORNERS", [6]),
    ]))
    story.append(badge_table)
    story.append(Spacer(1, 10))

    # Score + summary table
    verdict_text = {
        "HIGH":   "⚠  SIGNIFICANT ASYMMETRY DETECTED — Possible phishing clone. Login container "
                  "margins deviate >4% from perfect symmetry. Do NOT enter credentials.",
        "MEDIUM": "⚡  MILD ASYMMETRY DETECTED — Some alignment irregularities found. "
                  "Proceed with caution and verify the domain.",
        "LOW":    "✔  PAGE APPEARS SYMMETRIC — Login container margins are well-balanced. "
                  "Low risk of phishing clone based on symmetry analysis.",
        "NONE":   "ℹ  NO LOGIN FORM DETECTED — This page does not appear to contain a "
                  "login form. No symmetry analysis performed.",
    }

    sum_data = [
        [
            Paragraph("SYMMETRY SCORE", styles["label"]),
            Paragraph("OVERALL VERDICT", styles["label"]),
        ],
        [
            Paragraph(f"{score:.1f}<font size=9> / 100</font>", styles["score_big"]),
            Paragraph(verdict_text.get(risk, ""), styles["body"]),
        ],
    ]
    sum_table = Table(sum_data, colWidths=[5*cm, 11.5*cm])
    sum_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), C_CARD_BG),
        ("BACKGROUND",    (0,0), (-1, 0), C_LIGHT_BG),
        ("TOPPADDING",    (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("LEFTPADDING",   (0,0), (-1,-1), 10),
        ("RIGHTPADDING",  (0,0), (-1,-1), 10),
        ("LINEABOVE",     (0,1), (-1, 1), 0.5, C_BORDER),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("BOX",           (0,0), (-1,-1), 0.5, C_BORDER),
    ]))
    story.append(sum_table)
    story.append(Spacer(1, 12))

    # Page info table
    heuristic_rows = [
        ["PROPERTY", "VALUE"],
        ["URL", report.url[:80] + ("…" if len(report.url) > 80 else "")],
        ["Page Title", report.title[:70] or "—"],
        ["Domain", report.domain or "—"],
        ["Protocol", "HTTPS ✔" if report.uses_https else "HTTP ✘  (insecure)"],
        ["Login Keyword in URL", "Yes ⚠" if report.login_keyword_in_url else "No"],
        ["IP Address URL", "Yes ⚠  (suspicious)" if report.ip_address_url else "No"],
        ["Favicon Present", "Yes" if report.has_favicon else "No"],
        ["Login Forms Found", str(len(report.containers))],
        ["Scan Time", datetime.fromtimestamp(report.timestamp).strftime("%Y-%m-%d %H:%M:%S")],
    ]

    col_w = [4.5*cm, 12*cm]
    tbl = Table(heuristic_rows, colWidths=col_w)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C_BG),
        ("TEXTCOLOR",     (0, 0), (-1, 0), C_WHITE),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0), 8),
        ("FONTNAME",      (0, 1), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 1), (-1,-1), 8),
        ("TEXTCOLOR",     (0, 1), (0, -1), C_MUTED),
        ("BACKGROUND",    (0, 2), (-1, 2), C_CARD_BG),
        ("BACKGROUND",    (0, 4), (-1, 4), C_CARD_BG),
        ("BACKGROUND",    (0, 6), (-1, 6), C_CARD_BG),
        ("BACKGROUND",    (0, 8), (-1, 8), C_CARD_BG),
        ("TOPPADDING",    (0, 0), (-1,-1), 5),
        ("BOTTOMPADDING", (0, 0), (-1,-1), 5),
        ("LEFTPADDING",   (0, 0), (-1,-1), 8),
        ("GRID",          (0, 0), (-1,-1), 0.5, C_BORDER),
    ]))
    story.append(Paragraph("PAGE INFORMATION", styles["section_head"]))
    story.append(tbl)

    return story


def build_formula_section(styles: dict) -> list:
    story = []
    story.append(Paragraph("METHODOLOGY", styles["section_head"]))
    story.append(_hr())

    formula_data = [[
        Paragraph("Symmetry Ratio", styles["label"]),
        Paragraph("Risk Threshold", styles["label"]),
        Paragraph("Composite Score", styles["label"]),
    ], [
        Paragraph("R = left_margin / right_margin", styles["formula"]),
        Paragraph("|R - 1.0| > 4%  →  HIGH RISK", styles["formula"]),
        Paragraph("Score = dev% × 0.70 + child_misalign% × 0.30", styles["formula"]),
    ], [
        Paragraph("left_margin = container.x\nright_margin = viewport_width - (x + width)", styles["mono_muted"]),
        Paragraph("|R - 1.0| > 2%  →  MEDIUM\n|R - 1.0| ≤ 2%  →  LOW", styles["mono_muted"]),
        Paragraph("child_misalign = % of inputs/buttons\nwith own |R - 1| > 8%", styles["mono_muted"]),
    ]]

    ftbl = Table(formula_data, colWidths=[5.5*cm, 5.5*cm, 5.5*cm])
    ftbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C_LIGHT_BG),
        ("BACKGROUND",    (0, 1), (-1, 1), C_CARD_BG),
        ("BACKGROUND",    (0, 2), (-1, 2), C_WHITE),
        ("TOPPADDING",    (0, 0), (-1,-1), 8),
        ("BOTTOMPADDING", (0, 0), (-1,-1), 8),
        ("LEFTPADDING",   (0, 0), (-1,-1), 8),
        ("RIGHTPADDING",  (0, 0), (-1,-1), 8),
        ("GRID",          (0, 0), (-1,-1), 0.5, C_BORDER),
        ("VALIGN",        (0, 0), (-1,-1), "MIDDLE"),
        ("ALIGN",         (0, 0), (-1,-1), "CENTER"),
    ]))
    story.append(ftbl)
    return story


def build_container_section(report: PageReport, styles: dict) -> list:
    story = []
    story.append(Paragraph("LOGIN CONTAINER ANALYSIS", styles["section_head"]))
    story.append(_hr())

    if not report.containers:
        story.append(Paragraph("No login containers were detected on this page.", styles["body"]))
        return story

    for c in report.containers:
        rc = risk_color(c.risk_level)
        ratio_str = f"{c.symmetry_ratio:.4f}" if c.symmetry_ratio < 9000 else "∞"

        # Container header
        tag_str = f"<{c.tag}>"
        if c.id:
            tag_str += f"  #{c.id}"
        if c.classes:
            short_cls = c.classes[:50] + ("…" if len(c.classes) > 50 else "")
            tag_str += f"  .{short_cls}"

        header_data = [[
            Paragraph(f"Container #{c.index + 1}  —  {tag_str}", ParagraphStyle(
                "ch", fontName="Courier-Bold", fontSize=9, textColor=C_WHITE, leading=14,
            )),
            Paragraph(c.risk_level, ParagraphStyle(
                "rt", fontName="Helvetica-Bold", fontSize=9, textColor=C_WHITE,
                leading=14, alignment=TA_RIGHT,
            )),
        ]]
        htbl = Table(header_data, colWidths=[13*cm, 3.5*cm])
        htbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), C_BG),
            ("TOPPADDING",    (0,0), (-1,-1), 7),
            ("BOTTOMPADDING", (0,0), (-1,-1), 7),
            ("LEFTPADDING",   (0,0), (-1,-1), 10),
            ("RIGHTPADDING",  (0,0), (-1,-1), 10),
        ]))

        # Metrics table
        deviation_str = f"{c.deviation_pct:.2f}%"
        flag = "  ← FLAGGED" if c.deviation_pct > 4 else ("  ← WARNING" if c.deviation_pct > 2 else "")

        metrics = [
            ["METRIC", "VALUE", "NOTES"],
            ["Position (x, y)", f"({c.x}, {c.y}) px", f"Viewport: {c.viewport_width}px wide"],
            ["Size (w × h)", f"{c.width} × {c.height} px", "Login container dimensions"],
            ["Left Margin", f"{c.left_margin} px", "Distance from container left to viewport left"],
            ["Right Margin", f"{c.right_margin} px", "Distance from container right to viewport right"],
            ["Symmetry Ratio R", ratio_str, "R = left_margin / right_margin  (ideal = 1.0)"],
            ["Deviation |R−1|×100", deviation_str + flag, ">4% triggers HIGH RISK"],
            ["Child Misalignment", f"{c.child_misalign_pct:.1f}%", "% of inputs/buttons with own deviation >8%"],
            ["CSS margin-left", f"{c.css_margin_left} px", "Computed from window.getComputedStyle"],
            ["CSS margin-right", f"{c.css_margin_right} px", "Computed from window.getComputedStyle"],
            ["Composite Score", f"{c.composite_score:.1f} / 100", "dev×0.7 + child_misalign×0.3"],
        ]

        col_w = [4.5*cm, 3.5*cm, 8.5*cm]
        mtbl = Table(metrics, colWidths=col_w)
        risk_row_indices = [6]  # deviation row
        mtbl_style = [
            ("BACKGROUND",    (0, 0), (-1, 0), C_DARK),
            ("TEXTCOLOR",     (0, 0), (-1, 0), C_WHITE),
            ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, 0), 7.5),
            ("FONTNAME",      (0, 1), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE",      (0, 1), (-1,-1), 8),
            ("TEXTCOLOR",     (0, 1), (0, -1), C_MUTED),
            ("FONTNAME",      (1, 1), (1, -1), "Courier"),
            ("FONTSIZE",      (1, 1), (1, -1), 8),
            ("TEXTCOLOR",     (2, 1), (2, -1), C_MUTED),
            ("FONTSIZE",      (2, 1), (2, -1), 7.5),
            ("TOPPADDING",    (0, 0), (-1,-1), 5),
            ("BOTTOMPADDING", (0, 0), (-1,-1), 5),
            ("LEFTPADDING",   (0, 0), (-1,-1), 8),
            ("GRID",          (0, 0), (-1,-1), 0.5, C_BORDER),
            # Alternating rows
            ("BACKGROUND", (0, 2), (-1, 2), C_CARD_BG),
            ("BACKGROUND", (0, 4), (-1, 4), C_CARD_BG),
            ("BACKGROUND", (0, 6), (-1, 6), C_CARD_BG),
            ("BACKGROUND", (0, 8), (-1, 8), C_CARD_BG),
            ("BACKGROUND", (0,10), (-1,10), C_CARD_BG),
        ]
        # Highlight deviation row by risk
        if c.deviation_pct > 4:
            mtbl_style.append(("TEXTCOLOR", (1, 6), (1, 6), C_HIGH))
            mtbl_style.append(("FONTNAME",  (1, 6), (1, 6), "Courier-Bold"))
        elif c.deviation_pct > 2:
            mtbl_style.append(("TEXTCOLOR", (1, 6), (1, 6), C_MED))
            mtbl_style.append(("FONTNAME",  (1, 6), (1, 6), "Courier-Bold"))
        else:
            mtbl_style.append(("TEXTCOLOR", (1, 6), (1, 6), C_LOW))

        mtbl.setStyle(TableStyle(mtbl_style))

        story.append(KeepTogether([
            htbl,
            mtbl,
            Spacer(1, 12),
        ]))

    return story


def build_css_rules_section(css_rules: dict, styles: dict) -> list:
    story = []
    if not css_rules:
        return story

    story.append(Paragraph("CSS ANALYSIS — LOGIN-RELATED RULES", styles["section_head"]))
    story.append(_hr())
    story.append(Paragraph(
        "The following CSS selectors matching login-related patterns were extracted "
        "via BeautifulSoup from inline &lt;style&gt; blocks:",
        styles["body"]
    ))
    story.append(Spacer(1, 6))

    rows = [["SELECTOR", "margin-left", "margin-right", "padding-left", "padding-right"]]
    for sel, props in list(css_rules.items())[:20]:
        def fmt(v):
            return f"{v}px" if v is not None else "—"
        rows.append([
            sel[:45],
            fmt(props.get("margin_left")),
            fmt(props.get("margin_right")),
            fmt(props.get("padding_left")),
            fmt(props.get("padding_right")),
        ])

    col_w = [6.5*cm, 2.5*cm, 2.5*cm, 2.5*cm, 2.5*cm]
    tbl = Table(rows, colWidths=col_w)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C_BG),
        ("TEXTCOLOR",     (0, 0), (-1, 0), C_WHITE),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0), 7.5),
        ("FONTNAME",      (0, 1), (0, -1), "Courier"),
        ("FONTSIZE",      (0, 1), (-1,-1), 7.5),
        ("TEXTCOLOR",     (0, 1), (0, -1), C_BLUE_DARK),
        ("TOPPADDING",    (0, 0), (-1,-1), 4),
        ("BOTTOMPADDING", (0, 0), (-1,-1), 4),
        ("LEFTPADDING",   (0, 0), (-1,-1), 6),
        ("GRID",          (0, 0), (-1,-1), 0.5, C_BORDER),
        ("ROWBACKGROUNDS",(0, 1), (-1,-1), [C_WHITE, C_CARD_BG]),
    ]))
    story.append(tbl)
    return story


def build_recommendations_section(report: PageReport, styles: dict) -> list:
    story = []
    story.append(Paragraph("RECOMMENDATIONS", styles["section_head"]))
    story.append(_hr())

    recs = []

    if report.overall_risk == "HIGH":
        recs += [
            ("🔴 DO NOT enter credentials", "The login page shows >4% margin deviation, a hallmark of automated phishing kit cloning."),
            ("🔴 Verify the URL independently", "Type the official domain directly into your browser rather than clicking links."),
            ("🔴 Report the site", "Submit to Google Safe Browsing: https://safebrowsing.google.com/safebrowsing/report_phish/"),
        ]
    elif report.overall_risk == "MEDIUM":
        recs += [
            ("🟡 Verify domain carefully", "Check that the domain exactly matches the official service (watch for typosquatting)."),
            ("🟡 Inspect the SSL certificate", "Click the padlock in the browser bar and confirm the issuer matches the organization."),
        ]
    else:
        recs += [
            ("🟢 Page appears legitimate by symmetry analysis", "No significant asymmetry detected."),
        ]

    if not report.uses_https:
        recs.append(("🔴 HTTP (insecure)", "The page is not served over HTTPS. Never submit credentials on HTTP pages."))
    if report.ip_address_url:
        recs.append(("🔴 IP Address URL", "The URL uses a raw IP address instead of a domain — a common phishing indicator."))
    if report.login_keyword_in_url:
        recs.append(("🟡 Login keyword in URL", "URLs containing 'login', 'signin' can be legitimate but are also used in phishing."))

    rec_rows = [["FINDING", "DETAIL"]] + [[r[0], r[1]] for r in recs]
    rtbl = Table(rec_rows, colWidths=[5.5*cm, 11*cm])
    rtbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C_BG),
        ("TEXTCOLOR",     (0, 0), (-1, 0), C_WHITE),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, 0), 7.5),
        ("FONTSIZE",      (0, 1), (-1,-1), 8.5),
        ("TOPPADDING",    (0, 0), (-1,-1), 6),
        ("BOTTOMPADDING", (0, 0), (-1,-1), 6),
        ("LEFTPADDING",   (0, 0), (-1,-1), 8),
        ("GRID",          (0, 0), (-1,-1), 0.5, C_BORDER),
        ("VALIGN",        (0, 0), (-1,-1), "TOP"),
        ("ROWBACKGROUNDS",(0, 1), (-1,-1), [C_WHITE, C_CARD_BG]),
    ]))
    story.append(rtbl)
    return story


# ── Main entry point ──────────────────────────────────────────────────────────

def generate_report(report: PageReport, output_path: str, css_rules: Optional[dict] = None) -> str:
    """
    Generate a PDF security report from a PageReport.

    Args:
        report:      PageReport object from SymmetryAnalyzer.analyze()
        output_path: Path where the PDF should be saved
        css_rules:   Optional dict from CSSAnalyzer.extract_login_css_rules()

    Returns:
        Absolute path to the saved PDF
    """
    styles = build_styles()
    page_w, page_h = A4

    # Frame: leave room for header + footer
    frame = Frame(
        1.2*cm,               # x
        1.2*cm,               # y (above footer)
        page_w - 2.4*cm,      # width
        page_h - 3.0*cm,      # height (below header)
        leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0,
    )

    def make_canvas(filename, **kwargs):
        return ReportCanvas(filename, pagesize=A4, report_title=report.url)

    doc = BaseDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=1.2*cm,
        rightMargin=1.2*cm,
        topMargin=1.8*cm,
        bottomMargin=1.2*cm,
    )
    template = PageTemplate(id="main", frames=[frame])
    doc.addPageTemplates([template])

    # ── Build story ───────────────────────────────────────────────────────────
    story = []

    # Title block
    story.append(Paragraph("Symmetry-Based Phishing Guard", styles["title"]))
    story.append(Paragraph("Security Analysis Report", styles["subtitle"]))
    story.append(_hr(C_BLUE, 1.5))
    story.append(Spacer(1, 8))

    story += build_cover_section(report, styles)
    story.append(Spacer(1, 10))

    story += build_formula_section(styles)
    story.append(Spacer(1, 10))

    if report.has_login_form and report.containers:
        story += build_container_section(report, styles)

    if css_rules:
        story += build_css_rules_section(css_rules, styles)
        story.append(Spacer(1, 10))

    story += build_recommendations_section(report, styles)

    doc.build(story, canvasmaker=make_canvas)
    return os.path.abspath(output_path)
