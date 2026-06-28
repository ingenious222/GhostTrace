"""
reporting/pdf_exporter.py
──────────────────────────────────────────────────────────────
PDF export module. Primary: WeasyPrint. Fallback: ReportLab.
PDF generation is MANDATORY — both methods are attempted.
"""

from __future__ import annotations

import logging
import pathlib
from typing import Any

logger = logging.getLogger(__name__)


def export_pdf(
    html_path: str,
    output_path: str,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Convert an HTML report file to PDF.
    Tries WeasyPrint first; falls back to ReportLab on failure.

    Args:
        html_path:   Path to the rendered HTML file.
        output_path: Destination PDF path.
        context:     Optional report context dict (used by ReportLab fallback
                     to produce a properly structured PDF instead of raw text).

    Returns:
        {"status": "ok", "path": output_path}   on success
        {"status": "error", "error": msg}       on failure
    """
    # Method 1: WeasyPrint (best quality, CSS-accurate)
    result = _export_weasyprint(html_path, output_path)
    if result["status"] == "ok":
        return result

    logger.warning("WeasyPrint failed (%s), trying ReportLab fallback…", result.get("error"))

    # Method 2: ReportLab structured fallback
    result = _export_reportlab(output_path, context or {})
    return result


def _export_weasyprint(html_path: str, output_path: str) -> dict[str, Any]:
    try:
        from weasyprint import HTML, CSS  # type: ignore
        from weasyprint.text.fonts import FontConfiguration  # type: ignore

        font_config = FontConfiguration()
        html_doc = HTML(filename=html_path)
        css = CSS(string=_weasyprint_print_css(), font_config=font_config)
        html_doc.write_pdf(output_path, stylesheets=[css], font_config=font_config)
        logger.info("WeasyPrint PDF generated: %s", output_path)
        return {"status": "ok", "path": output_path, "engine": "weasyprint"}
    except ImportError:
        return {"status": "error", "error": "WeasyPrint not installed — run: pip install weasyprint"}
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "error": f"WeasyPrint error: {exc}"}


def _export_reportlab(output_path: str, ctx: dict[str, Any]) -> dict[str, Any]:
    """Structured ReportLab PDF — mirrors the HTML report structure exactly."""
    try:
        from reportlab.lib import colors  # type: ignore
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT  # type: ignore
        from reportlab.lib.pagesizes import A4  # type: ignore
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet  # type: ignore
        from reportlab.lib.units import cm, mm  # type: ignore
        from reportlab.platypus import (  # type: ignore
            HRFlowable,
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError:
        return {"status": "error", "error": "ReportLab not installed — run: pip install reportlab"}

    # ── Colour palette — Dark Pink / Magenta theme ───────────────────────────
    DARK_BG      = colors.HexColor("#0d0814")
    COVER_BG1    = colors.HexColor("#1a0a2e")
    COVER_BG2    = colors.HexColor("#2d0a3e")
    PINK         = colors.HexColor("#ec4899")
    MAGENTA      = colors.HexColor("#a855f7")
    PINK_LIGHT   = colors.HexColor("#f9a8d4")
    RED_C        = colors.HexColor("#d63031")
    RED_H        = colors.HexColor("#e17055")
    YELLOW_M     = colors.HexColor("#fdcb6e")
    GREEN_L      = colors.HexColor("#00b894")
    WHITE        = colors.white
    LIGHT_GRAY   = colors.HexColor("#e9d5ff")
    MID_GRAY     = colors.HexColor("#9c7ec0")
    NEAR_BLACK   = colors.HexColor("#1e1030")
    TABLE_HDR    = colors.HexColor("#4a1572")
    TABLE_ALT    = colors.HexColor("#fdf4ff")
    CODE_BG      = colors.HexColor("#1a0a2e")
    CODE_FG      = colors.HexColor("#f9a8d4")
    DIVIDER      = colors.HexColor("#7c3aed")
    # keep compat aliases
    DEEP_PURPLE  = colors.HexColor("#4a1572")
    ACCENT       = MAGENTA

    _SEV_HEX = {
        "CRITICAL": "#d63031", "HIGH": "#e17055",
        "MEDIUM":   "#e0a020", "LOW":  "#00b894", "INFO": "#74b9ff",
    }
    _level_col_map = {
        "LOW": GREEN_L, "MEDIUM": YELLOW_M, "HIGH": RED_H, "CRITICAL": RED_C,
    }

    # ── Styles ───────────────────────────────────────────────────────────────
    base = getSampleStyleSheet()

    def _s(name: str, **kw) -> ParagraphStyle:
        return ParagraphStyle(name, parent=base["Normal"], **kw)

    S_COVER_TITLE = _s("CoverTitle", fontSize=32, textColor=WHITE, leading=42,
                        alignment=TA_CENTER, fontName="Helvetica-Bold", spaceAfter=4)
    S_COVER_SUB   = _s("CoverSub",   fontSize=12, textColor=PINK_LIGHT, leading=18,
                        alignment=TA_CENTER, spaceAfter=4)
    S_PAGE_TITLE  = _s("PageTitle",  fontSize=16, textColor=PINK, leading=22,
                        fontName="Helvetica-Bold", spaceBefore=4, spaceAfter=6)
    S_H2          = _s("H2",  fontSize=12, textColor=MAGENTA, leading=16,
                        fontName="Helvetica-Bold", spaceBefore=10, spaceAfter=4)
    S_H3          = _s("H3",  fontSize=10, textColor=MID_GRAY, leading=14,
                        fontName="Helvetica-Bold", spaceBefore=7, spaceAfter=3)
    S_BODY        = _s("Body",   fontSize=9,   textColor=NEAR_BLACK, leading=13)
    S_MONO        = _s("Mono",   fontSize=7.5, textColor=NEAR_BLACK, leading=11,
                        fontName="Courier")
    S_CODE        = _s("Code",   fontSize=7,   textColor=CODE_FG,    leading=10,
                        fontName="Courier", backColor=CODE_BG,
                        leftIndent=6, rightIndent=6)
    S_BULLET      = _s("Bullet", fontSize=9,   textColor=NEAR_BLACK, leading=13,
                        leftIndent=14)
    S_EMPTY       = _s("Empty",  fontSize=9,   textColor=MID_GRAY, leading=13,
                        alignment=TA_CENTER)
    S_FOOTER_TXT  = _s("FooterTxt", fontSize=7, textColor=MID_GRAY, leading=10,
                        alignment=TA_CENTER)
    S_CAPTION     = _s("Caption",  fontSize=7.5, textColor=MID_GRAY, leading=11)

    # ── Context extraction ───────────────────────────────────────────────────
    case_id     = ctx.get("case_id", "UNKNOWN")
    dump_name   = ctx.get("dump_name", "unknown.mem")
    gen_at      = ctx.get("generated_at", "—")
    score_val   = int(ctx.get("score_value", 0))
    score_level = str(ctx.get("score_level", "UNKNOWN")).upper()
    level_col   = _level_col_map.get(score_level, MID_GRAY)
    breakdown   = ctx.get("breakdown", {})
    recs        = ctx.get("recommendations", [])
    timeline    = ctx.get("timeline", [])
    pslist      = ctx.get("pslist", [])
    malfind     = ctx.get("malfind", [])
    netscan     = ctx.get("netscan", [])
    proc_anom   = ctx.get("process_anomalies", [])
    net_anom    = ctx.get("network_anomalies", [])
    ps_finds    = ctx.get("powershell_findings", [])
    iocs        = ctx.get("iocs", [])
    notes       = ctx.get("investigator_notes", "")
    total_find  = int(ctx.get("total_findings", 0))

    PW = A4[0] - 4 * cm   # usable page width

    # ── Helper functions ──────────────────────────────────────────────────────
    def _trunc(s: object, n: int = 80) -> str:
        s = str(s or "")
        return (s[:n] + "…") if len(s) > n else s

    def _sev_para(sev: str) -> Paragraph:
        col = _SEV_HEX.get(str(sev).upper(), "#8090a8")
        return Paragraph(f'<font color="{col}"><b>{sev}</b></font>', S_MONO)

    def _page_title(text: str) -> list:
        return [
            Paragraph(text, S_PAGE_TITLE),
            HRFlowable(width="100%", thickness=2, color=PINK, spaceAfter=8),
        ]

    def _h2(text: str) -> list:
        return [
            Spacer(1, 3 * mm),
            Paragraph(text, S_H2),
            HRFlowable(width="100%", thickness=0.6, color=ACCENT, spaceAfter=4),
        ]

    def _table(header: list, rows: list, col_widths: list,
               row_colors: list | None = None) -> Table:
        def _th(h: str) -> Paragraph:
            return Paragraph(f'<font color="white"><b>{h}</b></font>', S_MONO)

        def _td(v: object) -> object:
            return v if isinstance(v, Paragraph) else Paragraph(_trunc(str(v), 300), S_MONO)

        data = [[_th(h) for h in header]]
        for row in rows:
            data.append([_td(c) for c in row])

        style = [
            ("BACKGROUND",    (0, 0), (-1, 0), TABLE_HDR),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [WHITE, TABLE_ALT]),
            ("GRID",          (0, 0), (-1, -1), 0.4, colors.HexColor("#c0c8d8")),
            ("TOPPADDING",    (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING",   (0, 0), (-1, -1), 5),
            ("RIGHTPADDING",  (0, 0), (-1, -1), 5),
            ("VALIGN",        (0, 0), (-1, -1), "TOP"),
            ("WORDWRAP",      (0, 0), (-1, -1), "CJK"),
        ]
        if row_colors:
            for i, col in enumerate(row_colors, start=1):
                if col:
                    style.append(("LINEAFTER", (0, i), (0, i), 2.5, col))
        t = Table(data, colWidths=col_widths, repeatRows=1)
        t.setStyle(TableStyle(style))
        return t

    # ── Bookmark flowable ───────────────────────────────────────────────────
    from reportlab.platypus.flowables import Flowable  # type: ignore

    class _Bookmark(Flowable):  # type: ignore[misc]
        """Invisible flowable that inserts a PDF outline bookmark at its position."""
        def __init__(self, title: str, key: str, level: int = 0) -> None:
            super().__init__()
            self.title = title
            self.key   = key
            self.level = level
            self.width  = 0
            self.height = 0

        def draw(self) -> None:
            self.canv.bookmarkPage(self.key)
            self.canv.addOutlineEntry(self.title, self.key, self.level, closed=False)

    def _bm(title: str, key: str, level: int = 0) -> "_Bookmark":
        return _Bookmark(title, key, level)

    def _add_page_number(canvas_obj: object, doc: object) -> None:
        canvas_obj.saveState()  # type: ignore[attr-defined]
        canvas_obj.setFont("Helvetica", 7)  # type: ignore[attr-defined]
        canvas_obj.setFillColor(PINK)  # type: ignore[attr-defined]
        pg = canvas_obj.getPageNumber()  # type: ignore[attr-defined]
        canvas_obj.drawCentredString(  # type: ignore[attr-defined]
            A4[0] / 2, 1.2 * cm,
            f"GhostTrace  ·  {case_id}  ·  Page {pg}"
        )
        canvas_obj.restoreState()  # type: ignore[attr-defined]

    # ── Score badge helper — nested table with fixed row heights to prevent overlap ──
    def _score_badge_table(
        sv: int, sl: str, tf: int, lc: object,
        bg: object, fg_light: object, pw: float,
        style_fn: "Any", ta_center: int,
    ) -> Table:
        _hex = {"LOW": "#00b894", "MEDIUM": "#fdcb6e", "HIGH": "#e17055", "CRITICAL": "#d63031"}
        hx = _hex.get(sl, "#9c7ec0")
        sub = Table(
            [
                [Paragraph(
                    f'<font name="Helvetica-Bold" size="40" color="{hx}"><b>{sv}/100</b></font>',
                    style_fn("ScB", alignment=ta_center, leading=50),
                )],
                [Paragraph(
                    f'<font name="Helvetica-Bold" size="15" color="{hx}">{sl}  THREAT</font>',
                    style_fn("ScL", alignment=ta_center, leading=22),
                )],
                [Paragraph(
                    f'<font size="10" color="#f9a8d4">Total Findings: {tf}</font>',
                    style_fn("ScF", alignment=ta_center, leading=14),
                )],
            ],
            colWidths=[pw],
            rowHeights=[58, 28, 18],
        )
        sub.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, -1), bg),
            ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
            ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",    (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        return sub

    story: list = []

    # ═══════════════════════════════════════════════════════════════════════
    # 1. COVER PAGE  (full-page dark pink/magenta with logo)
    # ═══════════════════════════════════════════════════════════════════════
    import pathlib as _pl
    from reportlab.platypus import Image as _RLImage  # type: ignore

    _LOGO_PDF = _pl.Path(__file__).parent.parent / "gui" / "logo_pdf.png"

    def _meta_cell(label: str, value: str) -> Paragraph:
        return Paragraph(
            f'<font size="7" color="#f9a8d4">{label}</font><br/>'
            f'<b><font color="white">{_trunc(value, 38)}</font></b>',
            _s(f"MC_{label}", fontSize=9, alignment=TA_CENTER, leading=14,
               backColor=colors.HexColor("#2d0a3e")),
        )

    meta_pairs = [
        ["Case ID",      case_id,              "Generated",    gen_at],
        ["Memory Image", dump_name,             "Threat Level", score_level],
        ["Score",        f"{score_val} / 100",  "Findings",     str(total_find)],
    ]
    meta_table_data = [
        [_meta_cell(r[0], r[1]), _meta_cell(r[2], r[3])]
        for r in meta_pairs
    ]
    meta_t = Table(meta_table_data, colWidths=[PW * 0.5, PW * 0.5])
    meta_t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), colors.HexColor("#2d0a3e")),
        ("GRID",          (0, 0), (-1, -1), 0.6, colors.HexColor("#7c3aed")),
        ("TOPPADDING",    (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))

    # Divider bar in pink gradient simulation (single colour in RL)
    divider_t = Table(
        [[Paragraph("", _s("Div"))]],
        colWidths=[PW], rowHeights=[3 * mm],
    )
    divider_t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), PINK),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))

    cover_rows: list = []

    # Logo
    if _LOGO_PDF.exists():
        logo_img = _RLImage(str(_LOGO_PDF), width=5.5 * cm, height=5.5 * cm)
        logo_img.hAlign = "CENTER"
        cover_rows += [
            [Spacer(1, 1 * cm)],
            [logo_img],
            [Spacer(1, 5 * mm)],
        ]
    else:
        cover_rows += [[Spacer(1, 2 * cm)]]

    cover_rows += [
        [Paragraph("GhostTrace", S_COVER_TITLE)],
        [Paragraph("Memory Forensics &amp; Threat Intelligence Platform",
                   _s("CSubPink", fontSize=11, textColor=PINK_LIGHT,
                      alignment=TA_CENTER, leading=16))],
        [Paragraph("Digital Forensic Examination Report — Court Admissible Copy",
                   _s("CSubCourt", fontSize=9, textColor=colors.HexColor("#c084fc"),
                      alignment=TA_CENTER, leading=13, spaceAfter=2))],
        [Spacer(1, 4 * mm)],
        [divider_t],
        [Spacer(1, 8 * mm)],
        [_score_badge_table(score_val, score_level, total_find, level_col, COVER_BG1, PINK_LIGHT, PW, _s, TA_CENTER)],
        [Spacer(1, 10 * mm)],
        [meta_t],
        [Spacer(1, 8 * mm)],
        [Paragraph(
            "GhostTrace v2.0 — Memory Forensics & Threat Intelligence",
            _s("CovDev", fontSize=8, textColor=PINK_LIGHT,
               alignment=TA_CENTER, leading=12),
        )],
        [Paragraph(
            "Digital Forensics & Cybersecurity",
            _s("CovFoot", fontSize=7, textColor=colors.HexColor("#7c3aed"),
               alignment=TA_CENTER, leading=11),
        )],
        [Spacer(1, 3 * mm)],
        [Paragraph(
            "⚠ CONFIDENTIAL — FOR LAW ENFORCEMENT / JUDICIAL USE ONLY ⚠",
            _s("CovConf", fontSize=7, textColor=colors.HexColor("#ff7675"),
               alignment=TA_CENTER, leading=10),
        )],
    ]

    cover_t = Table(cover_rows, colWidths=[PW])
    cover_t.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), COVER_BG1),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
    ]))
    story += [_bm("Cover Page", "sec_cover"), Spacer(1, 0), cover_t, PageBreak()]

    # ═══════════════════════════════════════════════════════════════════════
    # 2. EXECUTIVE SUMMARY
    # ═══════════════════════════════════════════════════════════════════════
    story += [_bm("Executive Summary", "sec_exec")]
    story += _page_title("🔬 Executive Summary")
    story += _h2("📊 Score Breakdown")
    if breakdown:
        bd_rows = []
        for k, v in sorted(
            breakdown.items(),
            key=lambda x: -(x[1].get("score", 0) if isinstance(x[1], dict) else x[1]),
        ):
            sc  = v.get("score", 0)  if isinstance(v, dict) else v
            mx  = v.get("max_score", 1) if isinstance(v, dict) else 100
            cnt = v.get("count", 0) if isinstance(v, dict) else 0
            pct = int(sc / mx * 20) if mx > 0 else 0
            bar = "█" * pct + "░" * (20 - pct)
            bd_rows.append([
                k.replace("_", " ").title(),
                f"{sc:.1f} / {mx}",
                str(cnt),
                Paragraph(f'<font color="#302b63" size="8">{bar}</font>', S_MONO),
            ])
        story.append(_table(
            ["Category", "Score / Max", "Findings", "Bar"],
            bd_rows,
            [PW * 0.40, PW * 0.18, PW * 0.12, PW * 0.30],
        ))
    else:
        story.append(Paragraph("No breakdown data available.", S_EMPTY))

    if notes and notes.strip():
        story += _h2("📝 Investigator Notes")
        for line in notes.strip().splitlines():
            story.append(Paragraph(line or " ", S_BODY))
        story.append(Spacer(1, 3 * mm))

    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════════════════════
    # 3. AI FORENSIC ANALYSIS NARRATIVE
    # ═══════════════════════════════════════════════════════════════════════
    ai_text = ctx.get("ai_analysis", "").strip()
    story += [_bm("AI Forensic Analysis", "sec_ai")]
    story += _page_title("🤖 AI Forensic Analysis")

    if ai_text:
        # Parse the AI output: lines starting with ## become _h2 headers,
        # blank lines become spacers, everything else is body text
        for raw_line in ai_text.splitlines():
            line = raw_line.strip()
            if not line:
                story.append(Spacer(1, 3 * mm))
            elif line.startswith("## "):
                story += _h2(line[3:])
            elif line.startswith("### "):
                story.append(Paragraph(line[4:], S_H3))
            elif line.startswith("- ") or line.startswith("* "):
                story.append(Paragraph(f"• {line[2:]}", S_BULLET))
            elif line.startswith("**") and line.endswith("**") and len(line) > 4:
                story.append(Paragraph(f"<b>{line[2:-2]}</b>", S_BODY))
            else:
                # Replace **bold** inline markers for ReportLab
                import re as _re
                formatted = _re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", line)
                story.append(Paragraph(formatted, S_BODY))
    else:
        story.append(Paragraph(
            "AI analysis was not available for this report. Ensure the LLM provider is "
            "configured in .env (LLM_PROVIDER=openrouter, OPENROUTER_API_KEY).",
            S_EMPTY,
        ))

    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════════════════════
    # 4. PROCESS ANALYSIS
    # ═══════════════════════════════════════════════════════════════════════
    story += [_bm("Process Analysis", "sec_proc")]
    story += _page_title("⚙️ Process Analysis")
    story += _h2(f"Running Processes — pslist ({len(pslist)} total)")
    if pslist:
        ps_rows = [
            [
                str(p.get("PID", p.get("pid", "?"))),
                str(p.get("PPID", p.get("ppid", "?"))),
                _trunc(str(p.get("Name", p.get("name", p.get("ImageFileName", "?")))), 30),
                str(p.get("Threads", p.get("threads", "?"))),
                str(p.get("Handles", p.get("handles", "?"))),
                _trunc(str(p.get("CreateTime", p.get("create_time", p.get("Start", "—")))), 28),
            ]
            for p in pslist[:60]
        ]
        story.append(_table(
            ["PID", "PPID", "Process Name", "Threads", "Handles", "Create Time"],
            ps_rows,
            [PW*0.08, PW*0.08, PW*0.22, PW*0.10, PW*0.10, PW*0.42],
        ))
        if len(pslist) > 60:
            story.append(Paragraph(f"… and {len(pslist) - 60} more processes.", S_CAPTION))
    else:
        story.append(Paragraph("No process data collected.", S_EMPTY))

    story += _h2(f"⚠️ Process Anomalies Detected ({len(proc_anom)})")
    if proc_anom:
        row_cols_p: list = []
        pa_rows: list = []
        for a in proc_anom:
            sev = str(a.get("severity", "INFO")).upper()
            row_cols_p.append(_level_col_map.get(sev, MID_GRAY))
            pa_rows.append([
                _sev_para(sev),
                _trunc(str(a.get("category", "—")).replace("_", " ").title(), 22),
                _trunc(str(a.get("process", a.get("name", "?"))), 22),
                str(a.get("pid", "?")),
                str(a.get("description", "—")),
            ])
        story.append(_table(
            ["Severity", "Category", "Process", "PID", "Description"],
            pa_rows,
            [PW*0.12, PW*0.18, PW*0.16, PW*0.08, PW*0.46],
            row_colors=row_cols_p,
        ))
    else:
        story.append(Paragraph("✅ No process anomalies detected.", S_EMPTY))

    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════════════════════
    # 5. MEMORY INJECTION EVIDENCE
    # ═══════════════════════════════════════════════════════════════════════
    story += [_bm("Memory Injection Evidence", "sec_malfind")]
    story += _page_title(f"💉 Memory Injection Evidence — malfind ({len(malfind)} regions)")
    if malfind:
        mf_rows = [
            [
                str(m.get("pid", m.get("PID", "?"))),
                str(m.get("process", m.get("Process", "?"))),
                str(m.get("address", m.get("Address", "?"))),
                str(m.get("protection", m.get("Protection", "?"))),
                str(m.get("vad_tag", m.get("VadTag", ""))),
                str(m.get("hex_preview", m.get("Disasm", m.get("hexdump", "")))),
            ]
            for m in malfind
        ]
        story.append(_table(
            ["PID", "Process", "Address", "Protection", "VAD Tag", "Hex / Disasm"],
            mf_rows,
            [PW*0.07, PW*0.15, PW*0.14, PW*0.16, PW*0.09, PW*0.39],
        ))
    else:
        story.append(Paragraph("✅ No injection regions detected by malfind.", S_EMPTY))

    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════════════════════
    # 6. POWERSHELL ANALYSIS
    # ═══════════════════════════════════════════════════════════════════════
    story += [_bm("PowerShell Analysis", "sec_ps")]
    story += _page_title(f"🖥️ PowerShell Analysis ({len(ps_finds)} findings)")
    if ps_finds:
        for idx, f in enumerate(ps_finds, 1):
            pid      = f.get("pid", "?")
            proc     = f.get("process", "?")
            raw      = str(f.get("raw_cmdline", f.get("raw", "")))
            decoded  = str(f.get("decoded_content", f.get("decoded", "")))
            patterns = f.get("patterns_found", [])
            f_iocs   = f.get("iocs", [])

            story += [Spacer(1, 4 * mm),
                      Paragraph(f"#{idx}  PID {pid} — {proc}", S_H3)]

            story.append(Paragraph("<b>Raw command:</b>", S_CAPTION))
            story.append(Paragraph(_trunc(raw, 500), S_CODE))
            story.append(Spacer(1, 2 * mm))

            if decoded.strip():
                story.append(Paragraph("<b>Decoded payload:</b>", S_CAPTION))
                story.append(Paragraph(_trunc(decoded, 700), S_CODE))
                story.append(Spacer(1, 2 * mm))

            if patterns:
                pat_rows = [
                    [
                        str(p.get("name", "?")),
                        _sev_para(str(p.get("severity", "INFO"))),
                        str(p.get("description", "")),
                    ]
                    for p in patterns
                ]
                story.append(Paragraph("<b>Patterns detected:</b>", S_CAPTION))
                story.append(_table(
                    ["Pattern", "Severity", "Description"],
                    pat_rows,
                    [PW * 0.28, PW * 0.15, PW * 0.57],
                ))

            if f_iocs:
                ioc_vals = ", ".join(str(x.get("value", x)) for x in f_iocs[:10])
                story.append(Paragraph(f"<b>IOCs:</b> {ioc_vals}", S_CAPTION))
    else:
        story.append(Paragraph("✅ No suspicious PowerShell activity detected.", S_EMPTY))

    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════════════════════
    # 7. NETWORK FORENSICS
    # ═══════════════════════════════════════════════════════════════════════
    story += [_bm("Network Forensics", "sec_net")]
    story += _page_title("🌐 Network Forensics")
    story += _h2(f"Network Connections — netscan ({len(netscan)} connections)")
    if netscan:
        ns_rows = [
            [
                str(n.get("Proto", n.get("proto", "-"))),
                _trunc(str(n.get("LocalAddr",   n.get("local_addr",   n.get("LocalAddress",  "-")))), 30),
                _trunc(str(n.get("ForeignAddr",  n.get("foreign_addr", n.get("ForeignAddress", "-")))), 30),
                str(n.get("State", n.get("state", "-"))),
                str(n.get("PID",   n.get("pid",   "-"))),
                _trunc(str(n.get("Owner", n.get("Process", "-"))), 20),
            ]
            for n in netscan[:60]
        ]
        story.append(_table(
            ["Proto", "Local", "Foreign", "State", "PID", "Owner"],
            ns_rows,
            [PW*0.10, PW*0.24, PW*0.24, PW*0.14, PW*0.08, PW*0.20],
        ))
        if len(netscan) > 60:
            story.append(Paragraph(f"… and {len(netscan) - 60} more connections.", S_CAPTION))
    else:
        story.append(Paragraph("No network data collected.", S_EMPTY))

    story += _h2(f"⚠️ Suspicious Connection Alerts ({len(net_anom)})")
    if net_anom:
        row_cols_n: list = []
        na_rows: list = []
        for a in net_anom:
            sev = str(a.get("severity", "INFO")).upper()
            row_cols_n.append(_level_col_map.get(sev, MID_GRAY))
            na_rows.append([
                _sev_para(sev),
                _trunc(str(a.get("category", "—")).replace("_", " ").title(), 22),
                _trunc(str(a.get("process", "?")), 18),
                _trunc(str(a.get("local",   "-")), 24),
                _trunc(str(a.get("foreign", "-")), 24),
                str(a.get("description", "—")),
            ])
        story.append(_table(
            ["Severity", "Type", "Process", "Local", "Foreign", "Description"],
            na_rows,
            [PW*0.11, PW*0.15, PW*0.13, PW*0.16, PW*0.16, PW*0.29],
            row_colors=row_cols_n,
        ))
    else:
        story.append(Paragraph("✅ No suspicious network connections detected.", S_EMPTY))

    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════════════════════
    # 8. IOCs (if any)
    # ═══════════════════════════════════════════════════════════════════════
    if iocs:
        story += [_bm("Indicators of Compromise", "sec_ioc")]
        story += _page_title(f"🎯 Indicators of Compromise ({len(iocs)} IOCs)")
        ioc_rows = [
            [
                str(ioc.get("type", "?")),
                _trunc(str(ioc.get("value", "?")), 50),
                _trunc(", ".join(ioc.get("sources", [])), 30),
                _trunc(str(ioc.get("recommendation", "")), 60),
            ]
            for ioc in iocs
        ]
        story.append(_table(
            ["Type", "Value", "Source(s)", "Recommendation"],
            ioc_rows,
            [PW*0.12, PW*0.33, PW*0.22, PW*0.33],
        ))
        story.append(PageBreak())

    # ═══════════════════════════════════════════════════════════════════════
    # 9. ATTACK TIMELINE
    # ═══════════════════════════════════════════════════════════════════════
    story += [_bm("Attack Timeline", "sec_tl")]
    story += _page_title(f"🕒 Attack Timeline Reconstruction ({len(timeline)} events)")
    if timeline:
        tl_rows: list = []
        tl_row_cols: list = []
        for e in timeline:
            sev    = str(e.get("severity", "INFO")).upper()
            ts     = _trunc(str(e.get("timestamp", e.get("time", "—"))), 22)
            evt    = str(e.get("event_type", e.get("event", ""))).replace("_", " ").upper()
            step   = str(e.get("step", ""))
            pid    = str(e.get("pid", ""))
            proc   = str(e.get("process", ""))
            source = str(e.get("source", ""))
            desc   = str(e.get("description", e.get("event", "—")))
            detail = desc
            if source:
                detail += f"\nSrc: {source}"
            if pid:
                detail += f"  PID: {pid}"
            if proc:
                detail += f"  ({proc})"
            tl_row_cols.append(_level_col_map.get(sev, MID_GRAY))
            tl_rows.append([
                step,
                ts,
                _sev_para(sev),
                evt,
                Paragraph(detail, S_MONO),
            ])
        story.append(_table(
            ["#", "Time", "Severity", "Event Type", "Description / Source"],
            tl_rows,
            [PW*0.04, PW*0.18, PW*0.12, PW*0.20, PW*0.46],
            row_colors=tl_row_cols,
        ))
    else:
        story.append(Paragraph("No timeline events reconstructed.", S_EMPTY))

    story.append(PageBreak())

    # ═══════════════════════════════════════════════════════════════════════
    # 10. RECOMMENDATIONS
    # ═══════════════════════════════════════════════════════════════════════
    story += [_bm("Recommendations", "sec_rec")]
    story += _page_title("💡 Recommendations")
    if recs:
        for rec in recs:
            story.append(Paragraph(f"• {rec}", S_BULLET))
            story.append(Spacer(1, 2 * mm))
    else:
        story.append(Paragraph("No specific recommendations generated.", S_EMPTY))

    story += [
        Spacer(1, 10 * mm),
        HRFlowable(width="100%", thickness=0.5, color=MID_GRAY),
        Spacer(1, 2 * mm),
        Paragraph(
            f"GhostTrace — Automated Memory Forensics Platform  ·  Case {case_id}  ·  {gen_at}",
            S_FOOTER_TXT,
        ),
        Paragraph(
            "This report is computer-assisted. Final forensic interpretation must be performed by a qualified investigator.",
            S_FOOTER_TXT,
        ),
    ]

    # ── Build PDF ─────────────────────────────────────────────────────────────
    try:
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            rightMargin=2 * cm,
            leftMargin=2 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
            title=f"Forensic Report — {case_id}",
            author="GhostTrace",
            subject="Digital Forensics Report",
        )

        def _first_page(c: object, d: object) -> None:
            c.showOutline()  # type: ignore[attr-defined]  # open bookmarks panel
            _add_page_number(c, d)

        doc.build(story, onFirstPage=_first_page, onLaterPages=_add_page_number)
        logger.info("ReportLab fallback PDF generated: %s", output_path)
        return {"status": "ok", "path": output_path, "engine": "reportlab"}
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "error": f"ReportLab build error: {exc}"}



def _weasyprint_print_css() -> str:
    """Additional print-specific CSS for WeasyPrint."""
    return """
    @page {
        size: A4;
        margin: 2cm 1.5cm;
        @bottom-center {
            content: "GhostTrace Forensic Report — Page " counter(page) " of " counter(pages);
            font-size: 8pt;
            color: #666;
        }
    }
    body { font-size: 10pt; }
    .no-print { display: none !important; }
    pre { font-size: 8pt; white-space: pre-wrap; word-break: break-all; }
    table { page-break-inside: avoid; }
    h2, h3 { page-break-after: avoid; }
    """
