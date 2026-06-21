"""
Shared PDF toolkit for the Robotics Security Platform interview-prep guide.

Every Part-N builder imports these helpers so all four PDFs share one look.
Pure reportlab (Platypus). Nothing here invents project facts — the builders
supply the content; this file only formats it.
"""
from __future__ import annotations

import html
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, PageBreak, XPreformatted,
    Table, TableStyle, HRFlowable, KeepTogether,
)

# ---- palette ----------------------------------------------------------
INK     = colors.HexColor('#1a1a2e')
ACCENT  = colors.HexColor('#2c3e9e')   # blue  — headings
OT_RED  = colors.HexColor('#b03a2e')   # OT / safety
GREEN   = colors.HexColor('#1e8449')   # SEC / pass
AMBER   = colors.HexColor('#b9770e')   # warning / trade-off
MUTED   = colors.HexColor('#5f5e5a')
HAIR    = colors.HexColor('#c9c7bd')
CODEBG  = colors.HexColor('#f3f3ee')
SAYBG   = colors.HexColor('#eaf3fb')   # "say this"
WHYBG   = colors.HexColor('#eef7ee')   # "why it matters"
WARNBG  = colors.HexColor('#fbf1df')   # "gotcha / trade-off"
EXBG    = colors.HexColor('#f4eefb')   # "plain example"

PAGE_W, PAGE_H = A4
LMAR = RMAR = 16 * mm
TMAR = 16 * mm
BMAR = 16 * mm
CONTENT_W = PAGE_W - LMAR - RMAR

# ---- styles -----------------------------------------------------------
def _styles():
    s = {}
    s['title']    = ParagraphStyle('title', fontName='Helvetica-Bold', fontSize=23, leading=27, textColor=INK, spaceAfter=4)
    s['subtitle'] = ParagraphStyle('subtitle', fontName='Helvetica', fontSize=12, leading=16, textColor=MUTED, spaceAfter=10)
    s['h1']       = ParagraphStyle('h1', fontName='Helvetica-Bold', fontSize=16, leading=20, textColor=ACCENT, spaceBefore=15, spaceAfter=5)
    s['h2']       = ParagraphStyle('h2', fontName='Helvetica-Bold', fontSize=13, leading=16, textColor=INK, spaceBefore=11, spaceAfter=3)
    s['h3']       = ParagraphStyle('h3', fontName='Helvetica-Bold', fontSize=11, leading=14, textColor=OT_RED, spaceBefore=8, spaceAfter=2)
    s['body']     = ParagraphStyle('body', fontName='Helvetica', fontSize=10.3, leading=15, textColor=INK, spaceAfter=6, alignment=TA_LEFT)
    s['bullet']   = ParagraphStyle('bullet', parent=s['body'], leftIndent=14, bulletIndent=3, spaceAfter=3)
    s['code']     = ParagraphStyle('code', fontName='Courier', fontSize=7.6, leading=9.3, textColor=INK)
    s['small']    = ParagraphStyle('small', fontName='Helvetica', fontSize=9, leading=12, textColor=MUTED, spaceAfter=5)
    s['cell']     = ParagraphStyle('cell', fontName='Helvetica', fontSize=9, leading=12, textColor=INK)
    s['cellb']    = ParagraphStyle('cellb', parent=s['cell'], fontName='Helvetica-Bold')
    s['cellh']    = ParagraphStyle('cellh', fontName='Helvetica-Bold', fontSize=9, leading=12, textColor=colors.white)
    s['cobody']   = ParagraphStyle('cobody', fontName='Helvetica', fontSize=9.7, leading=13.5, textColor=INK, spaceAfter=3)
    s['colabel']  = ParagraphStyle('colabel', fontName='Helvetica-Bold', fontSize=8.5, leading=11, textColor=ACCENT, spaceAfter=2)
    return s

S = _styles()

# ---- inline helpers ---------------------------------------------------
def P(text, style='body'):
    return Paragraph(text, S[style])

def H1(text):  return Paragraph(text, S['h1'])
def H2(text):  return Paragraph(text, S['h2'])
def H3(text):  return Paragraph(text, S['h3'])

def small(text): return Paragraph(text, S['small'])

def spacer(h=6): return Spacer(1, h)

def bullets(items, style='bullet'):
    out = []
    for it in items:
        out.append(Paragraph('&bull;&nbsp;&nbsp;' + it, S[style]))
    return out

def code(text):
    """ASCII diagram / command block. Escapes &, <, > and boxes it."""
    safe = html.escape(text)
    pre = XPreformatted(safe, S['code'])
    t = Table([[pre]], colWidths=[CONTENT_W])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), CODEBG),
        ('BOX', (0, 0), (-1, -1), 0.5, HAIR),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    return t

_CALLOUT = {
    'say':  ('SAY THIS IN THE INTERVIEW', SAYBG, ACCENT),
    'why':  ('WHY IT MATTERS', WHYBG, GREEN),
    'warn': ('TRADE-OFF / BE HONEST', WARNBG, AMBER),
    'ex':   ('PLAIN-ENGLISH EXAMPLE', EXBG, colors.HexColor('#6a3fb0')),
    'note': ('NOTE', colors.HexColor('#eef0f4'), MUTED),
}

def callout(text, kind='say', label=None):
    title, bg, bar = _CALLOUT[kind]
    if label:
        title = label
    inner = [Paragraph(title, S['colabel'])]
    if isinstance(text, (list, tuple)):
        for t in text:
            inner.append(Paragraph(t, S['cobody']))
    else:
        inner.append(Paragraph(text, S['cobody']))
    t = Table([[inner]], colWidths=[CONTENT_W])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), bg),
        ('LINEBEFORE', (0, 0), (0, -1), 3, bar),
        ('LEFTPADDING', (0, 0), (-1, -1), 9),
        ('RIGHTPADDING', (0, 0), (-1, -1), 9),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    return t

def tbl(data, col_widths, header=True, font_size=9):
    """data: list of rows; each cell a string (may contain <b>/<i>)."""
    rows = []
    for r_i, row in enumerate(data):
        cells = []
        for c in row:
            st = 'cellh' if (header and r_i == 0) else 'cell'
            cells.append(Paragraph(str(c), S[st]))
        rows.append(cells)
    t = Table(rows, colWidths=col_widths, repeatRows=1 if header else 0)
    style = [
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LINEBELOW', (0, 0), (-1, -1), 0.4, HAIR),
        ('LINEAFTER', (0, 0), (-2, -1), 0.4, HAIR),
        ('BOX', (0, 0), (-1, -1), 0.5, HAIR),
    ]
    if header:
        style += [
            ('BACKGROUND', (0, 0), (-1, 0), ACCENT),
            ('TOPPADDING', (0, 0), (-1, 0), 5),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 5),
        ]
    t.setStyle(TableStyle(style))
    return t

def rule():
    return HRFlowable(width='100%', thickness=0.6, color=HAIR, spaceBefore=8, spaceAfter=8)

def keep(flowables):
    return KeepTogether(flowables)

# ---- document build ---------------------------------------------------
def _flatten(items):
    """Allow story entries to be flowables OR (nested) lists of flowables."""
    out = []
    for it in items:
        if isinstance(it, (list, tuple)):
            out.extend(_flatten(it))
        else:
            out.append(it)
    return out


def build(path, part_label, story):
    story = _flatten(story)
    # The footer is drawn on the raw canvas, which renders text literally —
    # so convert any HTML entities to plain characters first.
    label_plain = html.unescape(part_label).replace('—', '-').replace('·', '-')
    doc = SimpleDocTemplate(
        path, pagesize=A4,
        leftMargin=LMAR, rightMargin=RMAR, topMargin=TMAR, bottomMargin=BMAR,
        title='Robotics Security Platform - Interview Prep - ' + label_plain,
        author='Interview prep guide',
    )

    def footer(canvas, _doc):
        canvas.saveState()
        canvas.setStrokeColor(HAIR)
        canvas.setLineWidth(0.5)
        canvas.line(LMAR, BMAR - 5, PAGE_W - RMAR, BMAR - 5)
        canvas.setFont('Helvetica', 7.5)
        canvas.setFillColor(MUTED)
        canvas.drawString(LMAR, BMAR - 14, 'Robotics Security Platform   -   Interview Preparation   -   ' + label_plain)
        canvas.drawRightString(PAGE_W - RMAR, BMAR - 14, 'p. %d' % _doc.page)
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return path
