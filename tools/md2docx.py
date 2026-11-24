#!/usr/bin/env python3
"""
md2docx.py — Convierte las guías Markdown de Desarrollo_Seguro a Word (.docx).

Uso:
    python md2docx.py <raiz_Desarrollo_Seguro>          # convierte todos los .md
    python md2docx.py <archivo.md> [<archivo.md> ...]   # convierte archivos concretos

Soporta el subconjunto de Markdown usado en la base de conocimiento:
encabezados (#..####), párrafos, listas (-, *, 1.), checklists (- [ ]),
tablas GFM, bloques de código con lenguaje, citas (>), separadores (---)
y formato en línea (**negrita**, *cursiva*, `código`, [enlace](url)).
Los enlaces relativos a .md se reescriben a .docx para navegar entre documentos Word.

Dependencia: python-docx >= 1.1
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

BODY_FONT = "Calibri"
CODE_FONT = "Consolas"
CODE_BG = "F3F4F6"
HEADER_BG = "1F3864"
QUOTE_BG = "EEF3FA"
LINK_COLOR = RGBColor(0x1F, 0x4E, 0x9A)

INLINE_RE = re.compile(
    r"(\*\*(?P<bold>.+?)\*\*)"
    r"|(`(?P<code>[^`]+)`)"
    r"|(\[(?P<ltext>[^\]]+)\]\((?P<lurl>[^)]+)\))"
    r"|(?<![\w*])\*(?P<ital>[^*\s][^*]*?)\*(?![\w*])"
)


# --------------------------------------------------------------------------- utilidades XML
def shade(element, fill: str) -> None:
    """Aplica sombreado de fondo a una celda (w:tcPr) o párrafo (w:pPr)."""
    if hasattr(element, "_tc"):            # docx.table._Cell
        pr = element._tc.get_or_add_tcPr()
    else:                                  # elemento w:p
        pr = element.get_or_add_pPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    pr.append(shd)


def add_hyperlink(paragraph, text: str, url: str, size: Pt | None = None) -> None:
    part = paragraph.part
    r_id = part.relate_to(url, "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink",
                          is_external=True)
    link = OxmlElement("w:hyperlink")
    link.set(qn("r:id"), r_id)
    run = OxmlElement("w:r")
    rpr = OxmlElement("w:rPr")
    color = OxmlElement("w:color")
    color.set(qn("w:val"), str(LINK_COLOR))
    underline = OxmlElement("w:u")
    underline.set(qn("w:val"), "single")
    rpr.append(color)
    rpr.append(underline)
    if size is not None:
        sz = OxmlElement("w:sz")
        sz.set(qn("w:val"), str(int(size.pt * 2)))
        rpr.append(sz)
    run.append(rpr)
    t = OxmlElement("w:t")
    t.text = text
    t.set(qn("xml:space"), "preserve")
    run.append(t)
    link.append(run)
    paragraph._p.append(link)


def add_page_number_field(paragraph) -> None:
    run = paragraph.add_run()
    for tag, attr in (("w:fldChar", "begin"), ("w:instrText", None), ("w:fldChar", "end")):
        el = OxmlElement(tag)
        if attr:
            el.set(qn("w:fldCharType"), attr)
        else:
            el.set(qn("xml:space"), "preserve")
            el.text = "PAGE"
        run._r.append(el)


def set_cell_margins(table, top=60, bottom=60, left=100, right=100) -> None:
    tbl_pr = table._tbl.tblPr
    mar = OxmlElement("w:tblCellMar")
    for side, val in (("top", top), ("bottom", bottom), ("left", left), ("right", right)):
        el = OxmlElement(f"w:{side}")
        el.set(qn("w:w"), str(val))
        el.set(qn("w:type"), "dxa")
        mar.append(el)
    tbl_pr.append(mar)


# --------------------------------------------------------------------------- formato en línea
def rewrite_url(url: str) -> str:
    if not re.match(r"^[a-z]+://", url) and url.endswith(".md"):
        return url[:-3] + ".docx"
    return url


def add_inline(paragraph, text: str, size: Pt | None = None, bold: bool = False, color: RGBColor | None = None):
    pos = 0
    for m in INLINE_RE.finditer(text):
        if m.start() > pos:
            _run(paragraph, text[pos:m.start()], size=size, bold=bold, color=color)
        if m.group("bold") is not None:
            add_inline(paragraph, m.group("bold"), size=size, bold=True, color=color)
        elif m.group("code") is not None:
            r = _run(paragraph, m.group("code"), size=Pt((size.pt if size else 10.5) - 1), bold=bold, color=color)
            r.font.name = CODE_FONT
            r._element.rPr.rFonts.set(qn("w:eastAsia"), CODE_FONT)
            r.font.color.rgb = color or RGBColor(0xA3, 0x1F, 0x34)
        elif m.group("ltext") is not None:
            url = rewrite_url(m.group("lurl"))
            add_hyperlink(paragraph, m.group("ltext"), url, size=size)
        elif m.group("ital") is not None:
            r = _run(paragraph, m.group("ital"), size=size, bold=bold, color=color)
            r.italic = True
        pos = m.end()
    if pos < len(text):
        _run(paragraph, text[pos:], size=size, bold=bold, color=color)


def _run(paragraph, text, size=None, bold=False, color=None):
    # URLs sueltas -> hipervínculo
    parts = re.split(r"(https?://[^\s)<>]+)", text)
    last = None
    for part in parts:
        if not part:
            continue
        if re.match(r"https?://", part):
            add_hyperlink(paragraph, part, part, size=size)
            continue
        last = paragraph.add_run(part)
        last.bold = bold or None
        if size:
            last.font.size = size
        if color:
            last.font.color.rgb = color
    if last is None:
        last = paragraph.add_run("")
    return last


# --------------------------------------------------------------------------- bloques
def add_code_block(doc, lines: list[str], lang: str) -> None:
    table = doc.add_table(rows=1, cols=1)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = True
    set_cell_margins(table, 80, 80, 140, 140)
    cell = table.rows[0].cells[0]
    shade(cell, CODE_BG)
    # No partir bloques de código entre páginas (los bloques largos fluyen igual si exceden una página)
    cant_split = OxmlElement("w:cantSplit")
    cant_split.set(qn("w:val"), "true")
    table.rows[0]._tr.get_or_add_trPr().append(cant_split)
    p = cell.paragraphs[0]
    p.paragraph_format.space_after = Pt(0)
    p.paragraph_format.space_before = Pt(0)
    if lang:
        tag = p.add_run(lang.upper() + "\n")
        tag.font.size = Pt(7)
        tag.font.bold = True
        tag.font.color.rgb = RGBColor(0x6B, 0x72, 0x80)
    for i, line in enumerate(lines):
        r = p.add_run(line.replace("\t", "    "))
        r.font.name = CODE_FONT
        r._element.rPr.rFonts.set(qn("w:eastAsia"), CODE_FONT)
        r.font.size = Pt(8)
        if i < len(lines) - 1:
            r.add_break()
    doc.add_paragraph().paragraph_format.space_after = Pt(2)


def split_row(line: str) -> list[str]:
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|"):
        line = line[:-1]
    # respetar \| escapados y pipes dentro de `código`
    cells, buf, in_code = [], "", False
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "`":
            in_code = not in_code
        if ch == "\\" and i + 1 < len(line) and line[i + 1] == "|":
            buf += "|"
            i += 2
            continue
        if ch == "|" and not in_code:
            cells.append(buf.strip())
            buf = ""
        else:
            buf += ch
        i += 1
    cells.append(buf.strip())
    return cells


def add_table(doc, rows: list[list[str]]) -> None:
    header, body = rows[0], rows[1:]
    ncols = len(header)
    table = doc.add_table(rows=1, cols=ncols)
    table.style = "Table Grid"
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    set_cell_margins(table)
    for j, text in enumerate(header):
        cell = table.rows[0].cells[j]
        shade(cell, HEADER_BG)
        p = cell.paragraphs[0]
        p.paragraph_format.space_after = Pt(0)
        p.paragraph_format.keep_with_next = True   # el encabezado no queda huérfano al pie de página
        add_inline(p, text, size=Pt(9), bold=True, color=RGBColor(0xFF, 0xFF, 0xFF))
    # repetir encabezado en cada página
    tr_pr = table.rows[0]._tr.get_or_add_trPr()
    hdr = OxmlElement("w:tblHeader")
    hdr.set(qn("w:val"), "true")
    tr_pr.append(hdr)
    for i, row in enumerate(body):
        cells = table.add_row().cells
        for j in range(ncols):
            text = row[j] if j < len(row) else ""
            p = cells[j].paragraphs[0]
            p.paragraph_format.space_after = Pt(0)
            add_inline(p, text, size=Pt(9))
            if i % 2 == 1:
                shade(cells[j], "F7F9FC")
    doc.add_paragraph().paragraph_format.space_after = Pt(2)


def add_quote(doc, text: str) -> None:
    p = doc.add_paragraph()
    p.paragraph_format.left_indent = Cm(0.6)
    p.paragraph_format.space_after = Pt(6)
    shade(p._p, QUOTE_BG)
    add_inline(p, text, size=Pt(9.5))


# --------------------------------------------------------------------------- documento
def setup_document(title: str) -> Document:
    doc = Document()
    for section in doc.sections:
        section.top_margin = section.bottom_margin = Cm(2)
        section.left_margin = section.right_margin = Cm(2)
        hp = section.header.paragraphs[0]
        hp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        hr = hp.add_run(title if title.startswith("Desarrollo Seguro") else f"Desarrollo Seguro · {title}")
        hr.font.size = Pt(8)
        hr.font.color.rgb = RGBColor(0x6B, 0x72, 0x80)
        fp = section.footer.paragraphs[0]
        fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
        fr = fp.add_run("Uso interno · Página ")
        fr.font.size = Pt(8)
        add_page_number_field(fp)

    normal = doc.styles["Normal"]
    normal.font.name = BODY_FONT
    normal.element.rPr.rFonts.set(qn("w:eastAsia"), BODY_FONT)
    normal.font.size = Pt(10.5)
    normal.paragraph_format.space_after = Pt(6)
    normal.paragraph_format.line_spacing = 1.1

    sizes = {"Title": 22, "Heading 1": 16, "Heading 2": 13.5, "Heading 3": 12, "Heading 4": 11}
    for name, size in sizes.items():
        st = doc.styles[name]
        st.font.name = BODY_FONT
        st.font.size = Pt(size)
        st.font.color.rgb = RGBColor(0x1F, 0x38, 0x64)
    doc.core_properties.title = title
    doc.core_properties.subject = "Base de conocimiento de Desarrollo Seguro (AppSec/DevSecOps)"
    doc.core_properties.language = "es-ES"
    return doc


LIST_RE = re.compile(r"^(?P<indent>\s*)(?P<marker>[-*]|\d+\.)\s+(?P<text>.*)$")


def convert(md_path: Path) -> Path:
    lines = md_path.read_text(encoding="utf-8").splitlines()
    first_h1 = next((l[2:].strip() for l in lines if l.startswith("# ")), md_path.stem)
    doc = setup_document(first_h1)

    i = 0
    para_buf: list[str] = []

    def flush_para():
        if para_buf:
            p = doc.add_paragraph()
            add_inline(p, " ".join(s.strip() for s in para_buf))
            para_buf.clear()

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # bloque de código
        if stripped.startswith("```"):
            flush_para()
            lang = stripped[3:].strip()
            code = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("```"):
                code.append(lines[i])
                i += 1
            add_code_block(doc, code, lang)
            i += 1
            continue

        # tabla
        if stripped.startswith("|") and i + 1 < len(lines) and re.match(r"^\s*\|?\s*:?-{3,}", lines[i + 1]):
            flush_para()
            rows = [split_row(line)]
            i += 2
            while i < len(lines) and lines[i].strip().startswith("|"):
                rows.append(split_row(lines[i]))
                i += 1
            add_table(doc, rows)
            continue

        if not stripped:
            flush_para()
            i += 1
            continue

        if re.match(r"^-{3,}$", stripped):
            flush_para()
            i += 1
            continue

        heading = re.match(r"^(#{1,4})\s+(.*)$", stripped)
        if heading:
            flush_para()
            level = len(heading.group(1))
            text = heading.group(2).strip()
            if level == 1:
                p = doc.add_paragraph(style="Title")
                add_inline(p, text)
            else:
                p = doc.add_heading(level=level - 1)
                add_inline(p, text)
            i += 1
            continue

        if stripped.startswith(">"):
            flush_para()
            quote = []
            while i < len(lines) and lines[i].strip().startswith(">"):
                quote.append(lines[i].strip()[1:].strip())
                i += 1
            # sublistas dentro de la cita se convierten en líneas con viñeta
            text = " ".join(q if not q.startswith("- ") else "• " + q[2:] for q in quote if q)
            add_quote(doc, text)
            continue

        lm = LIST_RE.match(line)
        if lm:
            flush_para()
            level = min(len(lm.group("indent").replace("\t", "  ")) // 2, 2)
            text = lm.group("text")
            numbered = lm.group("marker")[0].isdigit()
            check = re.match(r"^\[( |x|X)\]\s+(.*)$", text)
            style = "List Number" if numbered else "List Bullet"
            if level:
                style += f" {level + 1}"
            if check:
                # Checklist: casilla en lugar de viñeta, con sangría francesa
                p = doc.add_paragraph()
                p.paragraph_format.left_indent = Cm(0.9 + 0.6 * level)
                p.paragraph_format.first_line_indent = Cm(-0.6)
            else:
                p = doc.add_paragraph(style=style)
            p.paragraph_format.space_after = Pt(2)
            if check:
                box = p.add_run("☑ " if check.group(1).lower() == "x" else "☐ ")
                box.font.size = Pt(11)
                text = check.group(2)
            add_inline(p, text)
            i += 1
            continue

        para_buf.append(line)
        i += 1

    flush_para()
    out = md_path.with_suffix(".docx")
    doc.save(out)
    return out


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    targets: list[Path] = []
    for a in argv:
        p = Path(a)
        if p.is_dir():
            targets += sorted(x for x in p.rglob("*.md") if "_tools" not in x.parts)
        else:
            targets.append(p)
    for t in targets:
        out = convert(t)
        print(f"[OK] {t} -> {out.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
