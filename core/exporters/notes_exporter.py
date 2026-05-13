from __future__ import annotations

import html
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlparse


EMU_PER_INCH = 914400
DEFAULT_IMAGE_WIDTH_EMU = int(5.8 * EMU_PER_INCH)


@dataclass
class _ImagePart:
    rel_id: str
    source: Path
    target: str
    extension: str
    width_emu: int
    height_emu: int


def export_notes_docx(
    file_path: str | Path,
    *,
    title: str,
    notes_text: str,
    notes_html: str = "",
) -> Path:
    """Export project notes to a Word-compatible DOCX file with embedded images."""
    output = Path(file_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    blocks, image_parts = _document_blocks(notes_text=notes_text, notes_html=notes_html)
    document_xml = _document_xml(title=title, blocks=blocks)

    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as docx:
        docx.writestr("[Content_Types].xml", _content_types_xml(image_parts))
        docx.writestr("_rels/.rels", _package_rels_xml())
        docx.writestr("word/_rels/document.xml.rels", _document_rels_xml(image_parts))
        docx.writestr("word/document.xml", document_xml)
        for image in image_parts:
            docx.write(image.source, f"word/{image.target}")

    return output


def _document_blocks(*, notes_text: str, notes_html: str) -> tuple[list[str], list[_ImagePart]]:
    image_parts: list[_ImagePart] = []
    blocks: list[str] = []

    if notes_html:
        body = _html_body(notes_html)
        paragraph_matches = list(re.finditer(r"<p\b[^>]*>(.*?)</p>", body, flags=re.IGNORECASE | re.DOTALL))
        if paragraph_matches:
            for match in paragraph_matches:
                blocks.extend(_paragraph_blocks_from_html(match.group(1), image_parts))
        else:
            blocks.extend(_paragraph_blocks_from_html(body, image_parts))

    if not blocks:
        blocks = _plain_text_blocks(notes_text)

    return blocks, image_parts


def _paragraph_blocks_from_html(fragment: str, image_parts: list[_ImagePart]) -> list[str]:
    blocks: list[str] = []
    pos = 0
    saw_content = False
    for match in re.finditer(r"<img\b[^>]*\bsrc=[\"']([^\"']+)[\"'][^>]*>", fragment, flags=re.IGNORECASE):
        text = _html_to_text(fragment[pos:match.start()])
        if text:
            blocks.append(_paragraph(text))
            saw_content = True

        image = _image_part_from_src(match.group(1), len(image_parts) + 1)
        if image is not None:
            image_parts.append(image)
            blocks.append(_image_paragraph(image))
            saw_content = True
        pos = match.end()

    text = _html_to_text(fragment[pos:])
    if text:
        blocks.append(_paragraph(text))
        saw_content = True

    if not saw_content:
        blocks.append(_paragraph(""))
    return blocks


def _plain_text_blocks(notes_text: str) -> list[str]:
    blocks = []
    for raw_line in (notes_text or "").splitlines():
        line = raw_line.rstrip()
        if not line:
            blocks.append(_paragraph(""))
            continue

        stripped = line.strip()
        if stripped.startswith("**") and stripped.endswith("**") and len(stripped) > 4:
            blocks.append(_paragraph(stripped.strip("*").strip(), bold=True))
        else:
            blocks.append(_paragraph(line))
    return blocks


def _document_xml(*, title: str, blocks: list[str]) -> str:
    body = _paragraph(title or "Project notes", style="Title") + "".join(blocks)
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document '
        'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
        'xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" '
        'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" '
        'xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture">'
        f"<w:body>{body}<w:sectPr><w:pgSz w:w=\"11906\" w:h=\"16838\"/>"
        '<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" '
        'w:header="708" w:footer="708" w:gutter="0"/></w:sectPr></w:body></w:document>'
    )


def _paragraph(text: str, *, style: str = "", bold: bool = False) -> str:
    props = ""
    if style:
        props += f'<w:pStyle w:val="{html.escape(style)}"/>'
    run_props = "<w:rPr><w:b/></w:rPr>" if bold else ""
    escaped = html.escape(text or "")
    return f"<w:p>{'<w:pPr>' + props + '</w:pPr>' if props else ''}<w:r>{run_props}<w:t>{escaped}</w:t></w:r></w:p>"


def _image_paragraph(image: _ImagePart) -> str:
    name = html.escape(image.source.name)
    return (
        "<w:p><w:r><w:drawing><wp:inline distT=\"0\" distB=\"0\" distL=\"0\" distR=\"0\">"
        f"<wp:extent cx=\"{image.width_emu}\" cy=\"{image.height_emu}\"/>"
        "<wp:effectExtent l=\"0\" t=\"0\" r=\"0\" b=\"0\"/>"
        f"<wp:docPr id=\"{image.rel_id[3:]}\" name=\"{name}\"/>"
        "<wp:cNvGraphicFramePr><a:graphicFrameLocks noChangeAspect=\"1\"/></wp:cNvGraphicFramePr>"
        "<a:graphic><a:graphicData uri=\"http://schemas.openxmlformats.org/drawingml/2006/picture\">"
        "<pic:pic><pic:nvPicPr>"
        f"<pic:cNvPr id=\"{image.rel_id[3:]}\" name=\"{name}\"/>"
        "<pic:cNvPicPr/>"
        "</pic:nvPicPr><pic:blipFill>"
        f"<a:blip r:embed=\"{image.rel_id}\"/>"
        "<a:stretch><a:fillRect/></a:stretch>"
        "</pic:blipFill><pic:spPr>"
        f"<a:xfrm><a:off x=\"0\" y=\"0\"/><a:ext cx=\"{image.width_emu}\" cy=\"{image.height_emu}\"/></a:xfrm>"
        "<a:prstGeom prst=\"rect\"><a:avLst/></a:prstGeom>"
        "</pic:spPr></pic:pic></a:graphicData></a:graphic>"
        "</wp:inline></w:drawing></w:r></w:p>"
    )


def _image_part_from_src(src: str, index: int) -> _ImagePart | None:
    path = _path_from_src(src)
    if path is None or not path.exists() or not path.is_file():
        return None

    extension = _image_extension(path)
    if extension not in {"png", "jpg", "jpeg", "gif", "bmp"}:
        return None

    width, height = _image_dimensions(path, extension)
    if not width or not height:
        width, height = 760, 460
    target_width = DEFAULT_IMAGE_WIDTH_EMU
    target_height = max(1, int(target_width * (height / max(width, 1))))

    return _ImagePart(
        rel_id=f"rId{index}",
        source=path,
        target=f"media/image{index}.{extension}",
        extension=extension,
        width_emu=target_width,
        height_emu=target_height,
    )


def _path_from_src(src: str) -> Path | None:
    src = html.unescape(src or "").strip()
    if not src or src.startswith("data:"):
        return None
    if re.match(r"^[A-Za-z]:[\\/]", src):
        return Path(unquote(src))
    parsed = urlparse(src)
    if parsed.scheme == "file":
        return Path(unquote(parsed.path.lstrip("/")) if re.match(r"^/[A-Za-z]:", parsed.path) else unquote(parsed.path))
    if parsed.scheme:
        return None
    return Path(unquote(src))


def _image_extension(path: Path) -> str:
    ext = path.suffix.lower().lstrip(".")
    return "jpg" if ext == "jpe" else ext


def _image_dimensions(path: Path, extension: str) -> tuple[int, int]:
    data = path.read_bytes()[:32]
    if extension == "png" and data.startswith(b"\x89PNG\r\n\x1a\n") and len(data) >= 24:
        return int.from_bytes(data[16:20], "big"), int.from_bytes(data[20:24], "big")
    if extension in {"jpg", "jpeg"}:
        return _jpeg_dimensions(path)
    return 0, 0


def _jpeg_dimensions(path: Path) -> tuple[int, int]:
    data = path.read_bytes()
    idx = 2
    while idx + 9 < len(data):
        if data[idx] != 0xFF:
            idx += 1
            continue
        marker = data[idx + 1]
        idx += 2
        if marker in {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}:
            return int.from_bytes(data[idx + 3:idx + 5], "big"), int.from_bytes(data[idx + 5:idx + 7], "big")
        if idx + 2 > len(data):
            break
        length = int.from_bytes(data[idx:idx + 2], "big")
        idx += max(length, 2)
    return 0, 0


def _html_body(value: str) -> str:
    match = re.search(r"<body\b[^>]*>(.*?)</body>", value or "", flags=re.IGNORECASE | re.DOTALL)
    return match.group(1) if match else (value or "")


def _html_to_text(value: str) -> str:
    value = re.sub(r"<br\s*/?>", "\n", value or "", flags=re.IGNORECASE)
    value = re.sub(r"<[^>]+>", "", value)
    return html.unescape(value).replace("\xa0", " ").strip()


def _content_types_xml(image_parts: list[_ImagePart]) -> str:
    defaults = [
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>',
        '<Default Extension="xml" ContentType="application/xml"/>',
    ]
    content_types = {
        "png": "image/png",
        "jpg": "image/jpeg",
        "jpeg": "image/jpeg",
        "gif": "image/gif",
        "bmp": "image/bmp",
    }
    for extension in sorted({image.extension for image in image_parts}):
        defaults.append(f'<Default Extension="{extension}" ContentType="{content_types.get(extension, "application/octet-stream")}"/>')
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        + "".join(defaults)
        + '<Override PartName="/word/document.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        "</Types>"
    )


def _package_rels_xml() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="word/document.xml"/>'
        "</Relationships>"
    )


def _document_rels_xml(image_parts: list[_ImagePart]) -> str:
    relationships = []
    for image in image_parts:
        relationships.append(
            f'<Relationship Id="{image.rel_id}" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" '
            f'Target="{image.target}"/>'
        )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        + "".join(relationships)
        + "</Relationships>"
    )
