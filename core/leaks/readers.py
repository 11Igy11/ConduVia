from __future__ import annotations

import re
import zipfile
from pathlib import Path
from typing import Iterator

from core.leaks.encoding import decode_bytes

TEXT_SUFFIXES = {".txt", ".csv", ".tsv", ".log", ".dat"}
DOCX_SUFFIX = ".docx"

_WT_RE = re.compile(rb"<w:t[^>]*>(.*?)</w:t>", re.S)
_PARA_SPLIT = b"</w:p>"
_XML_ENTITIES = (
    (b"&amp;", b"&"),
    (b"&lt;", b"<"),
    (b"&gt;", b">"),
    (b"&quot;", b'"'),
    (b"&apos;", b"'"),
)


def iter_text_lines(path: str | Path, encoding: str = "utf-8") -> Iterator[str]:
    """Stream a leak file line by line without loading it into memory."""
    p = Path(path)
    suffix = p.suffix.lower()
    if suffix == DOCX_SUFFIX:
        yield from _iter_docx_lines(p)
        return
    with p.open("r", encoding=(encoding or "utf-8"), errors="replace", newline="") as handle:
        for line in handle:
            yield line.rstrip("\r\n")


def _iter_docx_lines(path: Path) -> Iterator[str]:
    with zipfile.ZipFile(path) as archive:
        with archive.open("word/document.xml") as stream:
            buffer = b""
            while True:
                chunk = stream.read(262144)
                if not chunk:
                    break
                buffer += chunk
                while _PARA_SPLIT in buffer:
                    head, buffer = buffer.split(_PARA_SPLIT, 1)
                    text = _paragraph_text(head)
                    if text:
                        yield text
            text = _paragraph_text(buffer)
            if text:
                yield text


def _paragraph_text(paragraph: bytes) -> str:
    runs = _WT_RE.findall(paragraph)
    if not runs:
        return ""
    joined = b"".join(runs)
    for entity, char in _XML_ENTITIES:
        joined = joined.replace(entity, char)
    return joined.decode("utf-8", errors="replace").strip()


def sample_lines(path: str | Path, encoding: str = "utf-8", count: int = 50) -> list[str]:
    out: list[str] = []
    for line in iter_text_lines(path, encoding):
        if line.strip():
            out.append(line)
        if len(out) >= count:
            break
    return out


def sample_raw_bytes(path: str | Path, size: int = 65536) -> bytes:
    """Raw bytes from a text file (used to preview/guess encoding)."""
    p = Path(path)
    if p.suffix.lower() == DOCX_SUFFIX:
        return b""
    with p.open("rb") as handle:
        return handle.read(size)


def guess_encoding(path: str | Path) -> str:
    """Lightweight encoding guess for the wizard default."""
    p = Path(path)
    if p.suffix.lower() == DOCX_SUFFIX:
        return "utf-8"
    data = sample_raw_bytes(p)
    if not data:
        return "utf-8"
    try:
        data.decode("utf-8", errors="strict")
        return "utf-8"
    except UnicodeDecodeError:
        return "cp1250"


def is_supported(path: str | Path) -> bool:
    suffix = Path(path).suffix.lower()
    return suffix in TEXT_SUFFIXES or suffix == DOCX_SUFFIX
