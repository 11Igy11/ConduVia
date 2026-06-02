from __future__ import annotations

import unicodedata

# Encodings offered in the import wizard. UTF-8 first, then common
# Central-European single-byte encodings that hold Croatian diacritics.
SUPPORTED_ENCODINGS: tuple[str, ...] = ("utf-8", "cp1250", "iso-8859-2", "latin-1")

# Explicit Croatian diacritic folding (applied before generic NFKD strip so
# that characters that NFKD does not decompose are still handled).
_FOLD_MAP = str.maketrans(
    {
        "š": "s", "Š": "S",
        "đ": "d", "Đ": "D",
        "č": "c", "Č": "C",
        "ć": "c", "Ć": "C",
        "ž": "z", "Ž": "Z",
    }
)


def ascii_fold(text: str) -> str:
    """Lower-cased ASCII representation for diacritic-insensitive search."""
    if not text:
        return ""
    folded = str(text).translate(_FOLD_MAP)
    decomposed = unicodedata.normalize("NFKD", folded)
    stripped = "".join(ch for ch in decomposed if not unicodedata.combining(ch))
    return stripped.lower().strip()


def decode_bytes(data: bytes, encoding: str) -> str:
    enc = (encoding or "utf-8").lower()
    if enc not in SUPPORTED_ENCODINGS:
        enc = "utf-8"
    return data.decode(enc, errors="replace")


def try_fix_mojibake(text: str) -> str:
    """Best-effort repair of text that was already decoded with the wrong
    single-byte codec (classic cp1250-as-latin1 mojibake)."""
    if not text or "\ufffd" not in text and not _has_mojibake_markers(text):
        return text
    try:
        repaired = text.encode("latin-1", errors="strict").decode("cp1250", errors="strict")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return text
    # Only accept the repair if it did not introduce replacement chars.
    if "\ufffd" in repaired:
        return text
    return repaired


def _has_mojibake_markers(text: str) -> bool:
    return any(marker in text for marker in ("Ã", "Å", "Ä", "â€"))
