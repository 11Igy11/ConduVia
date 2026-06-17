from __future__ import annotations

DELIMITER_CANDIDATES: tuple[str, ...] = (":", "\t", ";", "|", ",")


def detect_delimiter(sample_lines: list[str]) -> str:
    """Pick the delimiter that splits sample lines most consistently."""
    lines = [ln for ln in sample_lines if ln.strip()][:200]
    if not lines:
        return ":"
    best = ":"
    best_score = -1.0
    for delim in DELIMITER_CANDIDATES:
        counts = [ln.count(delim) for ln in lines]
        present = [c for c in counts if c > 0]
        if not present:
            continue
        # Consistency: how many lines share the modal count.
        modal = max(set(present), key=present.count)
        if modal == 0:
            continue
        consistency = present.count(modal) / len(lines)
        score = consistency * modal
        if score > best_score:
            best_score = score
            best = delim
    return best


def split_line(line: str, delimiter: str) -> list[str]:
    return [part.strip() for part in str(line).split(delimiter)]


def split_rows(sample_lines: list[str], delimiter: str) -> list[list[str]]:
    rows = []
    for ln in sample_lines:
        if ln.strip():
            rows.append(split_line(ln, delimiter))
    return rows
