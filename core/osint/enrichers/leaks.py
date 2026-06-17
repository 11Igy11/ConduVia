from __future__ import annotations

from core.osint.enrichers.base import EnrichResult


def enrich_leaks(entity_kind: str, entity_value: str, *, kind: str = "") -> EnrichResult:
    value = str(entity_value or "").strip()
    if entity_kind != "identifier":
        return EnrichResult(
            "repository", entity_kind, value, status="error",
            summary="Repository lookup only works for identifiers (phone/email/fb_id/OIB).",
        )
    if not value:
        return EnrichResult("repository", "identifier", value, status="error", summary="Missing value.")

    from core.leaks.search import lookup_identifier

    try:
        rows, total = lookup_identifier(value, kind=kind or None)
    except Exception as exc:
        return EnrichResult("repository", "identifier", value, status="error", summary=f"Repository lookup failed: {exc}")

    if total == 0:
        return EnrichResult(
            "repository", "identifier", value, status="ok",
            summary="No hits in the repository.",
            details={"hits": 0},
        )

    datasets: dict[str, int] = {}
    samples: list[str] = []
    for row in rows:
        name = str(row["dataset_name"] or "")
        datasets[name] = datasets.get(name, 0) + 1
        if len(samples) < 5:
            full_name = str(row["full_name"] or "").strip()
            phone = str(row["phone"] or "").strip()
            samples.append(" · ".join(p for p in (full_name, phone, name) if p))

    dataset_summary = ", ".join(f"{name} ({count})" for name, count in datasets.items())
    details = {
        "hits": total,
        "datasets": dataset_summary,
        "samples": samples,
    }
    return EnrichResult(
        "repository", "identifier", value, status="ok",
        summary=f"{total} hit(s) in the repository: {dataset_summary}",
        details=details,
    )
