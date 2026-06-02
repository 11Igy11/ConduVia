from __future__ import annotations

# Canonical (dedicated) columns stored directly on leak_records.
# Any mapped field not in this set is stored inside the `extra` JSON blob.
DEDICATED_FIELDS: tuple[str, ...] = (
    "phone",
    "email",
    "oib",
    "fb_id",
    "username",
    "first_name",
    "last_name",
    "full_name",
    "gender",
    "birthday",
    "city",
    "hometown",
    "employer",
    "address",
    "secret",
)

# Special mapping tokens used by the import wizard.
FIELD_SKIP = "skip"

# Fields the auto leak-lookup enricher matches exactly (no name search).
EXACT_LOOKUP_FIELDS: tuple[str, ...] = ("phone", "email", "fb_id", "oib")

# Free-text searchable columns indexed via FTS5.
FTS_FIELDS: tuple[str, ...] = ("full_name", "city", "hometown", "employer")

# Human-friendly labels for the UI mapping dropdown / viewer columns.
FIELD_LABELS: dict[str, str] = {
    "skip": "— ignore —",
    "phone": "Phone (MSISDN)",
    "email": "Email",
    "oib": "OIB",
    "fb_id": "Facebook ID",
    "username": "Username",
    "first_name": "First name",
    "last_name": "Last name",
    "full_name": "Full name",
    "gender": "Gender",
    "birthday": "Date of birth",
    "city": "City",
    "hometown": "Hometown",
    "employer": "Employer",
    "address": "Address",
    "secret": "Password/Hash",
    "relationship": "Relationship status",
    "source_date": "Date (source)",
}

# Suggested extra (non-dedicated) field names offered in the wizard dropdown.
KNOWN_EXTRA_FIELDS: tuple[str, ...] = ("relationship", "source_date")

# All field tokens selectable in the mapping wizard, in display order.
SELECTABLE_FIELDS: tuple[str, ...] = (
    (FIELD_SKIP,) + DEDICATED_FIELDS + KNOWN_EXTRA_FIELDS
)


def field_label(field: str) -> str:
    return FIELD_LABELS.get(field, field)
