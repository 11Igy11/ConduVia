from __future__ import annotations


SUPPORTED_OUTPUT_LANGUAGES = {
    "hr": "Croatian",
    "en": "English",
}


def normalize_output_language(value: str | None, default: str = "hr") -> str:
    raw = (value or "").strip().casefold()
    aliases = {
        "croatian": "hr",
        "hrvatski": "hr",
        "hr": "hr",
        "english": "en",
        "engleski": "en",
        "en": "en",
    }
    normalized = aliases.get(raw, raw)
    return normalized if normalized in SUPPORTED_OUTPUT_LANGUAGES else default


def output_language_label(value: str | None) -> str:
    return SUPPORTED_OUTPUT_LANGUAGES.get(normalize_output_language(value), "Croatian")


def ai_language_instruction(value: str | None) -> str:
    language = normalize_output_language(value)
    if language == "en":
        return "Write the response in English."
    return "Write the response in Croatian."
