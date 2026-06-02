from __future__ import annotations

import json
import re
from pathlib import Path

from core.db import APP_DATA_DIR

PROFILES_DIR = APP_DATA_DIR / "leaks" / "profiles"


def _slug(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", str(name or "").strip().lower()).strip("-")
    return slug or "profile"


def save_profile(profile: dict, *, profiles_dir: Path = PROFILES_DIR) -> Path:
    name = str(profile.get("name") or "").strip()
    if not name:
        raise ValueError("Profile must have a name.")
    profiles_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "name": name,
        "delimiter": profile.get("delimiter", ":"),
        "encoding": profile.get("encoding", "utf-8"),
        "has_header": bool(profile.get("has_header", False)),
        "columns": list(profile.get("columns", [])),
    }
    path = profiles_dir / f"{_slug(name)}.json"
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def list_profiles(*, profiles_dir: Path = PROFILES_DIR) -> list[str]:
    if not profiles_dir.exists():
        return []
    names = []
    for path in sorted(profiles_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        name = str(data.get("name") or path.stem)
        names.append(name)
    return names


def load_profile(name: str, *, profiles_dir: Path = PROFILES_DIR) -> dict | None:
    if not profiles_dir.exists():
        return None
    direct = profiles_dir / f"{_slug(name)}.json"
    if direct.exists():
        try:
            return json.loads(direct.read_text(encoding="utf-8"))
        except Exception:
            return None
    for path in profiles_dir.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if str(data.get("name") or "") == name:
            return data
    return None


def delete_profile(name: str, *, profiles_dir: Path = PROFILES_DIR) -> bool:
    path = profiles_dir / f"{_slug(name)}.json"
    if path.exists():
        path.unlink()
        return True
    return False
