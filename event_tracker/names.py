from __future__ import annotations

import json
from pathlib import Path

_story_cache: dict[int, str] | None = None
_card_cache: dict[int, str] | None = None
_chara_cache: dict[int, str] | None = None
# (partner_id, scenario_id) -> chara_id
_partner_cache: dict[tuple[int, int], int] | None = None

_data_dir: Path | None = None


def _load_text(text_data_path: Path) -> None:
    global _story_cache, _card_cache, _chara_cache
    with text_data_path.open(encoding="utf-8") as f:
        data = json.load(f)
    _story_cache = {int(r["index"]): r["text"] for r in data["rows"] if r["category"] == 181 and r.get("text")}
    _card_cache  = {int(r["index"]): r["text"] for r in data["rows"] if r["category"] == 75  and r.get("text")}
    _chara_cache = {int(r["index"]): r["text"] for r in data["rows"] if r["category"] == 170 and r.get("text")}


def _load_partners(data_dir: Path) -> None:
    global _partner_cache
    path = data_dir / "single_mode_unique_chara.json"
    rows = json.loads(path.read_text(encoding="utf-8"))["rows"]
    _partner_cache = {(r["partner_id"], r["scenario_id"]): r["chara_id"] for r in rows}


def build_lookup(text_data_path: Path) -> dict[int, str]:
    global _data_dir
    _data_dir = text_data_path.parent
    if _story_cache is None:
        _load_text(text_data_path)
        _load_partners(_data_dir)
    return _story_cache


def get_name(story_id: int, lookup: dict[int, str]) -> str:
    return lookup.get(story_id, f"[story {story_id}]")


def get_card_name(support_card_id: int) -> str:
    if _card_cache is None:
        return str(support_card_id)
    return _card_cache.get(support_card_id, str(support_card_id))


def get_npc_name(partner_id: int, scenario_id: int) -> str:
    if _partner_cache is None or _chara_cache is None:
        return f"npc_{partner_id}"
    chara_id = _partner_cache.get((partner_id, scenario_id))
    if chara_id is None:
        return f"npc_{partner_id}"
    return _chara_cache.get(chara_id, f"npc_{partner_id}")
