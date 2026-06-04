"""Decode GetChoiceReward gain_param_array into human-readable strings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_STAT_NAMES = {
    1: "SPD", 2: "STA", 3: "POW", 4: "GUT", 5: "WIT",
    6: "max_vital", 7: "SP", 10: "VIT", 11: "MOD", 30: "SP",
}

_EVT_VITAL  = 1  # v0=amount
_EVT_STAT   = 2  # v0=stat_id, v1=amount
_EVT_BOND   = 3  # v0=char_id, v1=amount
_EVT_SKILL  = 4  # v0=skill_id, v1=hint_lv (direct skill_id)
_EVT_HINT_G = 5  # v0=group_id, v1=hint_lv
_EVT_HINT_S = 6  # v0=skill_id, v1=hint_lv (also direct skill_id)

_reward_table: dict[int, dict] | None = None
_skill_names: dict[int, str] | None = None        # skill_id -> name
_group_to_skill: dict[int, int] | None = None      # group_id -> first skill_id


def _load(data_dir: Path) -> None:
    global _reward_table, _skill_names, _group_to_skill
    if _reward_table is not None:
        return

    rows = json.loads((data_dir / "single_mode_event_choice_reward.json").read_text(encoding="utf-8"))["rows"]
    _reward_table = {r["id"]: r for r in rows}

    text_rows = json.loads((data_dir / "text_data.json").read_text(encoding="utf-8"))["rows"]
    _skill_names = {r["index"]: r["text"] for r in text_rows if r["category"] == 47}

    skill_rows = json.loads((data_dir / "skill_data.json").read_text(encoding="utf-8"))["rows"]
    _group_to_skill = {}
    for r in skill_rows:
        if r["group_id"] not in _group_to_skill:
            _group_to_skill[r["group_id"]] = r["id"]


def _skill_name(skill_id: int) -> str:
    return _skill_names.get(skill_id, f"skill:{skill_id}")


def decode_reward(gain_param: dict[str, Any], data_dir: Path) -> str | None:
    _load(data_dir)
    did = int(gain_param.get("display_id") or 0)
    v0  = int(gain_param.get("effect_value_0") or 0)
    v1  = int(gain_param.get("effect_value_1") or 0)

    row = _reward_table.get(did)
    if not row:
        return f"disp{did}({v0},{v1})"

    evt0 = row["effect_value_type_0"]

    if evt0 == 0:
        return None

    if evt0 == _EVT_STAT:
        stat = _STAT_NAMES.get(v0, f"stat{v0}")
        if v1 > 0:  return f"{stat}+{v1}"
        if v1 < 0:  return f"{stat}{v1}"
        return None

    if evt0 == _EVT_VITAL:
        if v0 > 0:  return f"VIT+{v0}"
        if v0 < 0:  return f"VIT{v0}"
        return None

    if evt0 == _EVT_BOND:
        return f"bond+{v1}"

    if evt0 in (_EVT_SKILL, _EVT_HINT_S):
        name = _skill_name(v0)
        return f"hint:{name}+{v1}"

    if evt0 == _EVT_HINT_G:
        sid = _group_to_skill.get(v0)
        name = _skill_name(sid) if sid else f"group:{v0}"
        return f"hint:{name}+{v1 if v1 else 1}"

    return f"disp{did}({v0},{v1})"


def decode_rewards(gain_params: list[dict[str, Any]], data_dir: Path) -> list[str]:
    return [s for p in gain_params if (s := decode_reward(p, data_dir)) is not None]
