from __future__ import annotations

from typing import Any

from .names import get_card_name, get_npc_name, get_skill_name

STAT_FIELDS = ("speed", "stamina", "power", "guts", "wiz", "skill_point", "vital")

MOOD_LABELS = {1: "Bad", 2: "Poor", 3: "Normal", 4: "Good", 5: "Great"}


def diff_chara(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}

    result |= {
        f: delta
        for f in STAT_FIELDS
        if (b := before.get(f)) is not None and (a := after.get(f)) is not None
        and (delta := int(a) - int(b)) != 0
    }

    # VIT may be capped at max_vital — record it as capped if after==max and before<max
    a_vital = after.get("vital")
    b_vital = before.get("vital")
    max_vital = after.get("max_vital")
    if (a_vital is not None and b_vital is not None and max_vital is not None
            and int(a_vital) == int(max_vital) and int(b_vital) < int(max_vital)
            and "vital" not in result):
        result["vital_capped"] = True

    # skill_tips_array entries: {group_id, rarity, level}
    b_hints = {int(t["group_id"]): int(t.get("level") or 0) for t in before.get("skill_tips_array") or []}
    a_hints = {int(t["group_id"]): int(t.get("level") or 0) for t in after.get("skill_tips_array") or []}
    hints = [
        {"group_id": gid, "level_delta": a_lv - b_hints.get(gid, 0)}
        for gid, a_lv in a_hints.items()
        if a_lv > b_hints.get(gid, 0)
    ]
    if hints:
        result["hints"] = hints

    b_skills = {int(s["skill_id"]) for s in before.get("skill_array") or []}
    a_skills = {int(s["skill_id"]) for s in after.get("skill_array") or []}
    if new_skills := sorted(a_skills - b_skills):
        result["skills_gained"] = new_skills

    # bond: evaluation_info_array [{training_partner_id, evaluation}]
    # position 1-6 maps to support_card_array by position; 100+ are NPC characters
    sc_map = {int(s["position"]): int(s["support_card_id"]) for s in after.get("support_card_array") or []}
    scenario_id = int(after.get("scenario_id") or 0)
    b_eval = {int(e["training_partner_id"]): int(e["evaluation"]) for e in before.get("evaluation_info_array") or []}
    a_eval = {int(e["training_partner_id"]): int(e["evaluation"]) for e in after.get("evaluation_info_array") or []}

    def _partner_key(pid: int) -> str:
        if pid in sc_map:
            return get_card_name(sc_map[pid])
        return get_npc_name(pid, scenario_id)

    bond_state = {_partner_key(pid): a_eval[pid] for pid in a_eval}
    bond_delta = {_partner_key(pid): a_eval[pid] - b_eval.get(pid, 0)
                  for pid in a_eval if a_eval[pid] != b_eval.get(pid, 0)}
    if bond_state:
        result["bond_state"] = bond_state
    if bond_delta:
        result["bond_delta"] = bond_delta

    # motivation: always record state; record delta only if changed
    a_mot = after.get("motivation")
    b_mot = before.get("motivation")
    if a_mot is not None:
        result["mood"] = int(a_mot)
        if b_mot is not None and int(a_mot) != int(b_mot):
            result["mood_delta"] = int(a_mot) - int(b_mot)

    # conditions: chara_effect_id_array is a flat list of ints
    b_effects = {int(c) for c in before.get("chara_effect_id_array") or []}
    a_effects = {int(c) for c in after.get("chara_effect_id_array") or []}
    if gained := sorted(a_effects - b_effects):
        result["conditions_gained"] = gained
    if lost := sorted(b_effects - a_effects):
        result["conditions_lost"] = lost

    return result


def outcome_key(diff: dict[str, Any]) -> str:
    parts = (
        [f"{f}:{diff[f]:+d}" for f in STAT_FIELDS if f in diff]
        + ([f"mood:{diff['mood_delta']:+d}"] if "mood_delta" in diff else [])
        + [f"bond({pid}):{v:+d}" for pid, v in (diff.get("bond_delta") or {}).items()]
        + [f"hint:{get_skill_name(h['group_id'])}+{h['level_delta']}" for h in diff.get("hints", [])]
        + [f"skill:{s}" for s in diff.get("skills_gained", [])]
        + [f"cond+:{c}" for c in diff.get("conditions_gained", [])]
        + [f"cond-:{c}" for c in diff.get("conditions_lost", [])]
        + (["vital_capped"] if diff.get("vital_capped") else [])
    )
    return "|".join(parts) if parts else "no_change"
