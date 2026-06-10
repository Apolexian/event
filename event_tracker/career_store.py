from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_TARGET_TYPE_NAMES = {
    1: "speed", 2: "stamina", 3: "power", 4: "guts", 5: "wiz",
    10: "vital", 30: "skill_point",
}

_COMMAND_NAMES = {
    101: "speed", 102: "stamina", 103: "power", 105: "guts", 106: "wiz",
}


def run_path(careers_dir: Path, run_id: str) -> Path:
    return careers_dir / f"{run_id}.json"


def load_run(careers_dir: Path, run_id: str) -> dict[str, Any]:
    p = run_path(careers_dir, run_id)
    if p.exists():
        with p.open(encoding="utf-8") as f:
            return json.load(f)
    return {"run_id": run_id, "turns": []}


def save_run(careers_dir: Path, run_id: str, data: dict[str, Any]) -> None:
    careers_dir.mkdir(parents=True, exist_ok=True)
    with run_path(careers_dir, run_id).open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def _parse_options(command_info_array: list, support_card_map: dict[int, int]) -> dict:
    options = {}
    for cmd in command_info_array:
        cmd_id = int(cmd.get("command_id") or 0)
        cmd_type = int(cmd.get("command_type") or 0)
        if cmd_type != 1:
            continue
        gains = {
            _TARGET_TYPE_NAMES[int(p["target_type"])]: int(p["value"])
            for p in cmd.get("params_inc_dec_info_array") or []
            if int(p["target_type"]) in _TARGET_TYPE_NAMES
        }
        partners = [
            support_card_map[int(pos)]
            for pos in cmd.get("training_partner_array") or []
            if int(pos) in support_card_map
        ]
        options[str(cmd_id)] = {
            "name": _COMMAND_NAMES.get(cmd_id, str(cmd_id)),
            "gains": gains,
            "partners": partners,
            "failure_rate": int(cmd.get("failure_rate") or 0),
            "level": int(cmd.get("level") or 0),
        }
    return options


def parse_options_from_api(command_info_array: list, support_card_map: dict[int, int]) -> dict:
    return _parse_options(command_info_array, support_card_map)


def record_training(
    run_data: dict[str, Any],
    turn: int,
    chosen_command_id: int,
    actual_gains: dict[str, int],
    options: dict,
    raw: dict[str, Any],
) -> None:
    run_data["turns"].append({
        "turn": turn,
        "type": "training",
        "chosen": _COMMAND_NAMES.get(chosen_command_id, str(chosen_command_id)),
        "chosen_id": chosen_command_id,
        "actual_gains": actual_gains,
        "options": options,
        "raw": raw,
    })


def record_event(
    run_data: dict[str, Any],
    turn: int,
    story_id: int,
    event_name: str,
    choice: int,
    outcome: str,
    raw: dict[str, Any],
) -> None:
    run_data["turns"].append({
        "turn": turn,
        "type": "event",
        "story_id": story_id,
        "event_name": event_name,
        "choice": choice,
        "outcome": outcome,
        "raw": raw,
    })


def parse_training_turn(api_data: dict[str, Any], cmd_id: int, last_chara: dict[str, Any] | None) -> dict[str, int]:
    chara = api_data.get("chara_info") or {}
    if last_chara is not None:
        from .diff import diff_chara, STAT_FIELDS
        d = diff_chara(last_chara, chara)
        return {f: d[f] for f in STAT_FIELDS if f in d}
    return {}
