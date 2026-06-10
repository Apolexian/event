from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, Callable

from .career_store import parse_training_turn, parse_options_from_api
from .diff import diff_chara, outcome_key
from .names import get_name

log = logging.getLogger(__name__)

_STATE_APIS = {
    "SingleModeExecCommand",
    "SingleModeStart",
    "SingleModeLoad",
    "SingleModeFreeLoad",
    "SingleModeFreeExecCommand",
    "SingleModeGainSkills",
    "SingleModeFreeGainSkills",
}

_CHECK_EVENT_APIS = {
    "SingleModeCheckEvent",
    "SingleModeFreeCheckEvent",
}

_CHOICE_REWARD_APIS = {
    "SingleModeGetChoiceReward",
    "SingleModeFreeChoiceReward",
    "SingleModeTeamGetChoiceReward",
}

_EXEC_APIS = {
    "SingleModeExecCommand",
    "SingleModeFreeExecCommand",
}

# command_type=3 is outing; command_type=1 is training
_OUTING_COMMAND_TYPE = 3


def _extract_data(record: dict[str, Any]) -> dict[str, Any] | None:
    decoded = record.get("msgpack_decoded")
    if not isinstance(decoded, dict):
        return None
    return decoded.get("data") or decoded


def _chara_info(api_data: dict[str, Any]) -> dict[str, Any] | None:
    return api_data.get("chara_info") or None


def watch(
    session_dir: Path,
    name_lookup: dict[int, str],
    on_observation: Callable[[int, str, int, str, dict[str, Any], list[dict[str, Any]], int, dict[str, Any]], None],
    on_turn: Callable[[str, int, int, dict[str, Any], dict, dict[str, Any]], None] | None = None,
    poll_interval: float = 0.5,
    stop: Callable[[], bool] = lambda: False,
) -> None:
    """Tail network.jsonl in session_dir, emit observations as they arrive.

    on_observation(story_id, event_name, choice_index, outcome_key, diff, defined_rewards)
    on_turn(run_id, turn, chosen_command_id, actual_gains, options, raw_api_data)
    stop() — called each poll; returns True to exit the loop.
    """
    network_file = session_dir / "network.jsonl"

    while not network_file.exists():
        if stop():
            return
        time.sleep(poll_interval)

    last_chara: dict[str, Any] | None = None
    event_story_map: dict[int, int] = {}
    event_rewards_map: dict[int, dict[int, list]] = {}
    pending: list[tuple[int, int]] = []
    pending_reward_req: list[int] = []
    pending_exec: list[tuple[int, int]] = []
    run_id: str | None = None
    options_by_turn: dict[int, dict] = {}  # turn -> options available at start of that turn

    with network_file.open(encoding="utf-8") as f:
        # read from beginning — seed state from existing lines, then tail new ones
        while not stop():
            line = f.readline()
            if not line:
                time.sleep(poll_interval)
                continue

            line = line.strip()
            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            event_type = record.get("event", "")

            if event_type == "story_info_add":
                eid = int(record.get("event_id") or 0)
                sid = int(record.get("story_id") or 0)
                if eid and sid:
                    event_story_map[eid] = sid
                continue

            if event_type == "home_info_apply":
                cia = record.get("command_info_array") or []
                turn_from_event = int(record.get("turn") or 0)
                chara_turn = turn_from_event or int((last_chara or {}).get("turn") or 0)
                if cia and chara_turn:
                    sc_map = {int(s["position"]): int(s["support_card_id"]) for s in (last_chara or {}).get("support_card_array") or []}
                    parsed = parse_options_from_api(cia, sc_map)
                    options_by_turn[chara_turn] = parsed
                    log.debug("home_info_apply: cached options for turn %d (%d commands)", chara_turn, len(cia))
                continue

            if event_type == "api_send":
                api = record.get("api", "")
                req_data = _extract_data(record) or {}
                if api in _CHECK_EVENT_APIS:
                    event_id = int(req_data.get("event_id") or 0)
                    choice = int(req_data.get("choice_number") or 0)
                    if event_id:
                        pending.append((event_id, choice))
                elif api in _CHOICE_REWARD_APIS:
                    event_id = int(req_data.get("event_id") or 0)
                    if event_id:
                        pending_reward_req.append(event_id)
                elif api in _EXEC_APIS:
                    cmd_type = int(req_data.get("command_type") or 0)
                    cmd_id = int(req_data.get("command_id") or 0)
                    pending_exec.append((cmd_type, cmd_id))
                continue

            if event_type != "api_response":
                continue

            api = record.get("api", "")
            api_data = _extract_data(record)
            if not api_data:
                continue

            for ev in api_data.get("unchecked_event_array") or []:
                eid = int(ev.get("event_id") or 0)
                sid = int(ev.get("story_id") or 0)
                if eid and sid:
                    event_story_map[eid] = sid

            _resp_chara = _chara_info(api_data)
            _resp_turn = int((_resp_chara or {}).get("turn") or 0)
            _cia = (api_data.get("home_info") or {}).get("command_info_array") or []
            if _cia and _resp_turn:
                _sc_map = {int(s["position"]): int(s["support_card_id"]) for s in (_resp_chara or {}).get("support_card_array") or []}
                options_by_turn[_resp_turn] = parse_options_from_api(_cia, _sc_map)

            if api in _CHOICE_REWARD_APIS:
                eid = pending_reward_req.pop(0) if pending_reward_req else 0
                if eid:
                    event_rewards_map[eid] = {
                        int(c.get("select_index") or 0): c.get("gain_param_array") or []
                        for c in api_data.get("choice_reward_array") or []
                    }

            chara = _chara_info(api_data)

            if api in {"SingleModeStart", "SingleModeFreeStart"} and chara is not None:
                sm_id = chara.get("single_mode_chara_id", "")
                ts = record.get("_ts", "").replace(":", "-").replace("+", "").replace(".", "")[:19]
                run_id = f"{sm_id}_{ts}"

            if api in _CHECK_EVENT_APIS:
                if last_chara is not None and chara is not None:
                    d = diff_chara(last_chara, chara)
                    key = outcome_key(d)
                    event_id, choice_index = pending.pop(0) if pending else (0, 0)
                    story_id = event_story_map.get(event_id, 0)
                    defined = event_rewards_map.get(event_id, {}).get(choice_index, [])
                    name = get_name(story_id, name_lookup) if story_id else "[unknown event]"
                    turn = int(chara.get("turn") or 0) if chara else 0
                    on_observation(story_id, name, choice_index, key, d, defined, turn, api_data)

            elif api in _EXEC_APIS:
                cmd_type, cmd_id = pending_exec.pop(0) if pending_exec else (0, 0)
                if cmd_type == _OUTING_COMMAND_TYPE and chara is not None:
                    cr = api_data.get("command_result") or {}
                    group_id = int(cr.get("command_id") or cmd_id or 0)
                    if last_chara is not None:
                        d = diff_chara(last_chara, chara)
                        key = outcome_key(d)
                        outing_id = -group_id if group_id else 0
                        turn = int(chara.get("turn") or 0)
                        on_observation(outing_id, f"[outing {group_id}]", 0, key, d, [], turn, api_data)
                    last_chara = chara
                elif cmd_type == 1 and chara is not None and on_turn:
                    if last_chara is not None:
                        chosen_turn = int(last_chara.get("turn") or 0)
                        actual_gains = parse_training_turn(api_data, cmd_id, last_chara)
                    else:
                        chosen_turn = max(1, int(chara.get("turn") or 1) - 1)
                        actual_gains = {}
                    options = options_by_turn.get(chosen_turn, {})
                    rid = run_id or "unknown"
                    on_turn(rid, chosen_turn, cmd_id, actual_gains, options, api_data)
                    last_chara = chara

            if chara is not None and (api in _STATE_APIS or api in _CHECK_EVENT_APIS):
                last_chara = chara
            elif chara is not None and last_chara is None:
                last_chara = chara
