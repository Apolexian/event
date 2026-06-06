"""Persistent tally of observed event outcomes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load(path: Path) -> dict[str, Any]:
    if path.exists():
        with path.open(encoding="utf-8") as f:
            return json.load(f)
    return {}


def save(data: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def _recompute_percents(choice: dict[str, Any]) -> None:
    total = choice["seen"]
    for outcome in choice["outcomes"].values():
        outcome["percent"] = round(outcome["seen"] / total * 100, 1) if total else 0.0


def record(
    data: dict[str, Any],
    story_id: int,
    event_name: str,
    choice_index: int,
    outcome_key: str,
) -> None:
    sid = str(story_id)
    cidx = str(choice_index)

    if sid not in data:
        data[sid] = {"event_name": event_name, "choices": {}}

    event = data[sid]
    if event_name and event["event_name"].startswith("[story "):
        event["event_name"] = event_name

    choices = event["choices"]
    if cidx not in choices:
        choices[cidx] = {"seen": 0, "outcomes": {}}

    choice = choices[cidx]
    choice["seen"] += 1

    outcomes = choice["outcomes"]
    if outcome_key not in outcomes:
        outcomes[outcome_key] = {"seen": 0, "percent": 0.0}
    outcomes[outcome_key]["seen"] += 1

    _recompute_percents(choice)
