from __future__ import annotations

import base64
import json
import logging
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import click
import msgpack
from rich.console import Console

from .names import build_lookup
from .store import load, save, record
from .watcher import watch

console = Console()
log = logging.getLogger(__name__)

_SCRIPT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TEXT_DATA = _SCRIPT_ROOT / "data" / "text_data.json"
DEFAULT_OBS = _SCRIPT_ROOT / "observations.json"
SESSIONS_DIR = _SCRIPT_ROOT / "sessions"
JS_DIR = _SCRIPT_ROOT / "js"


def _load_js() -> str:
    return (
        (JS_DIR / "il2cpp_helpers.js").read_text(encoding="utf-8")
        + "\n"
        + (JS_DIR / "hook_network.js").read_text(encoding="utf-8")
    )


def _try_msgpack(raw: bytes) -> dict | None:
    try:
        return msgpack.unpackb(raw, raw=False, strict_map_key=False)
    except Exception:
        return None


def _start_collector(session_dir: Path, done: threading.Event, all_domains: bool = False) -> None:
    try:
        from lib.attach import attach
    except ImportError:
        sys.path.insert(0, str(_SCRIPT_ROOT))
        from lib.attach import attach

    network_path = session_dir / "network.jsonl"
    network_file = network_path.open("a", encoding="utf-8")

    def write(rec: dict, raw: bytes | None = None) -> None:
        if raw:
            decoded = _try_msgpack(raw)
            if decoded is not None:
                rec["msgpack_decoded"] = decoded
                rec["raw_b64"] = base64.b64encode(raw).decode("ascii")
            else:
                rec["raw_b64"] = base64.b64encode(raw).decode("ascii")
        rec.setdefault("_ts", datetime.now(timezone.utc).isoformat())
        network_file.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
        network_file.flush()

    def on_message(message, data):
        if message.get("type") == "error":
            log.error("[JS] %s", message.get("description", ""))
            return
        if message.get("type") != "send":
            return
        payload = message.get("payload")
        if not isinstance(payload, dict):
            return
        if payload.get("type") == "collect":
            domain = payload.get("domain", "")
            if domain == "network" or all_domains:
                write(payload.get("data", {}), bytes(data) if data else None)

    frida_session = attach()
    if not frida_session:
        log.error("Failed to attach to game.")
        done.set()
        network_file.close()
        return

    script = frida_session.create_script(_load_js())
    script.on("message", on_message)
    script.set_log_handler(lambda level, text: log.debug("[JS] %s", text))
    script.load()

    done.wait()

    try:
        script.unload()
    except Exception:
        pass
    try:
        frida_session.detach()
    except Exception:
        pass
    network_file.close()


@click.group()
def cli():
    """Uma Musume event outcome tracker."""


@cli.command("run")
@click.option("--text-data", type=click.Path(), default=str(DEFAULT_TEXT_DATA), show_default=True,
              help="Path to masterdb_readable/text_data.json.")
@click.option("--obs", type=click.Path(), default=str(DEFAULT_OBS), show_default=True,
              help="Observations output file.")
@click.option("--label", default="", help="Session label suffix.")
@click.option("--save-every", default=10, show_default=True,
              help="Save observations every N new records.")
@click.option("--debug", is_flag=True, default=False, help="Enable debug logging.")
def run_cmd(text_data, obs, label, save_every, debug):
    """Attach to game, capture events, tally outcomes live."""
    if debug:
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger("event_tracker").setLevel(logging.DEBUG)
    text_data_path = Path(text_data)
    obs_path = Path(obs)

    if not text_data_path.exists():
        console.print(f"[red]text_data.json not found: {text_data_path}[/red]")
        sys.exit(1)

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")
    session_dir = SESSIONS_DIR / (f"{ts}_{label}" if label else ts)
    session_dir.mkdir(parents=True, exist_ok=True)

    name_lookup = build_lookup(text_data_path)
    obs_data = load(obs_path)
    count = 0
    done = threading.Event()

    def on_observation(story_id: int, event_name: str, choice_index: int, key: str, diff: dict[str, Any], defined: list):
        nonlocal count
        record(obs_data, story_id, event_name, choice_index, key)
        count += 1
        diff_str = _format_diff(diff)
        from rich.markup import escape
        console.print(
            f"[cyan]{escape(event_name)}[/cyan] "
            f"[dim](story {story_id})[/dim] "
            f"choice [yellow]{choice_index}[/yellow] → {diff_str}"
        )
        if count % save_every == 0:
            save(obs_data, obs_path)
            console.print(f"[dim]  saved ({count} observations)[/dim]")

    console.print(f"Session: [bold]{session_dir.name}[/bold]")
    console.print("Waiting for game process...")

    collector = threading.Thread(target=_start_collector, args=(session_dir, done), daemon=True)
    collector.start()

    try:
        watch(session_dir, name_lookup, on_observation, stop=done.is_set)
    except KeyboardInterrupt:
        pass
    finally:
        done.set()
        collector.join(timeout=5)
        save(obs_data, obs_path)
        console.print(f"\nSaved {count} observations to [bold]{obs_path}[/bold]")


@cli.command("show")
@click.argument("story_id", required=False, type=int)
@click.option("--obs", type=click.Path(), default=str(DEFAULT_OBS), show_default=True)
def show_cmd(story_id, obs):
    """Show observed outcomes. Pass STORY_ID to filter to one event."""
    obs_path = Path(obs)
    obs_data = load(obs_path)

    if not obs_data:
        console.print("[yellow]No observations yet.[/yellow]")
        return

    entries = list(obs_data.items())
    if story_id is not None:
        entries = [(k, e) for k, e in entries if int(k) == story_id]
        if not entries:
            console.print(f"[yellow]No observations for story_id {story_id}[/yellow]")
            return

    def _print_entry(sid: str, entry: dict) -> None:
        console.rule(f"[bold]{entry['event_name']}[/bold] [dim](id {sid})[/dim]")
        for cidx, choice in sorted(entry["choices"].items(), key=lambda x: int(x[0])):
            console.print(f"  Choice [yellow]{cidx}[/yellow] — seen [bold]{choice['seen']}x[/bold]")
            for key, outcome in sorted(choice["outcomes"].items(), key=lambda x: x[1]["seen"], reverse=True):
                console.print(f"    {outcome['seen']:>4}x  ({outcome['percent']:5.1f}%)  {key}")

    events = sorted([(k, e) for k, e in entries if int(k) > 0], key=lambda x: x[1]["event_name"])
    outings = sorted([(k, e) for k, e in entries if int(k) < 0], key=lambda x: x[1]["event_name"])

    for sid, entry in events:
        _print_entry(sid, entry)
    if outings:
        console.rule("[dim]Outings[/dim]")
        for sid, entry in outings:
            _print_entry(sid, entry)


@cli.command("dump")
@click.option("--label", default="dump", help="Session label suffix.")
@click.option("--api", default=None, help="Filter to API name substring (e.g. SingleMode).")
@click.option("--debug", is_flag=True, default=False, help="Enable debug logging.")
def dump_cmd(label, api, debug):
    """Attach to game and print every API response in full."""
    if debug:
        logging.basicConfig(level=logging.DEBUG)

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")
    session_dir = SESSIONS_DIR / (f"{ts}_{label}" if label else ts)
    session_dir.mkdir(parents=True, exist_ok=True)

    done = threading.Event()
    collector = threading.Thread(target=_start_collector, args=(session_dir, done, True), daemon=True)
    collector.start()

    console.print(f"Session: [bold]{session_dir.name}[/bold]")
    console.print("Dumping all API traffic. Ctrl-C to stop.\n")

    network_file = session_dir / "network.jsonl"
    while not network_file.exists():
        if done.is_set():
            return
        time.sleep(0.2)

    try:
        with network_file.open(encoding="utf-8") as f:
            while not done.is_set():
                line = f.readline()
                if not line:
                    time.sleep(0.2)
                    continue
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                evt = rec.get("event", "")
                if evt in ("ssl_read", "ssl_write", "unitytls_write", "libnative_decrypt",
                           "libnative_encrypt", "schannel_decrypt", "schannel_encrypt",
                           "ssl_write_reassembled", "crypto_salt_found"):
                    continue
                api_name = rec.get("api", "")
                if api and api.lower() not in api_name.lower() and api.lower() not in evt.lower():
                    continue
                if evt in ("api_response", "api_send"):
                    body = rec.get("msgpack_decoded") or {}
                    direction = "→" if evt == "api_send" else "←"
                    color = "yellow" if evt == "api_send" else "cyan"
                    console.rule(f"[bold {color}]{direction} {api_name}[/bold {color}]")
                    if body:
                        console.print_json(json.dumps(body, ensure_ascii=False, default=str))
                else:
                    console.rule(f"[bold magenta]{evt}[/bold magenta]")
                    console.print_json(json.dumps({k: v for k, v in rec.items() if k not in ("_ts",)}, ensure_ascii=False, default=str))
    except KeyboardInterrupt:
        pass
    finally:
        done.set()
        collector.join(timeout=5)


@cli.command("export")
@click.option("--obs", type=click.Path(), default=str(DEFAULT_OBS), show_default=True)
@click.option("--out", type=click.Path(), default=None, help="Output file (default: stdout).")
def export_cmd(obs, out):
    """Export observations as JSON."""
    text = json.dumps(load(Path(obs)), ensure_ascii=False, indent=2)
    if out:
        Path(out).write_text(text, encoding="utf-8")
        console.print(f"Exported to {out}")
    else:
        print(text)


def _format_diff(diff: dict[str, Any]) -> str:
    stat_labels = {
        "speed": "SPD", "stamina": "STA", "power": "POW",
        "guts": "GUT", "wiz": "WIT", "skill_point": "SP",
        "vital": "VIT",
    }
    from .diff import MOOD_LABELS
    mood = diff.get("mood")
    mood_delta = diff.get("mood_delta")
    mood_str = []
    if mood is not None:
        label = MOOD_LABELS.get(mood, str(mood))
        if mood_delta:
            color = "green" if mood_delta > 0 else "red"
            mood_str = [f"MOOD [{color}]{mood_delta:+d}[/{color}]({label})"]
        else:
            mood_str = [f"MOOD [dim]{label}[/dim]"]
    parts = (
        [f"{lbl}[green]{diff[f]:+d}[/green]" if diff[f] > 0 else f"{lbl}[red]{diff[f]:+d}[/red]"
         for f, lbl in stat_labels.items() if f in diff]
        + mood_str
        + [f"[yellow]bond:{pid}+{v}[/yellow]" if v > 0 else f"[red]bond:{pid}{v}[/red]"
           for pid, v in (diff.get("bond_delta") or {}).items()]
        + [f"[magenta]hint:{h['group_id']}+{h['level_delta']}[/magenta]" for h in diff.get("hints", [])]
        + [f"[magenta]skill:{s}[/magenta]" for s in diff.get("skills_gained", [])]
        + [f"[blue]cond+:{c}[/blue]" for c in diff.get("conditions_gained", [])]
        + [f"[blue]cond-:{c}[/blue]" for c in diff.get("conditions_lost", [])]
        + (["[dim]VIT~full[/dim]"] if diff.get("vital_capped") else [])
    )
    return " ".join(parts) if parts else "[dim]no change[/dim]"


if __name__ == "__main__":
    cli()
