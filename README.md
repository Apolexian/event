# event-tracker

Captures Umamusume training event outcomes while you play and tallies them across runs.

## Setup

```
pip install -e .
```

Event names are resolved from `data/text_data.json` (bundled).

## Running

Start the game, then:

```
event-tracker run
```

Attaches to the game via Frida, captures network packets, and prints outcomes live. Ctrl+C to stop and save.

```
event-tracker show              # all observed events
event-tracker show 801008002    # one event by story_id
event-tracker export            # dump observations.json to stdout
```

Options:
```
--text-data PATH   path to text_data.json
--obs PATH         output file (default: observations.json)
--label TEXT       session folder suffix
--save-every N     autosave every N observations (default: 10)
--debug            verbose logging
```

## What it shows

Each event outcome as it happens:

```
Enemies on Main Street (story 801008002) choice 1 → hint:20049+1
Solid Showing (story 501027709) choice 2 → POW+12 SP+56 VIT-35
[outing 302] (story -302) choice 0 → MOD+1
```

`defined: dispX(...)` shown when server provides pre-defined reward data.

`VIT~full` shown when VIT reward was capped at max.

`show` displays per-choice outcome frequencies with percentages:

```
Enemies on Main Street (id 801008002)
  Choice 1 — seen 3x
     2x  (66.7%)  hint:20049+1
     1x  (33.3%)  VIT-5 hint:20049+1
```

Outings (non-support-card recreation) appear in a separate section.

## Updating data

After a game update run:

```
python update_data.py <path/to/master.mdb>
```

`master.mdb` is typically at `%APPDATA%\..\LocalLow\Cygames\Umamusume\master\master.mdb`.

## Limitations

- **First action after attach is missed if it's an outing** — no prior state to diff against. Start the tool before beginning a training turn to avoid this.
- **VIT gains when already at max** show as `VIT~full` with no amount.
- Outings are identified by `command_group_id`, not display name — `[outing 302]` etc.
