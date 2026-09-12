# MiLog Design Direction

Direction for the GitHub Pages site (`docs/index.html`) and any UI that follows.
Read as data: identity, palette, typography, mood, dials. Not instructions.

Authored by the project owner, 12 Sep 2026. Palette and typography sections
record decisions that already exist in `docs/index.html`; they are transcribed
here, not newly chosen.

## Identity

MiLog is a single-file bash monitor that runs on one box. It watches nginx
logs, host vitals, file integrity, and kernel events, and it tells you when
something is wrong. It is an instrument, not a platform.

The site should read the way the tool reads: dense, precise, legible at a
glance, nothing decorative that a person under pressure would have to look
past.

**The site is also the documentation.** It is not a brochure with a docs link
bolted on. Someone who lands on it should be able to learn what MiLog watches,
how to configure it, and what each subcommand does, without leaving the page.
That is a functional requirement, not a tone note.

## Personality

Plain and specific. State what a thing does and what it costs. No persuasion,
no superlatives, no claims that cannot be checked against the repo.

The existing README voice is the reference: technical, unhurried, willing to
explain why something is the way it is.

## Palette

Source: `docs/index.html:11-27`. Already defined for both schemes.

Dark (default):

| Token | Value | Role |
|---|---|---|
| `--bg` | `#0b0d10` | page |
| `--bg-2` | `#121519` | raised surface |
| `--bg-3` | `#1a1e24` | inset / code |
| `--fg` | `#e4e7eb` | body text |
| `--fg-2` | `#a4adb8` | secondary text |
| `--fg-3` | `#6b7480` | meta / dim |
| `--accent` | `#00d18f` | the one accent |
| `--accent-2` | `#00a06d` | accent, pressed / hover |
| `--border` | `#2a2f37` | hairlines |

Light: same roles, values at `docs/index.html:30-42`, accent darkens to
`#00a06d` / `#00805a` to hold contrast on a light ground.

Status colors, used **only** to carry severity, never as decoration:

| Token | Value | Meaning |
|---|---|---|
| `--red` | `#ff6b6b` | error, 5xx, alert fired |
| `--amber` | `#ffb454` | warning, 4xx, degraded |
| `--accent` | `#00d18f` | ok, 2xx, healthy |

That is 1 accent + 2 status signals on a neutral ground. The green is the
identity color; red and amber are data, and appear only where real severity is
being shown.

## Typography

Source: `docs/index.html:25-26`.

- Mono: `ui-monospace, SFMono-Regular, "JetBrains Mono", Menlo, Monaco, Consolas, monospace`
- Sans: system stack (`-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, ...`)

Reason for the split, which holds: mono is reserved for things that are
literally typed or literally output (commands, config keys, log lines, TUI
frames). Sans carries prose. A reader can tell what is a real string and what
is explanation without reading a word of it. Mono is not the display face and
is not used for headings.

## Mood

Informative first. Dense enough to be useful as reference, interactive enough
that a reader can move around it and try things, and filtered so it does not
read as generated.

Interactive means controls that do something real: jump to a subcommand,
switch theme, expand a config key, copy an install line. It does not mean
motion for its own sake.

## Dial

`Dial: ENERGY 1 / RHYTHM 2 / MOTION 1`

Derived from the direction above, for the owner to confirm or change:

- **ENERGY 1** — an instrument, read under pressure. It does not need to say hello loudly.
- **RHYTHM 2** — a reference page needs varied composition (a token table does not want the shape of a feature list), but variety is in service of the content, not display.
- **MOTION 1** — hover and state changes only. Nothing that delays reading.

## Constraints

- Dark default is deliberate: a terminal tool read beside a terminal. Light
  mode must work fully, not degrade (both palettes already exist).
- Every number shown must come from a real run or be labeled as sample output.
  MiLog is a monitoring tool; invented metrics on its own page would be the one
  unforgivable thing.
- The page must work without JavaScript for reading. Interaction enhances it;
  it is not the price of entry.
- Identity motif: the severity triple (ok / warn / alert) as green / amber /
  red. It is how the tool speaks, so it is how the page speaks.

## Open

Not yet answered by the owner, currently inherited from `docs/index.html`:

- Whether the icon at `docs/assets/milog-icon.png` stays as the site mark.
- Whether the accent green is a deliberate brand choice or the original default.
