# The window: WizTree's shape, aimed at evidence

```
rea-offline gui "C:\Program Files\SomeApp"
rea-offline gui Downloads --port 9100
rea-offline gui Downloads --output window.html --no-open   # shareable snapshot
rea-offline gui report.json --from-report                 # validated archived evidence
rea-offline gui                                           # picker: choose in the window
```

Double-clicking the .exe opens the same picker: the program is a console
tool, and a console opened by a double-click closes the moment the program
exits, so the no-command help text could never be read there. A launch
whose console belongs to the process alone (no terminal behind it) opens
the picker window instead; in a terminal, no command still prints help.

The GUI is a **single window with a treemap on the right and a size grid on
the left** — the layout WizTree made familiar — retargeted from "what is
using my disk" to "what did this installer bring, and how bad is it".

| WizTree does | rea-offline does |
|---|---|
| Pick a drive, scan it | Pick a **target** (folder or installer payload), analyze it |
| Trees/grid sorted by **size** | Same grid, also sorted by **risk** — one click flips it |
| Tiles coloured by **file type** | Tiles coloured by **risk**, so evidence is the first thing you see |
| Files/Extensions/Size filters | Path search + "hide clean" + "risk ≥ 12" |
| Details pane: name, path, size | Details pane: path, size, SHA-256, MD5, imphash, and the **rules that fired** |
| Export to CSV | Export to JSON / Markdown / text (the same files the CLI writes) |

## Why a browser window instead of a native Win32 window

This project builds with **zero crates** so that a release binary can be
produced on a machine with no network and no package registry. A real Win32
window means either raw `RegisterClassW`/`CreateWindowExW` plumbing plus a
custom owner-drawn tree control, or vendoring a GUI framework — hundreds of
lines of unsafe FFI and a large review surface for a window that mostly
displays a table.

A browser is a window manager every supported Windows edition already ships.
So `rea-offline gui`:

1. binds **`127.0.0.1` only** (nothing is exposed to the network — this tool
   is for air-gapped hosts),
2. serves one self-contained page (inline CSS and SVG, **no JavaScript**),
3. opens your default browser at it.

Everything the page shows is also reachable without a browser:
`--output window.html` writes the same HTML to a file, and `/json`, `/text`
and `/markdown` serve the report in the other formats.

## What is deliberately not there

* **No JavaScript.** Every control is a link. That keeps the window usable
  when a policy disables scripting, and means the page cannot be talked into
  doing something the server did not already decide.
* **No writes.** The server answers `GET` only; there is no endpoint that
  deletes, purges, or scans a *new* path. Purging stays a CLI action
  (`rea-offline purge`) so a stray click cannot destroy evidence.
* **No network fetches.** No fonts, no CDNs, no telemetry. The page renders
  identically with the network cable pulled.
* **No state beyond the URL.** Filters, sort, open folders and selection all
  live in the query string, so a colleague can be sent the exact view
  (`/view?filter=setup&hide_clean=1&expand=install`), and a refresh is
  harmless.

## Layout of the code

| File | Responsibility | Tested on |
|---|---|---|
| `src/gui/tree.rs` | size tree, grid rows, sort/filter, **squarified treemap**, details text | every platform (`cargo test`) |
| `src/gui/mod.rs` | HTML/SVG rendering, query-string state, loopback HTTP server | every platform |

The display model knows nothing about HTTP or HTML, which is why the treemap
geometry, the sort order and the filters have real unit tests: tiles must not
overlap, must stay inside their parent, and must cover the canvas; a filter
must not leave an empty folder behind; risk colouring must match the rules.

## Reading the window

* **Colour** — grey means nothing above `info`; green `low`, amber `medium`,
  orange `high`, red `critical`. Colour is never the only signal: the grid
  prints the score and the details pane prints the rule ids.
* **Size** — always the byte count of the file, summed up the tree. The map
  is area-proportional, so a 2 MiB dropper next to a 200 KiB signed DLL is
  visibly bigger *and* visibly red.
* **Verdict chip** (top right) — the same 0–100 score and band the JSON
  report carries, so the window, the CLI text output and the Markdown report
  can never disagree.
* **Coverage chip** — when `scan_issues` is nonempty, an amber incomplete-coverage
  chip remains visible regardless of the selected file; the summary lists the
  affected paths. Operational limitations never masquerade as risk findings.
* **Details pane** — for files, the hashes and findings. For folders, the
  report summary. Hashes are the part people copy into other tools, so they
  are printed in full, never truncated.

## Sandbox runs: one tree, three evidence sets

A sandbox report contains three analyses, and the window shows all of them
together instead of picking one:

| Folder in the grid | What it holds |
|---|---|
| `install/` | the install tree (`report`) |
| `_installer/` | the installer binary that was executed (`installer_report`) |
| anything else | files added/modified outside the install dir, relative to the sandbox root — e.g. `AppData/Roaming/payload.exe` (`drops_report`) |

Absolute installer paths are made relative and lose their drive letter, so
the grid never grows a `C:` folder. Findings are re-keyed to the same paths,
which is what keeps the tile colours and the details pane correct.

The verdict chip shows the **combined** score from the envelope, not the
install tree's — otherwise a clean install directory would sit next to a
critical dropped payload under a green chip. Plain scans are untouched: with
nothing to merge, paths stay exactly as the report recorded them.

## Limitations, honestly

* The page is rebuilt per request. Scans of very large trees (hundreds of
  thousands of files) make each click a re-render of the *report*, not a
  rescan, but the HTML grows with the tree. For a whole-drive sweep, prefer
  `scan` + `--format markdown` and open the document.
* The treemap draws down to tiles of ~1% of the pane; smaller files are still
  in the grid and in the JSON, just not visible as rectangles.
* The loopback port is not authenticated. It binds `127.0.0.1`, so only local
  processes can reach it — on a shared machine, stop the server when done
  (`Ctrl+C`).

## Coverage warnings

The window reads the envelope's `coverage` block when present (falling back to
per-report `scan_issues` for older archives) and shows an amber
`incomplete coverage — N issue(s)` chip beside the verdict. The compact summary
repeats the warning even when the file list is truncated, so a glance at a
partially observed run cannot read as a clean one. The chip is a statement
about what the inspection could see; it never changes the score.

When the envelope carries a `containment` block (sandbox runs), the compact
summary also states the facts the tree cannot show: whether the run was
elevated/root, and whether the registry hive mounted. Like the chip, it never
changes the score — it says which writes may have escaped the snapshot.
