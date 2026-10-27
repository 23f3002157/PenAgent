# PenAgent Console

A small, dependency-free website for PenAgent: a landing page explaining what
it does and why, an operator dashboard for watching it work live (audits,
evidence timeline, Component 5's approval inbox, Component 6's report with a
one-click PDF download, and a guided-run panel that drives real probes from
the browser), a full-surface exploration view, and a scored results/baselines
comparison. All of it reads from your running services, or from static JSON
exported by `demo/export_ui_data.py`, over plain `fetch()`.

No build step, no npm, no framework. Just `index.html` + `styles.css` +
`app.js`, consistent with the rest of this repository being Python-first.
Light/dark theme toggle in the top bar (persisted per browser); every data
table in the console is filterable, sortable, and downloadable as CSV.

## Run it

```bash
cd ui
python -m http.server 8800
```

Open <http://localhost:8800>. In the **Connection** panel, enter:

- **Executor (C3) base URL** — e.g. `http://127.0.0.1:9003`
- **Report (C6) base URL** — e.g. `http://127.0.0.1:9005`
- **Spec graph (C1) base URL** — e.g. `http://127.0.0.1:9001` (unauthenticated by
  design, same as the rest of C1; needed for the Explore tab's endpoint map)
- **Operator token** — your `PENAGENT_API_TOKENS` value (see `.env`)

These are only kept in this browser's `localStorage`; nothing is sent
anywhere except the two base URLs you configure. C3 and C6 both need CORS
enabled for the browser to reach them — this is on by default for any
`localhost`/`127.0.0.1` origin (see `install_cors` in
`penagent_common/api.py`); set `PENAGENT_UI_ORIGINS` (comma-separated) on
those services if you're serving the console from somewhere else.

## What you can do here

Four top-nav views: **Home** (the landing page), **Audits** (the operator
console), **Exploration** (PenAgent run against every real route Juice
Shop/DVWS expose, unscored), and **Results** (the paper's scored evaluation
numbers and the baseline comparison).

### Home view

The entry point — what PenAgent is, the problem it solves, and the evidence
that it works, before you touch a single form field:

- An animated hero with the three ways to go deeper (watch it explore, see
  the evidence, or open the operator console).
- **The problem** — three cards on why this exists (APIs outpace manual
  testing, scanners guess instead of verify, autonomy still needs a human
  approval gate).
- **How it works** — a clickable, animated pipeline diagram of all 6
  components in their real request flow, including Component 5's branch and
  the mutation/replanning loops. Click any node for what it actually does.
- **What it's actually found** — live stat tiles (routes executed, precision,
  F1 score, challenges solved, DVWS findings) that count up on scroll,
  computed from the same exported JSON the Exploration and Results views
  read — never hardcoded, never stale.
- **Why execution beats guessing** — a teaser of the head-to-head comparison,
  linking into the full version on the Results view.

Every animation here is plain CSS keyframes/transitions plus vanilla JS
(`IntersectionObserver` for scroll-reveal and count-up, no library), and
respects `prefers-reduced-motion`.

### Audits view

- **Sidebar** — list existing audits, create a new one against an
  already-authorized target (`dvws`, `srebench-api`, `juice-shop`, or
  `fixture` — a `datalist` suggests these). With no audit selected yet, two
  **Quick-start** buttons create and open an audit against DVWS or Juice Shop
  in one click.
- **Explore** tab — a live endpoint map: every operation C1 discovered for
  this target, laid out around the target as a hub, colored by its latest
  classification (grey = not yet probed). Next to it, a scrolling activity
  feed of every probe as it happens. For the three real targets, a **run
  panel** above the map lets you actually drive the pre-authored guided
  exploit chain from here — "Run this step" fires one probe+interpret call
  (`POST {c3}/v1/audits/{audit}/guided-step`) and advances the map live;
  "Run all remaining (paced)" walks the whole chain with the same ~2s cadence
  `demo/live_demo.py` uses, and stops cleanly if a step lands on Component 5
  (go resolve it in the Approvals tab, then continue). This is the literal
  "click to make the agent run things on DVWA/Juice Shop" control surface.
- **Evidence** tab — the live probe-by-probe timeline (classification,
  HTTP status, reasoning) and the audit's state-machine transition trail.
  Polls every few seconds while an audit is selected.
- **Approvals** tab — Component 5's inbox: every pending (or decided) request
  with its full human-readable description, and one-click approve/deny.
- **Report** tab — Component 6's CVSS-scored findings (severity-colored),
  observations, and operational issues, with a live classification summary
  and a **Download PDF report** link that fetches
  `GET {c6}/v1/audits/{audit}/report.pdf` with your operator token.
- **Session state** tab — tokens/cookies/object IDs/observations the audit
  has gathered so far (redacted unless you hold the owning operator token).

This mirrors `docs/WALKTHROUGH.md` exactly — that document is the narrated,
curl-based version of the same tour.

### Exploration view

Also needs no connection/token — reads `data/explore.json`, exported by
`python -m demo.export_ui_data` from `reports/explore-juice-shop.json` and
`reports/explore-dvws.json` (produced by `python -m demo.explore_run
--output reports/explore`, which drives PenAgent against **every** real
route each target exposes — 46 for Juice Shop, pulled directly off the
running container's `build/server.js`, not a curated subset — with plain
generic inputs, no scoring against hidden ground truth). Per target:

- **Stat tiles** — routes authorized, probes executed, STRONG/CONFIRMED
  findings, and how many of those same routes a zero-hint autonomous run
  (real C1→C2→C3, no human input at all) could even reach on its own.
- **Status-code bar** — protected (401/403) vs. exposed-to-anonymous (2xx)
  vs. target-crashed (5xx), legend + direct-labeled counts, colorblind-safe
  (validated with the dataviz skill's palette checker against this exact
  3-color set).
- **Method chips** and a **status-by-resource-area breakdown** — every op
  grouped into its resource area (Identity & auth, Admin, Basket & checkout,
  Orders, …) with its own protected/exposed/crash bar, so you can see which
  *parts* of the API are the weak ones, not just an aggregate number.
- **A clickable endpoint map** — every authorized route as a node around the
  target, colored the same way as the status bar. Click a node (or a row in
  the table at the bottom) to open the detail panel beside it: method+path,
  category, executor status, HTTP code, and — if PenAgent called it
  STRONG_SIGNAL/CONFIRMED — the full explanation, CVSS vector and
  remediation text, the same content the Report tab shows.
- **Findings** — any STRONG_SIGNAL/CONFIRMED result, as the same cards the
  Report tab uses.
- **Juice Shop's own challenge tracker** — a highlighted card listing
  challenges `GET /api/Challenges` independently confirms were solved (not
  PenAgent's self-grading).
- **A collapsible table** of every individual request and what came back —
  filterable by typing (path, category or status), sortable by clicking any
  column header, and downloadable as CSV, also click-to-expand into the
  same detail panel as the graph.

### Baselines & Results view

Needs no connection/token — it reads static JSON files exported by
`python -m demo.export_ui_data` (`data/guided-chains.json`,
`data/results.json`, `data/comparison.json`), regenerate them after a fresh
`demo/run_evaluation.py` / `demo/baseline_pentestgpt.py` run. Per target
(DVWS, SREBench-API, Juice Shop): a true-positive-rate bar chart comparing
PenAgent (autonomous vs. ground-truth-guided) against **six** local Ollama
PentestGPT-style baselines (1.0B–4.3B parameters, real sizes from
`ollama show`), plus a full metrics table (TPR, FPR, CVSS accuracy, chain
depth, time to first finding).

Above the per-target cards, a **head-to-head comparison** aggregates all
eight approaches (PenAgent guided + autonomous, six baselines) across all
three targets at once: ranked precision and F1 bar charts, a sortable,
downloadable table (precision/recall/F1/CVSS-accuracy/model size/wall
clock), and an evidence-based explanation of why PenAgent's F1 and precision
come out ahead of every baseline — because every `CONFIRMED_VULNERABILITY`
it reports passed a real HTTP request against a configured predicate, not a
language-model guess. The methodology caveats (n=1, no Burp/ZAP,
autonomous ≠ guided) are stated inline and in `docs/RESULTS.md`.
