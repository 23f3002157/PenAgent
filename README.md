# PenAgent
Components 1–2 provide spec ingestion and hypothesis planning. Components 3–4
add authorized HTTP execution, response interpretation and bounded mutation.
Existing C1/C2 HTTP contracts are preserved. Their SQLite connection helpers now
close handles explicitly; regression tests cover this resource-leak correction.

See the [audit](docs/AUDIT.md), [execution guide](docs/EXECUTION.md),
[paper compliance map](docs/COMPLIANCE.md) and [verification report](docs/VERIFICATION.md).

From this directory with Python 3.11+:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e '.[test]'
.\.venv\Scripts\python.exe -B -m pytest tests -q
.\.venv\Scripts\python.exe -B -m demo.run --output reports/demo.json
```

The demo runs the actual four FastAPI apps over ephemeral loopback TCP ports,
including a negative response and a **safely simulated** positive case. No LLM
key or external target is required. The example config authorizes no targets.
Destructive operations are denied at the missing Component 5 boundary.
Historical benchmark tests require specs/datasets absent from this checkout;
their actual failures are recorded separately from passing fixture tests.

Docker deployment (all four services and an isolated synthetic fixture):

```powershell
.\.venv\Scripts\python.exe -B -m demo.prepare_docker
docker compose build
docker compose up -d --wait --wait-timeout 120
.\.venv\Scripts\python.exe -B -m demo.docker_verify
```

Optional Gemini integration uses the ignored `.env`: configure `GOOGLE_API_KEY`
(preferred) or `GEMINI_API_KEY`, verify an accessible model with
`python -B -m demo.gemini_check --model <model-id>`, then set `GEMINI_MODEL` and
`PENAGENT_LLM_PROVIDER=gemini`. Recreate services and run
`python -B -m demo.docker_verify --require-gemini`. C4 uses LangChain's native
structured output; deterministic authorization and evidence rules remain binding.
No benchmarks, benchmark specifications, ground truth or datasets were created.
