# PenAgent — Component 2: Attack Hypothesis Generation Service (HGS)

The **Attack Hypothesis Generation Service (HGS)** is an independently deployable microservice that consumes the normalized **EndpointGraph** from Component 1 (SIS) and current agent knowledge state to synthesize a prioritized, schema-valid queue of `AttackHypothesis` objects. It re-ranks and synthesizes follow-up hypotheses on demand during live auditing (the **REPLANNING** transition).

---

## 1. Architectural Highlights

- **Plan-and-Execute Decoupling:** Decouples the strategic planner LLM loop from live tool execution. HGS produces a priority queue drained by Component 3 (Executor) via `GET /v1/queue/{target_id}/next`.
- **Candidate Surfacer:** Maps static attack-surface tags from SIS into OWASP API Top-10 categories:
  - `idor_candidate` / `cross_service_param` $\rightarrow$ **API1: BOLA**
  - Auth, token, and login endpoints $\rightarrow$ **API2: Broken Authentication**
  - `sensitive_response` / mass-assignment vectors $\rightarrow$ **API3: BOPLA**
  - `admin_surface` / `unauthenticated_sensitive_action` $\rightarrow$ **API5: BFLA**
  - Debug, environment, and actuator paths $\rightarrow$ **API8: Security Misconfiguration**
- **Hierarchical Context Summarizer:** Groups endpoints by logical service boundary and filters detailed operation nodes within a context budget (default 30) to mitigate context-window bloat on large API graphs.
- **Planner Engine:** Supports Anthropic Claude Sonnet with forced tool-use (`emit_hypotheses`) or OpenAI function calling. Includes a high-fidelity deterministic heuristic planner for zero-cost, reproducible offline testing and local CI runs.
- **Hallucination Guard (Hypothesis Validator):** Rejects any generated hypothesis whose `target_endpoints` or step `op` identifiers do not resolve to real node IDs in the ingested EndpointGraph.
- **Impact × Likelihood Scorer:**
  - *Impact*: Derived from CVSS category priors (e.g., API2: 0.88, API1: 0.82, API5: 0.80) boosted by endpoint sensitivity tags.
  - *Likelihood*: Derived from category prevalence priors boosted by structural graph edges (up to +0.22 bonus when chaining across high-confidence cross-service trust boundaries).
  - *Priority*: $\text{Impact} \times \text{Likelihood}$.
- **Category Diversity & Dedup Filter:** Caps hypotheses per OWASP category (default max 4) and eliminates near-duplicate sequences to prevent myopic over-focus on trivial endpoints.
- **Human Gate Pre-Flagging:** Evaluates operations in the attack sequence; any destructive actions (`DELETE`, purge, drop, reset) automatically set `requires_approval = True`.
- **Dynamic Replan Engine:** Listens to `finding.significant` events or `POST /v1/events/replan`, preserves executed hypotheses, boosts hypotheses that can consume leaked tokens/IDs, and updates queue ordering.

---

## 2. Public API Reference

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/hypotheses/generate` | Generates a prioritized, validated batch of hypotheses (`{target_id, mode, knowledge_state_delta, max_hypotheses}`) |
| `GET` | `/v1/hypotheses/{batch_id}` | Retrieves a previously emitted hypothesis batch |
| `POST` | `/v1/hypotheses/{hypothesis_id}/feedback` | Executor/Interpreter reports execution outcome (`confirmed_vulnerability`, `strong_signal`, `negative`) to update priors |
| `GET` | `/v1/queue/{target_id}/next` | Pops the next highest-priority pending hypothesis for Component 3 (Executor) |
| `GET` | `/v1/queue/{target_id}` | Peeks at the prioritized pending queue for a target |
| `POST` | `/v1/events/replan` | Triggered by significant findings to initiate dynamic replanning with new knowledge delta |
| `GET` | `/health` | Service health status |

---

## 3. Directory Structure

```
c2-hypothesis-gen/
├── Dockerfile                  # Container definition
├── requirements.txt            # Python dependencies
├── README.md                   # Documentation
├── hgs/
│   ├── __init__.py
│   ├── config.py               # Environment configuration & LLM settings
│   ├── models.py               # Data models (AttackHypothesis, AttackSequenceStep, HypothesisBatch)
│   ├── surfacer.py             # Candidate Surfacer (OWASP category bucketing)
│   ├── prompt.py               # Context budgeting, hierarchical summarizer & tool schemas
│   ├── planner.py              # LLM planner (Claude/OpenAI) & deterministic heuristic engine
│   ├── validator.py            # Hallucination Guard & destructive action gate pre-flagging
│   ├── scorer.py               # Impact × Likelihood scoring & diversity filter
│   ├── queue.py                # Priority Queue (Redis Sorted Set & SQLite persistence)
│   ├── replan.py               # Dynamic Replan Handler
│   ├── service.py              # Core HypothesisGenerationService orchestration
│   ├── api.py                  # FastAPI route handlers
│   └── main.py                 # Application entrypoint
└── tests/
    ├── __init__.py
    ├── conftest.py             # Pytest fixtures and isolated queue
    ├── test_surfacer.py        # Candidate surfacer bucketing tests
    ├── test_validator.py       # Hallucination rejection & approval gate tests
    ├── test_scorer.py          # Priority scoring & diversity filter tests
    ├── test_queue.py           # Priority queue push/pop and ordering tests
    ├── test_replan.py          # Dynamic replan merge and knowledge boost tests
    ├── test_api.py             # Public REST API test suite
    └── test_srebench_golden_eval.py # Ground-truth exploit chain coverage evaluation
```

---

## 4. Running the Service

### Standalone (Development)
```bash
cd c2-hypothesis-gen
pip install -r requirements.txt
uvicorn hgs.main:app --host 0.0.0.0 --port 9002 --reload
```

### With Docker
```bash
docker build -t hgs:latest hypothesis-gen
docker run -p 9002:9002 hgs:latest
```

---

## 5. Verification & Testing

Run the automated test suite:
```bash
python -m pytest c2-hypothesis-gen/tests -v
```

All 9 unit, integration, and golden-hypothesis tests validate that:
- Graph operations are accurately bucketed into OWASP API Top-10 categories.
- The Hallucination Guard cleanly rejects invalid or hallucinated node references.
- Destructive operations (`DELETE`) are pre-flagged `requires_approval = True`.
- SREBench-API multi-step exploit chains (e.g. SRE-01: Auth $\rightarrow$ Users $\rightarrow$ Vault) are correctly synthesized and prioritized ($\text{priority} \ge 0.50$).
- Dynamic replanning boosts follow-up hypotheses matching newly leaked credentials or object IDs while preserving existing executed tasks.
