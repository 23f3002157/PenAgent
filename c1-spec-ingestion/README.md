services# PenAgent — Component 1: Spec Ingestion Service (SIS)

The **Spec Ingestion Service (SIS)** is an independently deployable microservice responsible for ingesting, normalizing, and analyzing target API specifications (OpenAPI 3.x, Swagger 2.0, or synthesized surfaces) into a queryable, attack-surface-annotated **Endpoint Graph**.

---

## 1. Architectural Highlights

- **Service Boundary:** Standalone containerized service exposing a FastAPI REST interface and asynchronous event notifications via Redis Streams (with local in-memory fallback).
- **Multi-Target Adapters:**
  - `JuiceShopAdapter`: Ingests the sample OpenAPI spec for OWASP Juice Shop (`specs/juice_shop_sample.json`).
  - `SREBenchAdapter`: Ingests the auto-generated FastAPI specification (`specs/srebench_openapi.json`) and extracts cross-service scenario ground-truth metadata strictly for evaluation.
  - `DVWSAdapter`: Ingests the Damn Vulnerable Web Services specification (`specs/dvws_openapi.json`) and folds intrinsic OWASP API Top-10 tags directly into attack surface signals.
  - `GenericOpenAPIAdapter`: Discovers and ingests arbitrary OpenAPI/Swagger endpoints or files.
- **Spec Normalizer:** Resolves complex `$ref` references (handling cyclical graphs safely) and standardizes Swagger 2.0 to OpenAPI 3.0 Intermediate Representation (IR).
- **Graph Builder (NetworkX DiGraph):** Inters call-order dependency edges between API operations using 3 distinct signals:
  1. *OpenAPI Links* (explicit links declared in spec, confidence 0.95).
  2. *Producer-Consumer Parameter Matching* (response schema properties consumed by path/query parameters, confidence 0.75 - 0.85).
  3. *Shared Schema Fields* (common domain identifier keys shared across request/response bodies, confidence 0.68).
- **Static Attack-Surface Tagger:** Evaluates static vulnerability indicators without LLM hallucinations:
  - `idor_candidate`: Controllable path/query object identifiers (`{id}`, `{user_id}`, `{doc_id}`).
  - `state_mutation`: Mutating HTTP methods (`POST`, `PUT`, `PATCH`, `DELETE`).
  - `sensitive_response`: Exposure of credentials, JWTs, private keys, secrets, PII.
  - `admin_surface`: Privileged and administrative endpoints (`/admin`, `/sys`, `/debug`).
  - `cross_service_param`: Identifiers produced by one service and consumed across a trust boundary by another service.
- **Persistence & Drift Detection:** SQLite/Postgres storage storing versioned graphs and SHA-256 spec hashes for instant change detection on `/refresh`.

---

## 2. Public API Reference

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/ingest` | Initiates asynchronous ingestion (`{target_id, base_url, spec_source, auth_profile}`) $\rightarrow$ `{job_id}` |
| `GET` | `/v1/ingest/{job_id}` | Checks job status (`queued`, `parsing`, `building_graph`, `tagging`, `done`, `failed`) |
| `GET` | `/v1/graph/{target_id}` | Retrieves complete `EndpointGraph` (all nodes, metadata, and inferred edges) |
| `GET` | `/v1/graph/{target_id}/attack-surface` | Retrieves pruned, tag-annotated attack surface view consumed by Component 2 (HGS) |
| `POST` | `/v1/graph/{target_id}/augment` | Merges an undocumented endpoint discovered during live probing into the graph |
| `POST` | `/v1/graph/{target_id}/refresh` | Re-pulls spec, detects schema drift via SHA-256 hash diff, and updates graph |
| `GET` | `/health` | Service health check |

---

## 3. Directory Structure

```
c1-spec-ingestion/
├── Dockerfile                  # Container build definition
├── requirements.txt            # Python dependencies
├── README.md                   # Service documentation
├── sis/
│   ├── __init__.py
│   ├── config.py               # Environment configuration and defaults
│   ├── models.py               # Pydantic data contracts (EndpointNode, EndpointEdge, EndpointGraph, etc.)
│   ├── normalizer.py           # $ref resolution and Swagger 2.0 -> OpenAPI 3.0 IR
│   ├── tagger.py               # Static attack-surface tagging rule engine
│   ├── graph_builder.py        # NetworkX DiGraph builder and multi-signal edge inference
│   ├── storage.py              # Persistent SQLite/Postgres repository and hot cache
│   ├── events.py               # Redis Streams event publisher with in-memory fallback
│   ├── service.py              # Core SpecIngestionService orchestration
│   ├── api.py                  # FastAPI route handlers
│   ├── main.py                 # Application entrypoint
│   └── adapters/
│       ├── __init__.py         # Adapter factory
│       ├── base.py             # BaseAdapter abstract class
│       ├── juice_shop.py       # OWASP Juice Shop adapter
│       ├── srebench.py         # SREBench-API adapter with scenario evaluation layer
│       ├── dvws.py             # DVWS-Node adapter with OWASP Top-10 mappings
│       └── generic.py          # Generic OpenAPI/Swagger adapter
└── tests/
    ├── __init__.py
    ├── conftest.py             # Pytest fixtures and isolated storage harness
    ├── test_adapters.py        # Adapter unit tests against Juice Shop, SREBench, and DVWS
    ├── test_graph_builder.py   # Operation ID generation and multi-signal edge inference
    ├── test_tagger.py          # Static rule engine verification (IDOR, Admin, Cross-service)
    ├── test_storage_drift.py   # Storage persistence, augmentation, and drift detection
    ├── test_api.py             # TestClient testing all public REST endpoints
    └── test_srebench_edge_eval.py # Ground-truth exploit chain coverage evaluation
```

---

## 4. Running the Service

### Standalone (Development)
```bash
cd c1-spec-ingestion
pip install -r requirements.txt
uvicorn sis.main:app --host 0.0.0.0 --port 9001 --reload
```

### With Docker
```bash
docker build -t sis:latest spec-ingestion
docker run -p 9001:9001 sis:latest
```

---

## 5. Verification & Testing

Run the full automated test suite:
```bash
python -m pytest c1-spec-ingestion/tests -v
```

All 11 unit, integration, and ground-truth chain coverage tests validate that:
- All 3 benchmark targets (Juice Shop, SREBench, DVWS) parse cleanly.
- Cyclical and deep `$ref` dependencies resolve without corruption.
- Cross-service dependency edges (such as SRE-01's Auth $\rightarrow$ User $\rightarrow$ Vault chain) are inferred with high confidence ($\ge 0.80$).
- Dynamic augmentation and SHA-256 schema drift detection function as specified.
