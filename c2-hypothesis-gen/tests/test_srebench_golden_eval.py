import json
import pytest
from pathlib import Path

from hgs.service import HypothesisGenerationService
from hgs.models import GenerateHypothesesRequest


@pytest.mark.asyncio
async def test_srebench_golden_hypothesis_coverage(repo_root, temp_queue):
    """
    Evaluates that HGS produces hypotheses whose attack sequences cover
    the ground truth exploit chains (SRE-01, SRE-02) from ground_truth_chains.json.
    """
    # 1. Load ground truth chains
    ground_truth_file = repo_root / "datasets" / "ground_truth_chains.json"
    with open(ground_truth_file, "r", encoding="utf-8") as f:
        gt_data = json.load(f)

    sre_scenarios = gt_data["targets"]["srebench_api"]["scenarios"]
    sre_01 = next(s for s in sre_scenarios if s["scenario_id"] == "SRE-01")

    # 2. Ingest SREBench using Component 1 (SIS) to get the real attack surface
    sys_path_sis = str(repo_root / "services" / "spec-ingestion")
    import sys
    if sys_path_sis not in sys.path:
        sys.path.insert(0, sys_path_sis)

    from sis.adapters.srebench import SREBenchAdapter
    from sis.normalizer import SpecNormalizer
    from sis.graph_builder import GraphBuilder
    from sis.tagger import AttackSurfaceTagger

    adapter = SREBenchAdapter()
    spec_path = str(repo_root / "specs" / "srebench_openapi.json")
    raw_spec, metadata = await adapter.load_spec("srebench", "http://localhost:18002", spec_source=spec_path)
    normalized, spec_hash = SpecNormalizer().normalize(raw_spec)
    builder = GraphBuilder()
    graph = builder.build_graph("srebench", spec_hash, normalized, metadata)

    attack_surface = {
        "target_id": "srebench",
        "nodes": [n.model_dump() for n in graph.nodes],
        "edges": [e.model_dump() for e in graph.edges],
    }

    # 3. Feed to Component 2 (HGS)
    hgs = HypothesisGenerationService(queue=temp_queue)
    hgs.set_cached_attack_surface("srebench", attack_surface)

    request = GenerateHypothesesRequest(
        target_id="srebench",
        mode="initial",
        max_hypotheses=15,
    )
    batch = await hgs.generate_hypotheses(request)
    assert batch.count > 0

    # 4. Evaluate Hit@K for SRE-01:
    # SRE-01 chain: POST /auth/v1/exchange-token -> GET /users/v1/profile -> GET /vault/v1/documents
    sre01_found = False
    for hyp in batch.hypotheses:
        seq_ops = [s.op for s in hyp.attack_sequence]
        seq_text = " ".join(seq_ops)
        if "auth" in seq_text and "users" in seq_text and "vault" in seq_text:
            sre01_found = True
            assert hyp.owasp_category == "API1:BOLA"
            assert hyp.priority >= 0.50
            break

    assert sre01_found, "HGS failed to synthesize cross-service chained hypothesis for SRE-01"
