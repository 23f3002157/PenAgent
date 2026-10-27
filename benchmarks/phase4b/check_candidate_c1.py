"""Offline C1 ingestion of unadopted successor; no target/service requests."""
import json
import sys
from pathlib import Path
sys.path.insert(0,'/phase4/src/c1-spec-ingestion')
from sis.normalizer import SpecNormalizer
from sis.graph_builder import GraphBuilder
root=Path('/benchmarks')
spec=json.loads((root/'phase4b/candidates/dvws-node-prepared.json').read_text())
result={'source_type':'SUCCESSOR','adopted':False,'network':'none','database_written':False}
try:
    normalized,digest=SpecNormalizer().normalize(spec)
    graph=GraphBuilder().build_graph('dvws_node_candidate',digest,normalized,{})
    result.update(status='PARSED',operations=[{'method':n.method,'path':n.path,'node_id':n.id,
        'auth':n.auth.model_dump()} for n in graph.nodes],canonical_spec_hash=digest,
        duplicate_node_ids=len(graph.nodes)!=len({n.id for n in graph.nodes}),
        note='Graph paths omit /api server base; parsing is not executable compatibility')
except Exception as exc:result.update(status='FAILED',error_type=type(exc).__name__,error=str(exc)[:3000])
path=root/'phase4b/evidence/dvws-node-c1.json'
if path.exists():raise ValueError('Refusing overwrite')
path.write_text(json.dumps(result,indent=2)+'\n');print(result['status'])
