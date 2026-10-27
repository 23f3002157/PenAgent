"""Run real C1 parser/graph builder offline; no service DB or target traffic."""
import copy
import json
import sys
from pathlib import Path

sys.path.insert(0,'/phase4/src/c1-spec-ingestion')
from sis.normalizer import SpecNormalizer
from sis.graph_builder import GraphBuilder

root=Path('/phase4/benchmarks')
for label in ['b2b','readonly']:
    spec=json.loads((root/f'specs/prepared/juice-shop-20.0.0-{label}-host.json').read_text())
    normalized,spec_hash=SpecNormalizer().normalize(spec)
    first=GraphBuilder().build_graph('phase4_juice_shop',spec_hash,normalized,{})
    second=GraphBuilder().build_graph('phase4_juice_shop',spec_hash,normalized,{})
    expected={(method.upper(),path) for path,item in spec['paths'].items() for method in item if method in ['get','post','put','patch','delete','head','options','trace']}
    actual={(n.method,n.path) for n in first.nodes}
    report={'tool':'actual C1 normalizer and graph builder','network':'none','database_written':False,
        'canonical_spec_hash':spec_hash,'operations':[{'method':n.method,'path':n.path,'node_id':n.id,
        'parameters':[p.model_dump(by_alias=True) for p in n.parameters],'request_body':n.request_body_schema,
        'auth':n.auth.model_dump()} for n in first.nodes],
        'missing_spec_operations':sorted(expected-actual),'unexpected_spec_operations':sorted(actual-expected),
        'stable_operation_ids':[n.id for n in first.nodes]==[n.id for n in second.nodes],
        'original_server':spec['servers'],'note':'C1 graph paths do not include OpenAPI 3 server base path'}
    out=root/f'specs/validation/c1-{label}.json'
    if out.exists(): raise ValueError('Refusing to overwrite prior C1 evidence')
    out.write_text(json.dumps(report,indent=2)+'\n')
# Reproduce valid constructs C1 cannot faithfully preserve, without modifying it.
base={'openapi':'3.0.3','info':{'title':'SYNTHETIC CONTRACT TEST ONLY','version':'test'},'servers':[{'url':'http://127.0.0.1:18001'}],
      'paths':{'/x':{'trace':{'operationId':'traceX','responses':{'200':{'description':'test'}}}}}}
n,h=SpecNormalizer().normalize(base); trace=GraphBuilder().build_graph('synthetic',h,n,{})
collision=copy.deepcopy(base); collision['paths']={'/a':{'get':{'operationId':'A-B','responses':{'200':{'description':'test'}}}},
    '/b':{'get':{'operationId':'A_B','responses':{'200':{'description':'test'}}}}}
n,h=SpecNormalizer().normalize(collision); graph=GraphBuilder().build_graph('synthetic',h,n,{})
limitations={'fixture':'SYNTHETIC parser contract cases only; not benchmark endpoints',
    'trace_documented':1,'trace_nodes':len(trace.nodes),'collision_raw_operation_ids':['A-B','A_B'],
    'collision_generated_node_ids':[n.id for n in graph.nodes],
    'classification':'PenAgent ingestion limitation'}
(root/'specs/validation/c1-limitations.json').write_text(json.dumps(limitations,indent=2)+'\n')
print('C1 ingestion/graph evidence saved; no target requests or persistent service writes')
