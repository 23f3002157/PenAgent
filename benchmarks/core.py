"""Offline, non-attacking benchmark validation and inventory primitives."""
import copy
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlsplit

ROOT=Path(__file__).resolve().parent
METHODS={'get','put','post','delete','patch','options','head','trace'}
STATUSES={'READY','PARTIALLY READY','BLOCKED','NOT AVAILABLE','REQUIRES APPROVAL'}
CHECKS={'identity','version_pin','reproducible_deployment','isolated','known_operations',
        'valid_spec','spec_version_provenance','shared_operations','authentication',
        'operation_risks','reset_strategy','enforceable_scope'}

def require(ok,message):
    if not ok: raise ValueError(message)
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def stable(value): return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
def save(path,value):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    data=(json.dumps(value,indent=2,sort_keys=True)+'\n').encode()
    if path.exists():
        require(path.read_bytes()==data,'Refusing to overwrite differing artifact: '+str(path))
    else: path.write_bytes(data)
def load(path):
    text=Path(path).read_text(encoding='utf-8-sig')
    if Path(path).suffix.lower() in {'.yml','.yaml'}:
        import yaml
        return yaml.safe_load(text)
    return json.loads(text)
def pointer(root,ref):
    require(isinstance(ref,str) and ref.startswith('#/'),'External references must be bundled offline before validation')
    node=root
    try:
        for part in ref[2:].split('/'): node=node[part.replace('~1','/').replace('~0','~')]
    except (KeyError,TypeError): raise ValueError('Broken reference: '+ref) from None
    return node
def resolved(value,root):
    return pointer(root,value['$ref']) if isinstance(value,dict) and '$ref' in value else value
def path_normalize(path):
    require(isinstance(path,str) and path.startswith('/') and not path.startswith('//'),'Path must begin with one slash')
    require(not any(x in path for x in ['?','#','\\','\r','\n']) and '//' not in path,'Invalid operation path')
    require(not any(p in {'.','..'} for p in path.split('/')),'Traversal path')
    return path

def inspect_spec(spec,full=False):
    require(isinstance(spec,dict) and re.fullmatch(r'3\.(0|1)\.\d+',str(spec.get('openapi',''))),'Expected OpenAPI 3.0/3.1 document')
    require(isinstance(spec.get('info'),dict) and spec['info'].get('title') and spec['info'].get('version'),'Missing API title/version')
    require(isinstance(spec.get('paths'),dict) and spec['paths'],'Missing operation paths')
    servers=spec.get('servers'); require(isinstance(servers,list) and len(servers)==1 and servers[0].get('url'),'Exactly one explicit server required for benchmark inventory')
    server=servers[0]['url']; require('{' not in server,'Server variables need explicit resolution')
    u=urlsplit(server)
    require(not u.query and not u.fragment and not u.username and not u.password,'Unsafe server URL')
    require((u.scheme in {'http','https'} and u.hostname) or (not u.scheme and server.startswith('/')),'Invalid server URL')
    def walk(x):
        if isinstance(x,dict):
            if '$ref' in x: pointer(spec,x['$ref'])
            for v in x.values(): walk(v)
        elif isinstance(x,list):
            for v in x: walk(v)
    walk(spec)
    operations=[]; ids=set(); warnings=[]
    base=u.path.rstrip('/')
    schemes=spec.get('components',{}).get('securitySchemes',{})
    for path,item in spec['paths'].items():
        path_normalize(path); require(isinstance(item,dict),'Path item must be an object')
        require(not set(item)&{'$ref','servers'},'Unsupported path-level reference/server override; review separately')
        for method,op in item.items():
            if method not in METHODS: continue
            require(isinstance(op,dict) and op.get('responses'),'Operation responses required')
            require(not set(op)&{'servers','callbacks'},'Unsupported operation server/callback construct')
            oid=op.get('operationId')
            if oid:
                require(oid not in ids,'Duplicate operationId: '+oid); ids.add(oid)
            parameters={}
            for p in item.get('parameters',[])+op.get('parameters',[]):
                p=resolved(p,spec)
                require(p.get('name') and p.get('in') in {'path','query','header','cookie'},'Invalid parameter location/name')
                require('schema' in p or 'content' in p,'Parameter schema/content missing')
                parameters[(p['in'],p['name'])]=copy.deepcopy(p)
            templates=set(re.findall(r'\{([^{}]+)\}',path))
            declared={p['name'] for p in parameters.values() if p['in']=='path'}
            require(templates==declared,'Path template and parameter declarations differ')
            require(all(p.get('required') is True for p in parameters.values() if p['in']=='path'),'Path parameters must be required')
            security=op.get('security',spec.get('security',[]))
            require(isinstance(security,list),'Security requirements must be an array')
            for requirement in security:
                require(all(name in schemes for name in requirement),'Undefined authentication scheme')
            body=resolved(op.get('requestBody'),spec)
            if body: require(body.get('content'),'Request body content required')
            if method=='trace': warnings.append('C1 does not enumerate TRACE operations')
            if any(len(s)>1 for s in security) or len(security)>1:
                warnings.append('C1 represents only the first security requirement/scheme')
            public_path=path_normalize(base+path)
            operations.append({'method':method.upper(),'path':public_path,'spec_path':path,'operation_id':oid,
                'parameters':list(parameters.values()),'request_body':copy.deepcopy(body),
                'security':copy.deepcopy(security),'anonymous':not security or {} in security,
                'source_evidence':copy.deepcopy(op.get('x-penagent-evidence',[])),
                'schema_assurance':op.get('x-schema-assurance','official-as-published')})
    require(operations,'No operations documented')
    if full:
        from openapi_spec_validator import validate_spec
        validate_spec(spec)
    return {'openapi':spec['openapi'],'server':server,'base_path':base,
        'operations':sorted(operations,key=lambda o:(o['path'],o['method'])),
        'warnings':sorted(set(warnings)),'full_schema_validation':bool(full)}

def prepare_origin(spec,origin):
    inspect_spec(spec)
    u=urlsplit(origin)
    require(u.scheme=='http' and u.hostname in {'127.0.0.1','host.docker.internal'} and u.port in {3000,18001},'Preparation origin is not an approved local Juice Shop origin')
    require(u.path in {'','/'} and not u.query and not u.fragment and not u.username and not u.password,'Origin must not contain credentials, query, fragment or a base path')
    result=copy.deepcopy(spec)
    base=urlsplit(spec['servers'][0]['url']).path.rstrip('/')
    result['servers']=[{'url':origin.rstrip('/')+base}]
    return result

def operation_set(report):
    return {(o['method'],o['path']) for o in report.get('operations',[])}

def map_capture_paths(documented,captured):
    """Map concrete import examples to exactly one documented method/template.

    Keeps methods, literal segments and case distinct; ambiguity is an error.
    This maps parser traffic, and makes no claim about target reachability.
    """
    matches=set()
    for actual in captured:
        candidates=[]
        for op in documented:
            pattern=re.escape(op['path'])
            pattern=re.sub(r'\\\{[^{}]+\\\}',r'[^/]+',pattern)
            if actual['method']==op['method'] and re.fullmatch(pattern,actual['path']):
                candidates.append((op['method'],op['path']))
        require(len(candidates)==1,'Unknown or ambiguous captured operation: '+str(actual))
        matches.add(candidates[0])
    return matches

def missing_assets(paths,base=ROOT):
    return [p for p in paths if not (Path(base)/p).is_file()]

def intersect(spec_operations,penagent,zap,live,risk_review):
    expected={(o['method'],o['path']) for o in spec_operations}
    def keys(report): return {(o['method'],o['path']) for o in report.get('operations',[])}
    return expected & keys(penagent) & keys(zap) & set(live) & set(risk_review)

def readiness(checks,requires_approval=False,available=True):
    require(set(checks)==CHECKS and all(type(v) is bool for v in checks.values()),'Incomplete or non-boolean eligibility checklist')
    if not available: return 'NOT AVAILABLE'
    if requires_approval: return 'REQUIRES APPROVAL'
    if all(checks.values()): return 'READY'
    if not checks['identity'] or not checks['version_pin']: return 'BLOCKED'
    return 'PARTIALLY READY'

def validate_manifest(m,base=ROOT):
    required={'schema_version','benchmark_id','project','source_repository','target_version','image_digest',
        'deployment','specifications','host_origin','container_origin','authentication','inventory',
        'eligible_operations','excluded_operations','reset','penagent','zap','ground_truth',
        'requires_approval','readiness','checks','limitations'}
    require(set(m)==required,'Manifest fields missing or unknown: '+str(required^set(m)))
    require(m['schema_version']==1 and m['readiness'] in STATUSES,'Invalid manifest schema/status')
    if m['image_digest'] is not None: require(re.fullmatch(r'[^\s]+@sha256:[a-f0-9]{64}',m['image_digest']) is not None,'Image must have an immutable digest')
    require(m['readiness']==readiness(m['checks'],m['requires_approval'],m['deployment'].get('available',True)),'Readiness classification contradicts evidence checklist')
    for spec in m['specifications']:
        for key,hashkey in [('original','original_sha256'),('prepared','prepared_sha256'),('docker_prepared','docker_prepared_sha256')]:
            if spec.get(key): require(sha(Path(base)/spec[key])==spec[hashkey],'Specification hash mismatch: '+spec[key])
        require(spec.get('target_version')==m['target_version'],'Spec/deployed target version mismatch')
    require(not m['ground_truth'].get('verified'),'Phase 4 does not adjudicate benchmark ground truth')
    if m['deployment'].get('compose'):
        require(sha(Path(base)/m['deployment']['compose'])==m['deployment']['compose_sha256'],'Deployment hash mismatch')
    if m['readiness']=='READY': require(m['eligible_operations'],'READY requires non-empty shared eligible operation set')
    return m

def check_identity(expected,observed):
    for k in ['container_id','image_id','version']:
        require(expected[k]==observed[k],'Deployed target '+k+' mismatch')
    require(observed.get('running') is True,'Target is not running')
    return True
