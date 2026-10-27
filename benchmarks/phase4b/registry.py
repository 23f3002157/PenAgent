"""Unified original/successor/reproduction records and fail-closed validation."""
import copy
import re
from pathlib import Path
from benchmarks import core as c

FAMILIES={'juice_shop','dvws','srebench_api'}
REPO=c.ROOT.parent
TYPES={'ORIGINAL','SUCCESSOR','REPRODUCTION','SYNTHETIC'}
REQUIRED={'id','family','label','source_type','source','version','adopted','approval_required',
    'deployment','specification','inventory','authentication','network_scope','clean_state',
    'penagent','zap','readiness','limitations','ground_truth'}

def validate_record(record,base=c.ROOT):
    c.require(set(record)==REQUIRED,'Missing/unknown unified record fields')
    c.require(record['family'] in FAMILIES and record['source_type'] in TYPES,'Invalid family/source type')
    c.require(type(record['adopted']) is bool and type(record['approval_required']) is bool,'Approval flags must be boolean')
    if record['source_type'] in {'SUCCESSOR','REPRODUCTION'}:
        c.require(not record['adopted'] and record['approval_required'],'Unapproved replacement cannot be adopted')
        c.require('proposed successor' in record['label'] if record['source_type']=='SUCCESSOR'
            else record['label']=='Local reproduction based on the research proposal','Replacement label must be explicit')
    digest=record['deployment'].get('image_digest')
    if digest:c.require(re.fullmatch(r'[^\s]+@sha256:[a-f0-9]{64}',digest) is not None,'Image digest is not pinned')
    for asset in ['specification','inventory']:
        value=record[asset]
        if value['path']:
            path=(Path(base)/value['path']).resolve()
            c.require(path.is_relative_to(Path(base).resolve()),'Asset outside benchmark tree')
            c.require(path.is_file(),'Missing asset: '+value['path'])
            c.require(c.sha(path)==value['sha256'],'Asset hash mismatch: '+value['path'])
        else:c.require(bool(value.get('missing_reason')),'Missing asset needs an explicit reason')
    r=record['readiness']
    c.require(r['status'] in c.STATUSES,'Invalid readiness status')
    if r['status']=='READY':
        c.require(record['adopted'] and not record['approval_required'] and record['source_type']=='ORIGINAL',
            'Unapproved replacement cannot be READY')
        c.require(record['deployment']['running'] and r['shared_live_access_verified'] and
            record['clean_state']['repeatable_state_verified'] and record['specification']['valid'] and
            r['eligible_operations'],'READY lacks live, state, schema or operation evidence')
    c.require(record['ground_truth']['verified'] is False,'Phase 4B cannot adjudicate ground truth')
    return record

def validate_registry(registry,base=c.ROOT):
    c.require(registry['schema_version']==1,'Invalid registry schema')
    records=registry['benchmarks'];ids=[r['id'] for r in records]
    c.require(len(ids)==len(set(ids)),'Duplicate benchmark identity')
    c.require({r['family'] for r in records}==FAMILIES,'All THREE benchmark families must be addressed')
    for record in records:validate_record(record,base)
    c.require(sum(r['source_type']=='ORIGINAL' and r['family']=='dvws' for r in records)==1,'Original DVWS record must not disappear')
    return registry

def asset(path=None,valid=False,reason=None):
    return {'path':path,'sha256':c.sha(c.ROOT/path) if path else None,'valid':valid,'missing_reason':reason}

def build():
    root=c.ROOT/'phase4b';evidence=root/'evidence';connection=evidence/'connectivity-r2'
    run=c.load(connection/'connectivity-run.json');c.require(run['error'] is None,'Shared connectivity not verified')
    cfg=c.load(connection/'connectivity-config.json')
    old=c.load(c.ROOT/'inventories/juice-shop-20.0.0.json')
    by_request={o['request_path']:o for o in c.load(connection/'zap-connectivity.json')['operations']}
    inventory=copy.deepcopy(old)
    for op in inventory['operations']:
        example=op['path'].replace('{id}','1')+('?q=apple' if op['path'].endswith('/search') else '')
        observed=by_request.get(example)
        op.update(source_type='ORIGINAL',shared_live_example=observed,
            shared_access_verified=bool(observed),included_for_ground_truth_preparation=bool(observed and observed['status']==200),
            comparative_scanning_eligibility='CANDIDATE; future active-query policy and approval required' if observed and observed['status']==200 else 'EXCLUDED')
        op['included']=False
        op['exclusion_reasons']=['Active experiment not authorized; connectivity policy permits exact benign examples only']
        if not observed:op['exclusion_reasons']+=['B2B POST not executed; bearer, state-change and C1 base path limitations']
        elif observed['status']!=200:op['exclusion_reasons']+=['Country mapping returns 500 without required configuration']
    c.save(root/'juice-inventory.json',inventory)
    candidates=[o['stable_id'] for o in inventory['operations'] if o['included_for_ground_truth_preparation']]
    comparison={'schema_version':1,'execution_authorized':False,'target_image_digest':
        'bkimminich/juice-shop@sha256:25fd268112350ae9e0ddc7878371f9f12f5b0b546c7bf934d6599aa8e724418f',
        'eligible_operation_candidates':candidates,'authentication':'anonymous, same role for both tools',
        'exclusions':['B2B order POST','CTF country mapping','All operations outside this documented subset','All authenticated/state-changing workflows'],
        'budgets_proposed_for_review':{'wall_seconds':180,'cleanup_reserve_seconds':10,'max_forwarded_requests':100,'concurrency':1,'delay_ms':100},
        'independent_repeats_proposed':3,'repeats_executed':0,'initial_state':'Fresh independently named container and volume per tool/repeat; verify seed state equivalence first',
        'traffic':'Gateway method/path/status/counts/deadline, target identity, request/response hashes and raw tool evidence per run',
        'findings':'Retain original tool artifacts; normalize separately, do not equate an alert to ground truth',
        'blocker':'Existing baseline runner accepts host.docker.internal upstream only. A separately reviewed private-network runner adapter and active-input scope are still needed.',
        'scope_warning':'The Phase 4B connectivity gateway is intentionally unsuitable for active scanning; it blocks all parameter mutations.'}
    c.save(root/'comparison-plan.json',comparison)
    juice={'id':'juice-shop-20.0.0','family':'juice_shop','label':'OWASP Juice Shop 20.0.0','source_type':'ORIGINAL',
        'source':{'repository':'https://github.com/juice-shop/juice-shop','revision':'v20.0.0','provenance_verified':True},
        'version':'20.0.0','adopted':True,'approval_required':False,
        'deployment':{'running':True,'image_digest':comparison['target_image_digest'],'container_id':cfg['target']['id'],
            'configuration':'phase4b/deploy/juice-fresh.compose.yml','configuration_executed':False,
            'actual_topology':'Existing isolated Phase 4 target; two new isolated runtime clients through new dual-network gateway; both checks complete, run-owned clients/gateway stopped'},
        'specification':asset('specs/prepared/juice-shop-20.0.0-readonly-host.json',True),
        'inventory':asset('phase4b/juice-inventory.json',True),
        'authentication':{'verified_roles':['anonymous'],'authenticated_roles_verified':False,'description':'Four successful anonymous benign examples; B2B bearer excluded'},
        'network_scope':{'target_origin':cfg['target_origin'],'gateway_origin':cfg['gateway_origin'],
            'target_network':'penagent-phase4-juice20-r1_isolated','tools_network':cfg['tool_network'],
            'published_ports':[],'fixed_benign_GET_only':True,'evidence':'phase4b/evidence/connectivity-r2/connectivity-run.json'},
        'clean_state':{'strategy':'Fresh uniquely named image-pinned instance and independently named data volume per tool/repeat',
            'repeatable_state_verified':False,'reset_existing':False,'health':'Version GET, exact version and image/container checks',
            'initial_state':'Default seeded DB/data of image; volume copy-up/permissions and identical seed snapshots not yet exercised',
            'reset':'Allocate a NEW project and NEW volume; never restart/reset the existing target to claim clean state'},
        'penagent':{'parsed_operations':6,'equivalent_public_paths':5,'shared_benign_GET_examples':5,
            'note':'C3 image/httpx transport configuration and numeric-origin guard used; no Executor.execute or live C1 service DB change'},
        'zap':{'parsed_operations':6,'shared_benign_GET_examples':5,'active_scans':0,'spider_scans':0},
        'readiness':{'status':'PARTIALLY READY','shared_live_access_verified':True,'eligible_operations':candidates,
            'phase5_preparation':'Four operations can enter limited source-to-vulnerability mapping; no adjudication performed'},
        'limitations':['Six-operation collection is not a full API benchmark; only four successful anonymous GET candidates',
            'B2B C1 base path loss and unverified auth','Fresh volume reset equivalence not exercised',comparison['blocker'],comparison['scope_warning']],
        'ground_truth':{'verified':False,'sources':'Version-pinned source/challenge definitions and official companion guide'}}
    original=copy.deepcopy(juice)
    original.update(id='dvws-original',family='dvws',label='Original DVWS',source_type='ORIGINAL',
        source={'repository':'https://github.com/snoopysecurity/dvws','revision':'25a5a03aa1b13d8e647da66784c3e8445726e578',
            'provenance_verified':True,'beebs_2019_attribution_verified':False},version='25a5a03aa1b13d8e647da66784c3e8445726e578',adopted=True,approval_required=False,
        deployment={'running':False,'image_digest':None,'configuration':'phase4b/deploy/dvws-original.Dockerfile.proposed',
            'reason':'Exact official PHP runtime pull failed before build; no application deployed'},
        specification=asset(reason='No authoritative original OpenAPI in pinned source; no derived contracts fabricated'),
        inventory=asset('phase4b/evidence/dvws-original-review.json',False),
        authentication={'verified_roles':[],'description':'JWT exercises exist; no runtime/login verification'},
        network_scope={'published_ports':[],'proposed':'Internal isolated target with gateway-only access; no host legacy installation'},
        clean_state={'strategy':'Original setup PHP/database schema plus fresh pinned local MySQL/socket topology; blocked before build',
            'repeatable_state_verified':False,'reset_existing':False},
        penagent={'status':'NOT EXECUTED; no valid original spec/runtime'},zap={'status':'NOT EXECUTED; no valid original spec/runtime'},
        readiness={'status':'BLOCKED','shared_live_access_verified':False,'eligible_operations':[]},
        limitations=['Legacy image retrieval/extraction failure','Mixed mysql/mysqli and incomplete write branches require compatibility review',
            'Exact historical citation attribution unconfirmed','README GPL-3 versus LICENSE Apache-2.0 conflict'],
        ground_truth={'verified':False,'sources':'Upstream exercise descriptions; not operation-level adjudicated labels'})
    successor=copy.deepcopy(original)
    successor.update(id='dvws-node-proposed',label='DVWS-Node — proposed successor benchmark',source_type='SUCCESSOR',
        source={'repository':'https://github.com/snoopysecurity/dvws-node','revision':'35f999505028f580dd6acc8bb7ddecfb87fe4bf6','provenance_verified':True},
        version='35f999505028f580dd6acc8bb7ddecfb87fe4bf6',adopted=False,approval_required=True,
        deployment={'running':False,'image_digest':None,'configuration':'phase4b/deploy/dvws-node.compose.proposed.yml',
            'reason':'Not adopted; no candidate build/pull/seed/deployment executed'},
        specification=asset('phase4b/candidates/dvws-node-upstream-raw.json',False),
        inventory=asset('phase4b/candidates/dvws-node-inventory.json',False),
        authentication={'verified_roles':[],'description':'Bearer middleware and known mutable GET behavior reviewed statically; no accounts/tokens used'},
        clean_state={'strategy':'Dedicated fresh Mongo/MySQL volumes; seed script drops DB/data so must never point at existing resources',
            'repeatable_state_verified':False,'reset_existing':False},
        penagent={'parsed_operations':52,'note':'Ignores /api server base'},zap={'mapped_operations':52,'target_requests':0,'note':'Network-none fixture only'},
        readiness={'status':'REQUIRES APPROVAL','shared_live_access_verified':False,'eligible_operations':[]},
        limitations=['Separate successor, not equivalent to original findings','Official candidate spec has an invalid Swagger-style body parameter in an OAS3 document',
            'Tool parser acceptance does not cure invalid schema','Unverified deployment/auth/state','GPL-3 LICENSE versus MIT package metadata conflict'])
    sre=copy.deepcopy(original)
    sre.update(id='srebench-api-reproduction-proposal',family='srebench_api',label='Local reproduction based on the research proposal',source_type='REPRODUCTION',
        source={'repository':None,'revision':'provided-scenario-pdf-sha256:'+c.sha(REPO/'images/SREBench API.pdf'),
            'provenance_verified':True,'official_runnable_assets_verified':False},
        version='proposal-only; no executable version',adopted=False,approval_required=True,
        deployment={'running':False,'image_digest':None,'configuration':'phase4b/srebench/reproduction-plan.json',
            'reason':'Non-executable design only; services require explicit approval'},
        specification=asset(reason='Partial source path examples only; no genuine released OpenAPI accessible; do not invent complete contracts'),
        inventory=asset('phase4b/srebench/scenario-matrix.json',False),
        authentication={'verified_roles':[],'description':'Source-described identities only; remaining roles/contracts unresolved'},
        clean_state={'strategy':'Proposed deterministic per-scenario seeds/fresh volumes; not implemented',
            'repeatable_state_verified':False,'reset_existing':False},
        penagent={'status':'NOT EXECUTED; no executable spec'},zap={'status':'NOT EXECUTED; no executable spec'},
        readiness={'status':'REQUIRES APPROVAL','shared_live_access_verified':False,'eligible_operations':[]},
        limitations=['20 actual catalog rows; 5 require interpretation, 15 insufficient information',
            'Claimed image manifests inaccessible without authentication; not proof image does not exist',
            'No vulnerable services, fabricated endpoints or ground truth implemented'],
        ground_truth={'verified':False,'sources':'Provided scenario descriptions only; source claims are not executable adjudication'})
    registry={'schema_version':1,'phase':'4B','experiment_execution_authorized':False,
        'benchmarks':[juice,original,successor,sre]}
    validate_registry(registry)
    for record in registry['benchmarks']:c.save(root/f'manifests/{record["id"]}.json',record)
    c.save(root/'registry.json',registry)
    print('All three families recorded; original DVWS retained; successor/reproduction unadopted')

if __name__=='__main__':build()
