"""Derive Phase 4 inventory/manifests from preserved actual evidence, offline."""
from . import core as c

def build():
    root=c.ROOT
    live=c.load(root/'specs/validation/live-juice20.json')
    observations={(o['method'],o['path']):o for o in live['observations']}
    inventory=[];specifications=[];comparison=[]
    for label in ['b2b','readonly']:
        prepared=f'specs/prepared/juice-shop-20.0.0-{label}-host.json'
        original='specs/original/juice-shop-20.0.0-'+('b2b.yml' if label=='b2b' else 'readonly-derived.json')
        spec=c.load(root/prepared);report=c.inspect_spec(spec)
        pa=c.load(root/f'specs/validation/c1-{label}.json')
        zap=c.load(root/f'specs/validation/zap-{label}.json')
        mapped=c.map_capture_paths(report['operations'],zap['operations'])
        pa_keys=c.operation_set(pa)
        c.save(root/f'specs/validation/zap-{label}-mapped.json',{
            'source':f'specs/validation/zap-{label}.json','source_sha256':c.sha(root/f'specs/validation/zap-{label}.json'),
            'operations':[{'method':m,'path':p} for m,p in sorted(mapped)],
            'rule':'Concrete path examples map to exactly one documented method/template; raw capture retained',
            'transformed_specification_sha256':c.sha(root/f'local/zap-import/{label}-capture-only.json'),
            'transformation':'Only servers[0].url replaced with capture loopback origin, preserving base path'})
        for op in report['operations']:
            key=(op['method'],op['path']);observation=observations.get(key)
            parser_match=key in pa_keys and key in mapped
            candidate=parser_match and bool(observation and observation['verified']) and label=='readonly'
            reasons=[]
            if label=='b2b':reasons+=['State-changing order processing with executable orderLinesData; no request authorized','Bearer role/token unverified','C1 drops /b2b/v2 server base path']
            elif not observation['verified']:reasons+=['Actual route returned HTTP 500 with no CTF country mapping configured']
            if not live['host_port_published']:reasons+=['Host port not published on internal Docker network; equivalent tool access unverified']
            reasons+=['No API-level gateway configuration or active-scan approval exists']
            inventory.append({**op,'benchmark_id':'juice-shop-20.0.0','target_version':'20.0.0',
                'stable_id':'juice20_'+c.stable([op['method'],op['path']])[:20],
                'specification':prepared,'authentication_role':'anonymous' if op['anonymous'] else 'bearer user, role unverified',
                'state_changing':label=='b2b','potential_destructive_effects':'Order processing / code execution' if label=='b2b' else 'No intentional mutation for reviewed benign inputs; injected values can trigger challenges',
                'penagent_ingestion':'parsed; public base path mismatch' if label=='b2b' else 'accepted',
                'penagent_spec_path_imported':(op['method'],op['spec_path']) in pa_keys,
                'zap_import':'accepted; capture fixture only','live_verification':observation or {'status':'NOT EXECUTED; POST not authorized'},
                'candidate_after_connectivity_and_scope_fix':candidate,
                'included':False,'exclusion_reasons':reasons,
                'evidence_sources':[f'specs/validation/c1-{label}.json',f'specs/validation/zap-{label}-mapped.json','specs/validation/live-juice20.json']})
        specifications.append({'original':original,'original_sha256':c.sha(root/original),'prepared':prepared,
            'prepared_sha256':c.sha(root/prepared),'target_version':'20.0.0','official':label=='b2b',
            'completeness':'Official B2B order operation only' if label=='b2b' else 'Non-official five-operation subset; response schemas partial',
            'docker_prepared':f'specs/prepared/juice-shop-20.0.0-{label}-docker.json',
            'docker_prepared_sha256':c.sha(root/f'specs/prepared/juice-shop-20.0.0-{label}-docker.json')})
        comparison.append({'subset':label,'documented':len(report['operations']),'penagent_parsed':len(pa['operations']),
            'penagent_public_path_equivalent':len(c.operation_set(report)&pa_keys),'zap_imported':len(mapped),
            'live_successful':sum(bool(observations.get((o['method'],o['path']),{}).get('verified')) for o in report['operations'])})
    c.save(root/'inventories/juice-shop-20.0.0.json',{'schema_version':1,'benchmark_id':'juice-shop-20.0.0','operations':inventory})
    counts={'documented':len(inventory),'penagent_parsed':sum(x['penagent_parsed'] for x in comparison),
        'penagent_public_path_equivalent':sum(x['penagent_public_path_equivalent'] for x in comparison),
        'zap_imported':sum(x['zap_imported'] for x in comparison),'live_successful':sum(x['live_successful'] for x in comparison),
        'shared_eligible':0,'excluded':len(inventory),'not_live_exercised':1,'live_failed':1,
        'candidate_after_connectivity_and_scope_fix':sum(x['candidate_after_connectivity_and_scope_fix'] for x in inventory)}
    c.save(root/'inventories/comparison.json',{'juice-shop-20.0.0':counts,'subsets':comparison,
        'dvws-original':{'documented':None,'reason':'No verified specification/deployment'},
        'srebench-api':{'documented':None,'reason':'No executable assets or specification'}})
    checks=dict.fromkeys(c.CHECKS,True)
    checks.update(shared_operations=False,enforceable_scope=False)
    m={'schema_version':1,'benchmark_id':'juice-shop-20.0.0','project':'OWASP Juice Shop',
        'source_repository':'https://github.com/juice-shop/juice-shop/tree/v20.0.0','target_version':'20.0.0',
        'image_digest':'bkimminich/juice-shop@sha256:25fd268112350ae9e0ddc7878371f9f12f5b0b546c7bf934d6599aa8e724418f',
        'deployment':{'available':True,'compose':'deploy/juice-shop.compose.yml','compose_sha256':c.sha(root/'deploy/juice-shop.compose.yml'),
            'container_id':live['target']['id'],'image_id':live['target']['image'],'running':live['target']['running'],
            'host_port_published':live['host_port_published'],'isolated_network':'penagent-phase4-juice20-r1_isolated'},
        'specifications':specifications,'host_origin':'http://127.0.0.1:18001',
        'container_origin':'http://host.docker.internal:18001 (configured, NOT reachable/verified)',
        'authentication':{'anonymous':'Four observed successful GET operations; reviewed inputs only',
            'bearer':'Official B2B requires bearer; no accounts/tokens created; roles and expiry not verified',
            'template':'config/credentials.example.json'},'inventory':'inventories/juice-shop-20.0.0.json',
        'eligible_operations':[],'excluded_operations':[x['stable_id'] for x in inventory],
        'reset':{'strategy':'Fresh uniquely named digest-pinned isolated instance per run; do not reset existing containers',
            'executed':False,'verified_repeatable_state':False,'limitations':'Default DB and in-memory state; challenge progress can change. No clean-state snapshot/reset exercised.'},
        'penagent':{'parsed':6,'public_path_equivalent':5,'evidence':'specs/validation/c1-limitations.json'},
        'zap':{'imported':6,'active_scans':0,'crawls':0,'real_target_requests':0,'fixture_requests':6},
        'ground_truth':{'verified':False,'sources':['https://github.com/juice-shop/juice-shop/tree/v20.0.0/data/static',
            'https://pwning.owasp-juice.shop/'],'phase5':'Map source-seeded challenges to operations and review exploitability independently'},
        'requires_approval':False,'readiness':c.readiness(checks),'checks':checks,
        'limitations':['Internal network runtime has empty published port bindings; no shared tool access',
            'No API-level enforced allowlist exists; existing root-only smoke config must stay unchanged',
            'C1 ignores OpenAPI 3 server base path and loses body required/media metadata',
            'Official spec is narrow; derived spec deliberately partial; not total application API coverage',
            'No authenticated workflows, full benchmark, reset, or ground-truth adjudication performed']}
    c.validate_manifest(m);c.save(root/'manifests/juice-shop-20.0.0.json',m)
    for target,project,repo,reason in [
        ('dvws-original','Original DVWS candidate','https://github.com/snoopysecurity/dvws',
         'Beebs (2019) attribution unresolved; archived legacy PHP 5.5.38/XAMPP target. No authoritative container/OpenAPI or reproducible compatible deployment established.'),
        ('srebench-api','SREBench-API',None,
         'Proposal and scanned scenario descriptions only; no authoritative executable repository, image, version or OpenAPI located. NEEDS IMPLEMENTATION or supplied assets.')]:
        checks=dict.fromkeys(c.CHECKS,False)
        blocked={k:None for k in m}
        blocked.update(schema_version=1,benchmark_id=target,project=project,source_repository=repo,target_version=None,
            deployment={'available':True,'runnable_available':False,'reason':reason},specifications=[],
            authentication={'status':'NOT VERIFIED'},inventory=f'inventories/{target}.json',eligible_operations=[],excluded_operations=[],
            reset={'strategy':'Unavailable; no target deployed','executed':False},penagent={'status':'NOT EXECUTED; missing assets'},
            zap={'status':'NOT EXECUTED; missing assets'},ground_truth={'verified':False,'status':'Scenario descriptions are not adjudicated vulnerability labels'},
            requires_approval=False,readiness=c.readiness(checks),checks=checks,limitations=[reason])
        c.save(root/f'inventories/{target}.json',{'schema_version':1,'benchmark_id':target,'operations':None,'reason':reason})
        c.validate_manifest(blocked);c.save(root/f'manifests/{target}.json',blocked)
    metadata=c.load(root/'local/github-metadata.json')
    sources={}
    for name,info in metadata.items():
        repository=info['repository']
        sources[name]={k:repository.get(k) for k in ['html_url','archived','pushed_at','license','description']}
        sources[name]['latest_observed_commit']=info['latest_commit'][0]['sha']
        sources[name]['tags']=[x['name'] for x in info['tags']] if isinstance(info['tags'],list) else info['tags']
        sources[name]['releases']=[x['tag_name'] for x in info['releases']] if isinstance(info['releases'],list) else info['releases']
    sources['notes']={'dvws_license_conflict':'README claims GPL-3; LICENSE bytes are Apache-2.0; unresolved',
        'dvws_node':'Separate candidate ONLY, not adopted; Dockerfile/Compose/OpenAPI present at pinned commit, no build/deployment/import performed',
        'srebench_api':'Exact-name searches and provided research did not establish runnable assets; do not substitute unrelated SRE-Bench'}
    c.save(root/'sources/audit-summary.json',sources)
    print(counts)

if __name__=='__main__':build()
