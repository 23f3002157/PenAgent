"""Static source review and candidate OpenAPI preparation; no adoption/deployment."""
import copy
import json
import re
import sys
from pathlib import Path
REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO))
from benchmarks import core as c
sys.path.insert(0,str(c.ROOT/'local/validation-deps'))

def main():
    evidence=c.ROOT/'phase4b/evidence'
    archives=c.load(evidence/'upstream-archives.json')
    original=Path(archives['snoopysecurity/dvws']['local_source'])
    successor=Path(archives['snoopysecurity/dvws-node']['local_source'])
    def reference(root,path,repo):
        commit=archives[repo]['commit']
        return {'file':path,'sha256':c.sha(root/path),'url':f'https://github.com/{repo}/blob/{commit}/{path}'}
    source_paths=['README.md','LICENSE','instructions.php','vulnerabilities/sqli/api.php',
        'vulnerabilities/jwt/api.php','vulnerabilities/cmdi/server.php','vulnerabilities/wsdlenum/service.php']
    review={'source_type':'ORIGINAL','intended_citation_verified':False,'candidate':'snoopysecurity/dvws',
        'maintainer':'Sam Sanoop (snoopysecurity GitHub profile)','commit':archives['snoopysecurity/dvws']['commit'],
        'release':'No tagged release established; use commit identity, not a fabricated application version',
        'requirements':['PHP 5.5.38 per README','Apache/PHP execution','MySQL local DB dvws',
            'Legacy mysql AND mysqli extensions; source mixes both APIs','Vendored NuSOAP and XML-RPC implementations'],
        'source_facts':['SQL API uses PATH_INFO and GET/PUT/POST/DELETE switches',
            'SQL API opens mysqli but later invokes mysql_select_db/mysql_query; PUT/POST reference undefined $set',
            'Setup PHP creates DB/users table and inserts fixed seed rows; this was not executed',
            'SOAP/JSON-RPC/XML/JWT exercise source is present; no official OpenAPI in complete pinned tree'],
        'documented_php_entrypoints':[p['path'] for p in archives['snoopysecurity/dvws']['files']
            if p['path'].startswith('vulnerabilities/') and p['path'].endswith('.php') and '/lib/' not in p['path']],
        'operations':None,'operation_note':'PHP entrypoint filenames are not a validated method/path inventory',
        'license':'LICENSE Apache-2.0; README GPL-3 conflict; do not redistribute a derived image until clarified',
        'runtime_evidence':'phase4b/evidence/legacy-runtime.json',
        'deployment_status':'BLOCKED; official pinned PHP image retrieval/extraction failed locally',
        'compatibility_patches_applied':[],'source_evidence':[reference(original,p,'snoopysecurity/dvws') for p in source_paths],
        'approval_blocker':'Confirm intended original repository/version; no successor is automatically adopted'}
    c.save(evidence/'dvws-original-review.json',review)
    spec_path=successor/'docs/openapi/openapi.json';spec=c.load(spec_path)
    out=c.ROOT/'phase4b/candidates'
    c.save(out/'dvws-node-original.json',spec)
    prepared=copy.deepcopy(spec)
    prepared['servers']=[{'url':'http://127.0.0.1:18003/api'}]
    c.save(out/'dvws-node-prepared.json',prepared)
    try:
        validation=c.inspect_spec(prepared,True)
        validation['status']='VALID'
    except Exception as exc:
        validation={'status':'FAILED','error_type':type(exc).__name__,'error':str(exc)[:4000],
            'note':'No schema weakening or source repair applied'}
    validation.update({'source_type':'SUCCESSOR','adopted':False,'deployed':False,
        'source':reference(successor,'docs/openapi/openapi.json','snoopysecurity/dvws-node'),
        'original_sha256':c.sha(out/'dvws-node-original.json'),'prepared_sha256':c.sha(out/'dvws-node-prepared.json'),
        'transformation':'Only server URL changed to proposed local origin, preserving /api; no target running',
        'spec_api_version':spec['info']['version'],'package_version':c.load(successor/'package.json')['version']})
    c.save(evidence/'dvws-node-spec-validation.json',validation)
    from openapi_spec_validator import validate_spec
    # Extract documented operations without presenting them as reachable or safe.
    operations=[]
    for path,item in spec['paths'].items():
        for method,op in item.items():
            if method not in c.METHODS:continue
            operations.append({'stable_id':'dvwsnode_'+c.stable([method.upper(),'/api'+path])[:20],
                'method':method.upper(),'path':'/api'+path,'spec_path':path,'operation_id':op.get('operationId'),
                'security':op.get('security',spec.get('security',[])),
                'authentication_status':'Source middleware review required; specification metadata alone is insufficient',
                'parameters':op.get('parameters',[]),'request_body':op.get('requestBody'),
                'state_changing':'UNREVIEWED; GET can change state in this source',
                'eligible':False,'exclusion':'Successor adoption not approved; no deployment/identity/auth/reset validation',
                'live_status':'NOT EXECUTED','source':validation['source']['url']})
    c.save(out/'dvws-node-inventory.json',{'source_type':'SUCCESSOR','label':'DVWS-Node — proposed successor benchmark',
        'commit':archives['snoopysecurity/dvws-node']['commit'],'operations':operations,'shared_eligible_operations':[]})
    facts={'source_type':'SUCCESSOR','label':'DVWS-Node — proposed successor benchmark','adopted':False,
        'source_repository':'https://github.com/snoopysecurity/dvws-node','commit':archives['snoopysecurity/dvws-node']['commit'],
        'requirements':['Node >=22 <23','MongoDB','MySQL','Frontend npm build','Locked npm dependencies require separate reproducibility review'],
        'license':'LICENSE GPL-3.0; package.json says MIT; unresolved metadata conflict',
        'seed':'Upstream seed script drops/recreates dvws_sqldb and deletes Mongo data; only fresh dedicated per-run volumes permitted',
        'auth':'Bearer middleware deliberately allows HS256/none and ignores expiration; no credentials or tokens verified',
        'scope_warning':'GET login, notification-read and logout routes may mutate state; GET is not inherently safe',
        'official_spec_documented_operations':len(operations),'spec_validation':validation['status'],
        'source_evidence':[reference(successor,p,'snoopysecurity/dvws-node') for p in [
            'README.md','LICENSE','package.json','Dockerfile','docker-compose.yml','scripts/seed-database.js',
            'src/server.js','src/routes/users.js','src/middleware/auth.js','docs/openapi/openapi.json','CHALLENGES.md']],
        'status':'REQUIRES APPROVAL','approval':'Explicitly adopt this separately versioned successor, not the unresolved Beebs (2019) target'}
    c.save(evidence/'dvws-node-review.json',facts)
    print('Static original/successor evidence prepared; candidate operations:',len(operations),'schema:',validation['status'])

if __name__=='__main__':main()
