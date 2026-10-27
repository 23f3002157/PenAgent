"""Record independent schema errors, historical evidence and successor import gaps."""
import json
import sys
from pathlib import Path
REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO))
from benchmarks import core as c
sys.path.insert(0,str(c.ROOT/'local/validation-deps'))
from openapi_spec_validator import OpenAPIV30SpecValidator

def main():
    root=c.ROOT/'phase4b';evidence=root/'evidence'
    archives=c.load(evidence/'upstream-archives.json')
    original=Path(archives['snoopysecurity/dvws']['local_source'])
    node=Path(archives['snoopysecurity/dvws-node']['local_source'])
    raw=root/'candidates/dvws-node-upstream-raw.json'
    if raw.exists():raise ValueError('Refusing overwrite')
    raw.write_bytes((node/'docs/openapi/openapi.json').read_bytes())
    spec=c.load(raw)
    errors=list(OpenAPIV30SpecValidator(spec).iter_errors())
    c.save(evidence/'dvws-node-schema-errors.json',{'validator':'openapi-spec-validator 0.7.2 OpenAPIV30SpecValidator',
        'raw_upstream_sha256':c.sha(raw),'schema_valid':not errors,'error_count':len(errors),
        'errors':[{'path':list(e.path),'message':e.message[:1500]} for e in errors],
        'note':'Original/prepared JSON semantic copies retain source defects; raw upstream bytes are separately preserved. No corrections applied.'})
    zap=c.load(evidence/'dvws-node-zap.json');pa=c.load(evidence/'dvws-node-c1.json')
    operations=c.load(root/'candidates/dvws-node-inventory.json')['operations']
    mapped=c.map_capture_paths(operations,zap['operations'])
    c.save(evidence/'dvws-node-parser-comparison.json',{'documented':len(operations),
        'c1_parsed':len(pa.get('operations',[])),'c1_server_base_path_preserved':False,
        'zap_imported_mapped':len(mapped),'zap_fixture_requests':zap['capture_requests'],'schema_valid':not errors,
        'shared_live_eligible':0,'deployed':False,'adopted':False,
        'warning':'Permissive tool parsing of an invalid OpenAPI document is not valid benchmark readiness'})
    searches=c.load(evidence/'source-searches.json')
    history=next(x for x in searches if 'until=' in x['url'])
    before2019=history.get('response',[])
    c.save(evidence/'dvws-source-resolution.json',{'source_type':'ORIGINAL',
        'verified_original_repository':'https://github.com/snoopysecurity/dvws',
        'project_identity_verified':True,'relationship_to_successor_verified':True,
        'operator_clarification':'Original project and successor URL confirmed; exact Beebs (2019) attribution remains unconfirmed',
        'beebs_2019_attribution_verified':False,'source_created':'2016-01-12',
        'latest_archived_commit':'25a5a03aa1b13d8e647da66784c3e8445726e578',
        'latest_pre_2020_commit':[{'sha':x['sha'],'date':x['commit']['author']['date'],'message':x['commit']['message']} for x in before2019],
        'history_query':history['url'],'installed_last_compatible_version':None,
        'runtime_requirement':'PHP 5.5.38 per upstream; not an experimentally verified last compatible version',
        'blocker':'Pinned official runtime retrieval/extraction failed; no application deployed or code compatibility patches applied',
        'build_proposal':'phase4b/deploy/dvws-original.Dockerfile.proposed',
        'future_dependencies':['Verified usable exact PHP base or audited rebuild','Digest-pinned MySQL and isolated localhost/socket compatibility',
            'Source-review of mixed mysqli/mysql API and undefined $set branches without altering intended vulnerability behavior',
            'License metadata conflict resolved before redistribution'],
        'recommendation':'Prioritize original if faithful runtime can be restored; otherwise seek explicit approval for separately versioned DVWS-Node candidate'})
    print('Candidate full schema error count:',len(errors),'C1 parsed:',len(pa.get('operations',[])),'ZAP mapped:',len(mapped))

if __name__=='__main__':main()
