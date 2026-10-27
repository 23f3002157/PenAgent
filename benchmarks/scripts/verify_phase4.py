"""Run offline regressions, verify only existing run identities, preserve evidence."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO))
from benchmarks import core as c

def command(args,timeout=180):
    result=subprocess.run(args,cwd=REPO,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=timeout)
    return {'argv':args,'exit_code':result.returncode,'stdout':result.stdout,'stderr':result.stderr}

out=c.ROOT/'specs/validation/regressions.json'
if out.exists():raise ValueError('Refusing to overwrite verification evidence')
commands=[
    [sys.executable,'-B','-m','unittest','discover','-s','benchmarks/tests','-v'],
    [sys.executable,'-B','-m','unittest','discover','-s','baselines/zap/tests','-q'],
    ['docker','run','--rm','--network','none','--mount',f'type=bind,source={REPO},target=/phase4/src,readonly',
     '--workdir','/tmp','--entrypoint','python','penagent-sis:local','-B','-m','pytest',
     '/phase4/src/c1-spec-ingestion/tests/test_graph_builder.py','/phase4/src/c1-spec-ingestion/tests/test_tagger.py',
     '/phase4/src/c1-spec-ingestion/tests/test_storage_drift.py','-q','-p','no:cacheprovider']]
results=[]
for args in commands:
    result=command(args);results.append(result)
    print('exit',result['exit_code'],' '.join(args),flush=True)
    print(result['stdout'][-600:]+result['stderr'][-600:],flush=True)
c.save(out,results)
before=c.load(c.ROOT/'local/preservation-before.json')
missing=[name for name in before if not (REPO/name).is_file()]
changed=[name for name,digest in before.items() if (REPO/name).is_file() and c.sha(REPO/name)!=digest]
c.save(c.ROOT/'specs/validation/preservation.json',{'snapshot_sha256':c.sha(c.ROOT/'local/preservation-before.json'),
    'files_checked':len(before),'missing':missing,'changed':changed,
    'smoke_files_checked':sum('/local/juice-smoke-r1/' in name for name in before)})
identities=[]
for name in ['blissful_chebyshev','penagent-phase4-juice20-r1-target-1']:
    result=command(['docker','inspect','--format','{"container_id":{{json .Id}},"image_id":{{json .Image}},"running":{{json .State.Running}}}',name])
    if result['exit_code']:raise RuntimeError(result)
    observed=json.loads(result['stdout'])
    version=command(['docker','exec',name,'/nodejs/bin/node','-p',"require('/juice-shop/package.json').version"])
    if version['exit_code']:raise RuntimeError(version)
    observed['version']=version['stdout'].strip()
    expected={'container_id':'0356c18439557ca2fed64e8c69f73035c4b485ca069b6f961b1de038f17d9ac3' if name=='blissful_chebyshev' else c.load(c.ROOT/'manifests/juice-shop-20.0.0.json')['deployment']['container_id'],
        'image_id':'sha256:25fd268112350ae9e0ddc7878371f9f12f5b0b546c7bf934d6599aa8e724418f','version':'20.0.0'}
    c.check_identity(expected,observed)
    c.save(c.ROOT/f'specs/validation/{name}-expected.json',expected)
    c.save(c.ROOT/f'specs/validation/{name}-observed.json',observed)
    identities.append({'name':name,'expected':expected,'observed':observed,'commands':[result,version]})
c.save(c.ROOT/'specs/validation/target-identities.json',identities)
assert not missing and not changed,'Existing source/evidence changed'
assert all(r['exit_code']==0 for r in results),'Regression test failures; inspect saved outputs'
print('All regressions passed; existing source and smoke evidence hashes match; both target identities verified')
