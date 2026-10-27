"""Offline regressions, non-mutating configuration checks and preservation audit."""
import ast
import json
import os
import subprocess
import sys
from pathlib import Path
REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO))
from benchmarks import core as c
from benchmarks.phase4b.registry import validate_registry

def main():
    out=c.ROOT/'phase4b/evidence/verification.json'
    if out.exists():raise ValueError('Refusing to overwrite verification record')
    results=[]
    def command(args,env=None):
        p=subprocess.run(args,cwd=REPO,env=env,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=120)
        record={'argv':args,'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr};results.append(record)
        print('exit',p.returncode,':',' '.join(args[:7]),flush=True)
        print((p.stdout+p.stderr)[-700:],flush=True)
        return p
    command([sys.executable,'-B','-m','unittest','benchmarks.phase4b.test_gateway','benchmarks.phase4b.test_readiness','-v'])
    command([sys.executable,'-B','-m','unittest','discover','-s','benchmarks/tests','-v'])
    command([sys.executable,'-B','-m','unittest','discover','-s','baselines/zap/tests','-q'])
    command(['docker','run','--rm','--network','none','--mount',f'type=bind,source={REPO},target=/phase4/src,readonly',
        '--workdir','/tmp','--entrypoint','python','penagent-sis:local','-B','-m','pytest',
        '/phase4/src/c1-spec-ingestion/tests/test_graph_builder.py','/phase4/src/c1-spec-ingestion/tests/test_tagger.py',
        '/phase4/src/c1-spec-ingestion/tests/test_storage_drift.py','-q','-p','no:cacheprovider'])
    env=dict(os.environ,PHASE4B_FRESH_PROJECT='phase4b-config-validation-only',
        PHASE4B_FRESH_VOLUME='phase4b-validation-volume-not-created',PHASE4B_BENCHMARKS_DIR=str(c.ROOT),
        PHASE4B_FRESH_CONTROL=str(c.ROOT/'local/phase4b/config-validation-not-created'))
    command(['docker','compose','-f','benchmarks/phase4b/deploy/juice-fresh.compose.yml','config','--quiet'],env)
    identity=[]
    approved=c.load(c.ROOT/'manifests/juice-shop-20.0.0.json')
    for name,expected_id in [('blissful_chebyshev','0356c18439557ca2fed64e8c69f73035c4b485ca069b6f961b1de038f17d9ac3'),
        ('penagent-phase4-juice20-r1-target-1',approved['deployment']['container_id'])]:
        p=command(['docker','inspect','--format','{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"networks":{{json .NetworkSettings.Networks}},"ports":{{json .NetworkSettings.Ports}}}',name])
        observed=json.loads(p.stdout)
        assert observed['id']==expected_id and observed['running'] and observed['image']==approved['deployment']['image_id']
        identity.append({'name':name,**observed})
    baseline=c.load(c.ROOT/'phase4b/evidence/preservation-before.json')
    changed=[p for p,digest in baseline.items() if not (REPO/p).is_file() or c.sha(REPO/p)!=digest]
    registry=validate_registry(c.load(c.ROOT/'phase4b/registry.json'))
    syntax_count=0
    for path in (c.ROOT/'phase4b').rglob('*.py'):ast.parse(path.read_text(encoding='utf-8'));syntax_count+=1
    for path in (c.ROOT/'phase4b').rglob('*.json'):json.loads(path.read_text(encoding='utf-8'))
    result={'commands':results,'preserved_files_checked':len(baseline),'changed_or_missing':changed,
        'target_identities':identity,'new_python_syntax_checks':syntax_count,'registry_validated':True,
        'existing_targets_deleted_or_reset':False,'active_scans':0,'penagent_probes':0,
        'note':'Compose config only; no fresh target/volume or candidate deployment started. Offline regression Docker containers use --rm.'}
    c.save(out,result)
    assert not changed and all(r['exit_code']==0 for r in results),'Verification failed; preserved evidence identifies failures'
    print('All verification passed; original Phase 4, PenAgent and baseline files remain unchanged')

if __name__=='__main__':main()
