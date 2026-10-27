"""Resolve and try retrieving the official PHP 5.5.38 base, without execution."""
import json
import subprocess
import sys
from pathlib import Path
REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO))
from benchmarks import core as c

def main():
    out=c.ROOT/'phase4b/evidence/legacy-runtime.json'
    if out.exists():raise ValueError('Already attempted; do not retry automatically')
    results=[]
    args=['docker','manifest','inspect','--verbose','php:5.5.38-apache']
    p=subprocess.run(args,capture_output=True,text=True,encoding='utf-8',timeout=45)
    results.append({'argv':args,'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
    assert p.returncode==0
    descriptor=json.loads(p.stdout)['Descriptor'];digest=descriptor['digest']
    assert digest=='sha256:be7f9332d3bea49084d74a0718a5400f7b5d128c1937575e76f72df3a41e8eac'
    args=['docker','pull','php@'+digest]
    try:
        p=subprocess.run(args,capture_output=True,text=True,encoding='utf-8',timeout=120)
        results.append({'argv':args,'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
    except subprocess.TimeoutExpired as exc:
        results.append({'argv':args,'error':'120-second retrieval timeout','stdout':str(exc.stdout),'stderr':str(exc.stderr)})
    c.save(out,{'image':'php@'+digest,'platform':descriptor['platform'],'commands':results,
        'executed':False,'application_deployed':False,'note':'Official runtime retrieval feasibility only; no unknown third-party image used'})
    print('Legacy runtime retrieval recorded:',results[-1].get('exit_code',results[-1].get('error')))

if __name__=='__main__':main()
