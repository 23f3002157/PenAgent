"""Record dependency/spec hashes and final offline checks; no Docker or network."""
import ast
import importlib.metadata
import json
import subprocess
import sys
from pathlib import Path

repo=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(repo))
from benchmarks import core as c

deps=c.ROOT/'local/validation-deps'
c.save(c.ROOT/'specs/validation/dependencies.json',{
    'python':sys.version,'validation_environment':'ignored local/validation-deps',
    'packages':sorted([{'name':d.metadata['Name'],'version':d.version} for d in importlib.metadata.distributions(path=[str(deps)])],key=lambda d:d['name'].lower())})
manifest=c.load(c.ROOT/'manifests/juice-shop-20.0.0.json')
c.save(c.ROOT/'specs/validation/spec-hashes.json',manifest['specifications'])
outputs=[]
args_list=[]
for label in ['b2b','readonly']:
    for origin in ['host','docker']:
        args_list.append(['validate-spec',f'benchmarks/specs/prepared/juice-shop-20.0.0-{label}-{origin}.json','--full'])
for name in ['juice-shop-20.0.0','dvws-original','srebench-api']:
    args_list.append(['validate-manifest',f'benchmarks/manifests/{name}.json'])
for args in args_list:
    argv=[sys.executable,'-B','-m','benchmarks',*args]
    p=subprocess.run(argv,cwd=repo,capture_output=True,text=True,encoding='utf-8',timeout=30)
    outputs.append({'argv':argv,'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
    assert p.returncode==0,outputs[-1]
c.save(c.ROOT/'specs/validation/final-cli-checks.json',outputs)
files=[];python_count=json_count=0
for path in sorted(c.ROOT.rglob('*')):
    relative=path.relative_to(c.ROOT)
    if not path.is_file() or 'local' in relative.parts or '__pycache__' in relative.parts:continue
    if path.suffix=='.py':ast.parse(path.read_text(encoding='utf-8'));python_count+=1
    if path.suffix=='.json':json.loads(path.read_text(encoding='utf-8'));json_count+=1
    if relative.parts[0]!='sources' and path.suffix in {'.py','.json','.md','.yml','.txt'}:
        for number,line in enumerate(path.read_text(encoding='utf-8').splitlines(),1):
            assert line==line.rstrip(' \t'),f'Trailing whitespace: {relative}:{number}'
    files.append({'path':'benchmarks/'+relative.as_posix(),'sha256':c.sha(path)})
before=c.load(c.ROOT/'local/preservation-before.json')
assert all((repo/name).is_file() and c.sha(repo/name)==digest for name,digest in before.items())
c.save(c.ROOT/'specs/validation/files-created.json',{'note':'All Phase 4 files are new; local ignored working files and this self-referential index excluded',
    'python_syntax_checked':python_count,'json_parsed':json_count,'files':files})
print(f'Final checks passed: {len(outputs)} CLI validations, {python_count} Python syntax checks, {json_count} JSON parses; {len(before)} preserved hashes still match')

if __name__=='__main__':pass
