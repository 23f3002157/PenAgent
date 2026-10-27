"""Offline final artifact index and preservation/link checks; no execution of plans."""
import ast
import json
import re
import sys
from pathlib import Path
REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO))
from benchmarks import core as c
from benchmarks.phase4b.registry import validate_registry

def main():
    root=c.ROOT/'phase4b'
    validate_registry(c.load(root/'registry.json'))
    before=c.load(root/'evidence/preservation-before.json')
    assert all((REPO/p).is_file() and c.sha(REPO/p)==digest for p,digest in before.items())
    verification=c.load(root/'evidence/verification.json')
    assert not verification['changed_or_missing'] and all(r['exit_code']==0 for r in verification['commands'])
    report=c.ROOT/'docs/PHASE4B_COMPLETION.md'
    cfg=c.load(root/'evidence/connectivity-r2/connectivity-config.json')
    assert cfg['gateway_origin'].split('://')[1] in report.read_text(encoding='utf-8')
    files=sorted(p for p in root.rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    files += [report,c.ROOT/'docs/PHASE4B_COMMANDS.md']
    indexed=[]
    for path in files:
        if path.suffix=='.py':ast.parse(path.read_text(encoding='utf-8'))
        if path.suffix=='.json':json.loads(path.read_text(encoding='utf-8'))
        if path.suffix in {'.py','.json','.md','.yml'}:
            for line in path.read_text(encoding='utf-8').splitlines():assert line==line.rstrip(' \t'),str(path)
        indexed.append({'path':path.relative_to(REPO).as_posix(),'sha256':c.sha(path)})
    # Validate the two real new cross-document Markdown links.
    for path in [report,c.ROOT/'docs/PHASE4B_COMMANDS.md']:
        for target in re.findall(r'\]\(([^)]+)\)',path.read_text(encoding='utf-8')):
            if not target.startswith(('http://','https://')):assert (path.parent/target).is_file(),target
    c.save(root/'evidence/files-created.json',{'files':indexed,'existing_files_preserved':len(before),
        'original_smoke_files_preserved':27,'active_scans':0,'penagent_probes':0,
        'note':'Index excludes itself and ignored local working downloads/logs; all listed Phase 4B artifacts are new'})
    print(f'Final artifact checks passed: {len(indexed)} new files indexed, {len(before)} existing hashes unchanged')

if __name__=='__main__':main()
