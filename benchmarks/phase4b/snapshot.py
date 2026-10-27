"""Preserve existing Phase 4/component/baseline bytes before Phase 4B execution."""
from pathlib import Path
import sys
REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO))
from benchmarks import core as c

def main():
    files=c.load(c.ROOT/'local/preservation-before.json')
    assert all((REPO/p).is_file() and c.sha(REPO/p)==digest for p,digest in files.items())
    for p in c.ROOT.rglob('*'):
        relative=p.relative_to(c.ROOT)
        if p.is_file() and not {'local','phase4b','__pycache__'} & set(relative.parts):files['benchmarks/'+relative.as_posix()]=c.sha(p)
    c.save(c.ROOT/'phase4b/evidence/preservation-before.json',files)
    print('Preserved',len(files),'existing component/baseline/Phase 4 hashes')

if __name__=='__main__':main()
