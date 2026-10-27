"""Read pinned upstream archives/metadata and image manifests; execute no downloads."""
import concurrent.futures
import hashlib
import io
import json
import subprocess
import sys
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO))
from benchmarks import core as c

COMMITS={'snoopysecurity/dvws':'25a5a03aa1b13d8e647da66784c3e8445726e578',
    'snoopysecurity/dvws-node':'35f999505028f580dd6acc8bb7ddecfb87fe4bf6'}
OUT=c.ROOT/'phase4b/evidence'
LOCAL=c.ROOT/'local/phase4b/upstream'

def get(url):
    request=urllib.request.Request(url,headers={'User-Agent':'PenAgent-Phase4B-ReadOnly-Research'})
    with urllib.request.urlopen(request,timeout=35) as response:
        data=response.read(20*1024*1024+1)
        if len(data)>20*1024*1024:raise ValueError('Download exceeds cap')
        return data

def archive(item):
    repo,commit=item;url=f'https://codeload.github.com/{repo}/zip/{commit}'
    dest=LOCAL/repo.replace('/','_')
    if dest.exists():raise ValueError('Archive already captured')
    data=get(url);dest.mkdir(parents=True)
    (dest/'source.zip').write_bytes(data)
    files=[];total=0
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        if len(z.infolist())>2000:raise ValueError('Archive file cap')
        for entry in z.infolist():
            if entry.is_dir():continue
            parts=Path(entry.filename).parts[1:]
            if not parts or any(p in {'..','.'} for p in parts):raise ValueError('Unsafe archive path')
            if (entry.external_attr>>16)&0o170000==0o120000:raise ValueError('Archive symlink')
            path=(dest/'source').joinpath(*parts)
            if not path.resolve().is_relative_to((dest/'source').resolve()):raise ValueError('Archive traversal')
            total+=entry.file_size
            if total>60*1024*1024:raise ValueError('Uncompressed archive cap')
            path.parent.mkdir(parents=True,exist_ok=True);body=z.read(entry);path.write_bytes(body)
            files.append({'path':'/'.join(parts),'sha256':hashlib.sha256(body).hexdigest()})
    return repo,{'repository':'https://github.com/'+repo,'commit':commit,'archive_url':url,
        'archive_sha256':hashlib.sha256(data).hexdigest(),'local_source':str(dest/'source'),
        'executed':False,'files':files}

def metadata(url):
    try:return {'url':url,'response':json.loads(get(url))}
    except Exception as exc:return {'url':url,'error':type(exc).__name__+': '+str(exc)}

def main():
    if (OUT/'upstream-archives.json').exists():raise ValueError('Refusing to overwrite research evidence')
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results=dict(pool.map(archive,COMMITS.items()))
    c.save(OUT/'upstream-archives.json',results)
    urls=['https://api.github.com/users/snoopysecurity',
        'https://api.github.com/search/repositories?q=DVWS+user:beebs',
        'https://api.github.com/search/repositories?q=%22SREBench-API%22',
        'https://api.github.com/search/repositories?q=%22penagent-target-env%22',
        'https://api.github.com/repos/snoopysecurity/dvws/commits?until=2019-12-31T23:59:59Z&per_page=1']
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        c.save(OUT/'source-searches.json',list(pool.map(metadata,urls)))
    manifests=[]
    for image in ['php:5.5.38-apache','monisha117/penagent-test-env:latest','penagent-target-env:latest']:
        args=['docker','manifest','inspect',image]
        try:
            p=subprocess.run(args,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=45)
            manifests.append({'argv':args,'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr,'pulled_or_executed':False})
        except subprocess.TimeoutExpired:manifests.append({'argv':args,'error':'45-second metadata timeout','pulled_or_executed':False})
    c.save(OUT/'image-manifest-research.json',manifests)
    print('Pinned upstream source captured for static review; metadata recorded; no images pulled or executed')

if __name__=='__main__':main()
