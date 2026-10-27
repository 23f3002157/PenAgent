"""Five source-reviewed benign GETs against the NEW isolated Juice Shop only."""
import hashlib
import json
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT=Path('benchmarks')
NAME='penagent-phase4-juice20-r1-target-1'
def docker(*args):
    p=subprocess.run(['docker',*args],capture_output=True,text=True,encoding='utf-8',timeout=20)
    if p.returncode:raise RuntimeError(f'Docker exit {p.returncode}: {p.stderr} {p.stdout}')
    return p.stdout.strip()
metadata=json.loads(docker('inspect','--format','{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"ports":{{json .NetworkSettings.Ports}},"networks":{{json .NetworkSettings.Networks}}}',NAME))
assert metadata['running'] and metadata['image']=='sha256:25fd268112350ae9e0ddc7878371f9f12f5b0b546c7bf934d6599aa8e724418f'
requested=json.loads(docker('inspect','--format','{{json .HostConfig.PortBindings}}',NAME))
assert requested['3000/tcp']==[{'HostIp':'127.0.0.1','HostPort':'18001'}]
assert docker('network','inspect','--format','{{json .Internal}}','penagent-phase4-juice20-r1_isolated')=='true'
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
paths=[('/rest/admin/application-version','/rest/admin/application-version'),('/rest/languages','/rest/languages'),
       ('/rest/products/search','/rest/products/search?q=apple'),('/rest/products/{id}/reviews','/rest/products/1/reviews'),
       ('/rest/country-mapping','/rest/country-mapping')]
report={'target':metadata,'origin':'http://127.0.0.1:18001','active_scans':0,'crawls':0,'observations':[],
    'host_port_published':metadata['ports'].get('3000/tcp')==requested['3000/tcp'],
    'transport':'docker exec node fetch on target loopback; does not prove host/tool connectivity'}
out=ROOT/'specs/validation/live-juice20.json'
if out.exists():raise ValueError('Refusing to overwrite live evidence')
for template,path in paths:
    start=time.monotonic()
    # Fixed benign paths only; redirect following is disabled. No files written in target.
    script="const r=await fetch('http://127.0.0.1:3000'+process.argv[1],{redirect:'manual',signal:AbortSignal.timeout(8000)});const b=await r.text();console.log(JSON.stringify({status:r.status,type:r.headers.get('content-type'),body:b}));"
    result=json.loads(docker('exec',NAME,'/nodejs/bin/node','--input-type=module','-e',script,path))
    body=result['body'].encode();assert len(body)<=2*1024*1024
    try:value=json.loads(body);shape=type(value).__name__
    except (ValueError,UnicodeError):value=None;shape='not-json'
    entry={'method':'GET','path':template,'request_path':path,'http_status':result['status'],
        'content_type':result['type'],'body_sha256':hashlib.sha256(body).hexdigest(),
        'response_shape':shape,'duration_seconds':time.monotonic()-start,'verified':result['status']==200 and value is not None}
    if template.endswith('application-version'):
        assert value['version']=='20.0.0';entry['version']=value['version']
    report['observations'].append(entry)
out.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report['observations'],indent=2))
