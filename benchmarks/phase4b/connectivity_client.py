"""Only fixed benign GETs. No PenAgent probe execution or ZAP scan/import to target."""
import hashlib
import http.client
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT=Path('/benchmarks')
sys.path.insert(0,str(ROOT.parent))
from benchmarks.phase4b.gateway import REQUESTS

def main():
    kind=sys.argv[1];cfg=json.loads((ROOT/'phase4b/evidence/connectivity-config.json').read_text())
    gateway=cfg['gateway_ip'];origin=f'http://{gateway}:8088'
    evidence={'client':kind,'origin':origin,'network':cfg['tool_network'],'negative_connections':[],
        'operations':[],'denied_requests':[],'active_scans':0,'penagent_probes':0,'crawls':0}
    # TCP-only checks: send no HTTP or application payload to forbidden destinations.
    for host,port in cfg['forbidden_connections']:
        try:
            with socket.create_connection((host,port),timeout=.35):reachable=True
        except OSError:reachable=False
        evidence['negative_connections'].append({'host':host,'port':port,'reachable':reachable})
    if any(x['reachable'] for x in evidence['negative_connections']):raise RuntimeError('Network isolation failed; no GET checks performed')
    process=None;zap=None;log=None
    try:
        if kind=='zap':
            from zapv2 import ZAPv2
            log=(ROOT/'local/phase4b/zap-connectivity.log').open('w')
            process=subprocess.Popen(['zap.sh','-daemon','-host','127.0.0.1','-port','8090','-silent',
                '-config','api.key=phase4b-connectivity-only'],stdout=log,stderr=subprocess.STDOUT)
            zap=ZAPv2(apikey='phase4b-connectivity-only',proxies={'http':'http://127.0.0.1:8090','https':'http://127.0.0.1:8090'})
            for _ in range(180):
                try:
                    if zap.core.version=='2.17.0':break
                except Exception:pass
                time.sleep(.5)
            else:raise RuntimeError('ZAP not ready')
            assert zap.core.set_mode('safe')=='OK'
            assert zap.pscan.disable_all_scanners()=='OK'
            assert zap.ascan.disable_all_scanners()=='OK'
            import requests
            session=requests.Session();session.trust_env=False
            def get(path):
                response=session.get(origin+path,proxies={'http':'http://127.0.0.1:8090'},timeout=8,allow_redirects=False)
                return response.status_code,response.content
        elif kind=='penagent':
            import httpx
            from penagent_common.policy import origin as check_origin
            # C3's numeric-IP guard is applied, but execute/probe/workflow APIs are not called.
            check_origin(origin)
            session=httpx.Client(trust_env=False,follow_redirects=False,timeout=8)
            def get(path):
                response=session.get(origin+path);return response.status_code,response.content
            evidence['client_library']='httpx; same transport configuration as C3; no Executor.execute invocation'
        else:raise ValueError(kind)
        for path in REQUESTS:
            status,body=get(path)
            expected=500 if path=='/rest/country-mapping' else 200
            assert status==expected,(path,status)
            if path.endswith('application-version'):assert json.loads(body)['version']=='20.0.0'
            evidence['operations'].append({'method':'GET','request_path':path,'status':status,
                'response_sha256':hashlib.sha256(body).hexdigest()})
        session.close()
        # Invalid paths/methods are denied by the gateway, with no upstream forwarding.
        for method,path in [('GET','/__phase4b_outside_allowlist'),('POST','/rest/admin/application-version'),
                            ('GET','/rest/products/search?q=apple&extra=1')]:
            conn=http.client.HTTPConnection(gateway,8088,timeout=3);conn.request(method,path)
            response=conn.getresponse();response.read();assert response.status==403
            evidence['denied_requests'].append({'method':method,'path':path,'status':response.status});conn.close()
        if zap:
            evidence.update(zap_mode=zap.core.mode,zap_active_scans=zap.ascan.scans,zap_spider_scans=zap.spider.scans)
            assert not evidence['zap_active_scans'] and not evidence['zap_spider_scans']
        output=ROOT/f'phase4b/evidence/{kind}-connectivity.json'
        if output.exists():raise ValueError('Refusing to overwrite client evidence')
        output.write_text(json.dumps(evidence,indent=2)+'\n',encoding='utf-8')
        print(kind+': five benign GETs verified, three gateway denials, isolation checks passed')
    finally:
        if zap:
            try:zap.core.shutdown()
            except Exception:
                if process:process.terminate()
        if process:process.wait(timeout=15)
        if log:log.close()

if __name__=='__main__':main()
