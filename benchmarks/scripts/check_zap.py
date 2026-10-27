"""Offline OpenAPI imports in pinned ZAP; capture fixture ONLY, no real target."""
import copy
import json
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from zapv2 import ZAPv2

ROOT=Path('/phase4/benchmarks')
seen=[]
class Capture(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def capture(self):
        seen.append({'method':self.command,'path':urlsplit(self.path).path})
        length=int(self.headers.get('Content-Length','0'))
        if length:self.rfile.read(min(length,1024*1024))
        body=b'{}'
        self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length','2');self.end_headers();self.wfile.write(body)
    do_GET=do_POST=do_PUT=do_PATCH=do_DELETE=do_HEAD=do_OPTIONS=capture
server=ThreadingHTTPServer(('127.0.0.1',18080),Capture)
threading.Thread(target=server.serve_forever,daemon=True).start()
log=(ROOT/'local/zap-import/daemon.log').open('w')
process=subprocess.Popen(['zap.sh','-daemon','-host','127.0.0.1','-port','8090','-silent','-config','api.key=offline-phase4-only'],stdout=log,stderr=subprocess.STDOUT)
zap=ZAPv2(apikey='offline-phase4-only',proxies={'http':'http://127.0.0.1:8090','https':'http://127.0.0.1:8090'})
try:
    for attempt in range(90):
        try:
            if zap.core.version=='2.17.0':break
        except Exception:pass
        time.sleep(1)
    else:raise RuntimeError('ZAP daemon unavailable')
    assert zap.core.set_mode('safe')=='OK'
    assert zap.pscan.disable_all_scanners()=='OK'
    assert zap.ascan.disable_all_scanners()=='OK'
    for label in ['b2b','readonly']:
        spec=json.loads((ROOT/f'specs/prepared/juice-shop-20.0.0-{label}-host.json').read_text())
        original_servers=copy.deepcopy(spec['servers'])
        base=urlsplit(spec['servers'][0]['url']).path.rstrip('/')
        spec['servers']=[{'url':'http://127.0.0.1:18080'+base}]
        path=ROOT/f'local/zap-import/{label}-capture-only.json';path.write_text(json.dumps(spec))
        start=len(seen)
        result=zap.openapi.import_file(str(path))
        operations=sorted({(r['method'],r['path']) for r in seen[start:]})
        expected=sorted((method.upper(),base+p) for p,item in spec['paths'].items() for method in item if method in {'get','post','put','patch','delete','head','options','trace'})
        report={'tool':'actual ZAP 2.17.0 OpenAPI add-on','network':'none','mode':zap.core.mode,
            'passive_rules_disabled':True,'active_rules_disabled':True,'active_scans':zap.ascan.scans,
            'spider_scans':zap.spider.scans,'real_target_requests':0,'capture_fixture_requests':len(seen)-start,
            'original_servers':original_servers,'fixture_servers':spec['servers'],'import_result':result,
            'operations':[{'method':m,'path':p} for m,p in operations],
            'missing_operations':[list(x) for x in expected if x not in operations],
            'note':'Local fixture captures generated import examples only. This proves import/method-path mapping, not target reachability or authentication.'}
        assert not report['active_scans'] and not report['spider_scans']
        out=ROOT/f'specs/validation/zap-{label}.json'
        if out.exists():raise ValueError('Refusing to overwrite import evidence')
        out.write_text(json.dumps(report,indent=2)+'\n')
    print('Offline ZAP imports recorded; zero scans, zero real target requests')
finally:
    try:zap.core.shutdown()
    except Exception:process.terminate()
    process.wait(timeout=20);server.shutdown();server.server_close();log.close()
