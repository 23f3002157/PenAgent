"""Actual ZAP parser, network none, inert fixture only, unadopted successor."""
import hashlib
import json
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from zapv2 import ZAPv2

root=Path('/benchmarks');seen=[]
class Sink(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def sink(self):
        seen.append({'method':self.command,'path':urlsplit(self.path).path})
        length=int(self.headers.get('Content-Length','0'))
        if length:self.rfile.read(min(length,1024*1024))
        self.send_response(200);self.send_header('Content-Length','2');self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(b'{}')
    do_GET=do_POST=do_PUT=do_PATCH=do_DELETE=do_OPTIONS=do_HEAD=do_TRACE=sink
server=ThreadingHTTPServer(('127.0.0.1',18080),Sink)
threading.Thread(target=server.serve_forever,daemon=True).start()
log=(root/'local/phase4b/zap-candidate.log').open('w')
process=subprocess.Popen(['zap.sh','-daemon','-host','127.0.0.1','-port','8090','-silent','-config','api.key=offline-candidate-only'],stdout=log,stderr=subprocess.STDOUT)
zap=ZAPv2(apikey='offline-candidate-only',proxies={'http':'http://127.0.0.1:8090','https':'http://127.0.0.1:8090'})
report={'source_type':'SUCCESSOR','adopted':False,'network':'none','target_requests':0}
try:
    for _ in range(180):
        try:
            if zap.core.version=='2.17.0':break
        except Exception:pass
        time.sleep(.5)
    else:raise RuntimeError('ZAP unavailable')
    assert zap.core.set_mode('safe')=='OK'
    assert zap.pscan.disable_all_scanners()=='OK'
    assert zap.ascan.disable_all_scanners()=='OK'
    spec=json.loads((root/'phase4b/candidates/dvws-node-prepared.json').read_text())
    spec['servers']=[{'url':'http://127.0.0.1:18080/api'}]
    path=root/'local/phase4b/dvws-node-capture-only.json';path.write_text(json.dumps(spec))
    result=zap.openapi.import_file(str(path))
    report.update(status='IMPORT_RETURNED',import_result=result,
        transformation='Only server origin changed to loopback capture, retaining /api',
        transformed_spec_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        capture_requests=len(seen),operations=[{'method':m,'path':p} for m,p in sorted({(x['method'],x['path']) for x in seen})],
        active_scans=zap.ascan.scans,spider_scans=zap.spider.scans,mode=zap.core.mode)
    assert not report['active_scans'] and not report['spider_scans']
except Exception as exc:report.update(status='FAILED',error_type=type(exc).__name__,error=str(exc)[:3000])
finally:
    out=root/'phase4b/evidence/dvws-node-zap.json'
    if out.exists():raise ValueError('Refusing overwrite')
    out.write_text(json.dumps(report,indent=2)+'\n')
    try:zap.core.shutdown()
    except Exception:process.terminate()
    process.wait(timeout=20);server.shutdown();server.server_close();log.close()
print(report['status'])
