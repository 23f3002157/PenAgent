"""Connectivity-only gateway. Exact benign GET examples; never a scan gateway.

No arbitrary queries, credentials, request bodies, redirects or alternate origins.
The existing ZAP baseline and its approved root-only policy are not changed.
"""
import hashlib
import http.client
import ipaddress
import json
import math
import re
import socket
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

REQUESTS=(
    '/rest/admin/application-version', '/rest/languages',
    '/rest/products/search?q=apple', '/rest/products/1/reviews', '/rest/country-mapping')

class Gate:
    def __init__(self, policy, directory, clock=time.monotonic):
        def require(ok,message):
            if not ok:raise ValueError(message)
        require(set(policy)=={'target_ip','target_port','max_requests','wall_seconds','target_container_id','target_image_id'},'Invalid policy fields')
        ip=ipaddress.ip_address(policy['target_ip'])
        require(isinstance(ip,ipaddress.IPv4Address) and ip.is_private and not ip.is_loopback and not ip.is_link_local,'Invalid private target IP')
        require(policy['target_port']==3000 and policy['max_requests']==20 and policy['wall_seconds']==180,'Unapproved connectivity budgets or port')
        require(re.fullmatch(r'[a-f0-9]{64}',policy['target_container_id']) and re.fullmatch(r'sha256:[a-f0-9]{64}',policy['target_image_id']),'Invalid target identity')
        self.policy=policy;self.directory=Path(directory);self.clock=clock
        self.directory.mkdir(parents=True,exist_ok=True)
        self.anchor=clock();self.nonce=uuid.uuid4().hex;self.deadline=None
        self.closed=threading.Event();self.connection=None;self.lock=threading.Lock()
        self.forwarded=0;self.blocked=0
        self.write('anchor.json',{'nonce':self.nonce,'monotonic':self.anchor})
    def write(self,name,value):
        p=self.directory/name
        pending=p.with_suffix(p.suffix+'.pending')
        pending.write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8');pending.replace(p)
    def remaining(self):
        if self.closed.is_set():return 0
        if (self.directory/'closed').exists():self.seal();return 0
        if self.deadline is None:
            try:
                value=json.loads((self.directory/'armed.json').read_text())
                expires=value['expires_gateway_monotonic']
                if value['nonce']!=self.nonce or type(expires) not in {int,float} or not math.isfinite(expires):return 0
                self.deadline=min(expires,self.anchor+self.policy['wall_seconds'])
            except (OSError,ValueError,KeyError,TypeError):return 0
        remaining=self.deadline-self.clock()
        if remaining<=0:self.seal();return 0
        return remaining
    def seal(self):
        self.closed.set()
        if self.connection:
            try:
                if self.connection.sock:self.connection.sock.shutdown(socket.SHUT_RDWR)
            except OSError:pass
            self.connection.close()
    def permitted(self,method,path,headers=None):
        headers=headers or {}
        return method=='GET' and path in REQUESTS and not any(
            k.lower() in {'authorization','cookie','transfer-encoding','content-length'} for k in headers)
    def event(self,record):
        with (self.directory/'traffic.jsonl').open('a',encoding='utf-8') as stream:
            stream.write(json.dumps(record)+'\n')
        self.write('summary.json',{'forwarded':self.forwarded,'blocked':self.blocked,
            'closed':self.closed.is_set(),'deadline_monotonic':self.deadline})

def handler(gate):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def request(self):
            with gate.lock:
                allowed=gate.permitted(self.command,self.path,self.headers)
                if not allowed or gate.remaining()<=0 or gate.forwarded>=gate.policy['max_requests']:
                    gate.blocked+=1;gate.event({'allowed':False,'method':self.command,
                        'request_hash':hashlib.sha256(self.path.encode()).hexdigest()})
                    self.send_error(403);return
                conn=http.client.HTTPConnection(gate.policy['target_ip'],gate.policy['target_port'],timeout=min(5,gate.remaining()))
                gate.connection=conn
                try:
                    conn.connect()
                    remaining=gate.remaining()
                    if remaining<=0:self.send_error(403);return
                    conn.sock.settimeout(min(5,remaining))
                    gate.forwarded+=1
                    conn.request('GET',self.path,headers={'Accept':'application/json','User-Agent':'PenAgent-Phase4B-connectivity-only'})
                    response=conn.getresponse();body=response.read(2*1024*1024+1)
                    if len(body)>2*1024*1024:raise ValueError('Oversized response')
                    self.send_response_only(response.status)
                    self.send_header('Content-Type',response.getheader('Content-Type','application/octet-stream'))
                    self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
                    gate.event({'allowed':True,'method':'GET','path':self.path,'status':response.status,
                        'response_sha256':hashlib.sha256(body).hexdigest(),'upstream_ip':gate.policy['target_ip']})
                except (OSError,ValueError,http.client.HTTPException) as exc:
                    gate.event({'allowed':True,'error':type(exc).__name__})
                    try:self.send_error(502)
                    except OSError:pass
                finally:conn.close();gate.connection=None
        do_GET=do_POST=do_PUT=do_PATCH=do_DELETE=do_HEAD=do_OPTIONS=do_TRACE=do_CONNECT=request
    return Handler

def main():
    directory=Path('/phase4b')
    gate=Gate(json.loads((directory/'policy.json').read_text()),directory)
    def watch():
        while not gate.closed.wait(.05):gate.remaining()
    threading.Thread(target=watch,daemon=True).start()
    ThreadingHTTPServer(('0.0.0.0',8088),handler(gate)).serve_forever()

if __name__=='__main__':main()
