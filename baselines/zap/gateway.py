"""Restricted HTTP reverse gateway. Only this process can reach the target.

Not a scanner. Denied requests are never forwarded; logs omit secrets and queries.
"""
import argparse
import http.client
import json
import math
import socket
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

try:
    from .common import GATEWAY, match_operation, now, read, sha, validate, write
except ImportError:
    from common import GATEWAY, match_operation, now, read, sha, validate, write

HOP = {'connection', 'proxy-connection', 'keep-alive', 'transfer-encoding', 'te', 'trailer',
       'upgrade', 'proxy-authorization', 'proxy-authenticate', 'host', 'content-length', 'expect'}


class Gate:
    def __init__(self, manifest, directory, token=None, clock=None, control=None):
        self.m = validate(manifest)
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.token = token
        self.clock = clock or time.monotonic
        self.control = Path(control) if control is not None else None
        self.anchor = self.clock()
        self.nonce = uuid.uuid4().hex
        # Production is disarmed until the host supplies its remaining allowance.
        # In-process unit fixtures can still use their injected local clock alone.
        self.deadline = None if self.control is not None else self.anchor + manifest['budgets']['wall_seconds']
        self.closed = threading.Event()
        self.active_connection = None
        if self.control is not None:
            self.control.mkdir(parents=True, exist_ok=True)
            write(self.control / 'gateway-anchor.json', {'nonce': self.nonce, 'monotonic': self.anchor})
        self.last = 0
        self.sent = 0
        self.denied = 0
        self.exercised = set()
        self.lock = threading.Lock()

    def remaining(self):
        if self.closed.is_set(): return 0
        if self.control is not None:
            if (self.control / 'forwarding.closed').exists():
                self.seal(); return 0
            if self.deadline is None:
                try:
                    allowance = read(self.control / 'deadline.json')
                    expiry = allowance['expires_monotonic']
                    if (allowance['anchor_nonce'] != self.nonce or type(expiry) not in {int, float}
                            or not math.isfinite(expiry)):
                        return 0
                    # Cache once. Neither a later file write nor scanner shutdown
                    # may extend this gateway's forwarding permission.
                    self.deadline = min(expiry, self.anchor + self.m['budgets']['wall_seconds'])
                except (OSError, ValueError, KeyError, TypeError): return 0
        if self.deadline is None: return 0
        remaining = self.deadline - self.clock()
        if remaining <= 0:
            self.seal(); return 0
        return remaining

    def seal(self):
        self.closed.set()
        conn = self.active_connection
        if conn is not None:
            try:
                if conn.sock is not None: conn.sock.shutdown(socket.SHUT_RDWR)
            except (OSError, AttributeError): pass
            conn.close()

    def watch_deadline(self):
        def watch():
            while not self.closed.wait(.05):
                self.remaining()
        thread = threading.Thread(target=watch, name='gateway-deadline', daemon=True)
        thread.start()
        return thread

    def permitted(self, method, target):
        u = urlsplit(target)
        if u.scheme or u.netloc or u.fragment or '\r' in target or '\n' in target:
            return None
        if any(match_operation(method, u.path, [op]) for op in self.m['excluded_operations']):
            return None
        return match_operation(method, u.path, self.m['allowed_operations'])

    def event(self, data):
        with (self.directory / 'traffic.jsonl').open('a', encoding='utf-8') as stream:
            stream.write(json.dumps({'at': now(), **data}) + '\n')

    def snapshot(self):
        write(self.directory / 'gateway-summary.json', {
            'forwarded_requests': self.sent, 'denied_requests': self.denied,
            'exercised_operations': sorted(self.exercised),
            'request_budget_enforcement': 'gateway forwarded-request cap; attempts denied after cap',
            'deadline_enforcement': 'host remaining-time handshake, independent monotonic expiry and permanent revocation',
            'deadline_monotonic': self.deadline, 'forwarding_closed': self.closed.is_set()})


def handler(gate):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.0'

        def log_message(self, *_):
            pass

        def do_any(self):
            # Serialize forwarding: one in flight and minimum inter-request delay.
            with gate.lock:
                op = gate.permitted(self.command, self.path)
                def deny(reason):
                    gate.denied += 1
                    gate.event({'allowed': False, 'method': self.command, 'reason': reason,
                                'request_target_sha256': sha(self.path.encode())})
                    gate.snapshot()
                    self.send_error(403, 'Blocked by experiment scope or budget')
                if (not op or gate.remaining() <= 0
                        or gate.sent >= gate.m['budgets']['max_requests']):
                    deny('scope_or_budget_or_deadline')
                    return
                if self.headers.get('Transfer-Encoding') or len(self.headers.get_all('Content-Length', [])) > 1:
                    self.send_error(400); return
                try:
                    length = int(self.headers.get('Content-Length', '0'))
                except ValueError:
                    self.send_error(400); return
                if not 0 <= length <= 1024 * 1024:
                    self.send_error(413); return
                remaining = gate.remaining()
                if remaining <= 0: deny('deadline_before_body'); return
                self.connection.settimeout(min(gate.m['budgets']['timeout_seconds'], remaining))
                try:
                    body = self.rfile.read(length) if length else None
                except OSError:
                    self.send_error(408); return
                pause = gate.m['budgets']['delay_ms']/1000 - (gate.clock() - gate.last)
                if pause > 0:
                    time.sleep(min(pause, gate.remaining()))
                remaining = gate.remaining()
                if remaining <= 0:
                    deny('deadline_after_pacing'); return
                upstream = urlsplit(gate.m['target']['docker_origin'])
                headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP | {'authorization', 'cookie'}}
                if gate.token:
                    headers['Authorization'] = 'Bearer ' + gate.token
                conn = http.client.HTTPConnection(upstream.hostname, upstream.port,
                                                  timeout=min(gate.m['budgets']['timeout_seconds'], remaining))
                gate.active_connection = conn
                status = None
                admitted = False
                try:
                    conn.connect()
                    # DNS/connect may have used the remaining allowance. Never
                    # initiate an HTTP request after it, even during shutdown.
                    remaining = gate.remaining()
                    if remaining <= 0:
                        deny('deadline_after_connect'); return
                    conn.timeout = min(gate.m['budgets']['timeout_seconds'], remaining)
                    if conn.sock is not None: conn.sock.settimeout(conn.timeout)
                    gate.last = gate.clock(); gate.sent += 1; admitted = True
                    conn.request(self.command, self.path, body=body, headers=headers)
                    response = conn.getresponse(); status = response.status
                    payload = response.read(8*1024*1024 + 1)
                    if len(payload) > 8*1024*1024:
                        raise ValueError('Response exceeds research capture limit')
                    # Preserve target headers; do not introduce Python server fingerprints.
                    self.send_response_only(status)
                    for k, v in response.getheaders():
                        if k.lower() in HOP:
                            continue
                        if k.lower() == 'location':
                            dest = urlsplit(v)
                            if dest.netloc:
                                if dest.hostname not in {'host.docker.internal', '127.0.0.1', 'localhost'} or dest.port not in {upstream.port, None}:
                                    continue
                                v = GATEWAY + (dest.path or '/') + ('?' + dest.query if dest.query else '')
                        self.send_header(k, v)
                    self.send_header('Content-Length', str(len(payload))); self.end_headers()
                    if self.command != 'HEAD': self.wfile.write(payload)
                    gate.exercised.add(op)
                except (OSError, ValueError, http.client.HTTPException):
                    try: self.send_error(502, 'Target request failed')
                    except OSError: pass
                finally:
                    conn.close()
                    gate.active_connection = None
                    if admitted:
                        gate.event({'allowed': True, 'operation': op, 'status': status,
                                    'request_target_sha256': sha(self.path.encode())})
                    gate.snapshot()

        do_GET = do_HEAD = do_OPTIONS = do_POST = do_PUT = do_PATCH = do_DELETE = do_TRACE = do_CONNECT = do_any
    return Handler


def main():
    p = argparse.ArgumentParser(); p.add_argument('manifest'); p.add_argument('output'); p.add_argument('--token-file')
    p.add_argument('--control', required=True)
    a = p.parse_args(); m = read(a.manifest)
    token = Path(a.token_file).read_text().strip() if a.token_file else None
    if token and any(x in token for x in ['\r', '\n']):
        raise ValueError('Invalid bearer token file')
    gate = Gate(m, a.output, token, control=a.control)
    gate.snapshot()
    gate.watch_deadline()
    ThreadingHTTPServer(('0.0.0.0', 8088), handler(gate)).serve_forever()


if __name__ == '__main__': main()
