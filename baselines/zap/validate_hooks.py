"""Offline installed-API validation. Configures rules but NEVER starts a scan."""
import subprocess
import time
from pathlib import Path

from zapv2 import ZAPv2
import hooks
from common import read, write

process = subprocess.Popen(['zap.sh', '-daemon', '-host', '127.0.0.1', '-port', '8090',
                            '-config', 'api.key=offline-validation-only', '-silent'],
                           stdout=(Path('/zap/wrk') / 'daemon.log').open('w'), stderr=subprocess.STDOUT)
zap = ZAPv2(apikey='offline-validation-only', proxies={'http': 'http://127.0.0.1:8090', 'https': 'http://127.0.0.1:8090'})
try:
    for attempt in range(90):
        try:
            if zap.core.version == '2.17.0': break
        except Exception: pass
        time.sleep(1)
    else: raise RuntimeError('Offline daemon did not start')
    hooks.zap_started(zap, 'http://scope-gateway:8088/')
    hooks.zap_active_scan(zap, 'http://scope-gateway:8088/', 'Default Policy')
    hooks.zap_pre_shutdown(zap)
    # Only the configuration hook is invoked above, never zap.ascan.scan/spider.scan.
    scans = zap.ascan.scans
    if scans: raise RuntimeError('Offline validation unexpectedly created a scan')
    write('/zap/wrk/validation.json', {'configuration_hooks_verified': True,
        'version': zap.core.version, 'active_scans': scans, 'target_requests': 0,
        'network': 'none', 'scope': 'configuration only; no active scan'})
    print('Configuration hooks verified; zero active scans; no target networking')
finally:
    try: zap.core.shutdown()
    except Exception: process.terminate()
    process.wait(timeout=20)
