"""Official Docker packaged active-scanner orchestration with explicit approval."""
import json
import hashlib
import math
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

from .common import (ROOT, GATEWAY, canonical_sha, file_sha, implementation_sha, now,
                     read, require, validate, write, ZAP_IMAGE)
from .deadline import Deadline, DeadlineExpired, revoke, watchdog


def docker(args, timeout=30, *, deadline=None, cleanup=False):
    if deadline is not None:
        timeout = deadline.timeout(timeout, 'Docker ' + ' '.join(args[:2]), cleanup)
    result = subprocess.run(['docker', *args], capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('Docker operation failed: ' + ' '.join(args[:3]) + '\n' + result.stderr[-2000:])
    if deadline is not None and not cleanup:
        deadline.check('next phase after Docker ' + ' '.join(args[:2]))
    return result.stdout.strip()


def preflight(m, deadline=None):
    call = lambda args: docker(args, deadline=deadline)
    if deadline is not None: deadline.check('target preflight')
    validate(m, executable=True)
    if m['scan_mode'] == 'api':
        from .specs import transform
        expected = transform(read(m['openapi']['source']), m['allowed_operations'])
        require(expected == read(m['openapi']['prepared']), 'Prepared API semantics/operation set differ from reviewed source transformation')
    call(['version', '--format', '{{.Server.Version}}'])
    target = json.loads(call(['inspect', '--format',
        '{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"ports":{{json .NetworkSettings.Ports}}}',
        m['target']['container']]))
    require(target['running'] is True and target['id'] == m['target']['container_id']
            and target['image'] == m['target']['image_id'], 'Target identity/state changed')
    port = str(__import__('urllib.parse', fromlist=['urlsplit']).urlsplit(m['target']['host_origin']).port)
    require(any(x['HostPort'] == port and x['HostIp'] in {'127.0.0.1', '0.0.0.0'}
                for entries in target['ports'].values() for x in entries or []),
            'Expected target port mapping missing')
    digests = json.loads(call(['image', 'inspect', '--format', '{{json .RepoDigests}}', m['target']['image_id']]))
    require(m['target']['image_digest'] in digests, 'Target image digest mismatch')
    scanner = json.loads(call(['image', 'inspect', '--format', '{{json .RepoDigests}}', ZAP_IMAGE]))
    require(ZAP_IMAGE in scanner, 'Scanner image digest not present')
    if m['authentication']['mode'] == 'fixed_bearer':
        secret = Path(m['authentication']['secret_file']).resolve()
        require((ROOT / 'local').resolve() in secret.parents, 'Secrets must reside in ignored baseline local directory')
        token = secret.read_text().strip()
        require(token and '\r' not in token and '\n' not in token, 'Invalid bearer secret file')
    return target


def scanner_command(m, directory, network, name, run_id=None):
    """Argument list, never shell concatenation. No -S/passive baseline or published API."""
    script = 'zap-api-scan.py' if m['scan_mode'] == 'api' else 'zap-full-scan.py'
    target = '/zap/wrk/input.json' if m['scan_mode'] == 'api' else GATEWAY + '/'
    cmd = ['docker', 'run', '--name', name, '--network', network,
           '--label', 'penagent.zap-baseline=true', '--cap-drop', 'ALL',
           '--security-opt', 'no-new-privileges', '--memory', str(m['budgets']['memory_mb']) + 'm',
           '--cpus', str(m['budgets']['cpus']),
           '--mount', f'type=bind,source={(Path(directory)/"bundle").resolve()},target=/baseline,readonly',
           '--mount', f'type=bind,source={Path(directory).resolve()},target=/zap/wrk',
           ZAP_IMAGE, script, '-t', target,
           '-J', 'zap.json', '-r', 'zap.html', '-x', 'zap.xml',
           '-T', '2', '-z', '-silent', '--hook', '/baseline/hooks.py']
    if m['scan_mode'] == 'api': cmd += ['-f', 'openapi']
    else: cmd += ['-m', str(m['crawl']['spider_minutes'])]
    if run_id:
        cmd[2:2] = ['--label', 'penagent.zap-run-id=' + run_id]
    return cmd


def stage_bundle(directory):
    """Mount only runtime source, never the surrounding local secrets directory."""
    bundle = Path(directory) / 'bundle'; bundle.mkdir()
    for name in ['common.py', 'gateway.py', 'hooks.py']:
        shutil.copyfile(ROOT / name, bundle / name)
    write(Path(directory) / 'bundle-hashes.json', {p.name: file_sha(p) for p in bundle.iterdir()})


def plan(m, directory):
    validate(m)
    return {'active_scan': True, 'executed': False, 'approval_required': True,
            'manifest_sha256': canonical_sha(m), 'implementation_sha256': implementation_sha(),
            'scan_mode': m['scan_mode'], 'target': m['target'],
            'allowed_operations': m['allowed_operations'], 'excluded_operations': m['excluded_operations'],
            'policy': m['policy'], 'budgets': m['budgets'], 'crawl': m['crawl'],
            'authentication': {k: v for k, v in m['authentication'].items() if k != 'secret_file'},
            'gateway_origin': GATEWAY,
            'deadline': {'clock': 'monotonic', 'overall_seconds': m['budgets']['wall_seconds'],
                         'shutdown_reserve_seconds': 10,
                         'new_work_and_forwarding_cutoff_seconds': m['budgets']['wall_seconds'] - 10,
                         'expired_budget': 'refuse phase; never clamp to a positive timeout'},
            'network': 'Dedicated internal scanner network; gateway alone has upstream access; bypass checks required',
            'setup': {'gateway_entrypoint': 'python /baseline/gateway.py /zap/wrk/manifest.json /zap/wrk',
                      'gateway_networks': ['bridge (upstream)', 'new internal network (scanner)'],
                      'published_ports': [], 'scanner_api': 'container-local, no host port'},
            'command': scanner_command(m, directory, '<new-internal-network>', '<new-scanner-name>')}


def approve(m, operator, statement, destination):
    validate(m, executable=True)
    require(statement == 'I approve one bounded active scan', 'Exact explicit approval statement required')
    require(operator.strip(), 'Operator identity required')
    write(destination, {'operator': operator, 'statement': statement, 'at': now(),
          'manifest_sha256': canonical_sha(m), 'implementation_sha256': implementation_sha(),
          'runs_authorized': 1})


def verify_approval(m, approval):
    require(approval.get('statement') == 'I approve one bounded active scan' and approval.get('operator')
            and approval.get('runs_authorized') == 1
            and approval.get('manifest_sha256') == canonical_sha(m)
            and approval.get('implementation_sha256') == implementation_sha(), 'Approval absent or stale')


def classify(exit_code, timed_out, cancelled, directory):
    if timed_out: return 'timeout'
    if cancelled: return 'cancelled'
    if exit_code not in {0, 1, 2}: return 'failed'
    directory = Path(directory)
    if not all((directory / p).is_file() for p in ['active-starting.json', 'active-finished.json', 'scanner-statistics.json', 'zap.json']):
        return 'incomplete'
    statistics = read(directory / 'scanner-statistics.json')
    scans = statistics.get('active_scans', [])
    if not scans or any(str(s.get('progress')) != '100' for s in scans): return 'incomplete'
    if not (directory / 'gateway-summary.json').exists() or read(directory / 'gateway-summary.json').get('forwarded_requests', 0) == 0:
        return 'incomplete'
    return 'completed'


class OwnedContainers:
    """Only names reserved by this run AND carrying its exact UUID can be killed."""
    def __init__(self, run_id):
        self.run_id = run_id
        self.names = []

    def register(self, name):
        if name not in self.names: self.names.append(name)

    def cleanup(self, deadline):
        events = []
        # Gateway is registered first: close its transport before stopping ZAP.
        for name in self.names:
            try:
                deadline.check('container ownership check', cleanup=True)
                metadata = json.loads(docker(['inspect', '--format',
                    '{"owner":{{json (index .Config.Labels "penagent.zap-run-id")}},"running":{{json .State.Running}}}',
                    name], timeout=1, deadline=deadline, cleanup=True))
                if metadata.get('owner') != self.run_id:
                    events.append({'container': name, 'action': 'refused_owner_mismatch'})
                    continue
                if metadata.get('running'):
                    deadline.check('owned container shutdown', cleanup=True)
                    docker(['kill', name], timeout=1, deadline=deadline, cleanup=True)
                events.append({'container': name, 'action': 'killed' if metadata.get('running') else 'already_stopped'})
            except DeadlineExpired:
                events.append({'container': name, 'action': 'unconfirmed_deadline_exhausted'})
            except (RuntimeError, subprocess.SubprocessError, ValueError) as exc:
                missing = 'no such object:' in str(exc).lower() or 'no such container:' in str(exc).lower()
                events.append({'container': name, 'action': 'already_removed' if missing else 'unconfirmed', 'error': str(exc)})
        return events


def control_directory(directory, run_id):
    control = (ROOT / 'local' / 'runtime-control' / run_id).resolve()
    require(Path(directory).resolve() not in control.parents, 'Control files cannot be inside scanner output mount')
    control.mkdir(parents=True, exist_ok=False)
    return control


def arm_gateway(control, deadline):
    deadline.check('gateway clock handshake')
    anchor = read(Path(control) / 'gateway-anchor.json')
    # The gateway sample existed BEFORE this host observation. Adding the host's
    # remaining allowance to that older sample errs early, never extends the run.
    remaining = deadline.check('gateway arming')
    value = {'anchor_nonce': anchor['nonce'],
             'expires_monotonic': anchor['monotonic'] + remaining,
             'host_remaining_seconds_at_observation': remaining}
    pending = Path(control) / 'deadline.pending'
    write(pending, value)
    deadline.check('publishing gateway allowance')
    pending.replace(Path(control) / 'deadline.json')
    return value


def setup_gateway(m, directory, suffix, deadline=None, resources=None, control=None):
    deadline = deadline or Deadline(m['budgets']['wall_seconds'])
    resources = resources or OwnedContainers(suffix)
    control = control or control_directory(directory, suffix)
    network, gateway = 'pa-zap-scope-' + suffix, 'pa-zap-gate-' + suffix
    call = lambda args: docker(args, deadline=deadline)
    deadline.check('network setup')
    call(['network', 'create', '--internal', '--label', 'penagent.zap-baseline=true', network])
    cmd = ['run', '-d', '--name', gateway, '--label', 'penagent.zap-baseline=true',
           '--label', 'penagent.zap-run-id=' + resources.run_id,
           '--network', 'bridge', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
           '--memory', '256m', '--cpus', '.5',
           '--mount', f'type=bind,source={(directory/"bundle").resolve()},target=/baseline,readonly',
           '--mount', f'type=bind,source={directory.resolve()},target=/zap/wrk',
           '--mount', f'type=bind,source={control.resolve()},target=/run/penagent-control']
    if m['authentication']['mode'] == 'fixed_bearer':
        cmd += ['--mount', f"type=bind,source={Path(m['authentication']['secret_file']).resolve()},target=/run/target-token,readonly"]
    cmd += ['--entrypoint', 'python', ZAP_IMAGE, '/baseline/gateway.py', '/zap/wrk/manifest.json', '/zap/wrk',
            '--control', '/run/penagent-control']
    if m['authentication']['mode'] == 'fixed_bearer': cmd += ['--token-file', '/run/target-token']
    resources.register(gateway)
    try:
        call(cmd)
        call(['network', 'connect', '--alias', 'scope-gateway', network, gateway])
        from urllib.parse import urlsplit
        port = urlsplit(m['target']['docker_origin']).port
        ip = call(['inspect', '--format', '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}', m['target']['container']]).split()
        hosts = ['host.docker.internal', *ip]
        probe = ('import socket,json; hosts=' + repr(hosts) + '; port=' + str(port) + '; results=[]\n'
                 'for host in hosts:\n'
                 ' try:\n  c=socket.create_connection((host,port),2); c.close(); results.append(host)\n'
                 ' except OSError: pass\n'
                 'print(json.dumps(results))\n')
        def diagnostic(kind, code):
            deadline.check('network ' + kind)
            name = 'pa-zap-' + kind + '-' + suffix
            resources.register(name)
            return call(['run', '--rm', '--name', name, '--label', 'penagent.zap-run-id=' + resources.run_id,
                         '--network', network, '--entrypoint', 'python', ZAP_IMAGE, '-c', code])
        reachable = json.loads(diagnostic('probe', probe))
        require(not reachable, 'Scanner network can bypass the scope gateway; refusing scan')
        check = "import socket; c=socket.create_connection(('scope-gateway',8088),5); c.close(); print('ready')"
        require(diagnostic('ready', check) == 'ready', 'Gateway not ready')
        deadline.check('isolation record')
        write(directory / 'isolation.json', {'verified_at': now(), 'bypass_hosts_tested': hosts,
            'bypass_port': port, 'reachable_bypass_hosts': reachable, 'network': network,
            'network_internal': True, 'gateway': gateway})
        arm_gateway(control, deadline)
        return network, gateway
    except BaseException:
        revoke(control)
        # The caller owns cleanup, including a possibly timed-out Docker create.
        raise


def hash_artifacts(directory, deadline):
    output = {}
    for path in directory.iterdir():
        deadline.check('report collection')
        if not path.is_file() or path.name == 'run.json': continue
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            while True:
                deadline.check('report hashing')
                block = stream.read(1024 * 1024)
                if not block: break
                digest.update(block)
        output[path.name] = digest.hexdigest()
    return output


def run(m, approval_path, directory):
    deadline = Deadline(m['budgets']['wall_seconds'])
    validate(m, executable=True)
    deadline.check('approval validation')
    verify_approval(m, read(approval_path))
    used = Path(str(approval_path) + '.used')
    with used.open('x', encoding='utf-8') as f: f.write(now())
    directory = Path(directory).resolve()
    require(not directory.exists(), 'Result directory already exists; never overwrite runs')
    deadline.check('result directory setup')
    directory.mkdir(parents=True)
    suffix = uuid.uuid4().hex
    resources = OwnedContainers(suffix)
    control = control_directory(directory, suffix)
    stop_watchdog = watchdog(deadline, control)
    scanner_name = 'pa-zap-scanner-' + suffix
    gateway = None; process = None; exit_code = None; timed_out = cancelled = False
    record = json.loads(json.dumps(m)); record['started_at'] = now(); record['status'] = 'running'
    record['result_hashes'] = {}
    write(directory / 'run.json', record)
    try:
        deadline.check('preflight')
        preflight(m, deadline=deadline)
        deadline.check('bundle preparation')
        stage_bundle(directory)
        deadline.check('configuration records')
        write(directory / 'manifest.json', m)
        write(directory / 'approval.json', read(approval_path))
        write(directory / 'plan.json', plan(m, directory))
        if m['scan_mode'] == 'api':
            deadline.check('API preparation')
            shutil.copyfile(m['openapi']['prepared'], directory / 'input.json')
        deadline.check('gateway startup')
        network, gateway = setup_gateway(m, directory, suffix, deadline=deadline, resources=resources, control=control)
        deadline.check('scanner command preparation')
        command = scanner_command(m, directory, network, scanner_name, run_id=suffix)
        write(directory / 'command.json', command)
        with (directory / 'scanner.log').open('w', encoding='utf-8') as log:
            deadline.check('scanner launch')
            resources.register(scanner_name)
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
            exit_code = process.wait(timeout=deadline.check('scanner execution'))
        # Reports are generated within the packaged process, and are collected
        # here only while work time remains, preserving the shutdown reserve.
        deadline.check('report validation')
        record['status'] = classify(exit_code, False, False, directory)
        record['result_hashes'] = hash_artifacts(directory, deadline)
    except (DeadlineExpired, subprocess.TimeoutExpired) as exc:
        timed_out = True
        record['status'] = 'timeout'
        record['failure'] = {'type': type(exc).__name__, 'message': str(exc)}
    except KeyboardInterrupt:
        cancelled = True; record['status'] = 'cancelled'
    except (ValueError, RuntimeError, subprocess.SubprocessError, OSError) as exc:
        record['status'] = 'failed'
        record['failure'] = {'type': type(exc).__name__, 'message': str(exc)}
    finally:
        # Revoke first. Scanner shutdown can never extend gateway permission.
        revoke(control)
        stop_watchdog.set()
        cleanup = resources.cleanup(deadline)
        if record['status'] == 'completed' and any(e['action'].startswith(('unconfirmed', 'refused')) for e in cleanup):
            record['status'] = 'incomplete'
        if process is not None and process.poll() is None:
            process.kill()  # Only the local Docker client created by this run.
            try:
                process.wait(timeout=deadline.timeout(1, 'Docker client reap', cleanup=True))
            except (DeadlineExpired, subprocess.TimeoutExpired):
                cleanup.append({'process': 'docker client', 'action': 'reap_unconfirmed'})
        elapsed = deadline.clock() - deadline.started
        if elapsed >= m['budgets']['wall_seconds']:
            timed_out = True; record['status'] = 'timeout'
        record['ended_at'] = now()
        record['runtime'] = {'duration_seconds': elapsed, 'packaged_exit_code': exit_code,
            'timeout': timed_out, 'cancelled': cancelled, 'scanner_container': scanner_name,
            'gateway_container': gateway, 'run_id': suffix, 'control_directory': str(control),
            'shutdown_reserve_seconds': deadline.reserve, 'overall_deadline_monotonic': deadline.ends,
            'work_cutoff_monotonic': deadline.ends - deadline.reserve,
            'overrun_seconds': max(0, elapsed - m['budgets']['wall_seconds']), 'cleanup': cleanup,
            'exit_interpretation': {0: 'no FAIL/WARN', 1: 'FAIL alerts', 2: 'WARN alerts', 3: 'tool error'}.get(exit_code, 'not completed')}
        # Essential final evidence is saved even if an OS/daemon call overran its
        # timeout. This is local best-effort I/O, never permission for another phase.
        write(directory / 'run.json', record)
    return record
