"""Fail-closed protocol validation and shared helpers; no network on import."""
import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parent
GATEWAY = 'http://scope-gateway:8088'
ZAP_IMAGE = 'ghcr.io/zaproxy/zaproxy@sha256:5ccfff9a411743ab2615136a2edd7416bec9ce41572fa94e935df38c14adb2b6'
METHODS = {'GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'}
NA = 'N/A'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(path):
    return sha(Path(path).read_bytes())


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def write(path, value):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True) + '\n', encoding='utf-8')


def now():
    return datetime.now(timezone.utc).isoformat()


def canonical_sha(value):
    return sha(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())


def require(ok, message):
    if not ok:
        raise ValueError(message)


def keys(value, expected, label):
    require(isinstance(value, dict) and set(value) == set(expected.split()), f'Invalid {label} fields')


def numeric(value, low, high, label):
    require(type(value) in {int, float} and low <= value <= high, f'Invalid {label}')


def origin(url, container=False):
    u = urlsplit(url)
    require(u.scheme == 'http' and u.hostname and not u.username and not u.password,
            'Only explicit HTTP local test origins without credentials are supported')
    port = u.port or 80
    require(port in {3000, 18001, 18002, 18003, 8088}, 'Unexpected or service port')
    allowed_host = u.hostname in ({'host.docker.internal', 'scope-gateway'} if container else {'127.0.0.1'})
    require(allowed_host, 'Unapproved hostname; numeric host loopback or fixed Docker alias required')
    return f'http://{u.hostname}:{port}'


def safe_path(path):
    require(isinstance(path, str) and path.startswith('/') and not path.startswith('//'), 'Invalid path')
    decoded = unquote(path)
    require(not any(c in path for c in ['?', '#', '\\', '\r', '\n', '\x00'])
            and not re.search(r'%2f|%5c|%25|%00', path, re.I)
            and '\\' not in decoded and not any(s in {'.', '..'} for s in decoded.split('/')),
            'Ambiguous or unsafe path encoding')
    return path


def operation_pattern(operation):
    require(isinstance(operation, str) and ' ' in operation, 'Expected METHOD /path')
    method, path = operation.split(' ', 1)
    require(method in METHODS, 'Unsupported HTTP method')
    safe_path(path)
    parts = re.split(r'(\{[A-Za-z_][A-Za-z0-9_]*\})', path)
    regex = ''.join('[A-Za-z0-9_-]+' if p.startswith('{') and p.endswith('}') else re.escape(p) for p in parts)
    require('{' not in ''.join(p for p in parts if not (p.startswith('{') and p.endswith('}'))), 'Malformed path template')
    return method, re.compile('^' + regex + '$')


def match_operation(method, path, operations):
    try:
        safe_path(path)
    except ValueError:
        return None
    matches = [op for op in operations if (lambda x: x[0] == method and x[1].fullmatch(path))(operation_pattern(op))]
    return matches[0] if len(matches) == 1 else None


def validate(m, executable=False):
    keys(m, 'schema_version experiment_id condition_id repeat target scanner scan_mode openapi '
         'allowed_operations excluded_operations reviewed_operations authentication policy budgets '
         'crawl reset_record ground_truth_version penagent_commit status started_at ended_at result_hashes', 'manifest')
    require(m['schema_version'] == 1, 'Unsupported manifest version')
    for k in ['experiment_id', 'condition_id']:
        require(isinstance(m[k], str) and re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,79}', m[k]), 'Invalid experiment identifier')
    require(type(m['repeat']) is int and m['repeat'] in {1, 2, 3}, 'Repeat must be 1, 2 or 3')
    t = m['target']; keys(t, 'id name version container container_id image_digest image_id host_origin docker_origin identity_verified', 'target')
    require(t['id'] in {'juice_shop', 'dvws', 'srebench'}, 'Unknown target, fixture and services are forbidden')
    require(isinstance(t['container'], str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]+', t['container']), 'Invalid target container')
    require(t['identity_verified'] is True, 'Unknown/unverified target identity')
    require(isinstance(t['version'], str) and bool(t['version']), 'Target version required')
    require(re.fullmatch(r'[a-f0-9]{64}', t['container_id'] or ''), 'Target container ID required')
    require(re.fullmatch(r'sha256:[a-f0-9]{64}', t['image_id'] or ''), 'Target image ID required')
    require(re.fullmatch(r'[^\s]+@sha256:[a-f0-9]{64}', t['image_digest'] or ''), 'Immutable target digest required')
    require(t['host_origin'] == origin(t['host_origin']), 'Host URL must be an origin')
    require(t['docker_origin'] == origin(t['docker_origin'], True), 'Docker URL must be an origin')
    require(urlsplit(t['docker_origin']).hostname == 'host.docker.internal', 'Upstream must use verified host mapping')
    require(urlsplit(t['host_origin']).port == urlsplit(t['docker_origin']).port, 'Host/container mapping ports differ')
    s = m['scanner']; keys(s, 'image version help_verified', 'scanner')
    require(s['image'] == ZAP_IMAGE and s['version'] == '2.17.0' and s['help_verified'] is True,
            'This protocol supports only the inspected official image/version; revalidate before changing')
    require(m['scan_mode'] in {'api', 'full_web'}, 'Passive-only scanning is forbidden')
    for field in ['allowed_operations', 'excluded_operations', 'reviewed_operations']:
        require(isinstance(m[field], list) and len(m[field]) == len(set(m[field])), 'Operations must be unique lists')
        for op in m[field]: operation_pattern(op)
    require(bool(m['allowed_operations']), 'Explicit operation allowlist required')
    require(not set(m['allowed_operations']) & set(m['excluded_operations']), 'Allowed/excluded operation overlap')
    require(set(m['allowed_operations']) <= set(m['reviewed_operations']), 'All operations, including GET, require semantic safety review')
    a = m['authentication']; keys(a, 'mode role verified verification_ref secret_file', 'authentication')
    require(a['mode'] in {'none', 'fixed_bearer'}, 'Unsupported authentication workflow')
    require(a['verified'] is True and a['role'] and a['verification_ref'], 'Authentication context must be verified')
    require((a['mode'] == 'none' and a['secret_file'] is None) or
            (a['mode'] == 'fixed_bearer' and isinstance(a['secret_file'], str)), 'Invalid auth secret reference')
    p = m['policy']; keys(p, 'name attack_strength alert_threshold enabled_active_rules reviewed disabled_rule_policy', 'policy')
    require(p['reviewed'] is True and p['attack_strength'] == 'LOW' and p['alert_threshold'] == 'MEDIUM', 'Policy review required; supported strength LOW/threshold MEDIUM')
    require(p['disabled_rule_policy'] == 'disable_all_then_enable_allowlist', 'Default-deny policy required')
    require(isinstance(p['enabled_active_rules'], list) and p['enabled_active_rules'] and
            all(type(x) is int and x in {40018, 40012, 6} for x in p['enabled_active_rules']),
            'Only reviewed in-band SQL injection, reflected XSS and path traversal rules supported')
    b = m['budgets']; keys(b, 'wall_seconds max_requests concurrency delay_ms timeout_seconds memory_mb cpus', 'budgets')
    numeric(b['wall_seconds'], 30, 3600, 'time budget'); numeric(b['max_requests'], 1, 100000, 'request budget')
    require(type(b['max_requests']) is int and b['concurrency'] == 1, 'Integer request cap/concurrency one required')
    numeric(b['delay_ms'], 100, 10000, 'delay'); numeric(b['timeout_seconds'], 1, 30, 'network timeout')
    numeric(b['memory_mb'], 512, 8192, 'memory'); numeric(b['cpus'], .1, 4, 'CPUs')
    c = m['crawl']; keys(c, 'spider_minutes max_depth modern_spider', 'crawl')
    numeric(c['spider_minutes'], 1, 10, 'spider time'); numeric(c['max_depth'], 0, 5, 'crawl depth')
    require(c['modern_spider'] is False, 'Modern/AJAX spider disabled in this restricted protocol')
    require(re.fullmatch(r'[a-f0-9]{40}', m['penagent_commit'] or ''), 'PenAgent commit required')
    require(m['status'] in {'planned', 'running', 'completed', 'failed', 'timeout', 'cancelled', 'incomplete'}, 'Invalid status')
    times = []
    for key in ['started_at', 'ended_at']:
        v = m[key]
        parsed = datetime.fromisoformat(v.replace('Z', '+00:00')) if v else None
        require(parsed is None or parsed.tzinfo is not None, 'Timestamps need timezone')
        times.append(parsed)
    require(not times[1] or (times[0] and times[1] >= times[0]), 'Invalid timestamp order')
    require(isinstance(m['result_hashes'], dict), 'Invalid result hashes')
    if m['scan_mode'] == 'api':
        keys(m['openapi'], 'source source_sha256 prepared prepared_sha256 target_version_verified', 'OpenAPI')
        o = m['openapi']
        require(o['target_version_verified'] is True, 'Spec/deployed-version provenance unverified')
        require(all(isinstance(o[k], str) and re.fullmatch(r'[a-f0-9]{64}', o[k]) for k in ['source_sha256', 'prepared_sha256']), 'OpenAPI hashes required')
        if executable:
            require(file_sha(o['source']) == o['source_sha256'] and file_sha(o['prepared']) == o['prepared_sha256'], 'Specification bytes changed')
    else:
        require(m['openapi'] is None, 'Web fallback must be labeled without an API definition')
    if executable:
        require(m['status'] == 'planned', 'Run requires a fresh planned manifest')
    if m['status'] == 'completed':
        require(all(times) and bool(m['result_hashes']), 'Completed run needs timestamps and report hashes')
    return m


def implementation_sha():
    return canonical_sha({p.relative_to(ROOT).as_posix(): file_sha(p) for p in sorted(ROOT.rglob('*.py'))
                          if not {'local', 'results', 'tests'} & set(p.relative_to(ROOT).parts)})
