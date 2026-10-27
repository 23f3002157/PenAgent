"""Conservative JSON OpenAPI 3 preparation without invented endpoints."""
import copy
from pathlib import Path
from urllib.parse import urlsplit

from .common import GATEWAY, METHODS, file_sha, read, require, safe_path, write


def validate_spec(spec):
    require(isinstance(spec, dict) and str(spec.get('openapi', '')).startswith(('3.0.', '3.1.')), 'Only JSON OpenAPI 3.0/3.1 supported by this preparer')
    require(isinstance(spec.get('info'), dict) and spec['info'].get('title') and spec['info'].get('version'), 'OpenAPI info required')
    require(isinstance(spec.get('paths'), dict) and spec['paths'], 'OpenAPI paths required')
    def walk(x):
        if isinstance(x, dict):
            require(not set(x) & {'callbacks', 'webhooks'}, 'Callbacks/webhooks need separate review')
            if '$ref' in x:
                ref = x['$ref']; require(isinstance(ref, str) and ref.startswith('#/'), 'Bundle external references first')
                node = spec
                try:
                    for key in ref[2:].split('/'): node = node[key.replace('~1', '/').replace('~0', '~')]
                except (KeyError, TypeError): raise ValueError('Unresolved schema reference') from None
            for v in x.values(): walk(v)
        elif isinstance(x, list):
            for v in x: walk(v)
    walk(spec)
    servers = spec.get('servers')
    require(isinstance(servers, list) and len(servers) == 1 and isinstance(servers[0].get('url'), str), 'One explicit source server required')
    u = urlsplit(servers[0]['url'])
    require(u.scheme in {'http', 'https'} and u.hostname and not u.username and not u.password and not u.query
            and '{' not in servers[0]['url'], 'Source server must have a concrete absolute URL')
    base = u.path.rstrip('/')
    operations = set()
    for path, item in spec['paths'].items():
        safe_path(path); require(isinstance(item, dict) and not {'servers', '$ref'} & set(item), 'Unsupported path server/ref override')
        for method, operation in item.items():
            if method.upper() not in METHODS: continue
            require(isinstance(operation, dict) and 'servers' not in operation and operation.get('responses'), 'Invalid operation or server override')
            for param in item.get('parameters', []) + operation.get('parameters', []):
                if '$ref' in param: continue
                require(param.get('in') in {'path', 'query', 'header', 'cookie'} and param.get('name'), 'Invalid parameter')
                require(param.get('schema') is not None or param.get('content') is not None, 'Parameter schema missing')
                if param['in'] == 'path': require(param.get('required') is True, 'Path parameters must be required')
            body = operation.get('requestBody')
            if body and '$ref' not in body: require(bool(body.get('content')), 'Request body content missing')
            operations.add(method.upper() + ' ' + base + path)
    return operations, base


def transform(source, allowed):
    operations, base = validate_spec(source)
    require(set(allowed) and set(allowed) <= operations, 'Allowed operations absent from source spec')
    result = copy.deepcopy(source)
    result['paths'] = {}
    for path, item in source['paths'].items():
        selected = {k: v for k, v in item.items() if k.upper() not in METHODS}
        for method, op in item.items():
            if method.upper() in METHODS and method.upper() + ' ' + base + path in allowed:
                selected[method] = copy.deepcopy(op)
        if any(k.upper() in METHODS for k in selected): result['paths'][path] = selected
    result['servers'] = [{'url': GATEWAY + base}]
    return result


def prepare(source_path, allowed, destination):
    source = read(source_path)
    result = transform(source, allowed)
    write(destination, result)
    write(str(destination) + '.provenance.json', {'original_sha256': file_sha(source_path),
        'prepared_sha256': file_sha(destination), 'original_server': source['servers'][0],
        'prepared_server': result['servers'][0], 'allowed_operations': allowed,
        'transformations': ['Replace server origin only, preserve base path', 'Retain reviewed operation subset'],
        'validation': 'Structural checks only; full OAS validation and deployed-version review still required'})
    return result
