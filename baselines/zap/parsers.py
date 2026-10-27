"""ZAP packaged JSON/XML and actual C3 evidence adapters, with local evidence refs."""
import json
import re
from pathlib import Path
from urllib.parse import urlsplit
from xml.etree import ElementTree as ET

from .common import NA, canonical_sha, file_sha, origin, read, require

RISK = {'0': 'informational', '1': 'low', '2': 'medium', '3': 'high'}
CONFIDENCE = {'0': 'false_positive', '1': 'low', '2': 'medium', '3': 'high', '4': 'confirmed'}


def category(cwe):
    value = str(cwe or '').strip()
    return 'CWE-' + value if value.isdigit() and int(value) > 0 else 'UNMAPPED'


def normalized(target, tool, endpoint, method, cls, **extra):
    f = {'target': target, 'tool': tool, 'endpoint': endpoint, 'method': method,
         'category': cls, 'parameter': None, 'object': None, 'risk': None, 'confidence': None,
         'tool_classification': None, 'independently_verified': False, 'provenance': 'unknown',
         'evidence_refs': [], 'instances': []}
    f.update(extra)
    identity = {k: f[k] for k in ['target', 'tool', 'endpoint', 'method', 'category', 'parameter', 'object']}
    identity['plugin_id'] = f.get('plugin_id')
    if cls == 'UNMAPPED': identity['classification'] = f.get('tool_classification')
    f['id'] = canonical_sha(identity)
    return f


def dedupe(findings):
    merged = {}
    for f in findings:
        if f['id'] not in merged:
            merged[f['id']] = f
            f['occurrences'] = []
        merged[f['id']]['occurrences'].append({k: f.get(k) for k in ['risk', 'confidence', 'evidence_refs', 'instances']})
    return sorted(merged.values(), key=lambda f: f['id'])


def xml_to_json(raw):
    require(b'\x00' not in raw and not re.search(br'<!ENTITY|<!DOCTYPE', raw, re.I), 'Unsafe/unsupported XML DTD or encoding')
    try: root = ET.fromstring(raw)
    except ET.ParseError as e: raise ValueError('Malformed ZAP XML') from e
    require(root.tag == 'OWASPZAPReport', 'Expected OWASPZAPReport root')
    sites = []
    for site in root.findall('site'):
        alerts = []
        for alert in site.findall('./alerts/alertitem'):
            item = {child.tag: child.text for child in alert if child.tag != 'instances'}
            item['instances'] = [{c.tag: c.text for c in instance} for instance in alert.findall('./instances/instance')]
            alerts.append(item)
        sites.append({'@name': site.get('name'), 'alerts': alerts})
    return {'@version': root.get('version'), 'site': sites}


def import_zap(path, target, report_origin, provenance=None):
    raw = Path(path).read_bytes(); raw_hash = file_sha(path)
    try: doc = xml_to_json(raw) if Path(path).suffix.lower() == '.xml' else json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as e: raise ValueError('Malformed ZAP JSON') from e
    require(isinstance(doc, dict) and isinstance(doc.get('site'), list), 'Expected packaged ZAP report site array')
    findings = []
    for si, site in enumerate(doc['site']):
        require(isinstance(site.get('alerts'), list), 'Missing alert list')
        for ai, alert in enumerate(site['alerts']):
            instances = alert.get('instances')
            require(isinstance(instances, list), 'Alert instances missing')
            for ii, instance in enumerate(instances):
                url = instance.get('uri') or instance.get('url')
                require(isinstance(url, str), 'Alert instance URL missing')
                u = urlsplit(url); expected = urlsplit(report_origin)
                require((u.scheme, u.hostname, u.port or 80) == (expected.scheme, expected.hostname, expected.port or 80), 'Out-of-origin ZAP alert')
                ref = f'sha256:{raw_hash}#site/{si}/alerts/{ai}/instances/{ii}'
                plugin = str(alert.get('pluginid') or alert.get('pluginId') or '') or None
                risk = alert.get('riskcode'); confidence = alert.get('confidence')
                risk = None if risk is None else RISK.get(str(risk), 'unknown')
                confidence = None if confidence is None else CONFIDENCE.get(str(confidence), 'unknown')
                method = instance.get('method') or None
                method = method.upper() if method else None
                cls = category(alert.get('cweid'))
                findings.append(normalized(target, 'zap', u.path or '/', method, cls,
                    name='ZAP alert ' + (plugin or 'unknown'), name_ref=ref.rsplit('/instances/', 1)[0] + '/name',
                    plugin_id=plugin, cwe_id=alert.get('cweid'), wasc_id=alert.get('wascid'),
                    parameter=instance.get('param') or None, risk=risk, confidence=confidence,
                    provenance=(provenance or {}).get(plugin, 'unknown'),
                    evidence_refs=[ref], instances=[{'raw_ref': ref, 'evidence_ref': ref + '/evidence'}],
                    description_ref=ref.rsplit('/instances/', 1)[0] + '/desc',
                    solution_ref=ref.rsplit('/instances/', 1)[0] + '/solution',
                    affected_url=report_origin.rstrip('/') + (u.path or '/')))
    return {'schema_version': 1, 'tool': 'zap', 'scanner_version': doc.get('@version'),
            'raw_sha256': raw_hash, 'findings': dedupe(findings),
            'note': 'Alerts are not independently verified; sensitive free text retained by raw reference only'}


def import_penagent(trace, graph):
    require(trace['audit']['target'] == graph['target_id'], 'Trace/graph target mismatch')
    nodes = {node['id']: node for node in graph['nodes']}; findings = []
    for entry in trace['probes']:
        interpretation = entry.get('interpretation') or {}
        result = entry.get('result') or {}
        if interpretation.get('classification') != 'CONFIRMED_VULNERABILITY': continue
        require(result.get('status') == 'executed', 'Confirmed interpretation lacks executed probe')
        node = nodes.get(result.get('op')); require(node is not None, 'Probe operation missing from graph')
        findings.append(normalized(graph['target_id'], 'penagent', node['path'], node['method'].upper(),
            'UNMAPPED', name='PenAgent recorded confirmed interpretation',
            tool_classification='CONFIRMED_VULNERABILITY', provenance='c3-execution-c4-interpretation',
            confidence=interpretation.get('confidence'),
            evidence_refs=['probe:' + result['probe_id']],
            instances=[{'probe_id': result['probe_id'], 'op': result['op']}]))
    return {'schema_version': 1, 'tool': 'penagent', 'findings': dedupe(findings),
            'note': 'Tool-confirmed is separate from ground-truth verified; CWE/parameter not inferred'}
