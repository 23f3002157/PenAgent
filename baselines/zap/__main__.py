"""CLI entry point. Dry-run is offline; run requires a separate explicit approval."""
import argparse
import json
import platform
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from . import comparison, metrics, parsers, runner, specs
from .common import GATEWAY, ROOT, canonical_sha, file_sha, now, origin, read, require, validate, write


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs): return None


def fetch(url, target_origin):
    require(origin(url) == origin(target_origin), 'Definition URL must be on the approved host target origin')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(url, timeout=5) as response:
        raw = response.read(3*1024*1024 + 1)
    require(len(raw) <= 3*1024*1024, 'Definition too large')
    spec = json.loads(raw); specs.validate_spec(spec)
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    p = sub.add_parser('validate'); p.add_argument('manifest')
    p = sub.add_parser('dry-run'); p.add_argument('manifest'); p.add_argument('--out', required=True)
    p = sub.add_parser('approve'); p.add_argument('manifest'); p.add_argument('--operator', required=True); p.add_argument('--statement', required=True); p.add_argument('--out', required=True)
    p = sub.add_parser('run'); p.add_argument('manifest'); p.add_argument('--approval', required=True); p.add_argument('--out', required=True)
    p = sub.add_parser('verify-network'); p.add_argument('manifest'); p.add_argument('--out', required=True)
    p = sub.add_parser('prepare'); p.add_argument('--source', required=True); p.add_argument('--allowed-file', required=True); p.add_argument('--out', required=True); p.add_argument('--host-origin')
    p = sub.add_parser('import-zap'); p.add_argument('report'); p.add_argument('--target', required=True); p.add_argument('--report-origin', default=GATEWAY); p.add_argument('--rule-provenance'); p.add_argument('--out', required=True)
    p = sub.add_parser('import-penagent'); p.add_argument('trace'); p.add_argument('graph'); p.add_argument('--out', required=True)
    p = sub.add_parser('collect'); p.add_argument('directory')
    p = sub.add_parser('metrics'); p.add_argument('report'); p.add_argument('observations'); p.add_argument('manifest'); p.add_argument('--truth'); p.add_argument('--out', required=True)
    p = sub.add_parser('compare'); p.add_argument('zap'); p.add_argument('penagent'); p.add_argument('--zap-annotations'); p.add_argument('--penagent-annotations'); p.add_argument('--out', required=True)
    p = sub.add_parser('aggregate'); p.add_argument('reports', nargs='+'); p.add_argument('--out', required=True)
    a = parser.parse_args()
    if a.action == 'validate':
        validate(read(a.manifest)); print('Manifest structurally valid; scanning is not authorized')
    elif a.action == 'dry-run':
        print(json.dumps(runner.plan(read(a.manifest), a.out), indent=2))
    elif a.action == 'approve':
        runner.approve(read(a.manifest), a.operator, a.statement, a.out)
        print('One-use approval recorded; no scan launched')
    elif a.action == 'run':
        result = runner.run(read(a.manifest), a.approval, a.out)
        print(json.dumps({'status': result['status'], 'out': str(Path(a.out).resolve())}))
        return 0 if result['status'] == 'completed' else 3
    elif a.action == 'verify-network':
        m = validate(read(a.manifest), executable=True)
        deadline = runner.Deadline(m['budgets']['wall_seconds'])
        runner.preflight(m, deadline=deadline)
        directory = Path(a.out).resolve(); require(not directory.exists(), 'Verification directory already exists')
        deadline.check('network verification preparation')
        directory.mkdir(parents=True); runner.stage_bundle(directory); write(directory / 'manifest.json', m)
        run_id = __import__('uuid').uuid4().hex
        resources = runner.OwnedContainers(run_id)
        control = runner.control_directory(directory, run_id)
        stop = runner.watchdog(deadline, control)
        try:
            network, gateway = runner.setup_gateway(m, directory, run_id, deadline=deadline, resources=resources, control=control)
            print(json.dumps({'isolation': 'verified', 'active_scan': False, 'network': network}))
        finally:
            runner.revoke(control); stop.set()
            write(directory / 'cleanup.json', resources.cleanup(deadline))
    elif a.action == 'prepare':
        source = a.source
        if source.startswith(('http://', 'https://')):
            require(a.host_origin is not None, '--host-origin required for URL-based spec')
            raw = fetch(source, a.host_origin)
            source_path = Path(a.out).with_suffix('.original.json')
            require(not source_path.exists(), 'Preserved original already exists')
            source_path.parent.mkdir(parents=True, exist_ok=True); source_path.write_bytes(raw)
            write(str(source_path) + '.source.json', {'url': source, 'fetched_at': now(), 'sha256': file_sha(source_path)})
            source = str(source_path)
        specs.prepare(source, read(a.allowed_file), a.out)
        print('Prepared definition and provenance; deployed-version review still required')
    elif a.action == 'import-zap':
        write(a.out, parsers.import_zap(a.report, a.target, a.report_origin, read(a.rule_provenance) if a.rule_provenance else None))
    elif a.action == 'import-penagent':
        output = parsers.import_penagent(read(a.trace), read(a.graph))
        output['source_hashes'] = {'trace': file_sha(a.trace), 'graph': file_sha(a.graph)}
        write(a.out, output)
    elif a.action == 'collect':
        directory = Path(a.directory); run = read(directory / 'run.json')
        provenance = {}
        if (directory / 'scanner-statistics.json').exists():
            statistics = read(directory / 'scanner-statistics.json')
            provenance.update({str(s['id']): 'passive_rule' for s in statistics['passive_rules']})
            provenance.update({str(s['id']): 'active_rule' for s in statistics['active_rules']})
        normalized = parsers.import_zap(directory / 'zap.json', run['target']['id'], GATEWAY, provenance)
        write(directory / 'normalized.json', normalized)
        gate = read(directory / 'gateway-summary.json') if (directory / 'gateway-summary.json').exists() else {}
        observations = {'status': run['status'], 'duration_seconds': run['runtime']['duration_seconds'],
            'request_count': gate.get('forwarded_requests'),
            'request_count_definition': 'gateway attempted upstream requests including uncertain delivery; scanner-denied traffic excluded',
            'exercised_operations': gate.get('exercised_operations') if (directory / 'traffic.jsonl').exists() else None,
            'traffic_source': file_sha(directory / 'traffic.jsonl') if (directory / 'traffic.jsonl').exists() else None}
        write(directory / 'observations.json', observations)
        write(directory / 'metrics.json', metrics.compute(normalized, observations, read(directory / 'manifest.json')))
        write(directory / 'derived-hashes.json', {name: file_sha(directory / name)
            for name in ['normalized.json', 'observations.json', 'metrics.json']})
    elif a.action == 'metrics':
        write(a.out, metrics.compute(read(a.report), read(a.observations), read(a.manifest), read(a.truth) if a.truth else None))
    elif a.action == 'compare':
        reports = []
        provenance = {}
        for label, path, annotations in [('zap', a.zap, a.zap_annotations), ('penagent', a.penagent, a.penagent_annotations)]:
            source_hash = file_sha(path)
            reports.append(comparison.annotate(read(path), read(annotations) if annotations else None, source_hash))
            provenance[label] = {'source_sha256': source_hash, 'annotations_sha256': file_sha(annotations) if annotations else None}
        comparison.export(comparison.compare(*reports), a.out)
        write(Path(a.out) / 'provenance.json', provenance)
    else:
        write(a.out, metrics.aggregate([read(p) for p in a.reports]))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
