"""Conservative cross-tool candidate matching with separate reviewed annotation files."""
import copy
import csv
from pathlib import Path

from .common import NA, file_sha, require, write


def annotate(report, annotations, source_sha256):
    output = copy.deepcopy(report)
    if annotations is None: return output
    require(annotations.get('source_sha256') == source_sha256 and annotations.get('reviewer'), 'Annotations need exact source hash/reviewer')
    ids = {f['id'] for f in output['findings']}
    require(set(annotations['findings']) <= ids, 'Unknown annotated finding')
    allowed = {'category', 'endpoint', 'method', 'parameter', 'object', 'verified_defect_id'}
    for f in output['findings']:
        annotation = annotations['findings'].get(f['id'])
        if annotation:
            require(annotation.get('evidence_refs') and annotation.get('rationale'), 'Review evidence/rationale required')
            require(set(annotation['fields']) <= allowed, 'Annotation cannot overwrite scanner classification or evidence')
            f.update(annotation['fields'])
    return output


def compare(left, right):
    shared, tentative = [], []
    for z in left['findings']:
        for p in right['findings']:
            if any(z[k] != p[k] for k in ['target', 'endpoint', 'category']): continue
            if z['category'] == 'UNMAPPED': continue
            if any(z.get(k) and p.get(k) and z[k] != p[k] for k in ['method', 'parameter', 'object']): continue
            pair = {'zap': z['id'], 'penagent': p['id']}
            if (z.get('verified_defect_id') and z.get('verified_defect_id') == p.get('verified_defect_id')
                    and z.get('method') and z['method'] == p.get('method')): shared.append(pair)
            else: tentative.append(pair)
    known_z = {p['zap'] for p in shared + tentative}; known_p = {p['penagent'] for p in shared + tentative}
    zclasses = {f['category'] for f in left['findings']} - {'UNMAPPED'}
    pclasses = {f['category'] for f in right['findings']} - {'UNMAPPED'}
    zverified = {f['verified_defect_id'] for f in left['findings'] if f.get('verified_defect_id')}
    pverified = {f['verified_defect_id'] for f in right['findings'] if f.get('verified_defect_id')}
    return {'shared_verified_pairs': shared, 'tentative_pairs_requiring_review': tentative,
        'zap_only_candidates': [f['id'] for f in left['findings'] if f['id'] not in known_z],
        'penagent_only_candidates': [f['id'] for f in right['findings'] if f['id'] not in known_p],
        'verified_unique_findings': {'zap': sorted(zverified-pverified), 'penagent': sorted(pverified-zverified)}
            if zverified or pverified else NA,
        'class_overlap': sorted(zclasses & pclasses)}


def export(result, directory):
    directory = Path(directory); directory.mkdir(parents=True, exist_ok=True)
    write(directory / 'comparison.json', result)
    rows = [(key, len(value) if isinstance(value, list) else value) for key, value in result.items()]
    with (directory / 'summary.csv').open('w', encoding='utf-8', newline='') as stream:
        writer = csv.writer(stream); writer.writerow(['metric', 'value']); writer.writerows(rows)
    (directory / 'research.md').write_text('| Metric | Value |\n|---|---:|\n' +
        ''.join(f'| {k} | {v} |\n' for k, v in rows), encoding='utf-8')
