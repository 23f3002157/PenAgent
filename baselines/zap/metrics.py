"""Observation-supported metrics; no automatic benchmark truth or confirmation."""
import statistics

from .common import NA, canonical_sha, require


def detection(findings, truth):
    output = {k: NA for k in ['true_positives', 'false_positives', 'false_negatives', 'precision', 'recall',
        'f1', 'false_discovery_proportion', 'statistical_false_positive_rate', 'verified_unique_findings']}
    if truth is None: return output
    require(truth.get('verified') is True and truth.get('complete_eligible_universe') is True
            and truth.get('source') and truth.get('reviewer') and truth.get('target_version'),
            'Detection metrics require verified complete version-specific truth and reviewer')
    universe = set(truth['vulnerability_ids'])
    labels = truth['labels']; require(set(labels) == {f['id'] for f in findings}, 'Every finding needs adjudication')
    positives, false_ids = set(), set()
    for label in labels.values():
        require(label.get('evidence_refs'), 'Every truth label needs evidence')
        if label['verdict'] == 'true_positive':
            require(label.get('vulnerability_id') in universe, 'Truth ID outside eligible universe')
            positives.add(label['vulnerability_id'])
        elif label['verdict'] == 'false_positive':
            require(label.get('adjudicated_defect_id'), 'False positives need a deduplication identity')
            false_ids.add(label['adjudicated_defect_id'])
        else: raise ValueError('Unresolved truth verdict')
    tp, fp, fn = len(positives), len(false_ids), len(universe - positives)
    output.update(true_positives=tp, false_positives=fp, false_negatives=fn,
        precision=tp/(tp+fp) if tp+fp else NA, recall=tp/(tp+fn) if tp+fn else NA,
        f1=2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else NA,
        false_discovery_proportion=fp/(tp+fp) if tp+fp else NA, verified_unique_findings=tp)
    return output


def condition(m):
    """Repeat equivalence excludes instance identity but includes target, scope and policy."""
    return canonical_sha({
        'condition_id': m['condition_id'], 'scan_mode': m['scan_mode'],
        'target': {k: m['target'][k] for k in ['id', 'version', 'image_digest']},
        'spec_sha256': m['openapi']['source_sha256'] if m['openapi'] else None,
        'operations': sorted(m['allowed_operations']), 'exclusions': sorted(m['excluded_operations']),
        'authentication': {k: m['authentication'][k] for k in ['mode', 'role']},
        'policy': m['policy'], 'budgets': m['budgets'], 'crawl': m['crawl'],
        'scanner': m['scanner'], 'penagent_commit': m['penagent_commit'],
        'ground_truth_version': m['ground_truth_version']})


def compute(report, observations, manifest, truth=None):
    findings = report['findings']; duration = observations.get('duration_seconds')
    require(duration is None or (type(duration) in {int, float} and duration >= 0), 'Invalid duration')
    requests = observations.get('request_count')
    require(requests is None or (type(requests) is int and requests >= 0), 'Invalid request count')
    if truth:
        require(truth.get('target_version') == manifest['target']['version'], 'Ground truth target version mismatch')
    result = detection(findings, truth)
    eligible = set(manifest['allowed_operations'])
    exercised = observations.get('exercised_operations')
    if exercised is not None:
        require(observations.get('traffic_source'), 'Coverage requires complete traffic source provenance')
        require(set(exercised) <= eligible, 'Observed operation outside eligible set')
    result.update(experiment_id=manifest['experiment_id'], condition_id=manifest['condition_id'],
        condition_sha256=condition(manifest), repeat=manifest['repeat'], tool=report['tool'],
        scan_mode=manifest['scan_mode'], target_version=manifest['target']['version'],
        reset_record=manifest['reset_record'], status=observations.get('status', 'unknown'),
        eligible_operations=len(eligible), observed_operations=len(set(exercised)) if exercised is not None else NA,
        coverage_percent=100*len(set(exercised))/len(eligible) if exercised is not None and eligible else NA,
        methods_exercised=sorted({op.split(' ', 1)[0] for op in exercised}) if exercised is not None else NA,
        vulnerability_classes_reported=sorted({f['category'] for f in findings if f['category'] != 'UNMAPPED'}),
        duration_seconds=duration if duration is not None else NA,
        request_count=requests if requests is not None else NA,
        request_count_definition=observations.get('request_count_definition') or NA,
        alerts=len(findings), alerts_per_minute=len(findings)*60/duration if duration and duration > 0 else NA,
        verified_findings_per_minute=result['true_positives']*60/duration
            if isinstance(result['true_positives'], int) and duration and duration > 0 else NA,
        time_to_first_verified_finding_seconds=NA,
        resource_usage=observations.get('resource_usage') or NA)
    timestamps = observations.get('verified_finding_times_seconds')
    if truth and timestamps:
        require(set(timestamps) <= {f['id'] for f in findings}, 'Unknown finding timestamp')
        verified_times = [t for fid, t in timestamps.items() if truth['labels'][fid]['verdict'] == 'true_positive']
        require(all(type(t) in {int, float} and t >= 0 for t in verified_times), 'Invalid finding timestamps')
        if verified_times: result['time_to_first_verified_finding_seconds'] = min(verified_times)
    return result


def aggregate(reports):
    require(len(reports) == 3 and {r['repeat'] for r in reports} == {1, 2, 3}, 'Exactly three distinct repeats required')
    require(all(r['status'] == 'completed' for r in reports), 'Incomplete/failed runs cannot be pooled')
    for key in ['condition_sha256', 'tool', 'scan_mode', 'request_count_definition']:
        require(len({r[key] for r in reports}) == 1, 'Inequivalent experimental conditions')
    require(all(r.get('reset_record') for r in reports)
            and len({r['reset_record'] for r in reports}) == 3, 'Three independent equivalent reset records required')
    summary = {}
    excluded = {'repeat', 'experiment_id', 'condition_id', 'reset_record', 'condition_sha256'}
    for key in reports[0]:
        if key in excluded: continue
        values = [r.get(key) for r in reports]
        if all(type(v) in {int, float} for v in values):
            summary[key] = {'mean': statistics.mean(values), 'sample_standard_deviation': statistics.stdev(values), 'n': 3}
        else: summary[key] = NA
    return {'condition_sha256': reports[0]['condition_sha256'], 'tool': reports[0]['tool'],
            'scan_mode': reports[0]['scan_mode'], 'summary': summary,
            'note': 'Reset references assert equivalence; operator must retain actual reset and initial-state evidence'}
