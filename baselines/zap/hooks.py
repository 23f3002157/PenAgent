"""Documented packaged-scan hooks; mounted only inside the pinned official image."""
import json
import math
import sys
from pathlib import Path

sys.path.insert(0, '/baseline')
try:
    from .common import GATEWAY, operation_pattern, read, validate, write
except ImportError:
    from common import GATEWAY, operation_pattern, read, validate, write

WORK = Path('/zap/wrk')


def check(result):
    if result != 'OK':
        raise RuntimeError('ZAP rejected a required configuration action')


def zap_started(zap, target):
    m = validate(read(WORK / 'manifest.json'))
    context = 'penagent-reviewed-scope'
    cid = zap.context.new_context(context)
    if not str(cid).isdigit(): raise RuntimeError('Failed to create context')
    # Allow recursion from the origin root; gateway still denies root unless eligible.
    check(zap.context.include_in_context(context, r'http://scope-gateway:8088/?'))
    # Context regex limits URLs; method enforcement is independently at the gateway.
    for op in m['allowed_operations']:
        regex = operation_pattern(op)[1].pattern[1:-1]
        check(zap.context.include_in_context(context, r'http://scope-gateway:8088' + regex + r'(\?.*)?'))
    check(zap.context.set_context_in_scope(context, True))
    check(zap.core.set_mode('protect'))
    check(zap.core.set_option_timeout_in_secs(m['budgets']['timeout_seconds']))
    check(zap.ascan.set_option_thread_per_host(1))
    check(zap.ascan.set_option_host_per_scan(1))
    check(zap.ascan.set_option_delay_in_ms(m['budgets']['delay_ms']))
    check(zap.ascan.set_option_max_scan_duration_in_mins(math.ceil(m['budgets']['wall_seconds']/60)))
    check(zap.spider.set_option_max_depth(m['crawl']['max_depth']))
    write(WORK / 'hook-started.json', {'context_id': cid, 'mode': zap.core.mode,
                                     'version': zap.core.version, 'policy_configuration': 'pending'})
    return zap, target


def zap_active_scan(zap, target, policy):
    m = validate(read(WORK / 'manifest.json'))
    check(zap.ascan.disable_all_scanners(scanpolicyname=policy))
    available = {int(s['id']) for s in zap.ascan.scanners(policy)}
    wanted = m['policy']['enabled_active_rules']
    if not set(wanted) <= available: raise RuntimeError('A required active rule is unavailable')
    check(zap.ascan.enable_scanners(','.join(map(str, wanted)), scanpolicyname=policy))
    for rule in wanted:
        check(zap.ascan.set_scanner_attack_strength(str(rule), m['policy']['attack_strength'], scanpolicyname=policy))
        check(zap.ascan.set_scanner_alert_threshold(str(rule), m['policy']['alert_threshold'], scanpolicyname=policy))
    effective = zap.ascan.scanners(policy)
    enabled = {int(s['id']) for s in effective if str(s.get('enabled')).lower() == 'true'}
    if enabled != set(wanted) or zap.core.mode != 'protect':
        raise RuntimeError('Effective active policy/scope verification failed')
    write(WORK / 'active-starting.json', {'active_scan_requested': True, 'policy': policy,
        'rules': effective, 'version': zap.core.version, 'mode': zap.core.mode})
    return zap, target, policy


def zap_active_scan_wrap(unused):
    # The packaged helper returns only after its scan's progress reaches 100.
    write(WORK / 'active-finished.json', {'packaged_active_helper_returned': True})
    return unused


def zap_pre_shutdown(zap):
    write(WORK / 'scanner-statistics.json', {
        'version': zap.core.version, 'active_scans': zap.ascan.scans,
        'discovered_urls': zap.core.urls(), 'message_count': zap.core.number_of_messages(),
        'active_rules': zap.ascan.scanners(), 'passive_rules': zap.pscan.scanners})
    return (zap,)
