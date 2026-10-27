"""All reports, truth and approvals here are SYNTHETIC TOOL TEST DATA only."""
import contextlib
import copy
import io
import json
import tempfile
import socket
import subprocess
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from unittest.mock import Mock
from http.server import ThreadingHTTPServer

from baselines.zap import common as c, comparison, gateway, metrics, parsers, runner, specs
from baselines.zap.__main__ import main


class Tests(unittest.TestCase):
    def setUp(self):
        (c.ROOT / 'local').mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix='synthetic-tests-', dir=c.ROOT / 'local')
        self.addCleanup(self.temp.cleanup); self.path = Path(self.temp.name)
        self.m = c.read(c.ROOT / 'config/juice-smoke.json')
        self.m['experiment_id'] = 'synthetic-unit-test'

    def report(self, alert=None):
        return {'@version': 'SYNTHETIC', 'site': [{'@name': c.GATEWAY, 'alerts': [alert or {
            'pluginid': '40018', 'name': 'SQL injection SECRET', 'cweid': '89', 'wascid': '19',
            'riskcode': '3', 'confidence': '2', 'desc': 'SECRET', 'solution': 'SECRET',
            'instances': [{'uri': c.GATEWAY + '/?token=SECRET', 'method': 'GET', 'param': 'id', 'evidence': 'SECRET'}]}]}]}

    def parse(self, doc):
        p = self.path / 'synthetic.json'; c.write(p, doc)
        return parsers.import_zap(p, 'synthetic-target', c.GATEWAY)

    def finding(self, tool='zap', **extra):
        return parsers.normalized('synthetic-target', tool, '/', 'GET', 'CWE-89',
                                  evidence_refs=['synthetic-evidence'], **extra)

    def test_manifest(self): c.validate(self.m)

    def test_unknown_fields(self):
        self.m['automatic_scan'] = True
        with self.assertRaises(ValueError): c.validate(self.m)

    def test_identity(self):
        for key, value in [('id', 'fixture'), ('identity_verified', False), ('version', None), ('container_id', 'unknown')]:
            m = copy.deepcopy(self.m); m['target'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): c.validate(m)

    def test_forbidden_origins(self):
        for url in ['http://example.com:3000', 'http://127.0.0.1:9001', 'http://localhost:3000',
                    'http://secret@127.0.0.1:3000', 'http://127.0.0.1:4444']:
            with self.subTest(url=url), self.assertRaises(ValueError): c.origin(url)

    def test_unreviewed_get(self):
        self.m['reviewed_operations'] = []
        with self.assertRaises(ValueError): c.validate(self.m)

    def test_overlap(self):
        self.m['excluded_operations'].append('GET /')
        with self.assertRaises(ValueError): c.validate(self.m)

    def test_unverified_auth(self):
        self.m['authentication']['verified'] = False
        with self.assertRaises(ValueError): c.validate(self.m)

    def test_invalid_rules(self):
        self.m['policy']['enabled_active_rules'] = [999999]
        with self.assertRaises(ValueError): c.validate(self.m)

    def test_passive_mode_rejected(self):
        self.m['scan_mode'] = 'baseline'
        with self.assertRaises(ValueError): c.validate(self.m)

    def test_timestamps(self):
        self.m.update(started_at='2026-10-25T10:00:00Z', ended_at='2026-10-25T09:00:00Z')
        with self.assertRaises(ValueError): c.validate(self.m)

    def test_completed_requires_evidence(self):
        self.m['status'] = 'completed'
        with self.assertRaises(ValueError): c.validate(self.m)

    def test_scope_templates(self):
        self.assertEqual(c.match_operation('GET', '/users/123', ['GET /users/{id}']), 'GET /users/{id}')
        for path in ['/users/%2fadmin', '/users/../admin', '//evil', '/users/%252fadmin', '/users/a\\b']:
            self.assertIsNone(c.match_operation('GET', path, ['GET /users/{id}']))

    def test_gateway_method_scope(self):
        g = gateway.Gate(self.m, self.path)
        self.assertEqual(g.permitted('GET', '/?q=synthetic'), 'GET /')
        for method, path in [('POST', '/'), ('GET', '/admin'), ('GET', 'http://evil/'), ('CONNECT', '/')]:
            self.assertIsNone(g.permitted(method, path))

    def test_command_active_and_official(self):
        command = runner.scanner_command(self.m, self.path, 'synthetic-network', 'synthetic-container')
        self.assertIn('zap-full-scan.py', command); self.assertIn(c.ZAP_IMAGE, command)
        for flag in ['-S', 'zap-baseline.py', '-p', '--privileged', '--network=host']:
            self.assertNotIn(flag, command)
        self.assertIn('-J', command); self.assertIn('--hook', command)

    def test_api_command_flags(self):
        self.m['scan_mode'] = 'api'
        command = runner.scanner_command(self.m, self.path, 'synthetic-network', 'synthetic-container')
        self.assertIn('zap-api-scan.py', command); self.assertIn('openapi', command)
        self.assertNotIn('-m', command); self.assertNotIn('-S', command)

    def test_dry_run_has_no_process_or_files(self):
        with patch('subprocess.run', side_effect=AssertionError('dry-run called a process')):
            with patch('sys.argv', ['zap', 'dry-run', str(c.ROOT / 'config/juice-smoke.json'), '--out', str(self.path/'absent')]):
                with contextlib.redirect_stdout(io.StringIO()) as output: main()
        self.assertFalse((self.path/'absent').exists()); self.assertFalse(json.loads(output.getvalue())['executed'])

    def test_approval_not_implied_by_plan(self):
        with self.assertRaises(ValueError): runner.verify_approval(self.m, {})
        with self.assertRaises(ValueError): runner.approve(self.m, 'synthetic operator', 'yes', self.path/'approval.json')

    def test_stale_approval(self):
        approval = self.path/'synthetic-approval.json'
        runner.approve(self.m, 'SYNTHETIC TEST OPERATOR', 'I approve one bounded active scan', approval)
        runner.verify_approval(self.m, c.read(approval))
        self.m['budgets']['max_requests'] += 1
        with self.assertRaises(ValueError): runner.verify_approval(self.m, c.read(approval))

    def test_target_runtime_identity(self):
        with patch.object(runner, 'docker', side_effect=['29.4.3', json.dumps({'running': True, 'id': 'wrong', 'image': 'wrong', 'ports': {}})]):
            with self.assertRaises(ValueError): runner.preflight(self.m)

    def spec(self):
        return {'openapi': '3.0.3', 'info': {'title': 'SYNTHETIC', 'version': 'test'},
            'servers': [{'url': 'http://original.invalid/v1'}], 'paths': {'/items': {
                'get': {'responses': {'200': {'description': 'test'}}},
                'delete': {'responses': {'204': {'description': 'test'}}}}}}

    def test_openapi_semantics(self):
        source = self.path/'synthetic-source.json'; c.write(source, self.spec())
        result = specs.prepare(source, ['GET /v1/items'], self.path/'prepared.json')
        self.assertEqual(result['servers'], [{'url': c.GATEWAY+'/v1'}])
        self.assertNotIn('delete', result['paths']['/items'])
        self.assertEqual(c.read(source), self.spec())
        self.assertEqual(result['paths']['/items']['get'], self.spec()['paths']['/items']['get'])

    def test_openapi_bad_reference(self):
        s = self.spec(); s['components'] = {'schemas': {'x': {'$ref': 'http://external.invalid/spec'}}}
        with self.assertRaises(ValueError): specs.validate_spec(s)
        s['components']['schemas']['x']['$ref'] = '#/missing'
        with self.assertRaises(ValueError): specs.validate_spec(s)

    def test_openapi_overrides(self):
        s = self.spec(); s['paths']['/items']['servers'] = [{'url': 'http://other.invalid'}]
        with self.assertRaises(ValueError): specs.validate_spec(s)

    def test_invalid_path_parameter(self):
        s = self.spec(); s['paths']['/items']['get']['parameters'] = [{'in': 'path', 'name': 'id', 'schema': {'type': 'string'}}]
        with self.assertRaises(ValueError): specs.validate_spec(s)

    def test_unknown_operations_not_fabricated(self):
        source = self.path/'source.json'; c.write(source, self.spec())
        with self.assertRaises(ValueError): specs.prepare(source, ['GET /invented'], self.path/'prepared.json')

    def test_json_parse_and_redaction(self):
        result = self.parse(self.report()); f = result['findings'][0]
        self.assertEqual((f['category'], f['method'], f['parameter'], f['risk'], f['confidence']), ('CWE-89','GET','id','high','medium'))
        self.assertNotIn('SECRET', json.dumps(result))
        self.assertFalse(f['independently_verified']); self.assertEqual(f['provenance'], 'unknown')

    def test_provenance_explicit_only(self):
        source = self.path/'report.json'; c.write(source, self.report())
        f = parsers.import_zap(source, 'synthetic-target', c.GATEWAY, {'40018':'active_rule'})['findings'][0]
        self.assertEqual(f['provenance'], 'active_rule')

    def test_empty_report(self):
        self.assertEqual(self.parse({'site': []})['findings'], [])

    def test_malformed_and_missing(self):
        with self.assertRaises(FileNotFoundError): parsers.import_zap(self.path/'missing', 'synthetic', c.GATEWAY)
        p=self.path/'bad.json'; p.write_text('not json')
        with self.assertRaises(ValueError): parsers.import_zap(p, 'synthetic', c.GATEWAY)
        with self.assertRaises(ValueError): self.parse({})

    def test_xml(self):
        p=self.path/'synthetic.xml'; p.write_text('<OWASPZAPReport version="test"><site name="'+c.GATEWAY+'"><alerts><alertitem><pluginid>40018</pluginid><cweid>89</cweid><instances><instance><uri>'+c.GATEWAY+'/</uri><method>GET</method></instance></instances></alertitem></alerts></site></OWASPZAPReport>')
        f=parsers.import_zap(p,'synthetic',c.GATEWAY)['findings'][0]
        self.assertEqual(f['category'],'CWE-89'); self.assertIsNone(f['risk']); self.assertIsNone(f['confidence'])

    def test_xml_entities(self):
        p=self.path/'unsafe.xml'; p.write_text('<!DOCTYPE test [<!ENTITY x "SECRET">]><OWASPZAPReport/>')
        with self.assertRaises(ValueError): parsers.import_zap(p,'synthetic',c.GATEWAY)

    def test_deduplication(self):
        report=self.report(); report['site'][0]['alerts'] *= 2
        findings=self.parse(report)['findings']
        self.assertEqual(len(findings),1); self.assertEqual(len(findings[0]['occurrences']),2)

    def test_different_parameters_not_merged(self):
        report=self.report(); instance=copy.deepcopy(report['site'][0]['alerts'][0]['instances'][0]); instance['param']='other'
        report['site'][0]['alerts'][0]['instances'].append(instance)
        self.assertEqual(len(self.parse(report)['findings']),2)

    def test_foreign_alert(self):
        report=self.report(); report['site'][0]['alerts'][0]['instances'][0]['uri']='http://evil.invalid/'
        with self.assertRaises(ValueError): self.parse(report)

    def test_cwe_not_guessed(self):
        self.assertEqual(parsers.category('0'),'UNMAPPED'); self.assertEqual(parsers.category('API1:BOLA'),'UNMAPPED')

    def test_penagent_actual_shape(self):
        trace={'audit':{'target':'synthetic'},'probes':[{'result':{'status':'executed','op':'op1','probe_id':'p1'},
            'interpretation':{'classification':'CONFIRMED_VULNERABILITY','confidence':.98}}]}
        graph={'target_id':'synthetic','nodes':[{'id':'op1','method':'GET','path':'/'}]}
        self.assertEqual(parsers.import_penagent(trace,graph)['findings'][0]['category'],'UNMAPPED')
        for classification in ['WEAK_SIGNAL','STRONG_SIGNAL','ERROR_CRASH','NEGATIVE']:
            trace['probes'][0]['interpretation']['classification']=classification
            self.assertEqual(parsers.import_penagent(trace,graph)['findings'],[])

    def test_missing_ground_truth(self):
        result=metrics.compute({'tool':'zap','findings':[self.finding()]},{'duration_seconds':60},self.m)
        self.assertEqual(result['alerts_per_minute'],1)
        for key in ['precision','recall','f1','false_negatives','coverage_percent']:
            self.assertEqual(result[key],c.NA)

    def truth(self, f):
        return {'verified':True,'complete_eligible_universe':True,'target_version':'20.0.0',
            'source':'SYNTHETIC','reviewer':'UNIT TEST','vulnerability_ids':['v1','v2'],
            'labels':{f['id']:{'verdict':'true_positive','vulnerability_id':'v1','evidence_refs':['synthetic']}}}

    def test_detection_formulas(self):
        f=self.finding(); result=metrics.detection([f],self.truth(f))
        self.assertEqual((result['true_positives'],result['false_negatives'],result['precision'],result['recall']),(1,1,1,.5))
        self.assertAlmostEqual(result['f1'],2/3)
        self.assertEqual(result['statistical_false_positive_rate'],c.NA)

    def test_zero_denominators(self):
        truth=self.truth(self.finding()); truth['labels']={}; truth['vulnerability_ids']=[]
        result=metrics.detection([],truth)
        self.assertEqual(result['precision'],c.NA); self.assertEqual(result['recall'],c.NA); self.assertEqual(result['f1'],c.NA)

    def test_incomplete_truth(self):
        truth=self.truth(self.finding()); truth['complete_eligible_universe']=False
        with self.assertRaises(ValueError): metrics.detection([self.finding()],truth)

    def test_observed_coverage_only(self):
        result=metrics.compute({'tool':'zap','findings':[]},{'exercised_operations':['GET /'],'traffic_source':'synthetic log'},self.m)
        self.assertEqual(result['coverage_percent'],100)
        with self.assertRaises(ValueError): metrics.compute({'tool':'zap','findings':[]},{'exercised_operations':['GET /']},self.m)

    def test_timeouts_and_incomplete(self):
        self.assertEqual(runner.classify(0,True,False,self.path),'timeout')
        self.assertEqual(runner.classify(0,False,True,self.path),'cancelled')
        self.assertEqual(runner.classify(3,False,False,self.path),'failed')
        self.assertEqual(runner.classify(2,False,False,self.path),'incomplete')

    def test_three_repeats_equivalence(self):
        reports=[]
        for i in range(3):
            m=copy.deepcopy(self.m); m['repeat']=i+1; m['experiment_id']=f'synthetic-{i}'; m['reset_record']=f'synthetic-reset-{i}'
            reports.append(metrics.compute({'tool':'zap','findings':[]},{'status':'completed','duration_seconds':60+i,'request_count_definition':'synthetic'},m))
        out=metrics.aggregate(reports)
        self.assertEqual(out['summary']['duration_seconds']['mean'],61)
        self.assertEqual(out['summary']['duration_seconds']['sample_standard_deviation'],1)
        reports[0]['status']='timeout'
        with self.assertRaises(ValueError): metrics.aggregate(reports)

    def test_mode_stratification(self):
        first=metrics.condition(self.m); self.m['scan_mode']='api'
        self.m['openapi']={'source_sha256':'synthetic'}
        self.assertNotEqual(first,metrics.condition(self.m))

    def test_match_tentative_and_reviewed(self):
        left={'findings':[self.finding()]}; right={'findings':[self.finding('penagent')]}
        self.assertEqual(len(comparison.compare(left,right)['tentative_pairs_requiring_review']),1)
        for f in [left['findings'][0],right['findings'][0]]: f['verified_defect_id']='synthetic-defect'
        self.assertEqual(len(comparison.compare(left,right)['shared_verified_pairs']),1)

    def test_match_conflicts_and_unknown(self):
        left={'findings':[self.finding(parameter='id')]}; right={'findings':[self.finding('penagent',parameter='other')]}
        self.assertEqual(comparison.compare(left,right)['tentative_pairs_requiring_review'],[])
        left['findings'][0]['category']=right['findings'][0]['category']='UNMAPPED'
        self.assertEqual(comparison.compare(left,right)['shared_verified_pairs'],[])

    def test_annotations_do_not_modify_source(self):
        report={'findings':[self.finding()]}; before=copy.deepcopy(report); f=report['findings'][0]
        annotations={'source_sha256':'synthetic-hash','reviewer':'UNIT TEST','findings':{
            f['id']:{'fields':{'verified_defect_id':'synthetic'},'evidence_refs':['synthetic'],'rationale':'synthetic'}}}
        enriched=comparison.annotate(report,annotations,'synthetic-hash')
        self.assertEqual(report,before); self.assertIn('verified_defect_id',enriched['findings'][0])

    def test_comparison_outputs(self):
        result=comparison.compare({'findings':[]},{'findings':[]}); comparison.export(result,self.path)
        for filename in ['comparison.json','summary.csv','research.md']: self.assertTrue((self.path/filename).exists())

    def test_bundle_cannot_mount_surrounding_secrets(self):
        runner.stage_bundle(self.path)
        self.assertEqual({p.name for p in (self.path/'bundle').iterdir()}, {'common.py','gateway.py','hooks.py'})
        cmd=runner.scanner_command(self.m,self.path,'synthetic-network','synthetic-name')
        self.assertTrue(any('bundle' in s and 'target=/baseline,readonly' in s for s in cmd))

    def test_gateway_live_cap_and_auth_redaction(self):
        # Real local HTTP exercises the guard; upstream transport is a mock.
        self.m['budgets']['max_requests']=1
        gate=gateway.Gate(self.m,self.path,token='SYNTHETIC_SECRET')
        response=Mock(status=200)
        response.read.return_value=b'synthetic response'
        response.getheaders.return_value=[('Content-Type','text/plain')]
        upstream=Mock(); upstream.getresponse.return_value=response
        server=ThreadingHTTPServer(('127.0.0.1',0),gateway.handler(gate))
        worker=threading.Thread(target=server.serve_forever,daemon=True); worker.start()
        def request():
            with socket.create_connection(server.server_address,timeout=3) as client:
                client.sendall(b'GET /?token=SYNTHETIC_SECRET HTTP/1.0\r\nHost: test\r\nCookie: SYNTHETIC_SECRET\r\n\r\n')
                data=b''
                while True:
                    part=client.recv(4096)
                    if not part: break
                    data+=part
                return data
        try:
            with patch.object(gateway.http.client,'HTTPConnection',return_value=upstream):
                self.assertIn(b'200',request().splitlines()[0])
                self.assertIn(b'403',request().splitlines()[0])
            self.assertEqual(upstream.request.call_count,1)
            self.assertEqual(gate.sent,1); self.assertEqual(gate.denied,1)
            self.assertNotIn('SYNTHETIC_SECRET',(self.path/'traffic.jsonl').read_text())
            self.assertEqual(upstream.request.call_args.kwargs['headers']['Authorization'],'Bearer SYNTHETIC_SECRET')
            self.assertNotIn('Cookie',upstream.request.call_args.kwargs['headers'])
        finally:
            server.shutdown(); server.server_close(); worker.join(timeout=3)

    def test_runner_timeout_stops_own_containers(self):
        approval=self.path/'synthetic-approval.json'
        runner.approve(self.m,'SYNTHETIC UNIT TEST','I approve one bounded active scan',approval)
        process=Mock(); process.poll.return_value=None
        process.wait.side_effect=[subprocess.TimeoutExpired('synthetic',1),0]
        token='synthetic-current-run'
        def setup(*args,**kwargs):
            kwargs['resources'].register('synthetic-gate')
            return 'synthetic-net','synthetic-gate'
        def reply(args,**kwargs):
            return json.dumps({'owner':token,'running':True}) if args[0]=='inspect' else ''
        with patch.object(runner,'preflight'), patch.object(runner,'setup_gateway',side_effect=setup), patch.object(runner.uuid,'uuid4',return_value=Mock(hex=token)), patch.object(runner,'control_directory',return_value=self.path/'control'):
            with patch.object(runner.subprocess,'Popen',return_value=process), patch.object(runner,'docker',side_effect=reply) as docker:
                result=runner.run(self.m,approval,self.path/'synthetic-run')
        self.assertEqual(result['status'],'timeout')
        kills=[call.args[0] for call in docker.call_args_list if call.args[0][0]=='kill']
        self.assertEqual(kills,[['kill','synthetic-gate'],['kill','pa-zap-scanner-'+token]])
        process.kill.assert_called_once()
        self.assertTrue(Path(str(approval)+'.used').exists())

    def test_cancelled_approval_not_reused(self):
        approval=self.path/'synthetic-approval.json'
        runner.approve(self.m,'SYNTHETIC UNIT TEST','I approve one bounded active scan',approval)
        Path(str(approval)+'.used').write_text('synthetic prior attempt')
        with patch.object(runner,'preflight',side_effect=AssertionError('Approval was reused')):
            with self.assertRaises(FileExistsError): runner.run(self.m,approval,self.path/'not-created')


if __name__ == '__main__': unittest.main()
