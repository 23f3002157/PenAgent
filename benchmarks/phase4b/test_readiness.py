"""Honest source labels, real network evidence, missing assets and approval gates."""
import copy
import unittest
from pathlib import Path
from benchmarks import core as c
from benchmarks.phase4b.registry import validate_registry, validate_record

ROOT=c.ROOT/'phase4b'

class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.registry=c.load(ROOT/'registry.json')
    def record(self,name):return next(r for r in self.registry['benchmarks'] if r['id']==name)
    def test_registry_has_all_three_families(self):validate_registry(self.registry)
    def test_missing_family_rejected(self):
        self.registry['benchmarks']=[r for r in self.registry['benchmarks'] if r['family']!='srebench_api']
        with self.assertRaisesRegex(ValueError,'THREE'):validate_registry(self.registry)
    def test_original_dvws_cannot_be_silently_replaced(self):
        self.registry['benchmarks']=[r for r in self.registry['benchmarks'] if r['id']!='dvws-original']
        with self.assertRaisesRegex(ValueError,'Original DVWS'):validate_registry(self.registry)
    def test_successor_not_adopted(self):
        r=self.record('dvws-node-proposed');r['adopted']=True
        with self.assertRaisesRegex(ValueError,'cannot be adopted'):validate_record(r)
    def test_reproduction_not_official(self):
        r=self.record('srebench-api-reproduction-proposal');r['label']='Official SREBench-API'
        with self.assertRaisesRegex(ValueError,'label'):validate_record(r)
    def test_proposed_successor_label_required(self):
        r=self.record('dvws-node-proposed');r['label']='DVWS'
        with self.assertRaisesRegex(ValueError,'label'):validate_record(r)
    def test_digest_must_be_immutable(self):
        r=self.record('juice-shop-20.0.0');r['deployment']['image_digest']='bkimminich/juice-shop:latest'
        with self.assertRaisesRegex(ValueError,'digest'):validate_record(r)
    def test_false_ready_state_refused(self):
        r=self.record('juice-shop-20.0.0');r['readiness']['status']='READY'
        with self.assertRaisesRegex(ValueError,'READY lacks'):validate_record(r)
    def test_hash_mismatch_refused(self):
        r=self.record('juice-shop-20.0.0');r['specification']['sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'hash mismatch'):validate_record(r)
    def test_missing_asset_requires_reason(self):
        r=self.record('dvws-original');r['specification']['missing_reason']=''
        with self.assertRaisesRegex(ValueError,'explicit reason'):validate_record(r)
    def test_no_ground_truth_claims(self):
        r=self.record('juice-shop-20.0.0');r['ground_truth']['verified']=True
        with self.assertRaisesRegex(ValueError,'adjudicate'):validate_record(r)
    def test_reproducible_configuration_is_private_and_pinned(self):
        text=(ROOT/'deploy/juice-fresh.compose.yml').read_text()
        self.assertNotIn('ports:',text);self.assertEqual(text.count('gateway_mode_ipv4: isolated'),2)
        self.assertIn('@sha256:',text);self.assertIn('PHASE4B_FRESH_VOLUME:?',text)
        self.assertIn('/rest/admin/application-version',text)
    def test_actual_shared_route_proof(self):
        run=c.load(ROOT/'evidence/connectivity-r2/connectivity-run.json');self.assertIsNone(run['error'])
        config=c.load(ROOT/'evidence/connectivity-r2/connectivity-config.json')
        self.assertNotEqual(config['target_origin'],config['gateway_origin'])
        self.assertTrue(config['network']['internal'])
        self.assertEqual(config['network']['options']['com.docker.network.bridge.gateway_mode_ipv4'],'isolated')
        for client in ['penagent','zap']:
            evidence=c.load(ROOT/f'evidence/connectivity-r2/{client}-connectivity.json')
            self.assertFalse(any(x['reachable'] for x in evidence['negative_connections']))
            self.assertEqual(len(evidence['operations']),5);self.assertEqual(len(evidence['denied_requests']),3)
            self.assertEqual(evidence['origin'],config['gateway_origin']);self.assertEqual(evidence['penagent_probes'],0)
    def test_actual_gateway_counts(self):
        summary=c.load(ROOT/'evidence/connectivity-r2/gateway-summary.json')
        self.assertEqual((summary['forwarded'],summary['blocked']),(10,6))
        run=c.load(ROOT/'evidence/connectivity-r2/connectivity-run.json')
        self.assertTrue(run['forwarding_revoked']);self.assertLess(run['elapsed_seconds'],180)
    def test_exact_four_juice_candidates(self):
        r=self.record('juice-shop-20.0.0');self.assertEqual(len(r['readiness']['eligible_operations']),4)
        inventory=c.load(ROOT/'juice-inventory.json')['operations']
        self.assertEqual(len(inventory),6)
        self.assertEqual(sum(o['included_for_ground_truth_preparation'] for o in inventory),4)
        self.assertFalse(any(o['included'] for o in inventory))
    def test_permissive_import_does_not_hide_schema_failure(self):
        result=c.load(ROOT/'evidence/dvws-node-parser-comparison.json')
        self.assertEqual(result['c1_parsed'],52);self.assertEqual(result['zap_imported_mapped'],52)
        self.assertFalse(result['schema_valid']);self.assertEqual(result['shared_live_eligible'],0)
    def test_upstream_raw_bytes_provenance(self):
        archives=c.load(ROOT/'evidence/upstream-archives.json')
        for repo,item in archives.items():
            source=Path(item['local_source'])
            for relative in ['README.md','LICENSE']:
                expected=next(f['sha256'] for f in item['files'] if f['path']==relative)
                self.assertEqual(c.sha(source/relative),expected)
        node=Path(archives['snoopysecurity/dvws-node']['local_source'])
        self.assertEqual(c.sha(node/'docs/openapi/openapi.json'),c.sha(ROOT/'candidates/dvws-node-upstream-raw.json'))
    def test_original_identity_and_citation_separated(self):
        r=c.load(ROOT/'evidence/dvws-source-resolution.json')
        self.assertTrue(r['project_identity_verified']);self.assertFalse(r['beebs_2019_attribution_verified'])
    def test_legacy_runtime_failure_not_a_deployment_success(self):
        r=c.load(ROOT/'evidence/legacy-runtime.json')
        self.assertFalse(r['executed']);self.assertFalse(r['application_deployed'])
        self.assertNotEqual(r['commands'][-1].get('exit_code',-1),0)
    def test_twenty_source_scenarios(self):
        matrix=c.load(ROOT/'srebench/scenario-matrix.json')
        self.assertEqual([r['scenario_id'] for r in matrix['scenarios']],[f'SRE-{i:02d}' for i in range(1,21)])
        self.assertEqual(matrix['source_sha256'],c.sha(c.ROOT.parent/'images/SREBench API.pdf'))
        self.assertEqual(sum(r['classification']=='REQUIRES INTERPRETATION' for r in matrix['scenarios']),5)
        self.assertEqual(sum(r['classification']=='INSUFFICIENT INFORMATION' for r in matrix['scenarios']),15)
    def test_scenario_traceability_and_no_invented_paths(self):
        rows=c.load(ROOT/'srebench/scenario-matrix.json')['scenarios']
        detailed={'SRE-01','SRE-02','SRE-03','SRE-12','SRE-16'}
        for row in rows:
            self.assertTrue(row['source_reference']['pages_1_based']);self.assertTrue(row['missing_details'])
            self.assertFalse(row['implemented']);self.assertFalse(row['confidence_in_fidelity']['faithful_implementation_verified'])
            if row['scenario_id'] not in detailed:self.assertEqual(row['source_explicit_endpoints'],[])
    def test_reproduction_services_remain_unimplemented(self):
        plan=c.load(ROOT/'srebench/reproduction-plan.json')
        self.assertFalse(plan['executable']);self.assertFalse(plan['services_implemented'])
        self.assertFalse(plan['implementation_gate']['deploy_allowed'])
        self.assertFalse(list((ROOT/'srebench').glob('*.py')))

if __name__=='__main__':unittest.main()
