"""Synthetic parser contracts plus real prepared-artifact checks; no network."""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from benchmarks import core as c

sys.path.insert(0,str(c.ROOT/'local/validation-deps'))

def fixture():
    return {'openapi':'3.0.3','info':{'title':'SYNTHETIC TEST ONLY','version':'test'},
        'servers':[{'url':'http://127.0.0.1:18001'}],
        'paths':{'/items/{id}':{'get':{'operationId':'getItem','parameters':[
            {'name':'id','in':'path','required':True,'schema':{'type':'string'}}],
            'responses':{'200':{'description':'test'}}}}}}

class Contracts(unittest.TestCase):
    def setUp(self):self.s=fixture()
    def bad(self):
        with self.assertRaises(ValueError):c.inspect_spec(self.s)
    def test_valid_full(self):self.assertEqual(len(c.inspect_spec(self.s,True)['operations']),1)
    def test_invalid_version(self):self.s['openapi']='2.0';self.bad()
    def test_missing_server(self):self.s.pop('servers');self.bad()
    def test_duplicate_id(self):self.s['paths']['/another/{id}']=copy.deepcopy(self.s['paths']['/items/{id}']);self.bad()
    def test_broken_ref(self):self.s['components']={'schemas':{'x':{'$ref':'#/absent'}}};self.bad()
    def test_external_ref(self):self.s['components']={'schemas':{'x':{'$ref':'https://example.invalid/x'}}};self.bad()
    def test_server_variables(self):self.s['servers'][0]['url']='http://{host}';self.bad()
    def test_path_server_override(self):self.s['paths']['/items/{id}']['servers']=[];self.bad()
    def test_callbacks(self):self.s['paths']['/items/{id}']['get']['callbacks']={};self.bad()
    def test_normalization(self):
        self.assertEqual(c.path_normalize('/Items/{id}/'),'/Items/{id}/')
        for path in ['//x','/a//b','/a/../b','/x?q=1','/x#y','relative','/x\\y']:
            with self.subTest(path=path),self.assertRaises(ValueError):c.path_normalize(path)
    def test_parameters(self):
        op=c.inspect_spec(self.s)['operations'][0];self.assertTrue(op['parameters'][0]['required'])
    def test_missing_path_parameter(self):self.s['paths']['/items/{id}']['get']['parameters']=[];self.bad()
    def test_optional_path_parameter(self):self.s['paths']['/items/{id}']['get']['parameters'][0]['required']=False;self.bad()
    def test_auth(self):
        self.s['security']=[{'jwt':[]}];self.s['components']={'securitySchemes':{'jwt':{'type':'http','scheme':'bearer'}}}
        self.assertFalse(c.inspect_spec(self.s,True)['operations'][0]['anonymous'])
    def test_unknown_auth(self):self.s['security']=[{'missing':[]}];self.bad()
    def test_body(self):
        self.s['paths']['/items/{id}']['get']['requestBody']={'required':True,'content':{'application/json':{'schema':{'type':'object'}}}}
        self.assertTrue(c.inspect_spec(self.s)['operations'][0]['request_body']['required'])
    def test_base_path_retained(self):
        self.s['servers']=[{'url':'/b2b/v2'}]
        rewritten=c.prepare_origin(self.s,'http://127.0.0.1:18001')
        self.assertEqual(c.inspect_spec(rewritten)['operations'][0]['path'],'/b2b/v2/items/{id}')
    def test_external_origin_refused(self):
        with self.assertRaises(ValueError):c.prepare_origin(self.s,'http://example.com:18001')
    def test_methods_distinct(self):
        op=copy.deepcopy(self.s['paths']['/items/{id}']['get']);op['operationId']='postItem'
        self.s['paths']['/items/{id}']['post']=op
        self.assertEqual(len(c.operation_set(c.inspect_spec(self.s))),2)
    def test_template_mapping(self):
        ops=c.inspect_spec(self.s)['operations']
        self.assertEqual(c.map_capture_paths(ops,[{'method':'GET','path':'/items/1'}]),{('GET','/items/{id}')})
    def test_template_ambiguity(self):
        ops=[{'method':'GET','path':'/x/{id}'},{'method':'GET','path':'/x/{name}'}]
        with self.assertRaises(ValueError):c.map_capture_paths(ops,[{'method':'GET','path':'/x/1'}])
    def test_wrong_method_capture(self):
        with self.assertRaises(ValueError):c.map_capture_paths(c.inspect_spec(self.s)['operations'],[{'method':'POST','path':'/items/1'}])
    def test_intersection_requires_live_and_review(self):
        ops=c.inspect_spec(self.s)['operations'];report={'operations':ops};key=('GET','/items/{id}')
        self.assertEqual(c.intersect(ops,report,report,{key},{key}),{key})
        self.assertEqual(c.intersect(ops,report,report,set(),{key}),set())
    def test_missing_docker_assets(self):
        with tempfile.TemporaryDirectory() as d:self.assertEqual(c.missing_assets(['Dockerfile','compose.yml'],d),['Dockerfile','compose.yml'])
    def test_incomplete_manifest(self):
        with self.assertRaises(ValueError):c.validate_manifest({'schema_version':1})
    def test_identity_mismatch(self):
        expected={'container_id':'a','image_id':'b','version':'20'}
        with self.assertRaises(ValueError):c.check_identity(expected,{**expected,'version':'21','running':True})
    def test_identity_success(self):
        expected={'container_id':'a','image_id':'b','version':'20'}
        self.assertTrue(c.check_identity(expected,{**expected,'running':True}))
    def test_readiness(self):
        checks=dict.fromkeys(c.CHECKS,True)
        self.assertEqual(c.readiness(checks),'READY')
        checks['shared_operations']=False;self.assertEqual(c.readiness(checks),'PARTIALLY READY')
        checks['identity']=False;self.assertEqual(c.readiness(checks),'BLOCKED')
        self.assertEqual(c.readiness(checks,True),'REQUIRES APPROVAL')
        self.assertEqual(c.readiness(checks,available=False),'NOT AVAILABLE')
    def test_incomplete_checklist(self):
        with self.assertRaises(ValueError):c.readiness({'identity':True})
    def test_save_preserves_existing(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'artifact.json';c.save(p,{'a':1});c.save(p,{'a':1})
            with self.assertRaises(ValueError):c.save(p,{'a':2})
    def test_real_specs_full(self):
        for label in ['b2b','readonly']:
            s=c.load(c.ROOT/f'specs/prepared/juice-shop-20.0.0-{label}-host.json')
            self.assertTrue(c.inspect_spec(s,True)['full_schema_validation'])

class ManifestArtifacts(unittest.TestCase):
    def setUp(self):
        self.path=c.ROOT/'manifests/juice-shop-20.0.0.json'
        self.m=c.load(self.path)
    def test_manifest_hashes(self):c.validate_manifest(self.m)
    def test_hash_mismatch(self):
        self.m['specifications'][0]['prepared_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'hash mismatch'):c.validate_manifest(self.m)
    def test_version_mismatch(self):
        self.m['specifications'][0]['target_version']='99'
        with self.assertRaisesRegex(ValueError,'version mismatch'):c.validate_manifest(self.m)
    def test_false_ready(self):
        self.m['readiness']='READY'
        with self.assertRaisesRegex(ValueError,'contradicts'):c.validate_manifest(self.m)
    def test_all_target_manifests(self):
        for p in (c.ROOT/'manifests').glob('*.json'):c.validate_manifest(c.load(p))

if __name__=='__main__':unittest.main()
