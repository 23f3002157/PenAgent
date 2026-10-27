import json
import tempfile
import unittest
from pathlib import Path
from benchmarks.phase4b.gateway import Gate, REQUESTS

class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.clock_value=10
        self.gate=Gate({'target_ip':'172.24.0.2','target_port':3000,'max_requests':20,'wall_seconds':180,
            'target_container_id':'a'*64,'target_image_id':'sha256:'+'b'*64},self.temp.name,lambda:self.clock_value)
    def arm(self,expiry=30):
        (Path(self.temp.name)/'armed.json').write_text(json.dumps({'nonce':self.gate.nonce,'expires_gateway_monotonic':expiry}))
    def test_exact_benign_examples(self):self.assertTrue(all(self.gate.permitted('GET',p) for p in REQUESTS))
    def test_other_methods_denied(self):self.assertFalse(any(self.gate.permitted(m,REQUESTS[0]) for m in ['POST','PUT','HEAD','OPTIONS','CONNECT']))
    def test_query_restricted(self):self.assertFalse(self.gate.permitted('GET','/rest/products/search?q=pear'))
    def test_template_restricted_to_reviewed_id(self):self.assertFalse(self.gate.permitted('GET','/rest/products/2/reviews'))
    def test_authority_and_encoding_denied(self):
        for path in ['http://example.invalid/','//example.invalid/','/rest/%6canguages','/rest/languages?x=1']:
            self.assertFalse(self.gate.permitted('GET',path))
    def test_no_credentials_or_bodies(self):
        for key in ['Authorization','Cookie','Content-Length','Transfer-Encoding']:
            self.assertFalse(self.gate.permitted('GET',REQUESTS[0],{key:'test'}))
    def test_initially_disarmed(self):self.assertEqual(self.gate.remaining(),0)
    def test_wrong_nonce(self):
        self.arm();p=Path(self.temp.name)/'armed.json';data=json.loads(p.read_text());data['nonce']='wrong';p.write_text(json.dumps(data))
        self.assertEqual(self.gate.remaining(),0)
    def test_exact_deadline(self):self.arm();self.clock_value=30;self.assertEqual(self.gate.remaining(),0)
    def test_expired_deadline(self):self.arm();self.clock_value=31;self.assertEqual(self.gate.remaining(),0)
    def test_arm_cannot_extend_once_loaded(self):
        self.arm();self.assertEqual(self.gate.remaining(),20);self.arm(100);self.assertEqual(self.gate.remaining(),20)
    def test_revocation(self):
        self.arm();(Path(self.temp.name)/'closed').touch();self.assertEqual(self.gate.remaining(),0)

if __name__=='__main__':unittest.main()
