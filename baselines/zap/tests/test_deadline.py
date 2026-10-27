"""Deterministic deadline regressions. All clocks, Docker and scans are mocked."""
import copy
import io
import json
import subprocess
import tempfile
import unittest
from email.message import Message
from pathlib import Path
from unittest.mock import Mock, patch

from baselines.zap import runner, gateway
from baselines.zap import deadline as timing
from baselines.zap.common import ROOT, read, write


class Clock:
    def __init__(self, value=0): self.value = value
    def __call__(self): return self.value


class DeadlineTests(unittest.TestCase):
    def setUp(self):
        (ROOT/'local').mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix='synthetic-deadline-', dir=ROOT/'local')
        self.addCleanup(self.temp.cleanup); self.path = Path(self.temp.name)
        self.m = copy.deepcopy(read(ROOT/'config/juice-smoke.json'))
        self.m['experiment_id'] = 'synthetic-deadline-test'
        self.clock = Clock()

    def simulate(self, setup_elapsed=0, wait=None, preflight_elapsed=0):
        approval = self.path/'SYNTHETIC-APPROVAL.json'; write(approval, {'synthetic_only':True})
        process = Mock(); process.poll.return_value=0
        process.wait.side_effect = wait or (lambda timeout: 0)
        def setup(*args, **kwargs):
            kwargs['resources'].register('synthetic-gateway')
            self.clock.value = setup_elapsed
            return 'synthetic-network', 'synthetic-gateway'
        def preflight(*args, **kwargs): self.clock.value = preflight_elapsed
        def docker(args, **kwargs):
            self.assertTrue((self.path/'control'/'forwarding.closed').exists(), 'Revoke before cleanup')
            return json.dumps({'owner':'synthetic-token','running':True}) if args[0]=='inspect' else ''
        def control(*args):
            path=self.path/'control'; path.mkdir(); return path
        with patch.object(runner,'verify_approval'), patch.object(runner,'preflight',side_effect=preflight) as pf, \
             patch.object(runner,'setup_gateway',side_effect=setup) as sg, \
             patch.object(runner,'control_directory',side_effect=control), \
             patch.object(runner,'watchdog',return_value=Mock()), \
             patch.object(runner.uuid,'uuid4',return_value=Mock(hex='synthetic-token')), \
             patch.object(runner.time,'monotonic',side_effect=self.clock), \
             patch.object(runner,'docker',side_effect=docker) as dk, \
             patch.object(runner.subprocess,'Popen',return_value=process) as popen:
            result=runner.run(self.m,approval,self.path/'SIMULATION-NOT-A-SCAN')
        return result, popen, process, sg, dk

    def test_previously_failing_181_second_setup_does_not_launch(self):
        result,popen,process,setup,docker=self.simulate(181)
        popen.assert_not_called(); process.wait.assert_not_called(); docker.assert_not_called()
        self.assertEqual(result['status'],'timeout')
        self.assertEqual(result['runtime']['duration_seconds'],181)

    def test_exact_overall_deadline_does_not_launch(self):
        result,popen,*_=self.simulate(180)
        popen.assert_not_called(); self.assertEqual(result['status'],'timeout')

    def test_exact_work_cutoff_does_not_launch(self):
        result,popen,*_=self.simulate(170)
        popen.assert_not_called(); self.assertEqual(result['status'],'timeout')

    def test_nearly_exhausted_gets_only_fractional_remaining(self):
        result,popen,process,*_=self.simulate(169.75)
        popen.assert_called_once()
        self.assertEqual(process.wait.call_args.kwargs['timeout'],.25)
        self.assertNotEqual(process.wait.call_args.kwargs['timeout'],1)

    def test_deadline_exceeded_in_preflight_blocks_gateway(self):
        result,popen,process,setup,docker=self.simulate(preflight_elapsed=181)
        setup.assert_not_called(); popen.assert_not_called(); docker.assert_not_called()
        self.assertEqual(result['status'],'timeout')

    def test_timeout_during_active_work_revokes_before_owned_cleanup(self):
        def wait(timeout):
            self.assertEqual(timeout,150)
            self.clock.value=170
            raise subprocess.TimeoutExpired('synthetic scan',timeout)
        result,popen,process,setup,docker=self.simulate(20,wait=wait)
        self.assertEqual(result['status'],'timeout')
        killed=[call.args[0] for call in docker.call_args_list if call.args[0][0]=='kill']
        self.assertEqual(killed,[['kill','synthetic-gateway'],['kill','pa-zap-scanner-synthetic-token']])
        self.assertTrue((self.path/'control'/'forwarding.closed').exists())

    def test_docker_setup_command_receives_remaining_budget(self):
        d=timing.Deadline(180,clock=self.clock); self.clock.value=169.8
        response=Mock(returncode=0,stdout='created',stderr='')
        with patch.object(runner.subprocess,'run',return_value=response) as call:
            runner.docker(['network','create','synthetic'],deadline=d)
        self.assertAlmostEqual(call.call_args.kwargs['timeout'],.2)
        self.clock.value=170
        with patch.object(runner.subprocess,'run') as call:
            with self.assertRaises(timing.DeadlineExpired): runner.docker(['run','synthetic'],deadline=d)
        call.assert_not_called()

    def test_command_overrunning_setup_cannot_start_another_phase(self):
        d=timing.Deadline(180,clock=self.clock)
        def late(*args,**kwargs):
            self.clock.value=181
            return Mock(returncode=0,stdout='created',stderr='')
        with patch.object(runner.subprocess,'run',side_effect=late) as call:
            with self.assertRaises(timing.DeadlineExpired): runner.docker(['network','create','synthetic'],deadline=d)
        self.assertEqual(call.call_count,1)

    def test_cleanup_refuses_containers_without_current_owner(self):
        owned=runner.OwnedContainers('current-token'); owned.register('blissful_chebyshev')
        d=timing.Deadline(180,clock=self.clock)
        with patch.object(runner,'docker',return_value=json.dumps({'owner':'another-run','running':True})) as call:
            events=owned.cleanup(d)
        self.assertEqual(call.call_count,1); self.assertEqual(call.call_args.args[0][0],'inspect')
        self.assertEqual(events[0]['action'],'refused_owner_mismatch')

    def test_cleanup_timeouts_use_only_overall_remaining(self):
        owned=runner.OwnedContainers('token'); owned.register('synthetic-gateway')
        d=timing.Deadline(180,clock=self.clock); self.clock.value=179.75
        observed=[]
        def reply(command,**kwargs):
            observed.append(kwargs['timeout'])
            self.clock.value+=.2
            return Mock(returncode=0,stdout=json.dumps({'owner':'token','running':True}),stderr='')
        with patch.object(runner.subprocess,'run',side_effect=reply): owned.cleanup(d)
        self.assertAlmostEqual(observed[0],.25); self.assertAlmostEqual(observed[1],.05)
        self.clock.value=180
        with patch.object(runner.subprocess,'run') as call: events=owned.cleanup(d)
        call.assert_not_called(); self.assertEqual(events[0]['action'],'unconfirmed_deadline_exhausted')

    def test_already_removed_diagnostic_is_not_a_cleanup_failure(self):
        owned=runner.OwnedContainers('token'); owned.register('synthetic-probe')
        with patch.object(runner,'docker',side_effect=RuntimeError('error: no such object: synthetic-probe')) as call:
            events=owned.cleanup(timing.Deadline(180,clock=self.clock))
        self.assertEqual(events[0]['action'],'already_removed')
        self.assertEqual(call.call_count,1)

    def test_reports_cannot_borrow_shutdown_reserve(self):
        d=timing.Deadline(180,clock=self.clock); self.clock.value=170
        (self.path/'large-report.json').write_text('synthetic')
        with self.assertRaises(timing.DeadlineExpired): runner.hash_artifacts(self.path,d)

    def test_budget_uses_monotonic_not_wall_time(self):
        d=timing.Deadline(180,clock=self.clock)
        with patch('time.time',return_value=-1000000000):
            self.clock.value=40; self.assertEqual(d.remaining(),130)

    def test_watchdog_seals_without_calling_docker(self):
        d=timing.Deadline(180,clock=self.clock); event=Mock(); event.wait.return_value=False
        def immediate_thread(*args,**kwargs):
            return Mock(start=lambda:kwargs['target']())
        with patch.object(timing.threading,'Event',return_value=event), \
             patch.object(timing.threading,'Thread',side_effect=immediate_thread), \
             patch.object(runner,'docker',side_effect=AssertionError('Watchdog called Docker')):
            timing.watchdog(d,self.path/'control')
        event.wait.assert_called_once_with(170)
        self.assertTrue((self.path/'control'/'forwarding.closed').exists())


class GatewayDeadlineTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='synthetic-gate-deadline-',dir=ROOT/'local')
        self.addCleanup(self.temp.cleanup); self.path=Path(self.temp.name)
        self.m=read(ROOT/'config/juice-smoke.json'); self.clock=Clock(10000)
        self.control=self.path/'control'
        self.gate=gateway.Gate(self.m,self.path,clock=self.clock,control=self.control)

    def arm(self,expiry):
        write(self.control/'deadline.json',{'anchor_nonce':self.gate.nonce,'expires_monotonic':expiry})

    def request_handler(self):
        cls=gateway.handler(self.gate); request=cls.__new__(cls)
        request.command='GET'; request.path='/'
        request.headers=Message(); request.rfile=io.BytesIO(); request.wfile=io.BytesIO()
        request.connection=Mock()
        for method in ['send_error','send_response_only','send_header','end_headers']: setattr(request,method,Mock())
        return request

    def test_gateway_production_starts_disarmed(self):
        request=self.request_handler()
        with patch.object(gateway.http.client,'HTTPConnection') as connection: request.do_any()
        connection.assert_not_called(); self.assertEqual(self.gate.sent,0)

    def test_host_gateway_handshake_is_conservative_with_different_clocks(self):
        host=Clock(1000); d=timing.Deadline(180,clock=host); host.value=1007
        allowance=runner.arm_gateway(self.control,d)
        self.assertEqual(allowance['expires_monotonic'],10163)
        self.assertEqual(self.gate.remaining(),163)

    def test_exact_gateway_deadline_refuses_forwarding(self):
        self.arm(10001); self.clock.value=10001; request=self.request_handler()
        with patch.object(gateway.http.client,'HTTPConnection') as connection: request.do_any()
        connection.assert_not_called(); self.assertEqual(self.gate.denied,1)

    def test_slow_connect_crossing_deadline_never_sends_http(self):
        self.arm(10001); request=self.request_handler(); conn=Mock()
        conn.connect.side_effect=lambda:setattr(self.clock,'value',10002)
        with patch.object(gateway.http.client,'HTTPConnection',return_value=conn): request.do_any()
        conn.request.assert_not_called(); self.assertEqual(self.gate.sent,0)
        conn.close.assert_called(); self.assertEqual(self.gate.denied,1)

    def test_shutdown_revocation_is_permanent_even_if_file_removed(self):
        self.arm(10100); self.assertEqual(self.gate.remaining(),100)
        timing.revoke(self.control); self.assertEqual(self.gate.remaining(),0)
        (self.control/'forwarding.closed').unlink(); self.arm(10180)
        request=self.request_handler()
        with patch.object(gateway.http.client,'HTTPConnection') as connection: request.do_any()
        connection.assert_not_called(); self.assertEqual(self.gate.sent,0)

    def test_deadline_cannot_be_extended_after_arming(self):
        self.arm(10005); self.assertEqual(self.gate.remaining(),5)
        self.arm(100180); self.clock.value=10005
        self.assertEqual(self.gate.remaining(),0)

    def test_stale_anchor_cannot_arm_gateway(self):
        write(self.control/'deadline.json',{'anchor_nonce':'another-gateway','expires_monotonic':10010})
        self.assertEqual(self.gate.remaining(),0)


if __name__=='__main__': unittest.main()
