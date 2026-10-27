"""Create a connectivity-only gateway and isolated client containers; no scans.

Only newly created containers may be stopped. Existing target/network configuration
is preserved. The tool network has no host bridge address or published ports.
"""
import json
import subprocess
import sys
import threading
import time
from pathlib import Path

REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO))
from benchmarks import core as c
from baselines.zap.deadline import Deadline

ZAP='ghcr.io/zaproxy/zaproxy@sha256:5ccfff9a411743ab2615136a2edd7416bec9ce41572fa94e935df38c14adb2b6'
EXECUTOR='sha256:6b81fdd4e95f2106202bb33f1d5022696538f8dd1ad81f6818c1d29f17fc1561'
ATTEMPT=sys.argv[1] if len(sys.argv)>1 else 'r1'
assert ATTEMPT in {'r1','r2'},'Only explicitly selected connectivity attempts r1/r2 supported'
LABEL='penagent.phase4b=connectivity-'+ATTEMPT
TOOL_NETWORK='penagent-phase4b-tools-'+ATTEMPT
BACKEND='penagent-phase4-juice20-r1_isolated'
GATEWAY='penagent-phase4b-gateway-'+ATTEMPT
TARGET='penagent-phase4-juice20-r1-target-1'
OUTPUT=c.ROOT/'phase4b/evidence' if ATTEMPT=='r1' else c.ROOT/'phase4b/evidence/connectivity-r2'
RUNTIME=c.ROOT/'local/phase4b'/('connectivity-runtime' if ATTEMPT=='r1' else 'connectivity-runtime-r2')

def main():
    if (OUTPUT/'connectivity-run.json').exists() or RUNTIME.exists():raise ValueError('Run already attempted; do not automatically repeat')
    RUNTIME.mkdir(parents=True);OUTPUT.mkdir(parents=True,exist_ok=True)
    deadline=Deadline(180);commands=[];owned=[];error=None;stop=threading.Event()
    def docker(args,cap=30,cleanup=False):
        timeout=deadline.timeout(cap,'Docker '+args[0],cleanup)
        p=subprocess.run(['docker',*args],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=timeout)
        commands.append({'argv':['docker',*args],'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
        if p.returncode:raise RuntimeError(commands[-1])
        if not cleanup:deadline.check('next phase')
        return p.stdout.strip()
    def inspect(name):
        return json.loads(docker(['inspect','--format','{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"networks":{{json .NetworkSettings.Networks}},"ports":{{json .NetworkSettings.Ports}}}',name]))
    def cutoff():
        if not stop.wait(max(0,deadline.remaining())):(RUNTIME/'closed').touch()
    threading.Thread(target=cutoff,daemon=True).start()
    try:
        target=inspect(TARGET);approved=c.load(c.ROOT/'manifests/juice-shop-20.0.0.json')
        assert target['running'] and target['id']==approved['deployment']['container_id'] and target['image']==approved['deployment']['image_id']
        assert set(target['networks'])=={BACKEND} and all(not v for v in target['ports'].values())
        assert approved['image_digest'] in json.loads(docker(['image','inspect','--format','{{json .RepoDigests}}',target['image']]))
        assert docker(['network','inspect','--format','{{json .Internal}}',BACKEND])=='true'
        original=inspect('blissful_chebyshev')
        assert original['id']=='0356c18439557ca2fed64e8c69f73035c4b485ca069b6f961b1de038f17d9ac3'
        target_ip=target['networks'][BACKEND]['IPAddress']
        docker(['network','create','--internal','--opt','com.docker.network.bridge.gateway_mode_ipv4=isolated','--label',LABEL,TOOL_NETWORK])
        c.save(RUNTIME/'policy.json',{'target_ip':target_ip,'target_port':3000,'max_requests':20,'wall_seconds':180,
            'target_container_id':target['id'],'target_image_id':target['image']})
        gateway_args=['run','-d','--name',GATEWAY,'--label',LABEL,'--network',BACKEND,'--cap-drop','ALL',
            '--security-opt','no-new-privileges','--memory','256m','--cpus','.5',
            '--mount',f'type=bind,source={c.ROOT},target=/benchmarks,readonly',
            '--mount',f'type=bind,source={RUNTIME},target=/phase4b',
            '--entrypoint','python',ZAP,'-B','/benchmarks/phase4b/gateway.py']
        docker(gateway_args);owned.append(GATEWAY)
        docker(['network','connect','--alias','benchmark-gateway',TOOL_NETWORK,GATEWAY])
        gateway=inspect(GATEWAY);gateway_ip=gateway['networks'][TOOL_NETWORK]['IPAddress']
        network=json.loads(docker(['network','inspect','--format','{"internal":{{json .Internal}},"options":{{json .Options}},"ipam":{{json .IPAM.Config}}}',TOOL_NETWORK]))
        assert network['internal'] and network['options']['com.docker.network.bridge.gateway_mode_ipv4']=='isolated'
        forbidden=[(target_ip,3000),(original['networks']['bridge']['IPAddress'],3000),('172.24.0.1',3000),
            ('172.24.0.1',9003),('host.docker.internal',3000),('host.docker.internal',18001),('1.1.1.1',443)]
        forbidden += [('host.docker.internal',port) for port in [9001,9002,9003,9004]]
        c.save(OUTPUT/'connectivity-config.json',{'gateway_ip':gateway_ip,'gateway_origin':f'http://{gateway_ip}:8088',
            'target_ip':target_ip,'target_origin':f'http://{target_ip}:3000','tool_network':TOOL_NETWORK,
            'forbidden_connections':[list(x) for x in forbidden],'target':target,'gateway':gateway,'network':network})
        for _ in range(50):
            deadline.check('gateway anchor wait')
            if (RUNTIME/'anchor.json').exists():break
            time.sleep(.1)
        anchor=c.load(RUNTIME/'anchor.json')
        # Gateway sample predates this remaining-time observation: conservative across clock origins.
        c.save(RUNTIME/'armed.json',{'nonce':anchor['nonce'],
            'expires_gateway_monotonic':anchor['monotonic']+deadline.check('arming gateway')})
        for kind,image in [('penagent',EXECUTOR),('zap',ZAP)]:
            name='penagent-phase4b-'+kind+'-'+ATTEMPT
            docker(['create','--name',name,'--label',LABEL,'--network',TOOL_NETWORK,'--cap-drop','ALL',
                '--security-opt','no-new-privileges','--memory','2g' if kind=='zap' else '512m','--cpus','2' if kind=='zap' else '1',
                '--mount',f'type=bind,source={c.ROOT},target=/benchmarks,readonly',
                '--mount',f'type=bind,source={OUTPUT},target=/benchmarks/phase4b/evidence',
                '--mount',f'type=bind,source={c.ROOT / "local/phase4b"},target=/benchmarks/local/phase4b',
                '--entrypoint','python',image,'-B','/benchmarks/phase4b/connectivity_client.py',kind])
            owned.append(name)
            client=inspect(name)
            assert set(client['networks'])=={TOOL_NETWORK} and not client['ports']
            docker(['start','--attach',name],cap=115)
            state=json.loads(docker(['inspect','--format','{"exit":{{json .State.ExitCode}},"oom":{{json .State.OOMKilled}}}',name]))
            assert state=={'exit':0,'oom':False},state
        for kind in ['penagent','zap']:
            evidence=c.load(OUTPUT/f'{kind}-connectivity.json')
            assert len(evidence['operations'])==5 and not any(x['reachable'] for x in evidence['negative_connections'])
        assert [o['response_sha256'] for o in c.load(OUTPUT/'penagent-connectivity.json')['operations']]==[o['response_sha256'] for o in c.load(OUTPUT/'zap-connectivity.json')['operations']]
    except Exception as exc:
        error=type(exc).__name__+': '+str(exc)
    finally:
        (RUNTIME/'closed').touch();stop.set()
        # Ownership label is checked before stopping only containers created above.
        for name in reversed(owned):
            try:
                label=docker(['inspect','--format','{{index .Config.Labels "penagent.phase4b"}}',name],cap=2,cleanup=True)
                assert label=='connectivity-'+ATTEMPT
                state=docker(['inspect','--format','{{.State.Running}}',name],cap=2,cleanup=True)
                if state=='true':docker(['kill',name],cap=2,cleanup=True)
            except Exception as exc:commands.append({'cleanup_error':str(exc),'name':name})
        for file in ['policy.json','anchor.json','armed.json','summary.json','traffic.jsonl']:
            path=RUNTIME/file
            if path.is_file():
                destination=OUTPUT/('gateway-'+file)
                if destination.exists():raise ValueError('Refusing to overwrite gateway evidence')
                destination.write_bytes(path.read_bytes())
        c.save(OUTPUT/'connectivity-run.json',{'error':error,'elapsed_seconds':deadline.clock()-deadline.started,
            'overall_seconds':180,'cleanup_reserve_seconds':10,'commands':commands,'owned_containers':owned,
            'network_retained':TOOL_NETWORK,'active_scans':0,'penagent_probes':0,'forwarding_revoked':(RUNTIME/'closed').exists(),
            'note':'Stopped run-owned gateway/clients; retained their containers/network and all existing targets. No scan APIs called.'})
    if error:raise RuntimeError(error)
    print('Shared benign GET access verified through the same restricted gateway; no active scans or PenAgent probes')

if __name__=='__main__':main()
