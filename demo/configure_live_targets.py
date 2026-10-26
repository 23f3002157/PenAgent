"""Merges the real DVWS/SREBench-API/Juice Shop targets (guided-mode policy,
from demo/eval_targets.py) into runtime/docker.json, alongside the existing
synthetic fixture, so the already-running Docker Compose executor/interpreter
/report containers -- and therefore the UI connected to them -- can run and
watch real audits against the real benchmark container, not only the fixture.

Containers reach the benchmark container (published on the host's loopback,
127.0.0.1:18001-18003) via Docker Desktop's host.docker.internal gateway, not
127.0.0.1 (which inside a container means the container itself). That gateway
IP is numeric (required by penagent_common.policy.origin(), no hostnames) and
is resolved here, not hardcoded, since it can differ by machine/Docker version.

Usage: python -m demo.configure_live_targets
Then:  docker compose restart executor interpreter report
"""
import json
import socket
import subprocess
from pathlib import Path

from demo import eval_targets

CONFIG_PATH = Path("runtime/docker.json")


def container_gateway_ip(container: str = "penagent-local-executor-1") -> str:
    """The numeric IP `host.docker.internal` resolves to from inside a running
    compose container -- how containers reach the host's published ports."""
    result = subprocess.run(
        ["docker", "exec", container, "python3", "-c",
         "import socket; print(socket.gethostbyname('host.docker.internal'))"],
        capture_output=True, text=True, timeout=10, check=True)
    return result.stdout.strip()


def rewrite_base_url(target: dict, gateway_ip: str) -> dict:
    target = dict(target)
    for loopback_host in ("127.0.0.1", "localhost"):
        if f"://{loopback_host}:" in target["base_url"]:
            target["base_url"] = target["base_url"].replace(loopback_host, gateway_ip)
    return target


def main():
    if not CONFIG_PATH.exists():
        raise SystemExit(f"{CONFIG_PATH} not found -- run `python -m demo.prepare_docker` first.")
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    gateway_ip = container_gateway_ip()
    live_targets = eval_targets.all_targets("guided")
    for target_id, target in live_targets.items():
        config["targets"][target_id] = rewrite_base_url(target, gateway_ip)
    CONFIG_PATH.write_text(json.dumps(config, indent=2), encoding="utf-8")
    print(json.dumps({"status": "configured", "gateway_ip": gateway_ip,
        "targets_added": list(live_targets.keys()),
        "next_step": "docker compose restart executor interpreter report"}))


if __name__ == "__main__":
    main()
