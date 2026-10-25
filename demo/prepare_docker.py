"""Prepare isolated deployment config; never create benchmark artifacts."""
import argparse
import ipaddress
import json
import secrets
import subprocess
from pathlib import Path

from cryptography.fernet import Fernet
from dotenv import dotenv_values, set_key


def choose_subnet():
    ids = subprocess.run(["docker", "network", "ls", "-q"], capture_output=True, text=True, check=True).stdout.split()
    existing = []
    if ids:
        networks = json.loads(subprocess.run(["docker", "network", "inspect", *ids], capture_output=True, text=True, check=True).stdout)
        existing = [ipaddress.ip_network(c["Subnet"]) for n in networks for c in (n["IPAM"].get("Config") or []) if c.get("Subnet")]
    for _ in range(100):
        candidate = ipaddress.ip_network(f"172.{secrets.randbelow(11)+20}.{secrets.randbelow(255)}.0/24")
        if all(n.version != 4 or not candidate.overlaps(n) for n in existing):
            return candidate
    raise RuntimeError("No isolated unused test subnet selected")


def prepare():
    env = Path(".env")
    env.touch(exist_ok=True)
    current = dotenv_values(env)
    defaults = {"PENAGENT_STATE_KEY": Fernet.generate_key().decode(), "PENAGENT_SERVICE_TOKEN": secrets.token_urlsafe(32),
        "PENAGENT_API_TOKENS": json.dumps({"operator": secrets.token_urlsafe(32)}), "PENAGENT_LLM_PROVIDER": "none",
        "SIS_HOST_PORT": "9001", "HGS_HOST_PORT": "9002", "EXECUTOR_HOST_PORT": "9003", "INTERPRETER_HOST_PORT": "9004", "REPORT_HOST_PORT": "9005"}
    if not current.get("PENAGENT_TEST_SUBNET"):
        network = choose_subnet()
        defaults.update(PENAGENT_TEST_SUBNET=str(network), PENAGENT_FIXTURE_IP=str(network.network_address + 10))
    for key, value in defaults.items():
        if not current.get(key):
            set_key(str(env), key, value)
    current = dotenv_values(env)
    for directory in ("docker-state", "docker-sis", "docker-hgs"):
        Path("runtime", directory).mkdir(parents=True, exist_ok=True)
    config = {"database": "/data/execution.db", "sis_url": "http://sis:9001", "hgs_url": "http://hgs:9002",
        "interpreter_url": "http://interpreter:9004", "llm_timeout": 20.0, "llm_retries": 1,
        "service_timeout": 60.0, "max_duration": 900.0, "max_probes": 30, "max_llm_calls": 6,
        "targets": {"fixture": {"base_url": f"http://{current['PENAGENT_FIXTURE_IP']}:9010", "credential_refs": ["op_fixture_session.access_token"], "operations": {
            "op_fixture_object": {"method": "GET", "path": "/admin/object", "allowed_headers": ["X-Test-Context"],
                "header_variations": {"X-Test-Context": ["fixture-only"]}, "expectation": {"expected_behavior": "Anonymous clients must not receive tenant-b private data",
                    "protected_fields": ["private_data"], "signal_fields": ["signal"], "forbidden_values": {"owner": "tenant-b"}}},
            # Marked destructive so the Docker verification flow can exercise the
            # Component 5 approval gate against a real running container.
            "op_fixture_denied": {"method": "GET", "path": "/admin/denied", "risk": "destructive"},
            "op_fixture_error": {"method": "GET", "path": "/admin/error"},
            "op_fixture_session": {"method": "GET", "path": "/session", "response_credentials": ["access_token"]},
            "op_fixture_dependent": {"method": "GET", "path": "/objects/{object_id}"}}}}}
    destination = Path("runtime/docker.json")
    if destination.exists():
        # Preserve operator-added policies and journal settings on reruns.
        previous = json.loads(destination.read_text(encoding="utf-8"))
        config.update(previous)
    destination.write_text(json.dumps(config, indent=2), encoding="utf-8")
    print(json.dumps({"status": "prepared", "config": str(destination), "credentials": "existing values preserved; secrets not displayed", "benchmark_files_created": False}))


if __name__ == "__main__":
    prepare()
