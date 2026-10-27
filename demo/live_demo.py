"""Paced, step-by-step driver for watching PenAgent work against a real target
through the UI. Submits each step of demo/run_evaluation.py's GUIDED_CHAINS
through the real, already-running C3/C4/C6 HTTP services (not in-process), one
probe at a time with a pause in between, so a person watching the Console's
Explore tab sees each node light up live.

Prerequisites (one-time): the target's spec has been ingested into C1 and its
TargetPolicy merged into the running executor/interpreter/report containers.
See demo/configure_live_targets.py and the ingest commands in
docs/WALKTHROUGH.md's "watch it live" section.

Usage: python -m demo.live_demo juice-shop --audit demo-live-1 --pause 3
"""
import argparse
import json
import secrets
import time
import urllib.error
import urllib.request

from demo.eval_targets import all_targets
from demo.run_evaluation import GUIDED_CHAINS


def _env_token(key: str) -> str:
    from dotenv import dotenv_values
    return dotenv_values(".env")[key]


def call(base, method, path, token, payload=None):
    headers = {"Content-Type": "application/json", "Authorization": "Bearer " + token}
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read()
            return json.loads(body) if body else None
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise RuntimeError(f"{exc.code} {path}: {detail}") from exc


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", choices=sorted(GUIDED_CHAINS))
    parser.add_argument("--audit", default=None, help="Audit ID to create (default: <target>-live-<random>)")
    parser.add_argument("--pause", type=float, default=3.0, help="Seconds between steps, for watching it unfold")
    parser.add_argument("--c3", default="http://127.0.0.1:9003")
    parser.add_argument("--c4", default="http://127.0.0.1:9004")
    args = parser.parse_args()

    operator_token = json.loads(_env_token("PENAGENT_API_TOKENS"))["operator"]
    machine_token = _env_token("PENAGENT_SERVICE_TOKEN")
    operator = "operator"  # must match the principal name PENAGENT_API_TOKENS maps that token to

    audit = args.audit or f"{args.target}-live-{secrets.token_hex(3)}"
    print(f"Creating audit '{audit}' against '{args.target}' -- open it in the Console now.")
    call(args.c3, "POST", "/v1/audits", operator_token,
         {"audit_id": audit, "target_id": args.target, "acknowledged_authorization": True})

    operations = all_targets()[args.target]["operations"]
    chain = GUIDED_CHAINS[args.target]
    # No live Python state to capture into here -- this script replays each
    # step through the real, already-running C3 over plain HTTP, and the
    # public probe-result endpoint never returns raw response bodies (by
    # design: see penagent_common.policy.redact). A step whose binding needs
    # an earlier step's captured value (Juice Shop's basket id) has nothing
    # to resolve it with and is skipped, cleanly, with an explanation --
    # not guessed, not silently sent with a placeholder.
    ctx = {"email": f"live-{secrets.token_hex(6)}@test.local", "password": "Test1234!"}
    for i, step in enumerate(chain):
        op_id = step["op"]
        try:
            binding = step["binding"](ctx) if callable(step["binding"]) else step["binding"]
        except KeyError:
            print(f"\n[{i + 1}/{len(chain)}] {op_id} -- skipped (needs a value from an earlier step this "
                  f"HTTP-only demo can't observe; the public probe result never returns a raw response body)")
            continue
        categories = operations.get(op_id, {}).get("expectation", {}).get("owasp_categories") or []
        category = categories[0] if categories else "guided-demo"
        hypothesis = {"id": f"{audit}-h{i}", "target_endpoints": [op_id], "owasp_category": category,
                      "attack_sequence": [{"step": 1, "op": op_id}]}
        print(f"\n[{i + 1}/{len(chain)}] {op_id} ...")
        result = call(args.c3, "POST", f"/v1/audits/{audit}/probes", operator_token,
                      {"hypothesis": hypothesis, "probe": {"hypothesis_id": hypothesis["id"], "op": op_id, "binding": binding}})
        print(f"    -> {result['status']} (HTTP {result.get('status_code')})")

        if result["status"] == "awaiting_approval":
            print("    -> paused for Component 5 approval -- approve/deny it live in the Console's Approvals tab")
            print("       (waiting up to 60s for your decision before moving on...)")
            for _ in range(20):
                time.sleep(3)
                approvals = call(args.c3, "GET", f"/v1/audits/{audit}/approvals", operator_token)
                current = next((a for a in approvals["approvals"] if a["probe_id"] == result["probe_id"]), None)
                if current and current["status"] != "pending":
                    print(f"    -> {current['status']} by operator")
                    break
            else:
                print("    -> no decision yet; moving on (resolve it later from the Console)")
            time.sleep(args.pause)
            continue

        if result["status"] == "executed":
            interpretation = call(args.c4, "POST", f"/v1/audits/{audit}/interpret", machine_token,
                                   {"owner": operator, "probe_id": result["probe_id"]})
            print(f"    -> classified {interpretation['classification']}: {interpretation['reasoning_summary']}")
        time.sleep(args.pause)

    print(f"\nDone. Audit '{audit}' -- check the Report tab in the Console for the full write-up.")


if __name__ == "__main__":
    main()
