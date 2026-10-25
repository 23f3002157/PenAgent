"""Run from repository root: python -m demo.run --output reports/demo.json"""
import argparse
import json
import tempfile
from pathlib import Path
from demo.harness import demonstration


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="reports/demo.json")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="penagent-fixture-") as directory:
        result = demonstration(directory)
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(path), "probes": len(result["trace"]["probes"]), "classifications": sorted({p["interpretation"]["classification"] for p in result["trace"]["probes"] if p["interpretation"]})}))


if __name__ == "__main__":
    main()
