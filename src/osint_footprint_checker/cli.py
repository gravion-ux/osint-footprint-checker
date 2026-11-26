"""CLI for osint-footprint-checker."""
import argparse
import json
import sys
from pathlib import Path

from .checks import run_checks, score


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Score the public footprint of an asset you own.")
    p.add_argument("snapshot", help="JSON snapshot of your asset's public footprint")
    p.add_argument("--format", choices=["text", "json"], default="text")
    args = p.parse_args(argv)
    snapshot = json.loads(Path(args.snapshot).read_text(encoding="utf-8"))
    findings = run_checks(snapshot)
    result = {"score": score(findings),
              "findings": [{"check": f.check, "severity": f.severity,
                            "detail": f.detail, "fix": f.fix} for f in findings]}
    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(f"Footprint score: {result['score']}/100")
        for f in findings:
            print(f"[{f.severity}] {f.check}: {f.detail}")
            print(f"    fix: {f.fix}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
