"""Run a benchmark scenario: python -m bench.run SCENARIO [--calls N] [--seed S] [--json]

    python -m bench.run --list
    python -m bench.run single --calls 500 --seed 20261126
    python -m bench.run --all --seed 20261126

Prints the machine spec and the seed with every result. It sets no threshold and exits 0 when the
scenario ran. See bench/README.md.
"""

from __future__ import annotations

import argparse
import json
import sys

from bench import harness

DEFAULT_SEED = 20261126


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Gate benchmark harness.")
    parser.add_argument("scenario", nargs="?")
    parser.add_argument("--calls", type=int)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--json", action="store_true", help="one JSON object per result")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--all", action="store_true")
    args = parser.parse_args(argv)
    if args.list:
        for name, spec in harness.SCENARIOS.items():
            print(f"{name:18} {spec['doc']}")
        return 0
    names = list(harness.SCENARIOS) if args.all else [args.scenario]
    if not names or names == [None]:
        parser.error("name a scenario, or use --list or --all")
    for name in names:
        if name not in harness.SCENARIOS:
            parser.error(f"unknown scenario {name!r}; see --list")
        result = harness.run_scenario(name, args.seed, args.calls)
        print(json.dumps(result) if args.json else harness.render(result) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
