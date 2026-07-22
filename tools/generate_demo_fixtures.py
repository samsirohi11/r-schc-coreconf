#!/usr/bin/env python3
"""Generate and verify the deterministic demonstration SCHC fixtures.

The JSON inputs use the OpenSCHC format accepted by rule2sor 0.1.0.
This script deliberately invokes the documented rule2sor executable instead
of importing its implementation, so a missing external tool fails clearly.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "fixtures" / "demo"
SID = DEMO / "ietf-schc@2026-05-07.sid"
RULE2SOR_VERSION = "0.1.0"
RULE2SOR_WHEEL_SHA256 = (
    "8893b4cd5d9f2008cc6a8eb484ff241d84631f5e224ab1b861fc104f6e3631d7"
)
FIXTURES = (
    (DEMO / "initial-rules.json", DEMO / "initial.sor"),
    (DEMO / "updated-rules.json", DEMO / "updated.sor"),
)


def parse_args() -> argparse.Namespace:
    """Parse generator options."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="regenerate in temporary files and compare bytes without modifying fixtures",
    )
    parser.add_argument(
        "--rule2sor",
        type=Path,
        default=Path(os.environ.get("RULE2SOR", "rule2sor")),
        help="rule2sor 0.1.0 executable (default: RULE2SOR or rule2sor)",
    )
    return parser.parse_args()


def run_rule2sor(tool: Path, rules: Path, output: Path) -> bytes:
    """Run the documented rule2sor CLI and return its captured diagnostics."""
    command = [str(tool), str(rules), "-s", str(SID), "-o", str(output), "-q"]
    try:
        completed = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError as error:
        raise SystemExit(
            f"rule2sor executable unavailable: {tool}. "
            f"Install rule2sor=={RULE2SOR_VERSION} and verify wheel SHA-256 "
            f"{RULE2SOR_WHEEL_SHA256}, or pass --rule2sor PATH."
        ) from error
    except OSError as error:
        raise SystemExit(f"cannot execute rule2sor at {tool}: {error}") from error

    if completed.returncode != 0:
        details = (completed.stderr or completed.stdout).strip()
        raise SystemExit(
            f"rule2sor failed with exit status {completed.returncode}: "
            f"{' '.join(command)}\n{details}"
        )
    return completed.stdout.encode() + completed.stderr.encode()


def regenerate(tool: Path, rules: Path, output: Path) -> None:
    """Regenerate one SoR and fail if rule2sor did not produce it."""
    run_rule2sor(tool, rules, output)
    if not output.is_file():
        raise SystemExit(f"rule2sor did not create expected output: {output}")


def check_one(tool: Path, rules: Path, expected: Path) -> None:
    """Check one checked-in SoR and invoke the generator twice for determinism."""
    if not rules.is_file():
        raise SystemExit(f"missing rule source: {rules}")
    if not expected.is_file():
        raise SystemExit(f"missing checked-in SoR: {expected}")

    with tempfile.TemporaryDirectory(prefix="r-schc-demo-") as directory:
        first = Path(directory) / "first.sor"
        second = Path(directory) / "second.sor"
        regenerate(tool, rules, first)
        regenerate(tool, rules, second)
        first_bytes = first.read_bytes()
        second_bytes = second.read_bytes()
        expected_bytes = expected.read_bytes()
        if first_bytes != second_bytes:
            raise SystemExit(f"rule2sor output is nondeterministic for {rules}")
        if first_bytes != expected_bytes:
            raise SystemExit(f"checked-in SoR mismatch: {expected}")
        print(f"{expected.relative_to(ROOT)}: byte-identical and deterministic ({len(first_bytes)} bytes)")


def generate_one(tool: Path, rules: Path, destination: Path) -> None:
    """Generate one checked-in SoR through a temporary file then replace it."""
    DEMO.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="r-schc-demo-") as directory:
        output = Path(directory) / destination.name
        regenerate(tool, rules, output)
        shutil.copyfile(output, destination)
        print(f"generated {destination.relative_to(ROOT)} ({output.stat().st_size} bytes)")


def main() -> None:
    """Generate or verify both demonstration SoRs."""
    args = parse_args()
    if not SID.is_file():
        raise SystemExit(f"missing SID fixture: {SID}")
    tool = args.rule2sor.expanduser()
    if args.check:
        for rules, expected in FIXTURES:
            check_one(tool, rules, expected)
    else:
        for rules, destination in FIXTURES:
            generate_one(tool, rules, destination)
    print(
        f"rule2sor {RULE2SOR_VERSION} expected; wheel SHA-256 "
        f"{RULE2SOR_WHEEL_SHA256}"
    )


if __name__ == "__main__":
    main()
