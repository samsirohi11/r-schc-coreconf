#!/usr/bin/env python3
"""Generate and verify the deterministic demonstration SCHC fixtures."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "fixtures" / "demo"
SID = DEMO / "ietf-schc@2026-09-22.sid"
RULES = DEMO / "initial-rules.json"
SOR = DEMO / "initial.sor"


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
        required=True,
        help="path to a compatible rule2sor executable or source/package directory",
    )
    return parser.parse_args()


def run_rule2sor(tool: Path, rules: Path, output: Path) -> None:
    """Run rule2sor from an explicit executable or source directory."""
    environment = None
    if tool.is_dir():
        command = [sys.executable, "-m", "rule2sor.cli"]
        environment = os.environ.copy()
        source_path = tool.resolve()
        source_root = str(
            source_path.parent if (source_path / "__init__.py").is_file() else source_path
        )
        environment["PYTHONPATH"] = os.pathsep.join(
            part for part in (source_root, environment.get("PYTHONPATH")) if part
        )
    else:
        command = [str(tool)]
    command.extend([str(rules), "-s", str(SID), "-o", str(output), "-q"])
    try:
        completed = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
        )
    except FileNotFoundError as error:
        raise SystemExit(
            f"rule2sor tool unavailable: {tool}; install a compatible package or "
            "clone its repository, then pass its executable or source directory "
            "with --rule2sor PATH."
        ) from error
    except OSError as error:
        raise SystemExit(f"cannot execute rule2sor at {tool}: {error}") from error

    if completed.returncode != 0:
        details = (completed.stderr or completed.stdout).strip()
        raise SystemExit(
            f"rule2sor failed with exit status {completed.returncode}: "
            f"{' '.join(command)}\n{details}"
        )


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
    """Generate or verify the checked-in demonstration SoR."""
    args = parse_args()
    if not SID.is_file():
        raise SystemExit(f"missing SID fixture: {SID}")
    tool = args.rule2sor.expanduser()
    if args.check:
        check_one(tool, RULES, SOR)
    else:
        generate_one(tool, RULES, SOR)


if __name__ == "__main__":
    main()
