#!/usr/bin/env python3
"""Check the checked-in generic IPv6/UDP RuleID tree against its SoR."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import cbor2


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "generic-ipv6-udp"
SID = FIXTURE / "ietf-schc@2026-09-22.sid"


def regenerate(tool: Path, rules: Path, output: Path) -> None:
    """Regenerate one SoR through an explicit command or source directory."""
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
            command, check=False, capture_output=True, text=True, env=environment
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
        raise SystemExit(f"rule2sor failed: {' '.join(command)}\n{details}")
    if not output.is_file():
        raise SystemExit(f"rule2sor did not create expected output: {output}")


def parse_args() -> argparse.Namespace:
    """Parse optional fixture regeneration arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--rule2sor",
        type=Path,
        help="optionally regenerate with a compatible rule2sor executable or source/package directory",
    )
    return parser.parse_args()


def main() -> None:
    """Validate profile/tree metadata and all RuleIDs in the initial SoR."""
    args = parse_args()
    profile = json.loads((FIXTURE / "profile.json").read_text())
    tree = json.loads((FIXTURE / "rule-tree.json").read_text())
    source = json.loads((FIXTURE / "rules.json").read_text())
    expected = sorted(
        (item["value"], item["length"])
        for item in tree["rules"]
    )
    sid = json.loads(SID.read_text())
    sid_items = sid["ietf-sid-file:sid-file"]["item"]
    root_sid = next(item["sid"] for item in sid_items
                    if item["namespace"] == "data" and item["identifier"] == "/ietf-schc:schc")
    decoded = cbor2.loads((FIXTURE / "initial.sor").read_bytes())
    root = decoded[root_sid]
    rule_list = next(
        value for value in root.values()
        if isinstance(value, list) and value and isinstance(value[0], dict)
        and 1 in value[0] and 2 in value[0]
    )
    actual = sorted(
        (rule[2], rule[1])
        for rule in rule_list
    )
    if expected != actual:
        raise SystemExit(f"RuleID tree does not match initial.sor: {actual!r}")
    namespace = tree["dynamic_namespace"]
    if profile["dynamic_rule_ids"] != namespace:
        raise SystemExit("profile dynamic namespace differs from rule-tree source")
    management_sid = next(item["sid"] for item in sid_items
                          if item["namespace"] == "identity"
                          and item["identifier"] == "nature-management")
    actual_management = sorted(
        (rule[2], rule[1]) for rule in rule_list if rule.get(3) == management_sid
    )
    expected_management = sorted(
        (rule["RuleID"], rule["RuleIDLength"])
        for rule in source["SoR"] if rule.get("RuleNature", "").lower() == "management"
    )
    if actual_management != expected_management:
        raise SystemExit(
            f"decoded management natures differ from rules.json: {actual_management!r}"
        )
    rules = FIXTURE / "rules.json"
    if args.rule2sor is not None:
        tool = args.rule2sor.expanduser()
        with tempfile.TemporaryDirectory(prefix="r-schc-generic-") as directory:
            first = Path(directory) / "first.sor"
            second = Path(directory) / "second.sor"
            regenerate(tool, rules, first)
            regenerate(tool, rules, second)
            if first.read_bytes() != second.read_bytes():
                raise SystemExit("rule2sor output is nondeterministic")
            if first.read_bytes() != (FIXTURE / "initial.sor").read_bytes():
                raise SystemExit("checked-in generic initial.sor mismatch")
    print(
        f"validated {FIXTURE.relative_to(ROOT)} ({len(actual)} pre-provisioned rules; "
        f"{len(actual_management)} management-nature rules)"
    )


if __name__ == "__main__":
    main()
