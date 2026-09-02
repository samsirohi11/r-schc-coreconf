#!/usr/bin/env python3
"""Check the checked-in generic IPv6/UDP RuleID tree against its SoR."""

from __future__ import annotations

import json
from pathlib import Path

import cbor2


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "fixtures" / "generic-ipv6-udp"


def main() -> None:
    """Validate profile/tree metadata and all RuleIDs in the initial SoR."""
    profile = json.loads((FIXTURE / "profile.json").read_text())
    tree = json.loads((FIXTURE / "rule-tree.json").read_text())
    expected = sorted(
        (item["value"], item["length"])
        for item in tree["rules"]
    )
    actual = sorted(
        (rule[2], rule[1])
        for rule in cbor2.loads((FIXTURE / "initial.sor").read_bytes())[2574][23]
    )
    if expected != actual:
        raise SystemExit(f"RuleID tree does not match initial.sor: {actual!r}")
    namespace = tree["dynamic_namespace"]
    if profile["dynamic_rule_ids"] != namespace:
        raise SystemExit("profile dynamic namespace differs from rule-tree source")
    protected = sorted(
        (item["value"], item["length"])
        for item in profile["protected_rule_ids"]
    )
    if protected != sorted(
        (item["value"], item["length"])
        for item in tree["rules"]
        if item["role"] == "protected-management"
    ):
        raise SystemExit("profile protected rules differ from rule-tree source")
    print(f"validated {FIXTURE.relative_to(ROOT)} ({len(actual)} pre-provisioned rules)")


if __name__ == "__main__":
    main()
