#!/usr/bin/env python3
"""Derive reproducible namespace-demo proof lines from endpoint logs."""

from __future__ import annotations

import argparse
import math
import re
from dataclasses import dataclass
from pathlib import Path

REPORT_RE = re.compile(
    r"^(TX|RX)\s+(APP|MGMT)\s+(\d+)/(\d+)\s+(\d+) B -> (\d+) B$"
)
MEANINGFUL_RE = re.compile(r"^\s+meaningful\s+(\d+) bits$")
PADDED_RE = re.compile(r"^\s+padded\s+(\d+) B$")
CODE_RE = re.compile(r"^\s+code\s+0x([0-9a-fA-F]+)\s+")
MID_RE = re.compile(r"^\s+message ID\s+(\d+)$")


@dataclass(frozen=True)
class Report:
    direction: str
    traffic: str
    rule: str
    packet_bytes: int
    transmitted_bytes: int
    meaningful_bits: int | None
    code: int | None
    message_id: int | None


def parse_reports(text: str) -> list[Report]:
    """Parse concise and debug report fields without depending on log timing."""
    parsed: list[dict[str, int | str | None]] = []
    for line in text.splitlines():
        match = REPORT_RE.match(line)
        if match:
            parsed.append(
                {
                    "direction": match.group(1),
                    "traffic": match.group(2),
                    "rule": f"{match.group(3)}/{match.group(4)}",
                    "packet_bytes": int(match.group(5)),
                    "transmitted_bytes": int(match.group(6)),
                    "meaningful_bits": None,
                    "code": None,
                    "message_id": None,
                }
            )
            continue
        if not parsed:
            continue
        meaningful = MEANINGFUL_RE.match(line)
        if meaningful:
            parsed[-1]["meaningful_bits"] = int(meaningful.group(1))
            continue
        padded = PADDED_RE.match(line)
        if padded:
            parsed[-1]["transmitted_bytes"] = int(padded.group(1))
            continue
        code = CODE_RE.match(line)
        if code:
            parsed[-1]["code"] = int(code.group(1), 16)
            continue
        mid = MID_RE.match(line)
        if mid:
            parsed[-1]["message_id"] = int(mid.group(1))

    return [Report(**item) for item in parsed]


def _fail(message: str) -> None:
    raise ValueError(message)


def _same_reports(left: list[Report], right: list[Report], label: str) -> None:
    if len(left) != len(right):
        _fail(f"{label} report count mismatch: {len(left)} != {len(right)}")
    for index, (a, b) in enumerate(zip(left, right)):
        if (a.rule, a.packet_bytes, a.transmitted_bytes, a.meaningful_bits) != (
            b.rule,
            b.packet_bytes,
            b.transmitted_bytes,
            b.meaningful_bits,
        ):
            _fail(f"{label} report mismatch at index {index}: {a} != {b}")
        if a.code is not None and b.code is not None and a.code != b.code:
            _fail(f"{label} CoAP code mismatch at index {index}")
        if a.message_id is not None and b.message_id is not None and a.message_id != b.message_id:
            _fail(f"{label} CoAP MID mismatch at index {index}")


def _with_code(reports: list[Report], code: int) -> list[Report]:
    selected = [report for report in reports if report.code == code]
    if not selected:
        _fail(f"no reports with CoAP code {code}")
    return selected


def _meaningful_bits(report: Report, label: str) -> int:
    if report.meaningful_bits is None:
        _fail(f"{label} report has no meaningful SCHC bit count")
    expected_bytes = math.ceil(report.meaningful_bits / 8)
    if report.transmitted_bytes != expected_bytes:
        _fail(
            f"{label} padded size is {report.transmitted_bytes}, "
            f"expected {expected_bytes} for {report.meaningful_bits} bits"
        )
    return report.meaningful_bits


def _validate_report_bits(reports: list[Report], label: str) -> None:
    for index, report in enumerate(reports):
        _meaningful_bits(report, f"{label} report {index}")


def derive_proof(core_text: str, device_text: str, server_text: str, client_text: str) -> str:
    core = parse_reports(core_text)
    device = parse_reports(device_text)
    _validate_report_bits(core, "core")
    _validate_report_bits(device, "device")
    server_rx = re.findall(r"^RX APP\s+(\d+) B$", server_text, re.MULTILINE)
    core_app_tx = [r for r in core if r.direction == "TX" and r.traffic == "APP"]
    device_app_rx = [r for r in device if r.direction == "RX" and r.traffic == "APP"]
    device_app_tx = [r for r in device if r.direction == "TX" and r.traffic == "APP"]
    core_app_rx = [r for r in core if r.direction == "RX" and r.traffic == "APP"]
    _same_reports(core_app_tx, device_app_rx, "core TX/device RX application")
    _same_reports(device_app_tx, core_app_rx, "device TX/core RX application")
    if len(server_rx) != len(core_app_tx):
        _fail(
            f"application server saw {len(server_rx)} requests, "
            f"but core forwarded {len(core_app_tx)} application packets"
        )
    if "MGMT" in server_text:
        _fail("application server log contains management traffic")

    fetch_before_after = _with_code(core_app_tx, 5)
    if len(fetch_before_after) < 2:
        _fail("need FETCH reports before and after duplicate management")
    before = fetch_before_after[0]
    after = fetch_before_after[-1]
    if before.rule != "25/8" or after.rule != "22/8":
        _fail(f"adaptive RuleIDs were {before.rule} and {after.rule}")
    if before.packet_bytes != after.packet_bytes:
        _fail(
            "adaptive FETCH changed the original packet size: "
            f"{before.packet_bytes} != {after.packet_bytes}"
        )
    before_bits = _meaningful_bits(before, "fallback FETCH")
    after_bits = _meaningful_bits(after, "specialized FETCH")
    saved = before_bits - after_bits
    if saved <= 0:
        _fail(f"specialized FETCH did not reduce SCHC bits: {before_bits} -> {after_bits}")
    padded_saved = before.transmitted_bytes - after.transmitted_bytes

    duplicate = [
        report
        for report in core
        if report.direction == "TX" and report.traffic == "MGMT" and report.rule == "29/8"
    ]
    duplicate_rx = [
        report
        for report in device
        if report.direction == "RX" and report.traffic == "MGMT" and report.rule == "29/8"
    ]
    if len(duplicate) != 1 or len(duplicate_rx) != 1:
        _fail(f"duplicate management was transmitted {len(duplicate)} times")
    duplicate_report = duplicate[0]
    _same_reports(duplicate, duplicate_rx, "duplicate management")
    duplicate_bits = _meaningful_bits(duplicate_report, "duplicate management")
    if duplicate_report.message_id is None:
        _fail("duplicate management report has no CoAP message ID")
    duplicate_responses = [
        report
        for report in device
        if report.direction == "TX"
        and report.traffic == "MGMT"
        and report.message_id == duplicate_report.message_id
    ]
    if duplicate_responses:
        _fail("duplicate management produced a response")
    if "OK duplicate 20/8 -> 22/8  local=installed  remote=unacknowledged" not in core_text:
        _fail("core duplicate completion line is missing")
    if not re.search(r"^OK duplicate\s+local=(installed|idempotent)\s+response=none$", device_text, re.MULTILINE):
        _fail("device duplicate completion line is missing")
    if core_text.count("OK context check  equal") < 3:
        _fail("context checks did not prove initial, update, and duplicate equality")

    for expected in ("OK set", "OK delete", "OK reload", "not found"):
        if expected not in client_text:
            _fail(f"client result is missing {expected!r}")
    break_even = math.ceil(duplicate_bits / saved)
    return "\n".join(
        [
            "DEMO PROOF namespaces=3 processes=4",
            "DEMO PROOF application_before "
            f"rule={before.rule} original_bytes={before.packet_bytes} "
            f"meaningful_bits={before_bits} transmitted_bytes={before.transmitted_bytes}",
            "DEMO PROOF duplicate_management "
            f"rule={duplicate_report.rule} original_bytes={duplicate_report.packet_bytes} "
            f"meaningful_bits={duplicate_bits} "
            f"transmitted_bytes={duplicate_report.transmitted_bytes} response=none",
            "DEMO PROOF application_after "
            f"rule={after.rule} original_bytes={after.packet_bytes} "
            f"meaningful_bits={after_bits} transmitted_bytes={after.transmitted_bytes}",
            "DEMO PROOF application_savings "
            f"meaningful_bits_saved={saved} transmitted_bytes_saved={padded_saved} "
            f"break_even_packets={break_even}",
            "DEMO PROOF management_internal=yes application_server_management_requests=0",
            "DEMO COMPLETE namespaces=3 processes=4 management_internal=yes application_e2e=yes",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-log", type=Path, required=True)
    parser.add_argument("--device-log", type=Path, required=True)
    parser.add_argument("--server-log", type=Path, required=True)
    parser.add_argument("--client-log", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(
            derive_proof(
                args.core_log.read_text(),
                args.device_log.read_text(),
                args.server_log.read_text(),
                args.client_log.read_text(),
            )
        )
    except (OSError, ValueError) as error:
        print(f"DEMO ERROR proof validation failed: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
