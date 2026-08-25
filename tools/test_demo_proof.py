#!/usr/bin/env python3
import unittest

from demo_proof import derive_proof, parse_reports


def report(direction, traffic, rule, packet, padded, bits, code, message_id=1):
    return (
        f"{direction} {traffic:<4}  {rule}  {packet} B -> {padded} B\n"
        f"  CoAP\n    code              0x{code:02x} FETCH\n"
        f"    message ID        {message_id}\n"
        f"  SCHC\n    meaningful      {bits} bits\n    padded           {padded} B\n"
    )


def valid_logs(before_bits=149, after_bits=101, after_padded=13):
    core = (
        report("TX", "APP", "25/8", 73, 19, before_bits, 5)
        + report("RX", "APP", "21/8", 60, 8, 60, 69)
        + report("TX", "MGMT", "29/8", 91, 17, 131, 2)
        + report("RX", "APP", "21/8", 60, 8, 60, 69)
        + report("TX", "APP", "22/8", 73, after_padded, after_bits, 5)
        + "OK duplicate 20/8 -> 22/8  local=installed  remote=unacknowledged\n"
        + "OK context check  equal\n" * 3
    )
    device = (
        report("RX", "APP", "25/8", 73, 19, before_bits, 5)
        + report("TX", "APP", "21/8", 60, 8, 60, 69)
        + report("RX", "MGMT", "29/8", 91, 17, 131, 2)
        + report("TX", "APP", "21/8", 60, 8, 60, 69)
        + report("RX", "APP", "22/8", 73, after_padded, after_bits, 5)
        + "OK duplicate  local=installed  response=none\n"
    )
    server = "RX APP   73 B\nRX APP   73 B\n"
    client = "7\n42\nnot found\nOK set\nOK delete\nOK reload\n"
    return core, device, server, client


class DemoProofTests(unittest.TestCase):
    def test_parse_reports_keeps_direction_sizes_code_and_mid(self):
        reports = parse_reports(report("TX", "APP", "25/8", 73, 19, 149, 5))
        self.assertEqual(len(reports), 1)
        self.assertEqual(
            reports[0],
            reports[0].__class__("TX", "APP", "25/8", 73, 19, 149, 5, 1),
        )

    def test_derive_proof_calculates_observed_savings_and_break_even(self):
        proof = derive_proof(*valid_logs())
        self.assertIn("application_savings meaningful_bits_saved=48", proof)
        self.assertIn("transmitted_bytes_saved=6 break_even_packets=3", proof)
        self.assertIn("application_before rule=25/8", proof)
        self.assertIn("application_after rule=22/8", proof)

    def test_derive_proof_rejects_missing_meaningful_bits(self):
        core, device, server, client = valid_logs()
        core = core.replace("    meaningful      149 bits\n", "")
        with self.assertRaisesRegex(ValueError, "has no meaningful SCHC bit count"):
            derive_proof(core, device, server, client)

    def test_derive_proof_rejects_invalid_padding(self):
        logs = valid_logs(after_bits=105, after_padded=13)
        with self.assertRaisesRegex(ValueError, "expected 14 for 105 bits"):
            derive_proof(*logs)

    def test_derive_proof_rejects_no_compression_improvement(self):
        logs = valid_logs(after_bits=149, after_padded=19)
        with self.assertRaisesRegex(ValueError, "did not reduce SCHC bits"):
            derive_proof(*logs)

    def test_derive_proof_rejects_duplicate_retry(self):
        core, device, server, client = valid_logs()
        core = core.replace(
            report("TX", "MGMT", "29/8", 91, 17, 131, 2),
            report("TX", "MGMT", "29/8", 91, 17, 131, 2) * 2,
        )
        device = device.replace(
            report("RX", "MGMT", "29/8", 91, 17, 131, 2),
            report("RX", "MGMT", "29/8", 91, 17, 131, 2) * 2,
        )
        with self.assertRaisesRegex(ValueError, "transmitted 2 times"):
            derive_proof(core, device, server, client)

    def test_derive_proof_rejects_duplicate_response_with_matching_mid(self):
        core, device, server, client = valid_logs()
        device = device.replace(
            "OK duplicate  local=installed  response=none\n",
            report("TX", "MGMT", "17/8", 60, 8, 60, 69)
            + "OK duplicate  local=installed  response=none\n",
        )
        with self.assertRaisesRegex(ValueError, "produced a response"):
            derive_proof(core, device, server, client)


if __name__ == "__main__":
    unittest.main()
