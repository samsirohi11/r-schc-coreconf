#!/usr/bin/env python3
"""Generate the managed fixture from pinned submodule content.

The final management SoR is deferred, while this foundation needs a
reproducible context and explicit protected slots.
"""

import argparse
from hashlib import sha256
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
RSCHC = ROOT / "deps" / "r-schc"
OUT = ROOT / "fixtures" / "managed"
PINNED_RSCHC = "cf0b9bc"
PINNED_RUSTCONF = "1611ec1"
FIXTURES = {
    "ietf-schc@2026-05-07.sid": (
        "fixtures/core/ietf-schc@2026-05-07.sid",
        "9053856d017170092aa066f47d559169df87b71c0b32e7b702542c2b37eb78ff",
    ),
    "core.sor": (
        "fixtures/core/core.sor",
        "1896b1d1fb5bda7be889ea10523560fe1c2cbe89595510fd453eeeeffd88c4a6",
    ),
}


def git_show(repository: Path, revision: str, path: str) -> bytes:
    """Read one immutable blob from a dependency revision."""
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository), "show", f"{revision}:{path}"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"cannot read {repository} at {revision}:{path}: {error}") from error
    return completed.stdout


def parse_args() -> argparse.Namespace:
    """Parse generator options."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify checked-in fixtures without modifying them",
    )
    return parser.parse_args()


def fixture_path(name: str) -> Path:
    """Resolve one allowlisted fixture name to its fixed destination."""
    if name == "ietf-schc@2026-05-07.sid":
        return OUT / "ietf-schc@2026-05-07.sid"
    if name == "core.sor":
        return OUT / "core.sor"
    raise SystemExit(f"unknown fixture name: {name}")


def write_fixture(name: str, content: bytes) -> None:
    """Write one allowlisted fixture without accepting a caller-supplied path."""
    if name == "ietf-schc@2026-05-07.sid":
        (OUT / "ietf-schc@2026-05-07.sid").write_bytes(content)
        return
    if name == "core.sor":
        (OUT / "core.sor").write_bytes(content)
        return
    raise SystemExit(f"unknown fixture name: {name}")


def main() -> None:
    """Generate or verify every pinned fixture."""
    args = parse_args()
    if not args.check:
        OUT.mkdir(parents=True, exist_ok=True)

    for name, (source_path, expected_hash) in FIXTURES.items():
        content = git_show(RSCHC, PINNED_RSCHC, source_path)
        actual_hash = sha256(content).hexdigest()
        if actual_hash != expected_hash:
            raise SystemExit(
                f"unexpected hash for {source_path} at {PINNED_RSCHC}: "
                f"{actual_hash} != {expected_hash}"
            )

        destination = fixture_path(name)
        if args.check:
            if not destination.is_file():
                raise SystemExit(f"missing checked-in fixture: {destination}")
        else:
            write_fixture(name, content)

        checked_in = destination.read_bytes()
        checked_in_hash = sha256(checked_in).hexdigest()
        if checked_in_hash != expected_hash or checked_in != content:
            raise SystemExit(f"checked-in fixture mismatch: {destination}")
        action = "verified" if args.check else "generated"
        sys.stdout.write(
            f"{name}: {action} from r-schc {PINNED_RSCHC} "
            f"(sha256 {expected_hash})\n"
        )

    sys.stdout.write(
        f"r-schc {PINNED_RSCHC}; rustconf {PINNED_RUSTCONF} "
        "(recorded dependency revision)\n"
    )


if __name__ == "__main__":
    main()
