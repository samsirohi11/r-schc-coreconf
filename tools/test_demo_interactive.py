#!/usr/bin/env python3
"""Exercise interactive demo command construction without Linux networking."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "tools" / "run_demo_interactive.sh"


def run_print_commands(name: str) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory(prefix="schc-demo-terminal-") as directory:
        fake = Path(directory) / name
        fake.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake.chmod(0o700)
        environment = os.environ.copy()
        environment["PATH"] = f"{directory}:{environment.get('PATH', '')}"
        environment["DEMO_TERMINAL"] = name
        return subprocess.run(
            ["bash", str(LAUNCHER), "--print-commands"],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )


def main() -> None:
    ghostty = run_print_commands("ghostty")
    assert ghostty.returncode == 0, ghostty.stderr
    assert ghostty.stdout.count("ROLE ") == 4
    assert "ROLE device:" in ghostty.stdout
    assert "ROLE core:" in ghostty.stdout
    assert "ROLE server:" in ghostty.stdout
    assert "ROLE client:" in ghostty.stdout
    assert "sudo ip netns exec" in ghostty.stdout
    assert "demo_role.sh --root" in ghostty.stdout
    assert "--title=Device -e" in ghostty.stdout

    with tempfile.TemporaryDirectory(prefix="schc-demo-ready-") as directory:
        stale_log = Path(directory) / "stale-role.log"
        stale_launcher = subprocess.run(
            [
                "bash",
                "-c",
                'error() { printf "ERROR %s\\n" "$*" >&2; exit 1; }; '
                'source "$1"; (sleep 1; printf "READY role\\n" >"$2") & '
                '(exit 0) & launcher=$!; wait "$launcher"; '
                'wait_for_literal "$2" "READY role" "$launcher" 2',
                "test-demo-readiness",
                str(ROOT / "tools" / "demo_common.sh"),
                str(stale_log),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        assert stale_launcher.returncode != 0
        assert "exited before 'READY role'" in stale_launcher.stderr

        log = Path(directory) / "role.log"
        delayed_ready = subprocess.run(
            [
                "bash",
                "-c",
                'error() { printf "ERROR %s\\n" "$*" >&2; exit 1; }; '
                'source "$1"; (sleep 0.1; printf "READY role\\n" >"$2") & '
                'wait_for_literal "$2" "READY role" "" 2',
                "test-demo-readiness",
                str(ROOT / "tools" / "demo_common.sh"),
                str(log),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        assert delayed_ready.returncode == 0, delayed_ready.stderr

        status_log = Path(directory) / "status.log"
        status_file = Path(directory) / "status"
        role = subprocess.run(
            [
                "bash",
                str(ROOT / "tools" / "demo_role.sh"),
                "--root",
                str(status_log),
                str(status_file),
                "bash",
                "-c",
                "printf 'role output\\n'; exit 7",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        assert role.returncode == 7
        assert status_file.read_text(encoding="utf-8").strip() == "7"
        assert "role output" in status_log.read_text(encoding="utf-8")

    gnome = run_print_commands("gnome-terminal")
    assert gnome.returncode == 0, gnome.stderr
    assert "--window --title Device --wait --" in gnome.stdout

    environment = os.environ.copy()
    environment["DEMO_TERMINAL"] = "not-a-supported-terminal"
    missing = subprocess.run(
        ["bash", str(LAUNCHER), "--print-commands"],
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )
    assert missing.returncode != 0
    assert "was not found on PATH" in missing.stderr
    assert "DEMO SETUP" not in missing.stdout

    with tempfile.TemporaryDirectory(prefix="schc-demo-no-terminal-") as directory:
        basename = shutil.which("basename")
        dirname = shutil.which("dirname")
        assert basename is not None
        assert dirname is not None
        os.symlink(basename, Path(directory) / "basename")
        os.symlink(dirname, Path(directory) / "dirname")
        environment = os.environ.copy()
        environment["PATH"] = directory
        environment.pop("DEMO_TERMINAL", None)
        unavailable = subprocess.run(
            ["/bin/bash", str(LAUNCHER)],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
    assert unavailable.returncode != 0
    assert "no supported terminal found" in unavailable.stderr
    assert "DEMO_TERMINAL=ghostty" in unavailable.stderr
    for role in ("device", "core", "server", "client"):
        assert f"ROLE {role}: sudo ip netns exec" in unavailable.stdout
    print("interactive demo command tests: 7 cases passed")


if __name__ == "__main__":
    main()
