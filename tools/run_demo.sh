#!/usr/bin/env bash
# Run the complete localhost SCHC/CORECONF demonstration without root privileges.
set -Eeuo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"
BUILD_DEMO_BINARIES=${DEMO_BUILD:-1}
BIN_DIR=${DEMO_BIN_DIR:-"$ROOT/target/debug"}
DEVICE_LINK_PORT=${DEMO_DEVICE_LINK_PORT:-41081}
CORE_LINK_PORT=${DEMO_CORE_LINK_PORT:-41082}
CORE_APP_PORT=${DEMO_CORE_APP_PORT:-41083}

DEVICE="$BIN_DIR/schc-coreconf-device"
CORE="$BIN_DIR/schc-coreconf-core"
CLIENT="$BIN_DIR/schc-data-client"
APP_SID="$ROOT/fixtures/demo/demo-data.sid"
APP_DATA="$ROOT/fixtures/demo/app-data.json"

TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/schc-coreconf-demo.XXXXXX")
CORE_FIFO="$TMP_DIR/core.stdin"
DEVICE_LOG="$TMP_DIR/device.log"
CORE_LOG="$TMP_DIR/core.log"
BEFORE_LOG="$TMP_DIR/client-before.log"
AFTER_LOG="$TMP_DIR/client-after.log"
DEVICE_PID=""
CORE_PID=""
cleanup() {
	local status=$1
	set +e
	{ exec 3>&-; } 2>/dev/null || true
	if [[ -n "$CORE_PID" ]] && kill -0 "$CORE_PID" 2>/dev/null; then
		kill "$CORE_PID" 2>/dev/null || true
	fi
	if [[ -n "$DEVICE_PID" ]] && kill -0 "$DEVICE_PID" 2>/dev/null; then
		kill "$DEVICE_PID" 2>/dev/null || true
	fi
	if [[ -n "$CORE_PID" ]]; then
		wait "$CORE_PID" 2>/dev/null || true
	fi
	if [[ -n "$DEVICE_PID" ]]; then
		wait "$DEVICE_PID" 2>/dev/null || true
	fi
	if [[ "$status" -ne 0 ]]; then
		printf 'DEMO FAILED; captured logs follow:\n' >&2
		for log in "$DEVICE_LOG" "$CORE_LOG" "$BEFORE_LOG" "$AFTER_LOG"; do
			if [[ -f "$log" ]]; then
				printf '%s:\n' "$log" >&2
				cat "$log" >&2
			fi
		done
	fi
	rm -rf "$TMP_DIR"
}
trap 'cleanup "$?"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

fail() {
	printf 'ERROR: %s\n' "$*" >&2
	exit 1
}

wait_for_line() {
	local file=$1
	local needle=$2
	local pid=$3
	local deadline=$((SECONDS + 20))
	while ((SECONDS < deadline)); do
		if grep -Fq -- "$needle" "$file"; then
			return 0
		fi
		if ! kill -0 "$pid" 2>/dev/null; then
			fail "process $pid exited before printing '$needle'"
		fi
		sleep 0.05
	done
	fail "timed out waiting for '$needle' in $file"
}

wait_for_count() {
	local file=$1
	local needle=$2
	local expected=$3
	local pid=$4
	local deadline=$((SECONDS + 30))
	while ((SECONDS < deadline)); do
		local count
		count=$(grep -Fc -- "$needle" "$file" || true)
		if ((count >= expected)); then
			return 0
		fi
		if ! kill -0 "$pid" 2>/dev/null; then
			fail "process $pid exited while waiting for $expected '$needle' lines"
		fi
		sleep 0.05
	done
	fail "timed out waiting for $expected '$needle' lines in $file"
}

run_client() {
	local output=$1
	shift
	"$CLIENT" \
		--sid "$APP_SID" \
		--server "127.0.0.1:$CORE_APP_PORT" \
		--path c \
		>"$output" 2>&1 <<EOF
$*
EOF
}

case "$BUILD_DEMO_BINARIES" in
1)
	[[ -z "${DEMO_BIN_DIR:-}" ]] || fail "DEMO_BIN_DIR requires DEMO_BUILD=0 because Cargo writes to target/debug"
	printf 'Building demonstration binaries from the checked-out source...\n'
	cargo build -p schc-coreconf --bins
	;;
0)
	;;
*)
	fail "DEMO_BUILD must be 0 or 1"
	;;
esac
[[ -x "$DEVICE" && -x "$CORE" && -x "$CLIENT" ]] || fail "demonstration binaries are unavailable in $BIN_DIR"
[[ -f "$APP_SID" && -f "$APP_DATA" ]] || fail "application fixtures are missing"

mkfifo "$CORE_FIFO"
exec 3<>"$CORE_FIFO"

"$DEVICE" \
	--debug \
	--link-bind "127.0.0.1:$DEVICE_LINK_PORT" \
	--link-peer "127.0.0.1:$CORE_LINK_PORT" \
	--app-sid "$APP_SID" \
	--app-data "$APP_DATA" \
	>"$DEVICE_LOG" 2>&1 </dev/null &
DEVICE_PID=$!
wait_for_line "$DEVICE_LOG" "READY device  " "$DEVICE_PID"

"$CORE" \
	--debug \
	--link-bind "127.0.0.1:$CORE_LINK_PORT" \
	--link-peer "127.0.0.1:$DEVICE_LINK_PORT" \
	--app-bind "127.0.0.1:$CORE_APP_PORT" \
	>"$CORE_LOG" 2>&1 <"$CORE_FIFO" &
CORE_PID=$!
wait_for_line "$CORE_LOG" "READY core  " "$CORE_PID"

run_client "$BEFORE_LOG" "discover d=0
schema demo-data
fetch /demo-data:config/count
quit"
grep -Fxq '7' "$BEFORE_LOG" || fail "before-update FETCH did not return an exact output line 7"
wait_for_count "$CORE_LOG" "TX APP" 2 "$CORE_PID"

printf '%s\n' \
	'context check' \
	'rule list device' \
	'rule get device 20/8' >&3
wait_for_line "$CORE_LOG" "tv=0x0000000000000005" "$CORE_PID"

grep -Fq 'RULE 20/8 nature=compression' "$CORE_LOG" || fail "initial Rule20 inspection was not printed"

printf '%s\n' \
	'rule update 20/8 fid=ipv6.app-iid tv=2 --if-match' >&3
wait_for_line "$CORE_LOG" "OK update 20/8 entry=9  device=changed  local=changed" "$CORE_PID"

printf '%s\n' \
	'context check' \
	'rule get core 20/8' \
	'rule get device 20/8' >&3
wait_for_line "$CORE_LOG" "tv=0x0000000000000002" "$CORE_PID"

run_client "$AFTER_LOG" "discover d=0
schema demo-data
fetch /demo-data:config/count
quit"
grep -Fxq '7' "$AFTER_LOG" || fail "after-update FETCH did not return an exact output line 7"
wait_for_count "$CORE_LOG" "TX APP" 4 "$CORE_PID"

printf '%s\n' quit >&3
exec 3>&-
wait "$CORE_PID"
CORE_PID=""
kill "$DEVICE_PID" 2>/dev/null || true
wait "$DEVICE_PID" 2>/dev/null || true
DEVICE_PID=""

python3 - "$CORE_LOG" "$DEVICE_LOG" <<'PY'
import re
import sys

core_log, device_log = sys.argv[1:]

def read(path):
    with open(path, encoding="utf-8") as stream:
        return stream.read()

def reports(text, direction):
    pattern = re.compile(rf"^{direction} APP   (\d+/\d+)  (\d+) B -> (\d+) B$")
    result = []
    for line in text.splitlines():
        match = pattern.fullmatch(line)
        if match:
            result.append({"rule": match.group(1), "packet_bytes": int(match.group(2)), "frame_bytes": int(match.group(3))})
    return result

def require(condition, message):
    if not condition:
        raise SystemExit(message)

core = read(core_log)
device = read(device_log)
require("packet_hex" not in core and "frame_hex" not in core, "core debug output retained raw hexadecimal")
require("packet_hex" not in device and "frame_hex" not in device, "device debug output retained raw hexadecimal")
core_tx = reports(core, "TX")
core_rx = reports(core, "RX")
device_rx = reports(device, "RX")
device_tx = reports(device, "TX")
require(len(core_tx) == 4, f"expected 4 core request reports, got {len(core_tx)}")
require(len(core_rx) == 4, f"expected 4 core response reports, got {len(core_rx)}")
require(len(device_rx) == 4, f"expected 4 device request reports, got {len(device_rx)}")
require(len(device_tx) == 4, f"expected 4 device response reports, got {len(device_tx)}")

before_request, after_request = core_tx[1], core_tx[3]
before_response, after_response = core_rx[1], core_rx[3]
device_before_request, device_after_request = device_rx[1], device_rx[3]
device_before_response, device_after_response = device_tx[1], device_tx[3]
require(before_request["rule"] == "25/8", "initial request did not use fallback Rule25")
require(after_request["rule"] == "20/8", "updated request did not use Rule20")
require(before_response["rule"] == after_response["rule"] == "21/8", "responses did not use Rule21")
require(device_before_response["rule"] == device_after_response["rule"] == "21/8", "device responses did not use Rule21")
require(before_request["packet_bytes"] == after_request["packet_bytes"], "request original size changed")
require(before_response["packet_bytes"] == after_response["packet_bytes"], "response original size changed")
require(after_request["frame_bytes"] < before_request["frame_bytes"], "updated request did not use fewer transmitted bytes")

for sender, receiver, label in (
    (before_request, device_before_request, "before request core TX/device RX"),
    (after_request, device_after_request, "after request core TX/device RX"),
    (device_before_response, before_response, "before response device TX/core RX"),
    (device_after_response, after_response, "after response device TX/core RX"),
):
    require(sender == receiver, f"visible packet report mismatch for {label}")

matches = re.findall(r"^  core tag=(\S+)  device tag=(\S+)$", core, re.MULTILINE)
require(len(matches) == 2, "expected pre-update and post-update equal context checks")
require(all(core_tag == device_tag for core_tag, device_tag in matches), "context tags differ")
require(matches[0][0] != matches[1][0], "context update did not publish a new tag")

print(f"DEMO PROOF request_original_bytes={before_request['packet_bytes']}")
print(f"DEMO PROOF request_transmitted_bytes_before={before_request['frame_bytes']} request_transmitted_bytes_after={after_request['frame_bytes']}")
print(f"DEMO PROOF request_rule_before={before_request['rule']} request_rule_after={after_request['rule']}")
print(f"DEMO PROOF response_original_bytes={before_response['packet_bytes']} response_transmitted_bytes={before_response['frame_bytes']}")
print("DEMO PROOF visible_sender_receiver_reports_match=yes")
print("DEMO PROOF raw_sender_receiver_equality=not-observed")
print("DEMO PROOF application_result_before=7 application_result_after=7")
print(f"DEMO PROOF context_tags_equal=yes tag={matches[-1][0]}")
print("DEMO PROOF context_tag_changed=yes")
PY

printf 'DEMO COMPLETE localhost_udp=yes root_required=no\n'
