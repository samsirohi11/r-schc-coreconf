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
wait_for_line "$DEVICE_LOG" "READY role=device" "$DEVICE_PID"

"$CORE" \
	--debug \
	--link-bind "127.0.0.1:$CORE_LINK_PORT" \
	--link-peer "127.0.0.1:$DEVICE_LINK_PORT" \
	--app-bind "127.0.0.1:$CORE_APP_PORT" \
	>"$CORE_LOG" 2>&1 <"$CORE_FIFO" &
CORE_PID=$!
wait_for_line "$CORE_LOG" "READY role=core" "$CORE_PID"

run_client "$BEFORE_LOG" "discover d=0
schema demo-data
fetch /demo-data:config/count
quit"
grep -Fxq '7' "$BEFORE_LOG" || fail "before-update FETCH did not return an exact output line 7"
wait_for_count "$CORE_LOG" "CORE DONE" 2 "$CORE_PID"

printf '%s\n' \
	'context check' \
	'rule list device' \
	'rule get device 20/8' >&3
wait_for_line "$CORE_LOG" "tv=0x0000000000000005" "$CORE_PID"

grep -Fq 'RULE 20/8 nature=compression' "$CORE_LOG" || fail "initial Rule20 inspection was not printed"

printf '%s\n' \
	'rule update 20/8 fid=ipv6.app-iid tv=2 --if-match' >&3
wait_for_line "$CORE_LOG" "RULE UPDATE 20/8 entry=9 device=2.04 local=2.04" "$CORE_PID"

printf '%s\n' \
	'context check' \
	'rule get core 20/8' \
	'rule get device 20/8' >&3
wait_for_line "$CORE_LOG" "tv=0x0000000000000002" "$CORE_PID"

run_client "$AFTER_LOG" "fetch /demo-data:config/count
quit"
grep -Fxq '7' "$AFTER_LOG" || fail "after-update FETCH did not return an exact output line 7"
wait_for_count "$CORE_LOG" "CORE DONE" 3 "$CORE_PID"

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

def reports(text, prefix):
    result = []
    for line in text.splitlines():
        if not line.startswith(prefix):
            continue
        fields = dict(re.findall(r"([a-z_]+)=([^ ]+)", line))
        result.append(fields)
    return result

def require(condition, message):
    if not condition:
        raise SystemExit(message)

core = read(core_log)
device = read(device_log)
core_tx = reports(core, "CORE TX class=Ordinary ")
core_rx = reports(core, "CORE RX class=Ordinary ")
device_rx = reports(device, "DEVICE RX class=Ordinary ")
device_tx = reports(device, "DEVICE TX class=Ordinary ")
require(len(core_tx) == 3, f"expected 3 core request reports, got {len(core_tx)}")
require(len(core_rx) == 3, f"expected 3 core response reports, got {len(core_rx)}")
require(len(device_rx) == 3, f"expected 3 device request reports, got {len(device_rx)}")
require(len(device_tx) == 3, f"expected 3 device response reports, got {len(device_tx)}")

before_request, after_request = core_tx[1:]
before_response, after_response = core_rx[1:]
device_before_request, device_after_request = device_rx[1:]
device_before_response, device_after_response = device_tx[1:]
require(before_request["rule"] == "25/8", "initial request did not use fallback Rule25")
require(after_request["rule"] == "20/8", "updated request did not use Rule20")
require(before_response["rule"] == after_response["rule"] == "21/8", "responses did not use Rule21")
require(device_before_response["rule"] == device_after_response["rule"] == "21/8", "device responses did not use Rule21")
require(before_request["packet_hex"] == after_request["packet_hex"], "request packet bytes changed")
require(before_response["packet_hex"] == after_response["packet_hex"], "response packet bytes changed")
require(int(after_request["frame_bits"]) < int(before_request["frame_bits"]), "updated request did not use fewer SCHC bits")

def require_link_pair(sender, receiver, label):
    require(sender["packet_hex"] == receiver["packet_hex"], f"packet mismatch for {label}")
    require(sender["frame_hex"] == receiver["frame_hex"], f"raw frame mismatch for {label}")
    require(len(sender["frame_hex"]) // 2 == int(sender["frame_bytes"]), f"invalid padded frame length for {label}")
    require(int(sender["frame_bits"]) <= int(sender["frame_bytes"]) * 8, f"invalid frame bit count for {label}")

for sender, receiver, label in (
    (before_request, device_before_request, "before request core TX/device RX"),
    (after_request, device_after_request, "after request core TX/device RX"),
    (device_before_response, before_response, "before response device TX/core RX"),
    (device_after_response, after_response, "after response device TX/core RX"),
):
    require_link_pair(sender, receiver, label)

matches = re.findall(r"CONTEXT CHECK equal core_tag=(\S+) device_tag=(\S+)", core)
require(len(matches) == 2, "expected pre-update and post-update equal context checks")
require(all(core_tag == device_tag for core_tag, device_tag in matches), "context tags differ")
require(matches[0][0] != matches[1][0], "context update did not publish a new tag")

print("DEMO PROOF request_packet_identical=yes")
print("DEMO PROOF response_packet_identical=yes")
print(f"DEMO PROOF request_rule_before={before_request['rule']} request_rule_after={after_request['rule']}")
print(f"DEMO PROOF request_schc_bits_before={before_request['frame_bits']} request_schc_bits_after={after_request['frame_bits']}")
print("DEMO PROOF response_rule=21/8")
print(f"DEMO PROOF context_tags_equal=yes tag={matches[-1][0]}")
print("DEMO PROOF context_tag_changed=yes")
print("DEMO PROOF raw_padded_frames_sender_receiver_match=yes")
PY

printf 'DEMO COMPLETE localhost_udp=yes root_required=no\n'
