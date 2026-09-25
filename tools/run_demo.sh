#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
CLIENT_BIN="$ROOT/target/debug/schc-data-client"
SERVER_BIN="$ROOT/target/debug/schc-data-server"
CORE_BIN="$ROOT/target/debug/schc-coreconf-core"
DEVICE_BIN="$ROOT/target/debug/schc-coreconf-device"
APP_SID="$ROOT/fixtures/demo/demo-data.sid"
APP_DATA="$ROOT/fixtures/demo/app-data.json"

NO_BUILD=0
CHECK_ONLY=0
KEEP_LOGS=0

usage() {
    cat <<'USAGE'
Usage: tools/run_demo.sh [--check] [--no-build] [--keep-logs]

Builds the four endpoint binaries as the invoking user, then automatically
enters the privileged namespace phase when not already root.
--check performs only unprivileged preflight validation.
--no-build reuses target/debug binaries.
--keep-logs preserves successful-run logs as well as failure logs.
USAGE
}

error() {
    printf 'ERROR %s\n' "$*" >&2
    exit 1
}

source "$SCRIPT_DIR/demo_common.sh"

init_demo_fifos() {
    CORE_FIFO="$TMP_DIR/core.stdin"
    CLIENT_FIFO="$TMP_DIR/client.stdin"
    mkfifo "$CORE_FIFO" "$CLIENT_FIFO"
}

for argument in "$@"; do
    case "$argument" in
        --check) CHECK_ONLY=1 ;;
        --no-build) NO_BUILD=1 ;;
        --keep-logs) KEEP_LOGS=1 ;;
        -h|--help) usage; exit 0 ;;
        *) error "unknown argument $argument; use --help" ;;
    esac
done

require_command() {
    command -v "$1" >/dev/null 2>&1 || error "missing command '$1'"
}

preflight() {
    local command_name
    for command_name in bash ip stdbuf python3 grep mkfifo sysctl; do
        require_command "$command_name"
    done
    if (( EUID != 0 )); then
        require_command sudo
    fi
    if (( ! NO_BUILD && ! CHECK_ONLY )); then
        require_command cargo
    fi
    [[ -e /dev/net/tun ]] || error "missing /dev/net/tun; Linux TUN support is required"
    [[ -r "$APP_SID" ]] || error "missing application SID fixture: $APP_SID"
    [[ -r "$APP_DATA" ]] || error "missing application data fixture: $APP_DATA"
    [[ -r "$ROOT/Cargo.toml" ]] || error "repository root is not a Cargo workspace: $ROOT"
    [[ -r "$ROOT/tools/demo_proof.py" ]] || error "missing proof parser: $ROOT/tools/demo_proof.py"
    [[ -r "$ROOT/tools/test_demo_proof.py" ]] || error "missing proof tests: $ROOT/tools/test_demo_proof.py"
    if (( NO_BUILD || CHECK_ONLY )); then
        for binary in "$CLIENT_BIN" "$SERVER_BIN" "$CORE_BIN" "$DEVICE_BIN"; do
            [[ -x "$binary" ]] || error "missing binary $binary; run cargo build --workspace --bins or omit --no-build"
        done
    fi
    printf 'DEMO CHECK OK commands=present tun=present fixtures=present\n'
    printf 'DEMO CHECK INFO privilege=deferred namespace_mutation=none\n'
}

preflight

if (( CHECK_ONLY )); then
    exit 0
fi

if (( ! NO_BUILD )); then
    printf 'Building endpoint binaries as uid %s...\n' "$(id -u)" >&2
    (cd "$ROOT" && cargo build -p schc-coreconf --bins)
fi

if (( EUID != 0 )); then
    sudo_args=(--no-build)
    (( KEEP_LOGS )) && sudo_args+=(--keep-logs)
    exec sudo "$SCRIPT_DIR/run_demo.sh" "${sudo_args[@]}"
fi

for binary in "$CLIENT_BIN" "$SERVER_BIN" "$CORE_BIN" "$DEVICE_BIN"; do
    [[ -x "$binary" ]] || error "missing binary $binary; rerun without --no-build as the invoking user"
done
require_command sysctl

init_demo_resources
init_demo_fifos
trap cleanup EXIT
trap 'exit 130' INT TERM

send_and_wait_literal() {
    local fd=$1
    local file=$2
    local command=$3
    local needle=$4
    local pid=$5
    local before
    before=$(count_literal "$file" "$needle")
    printf '%s\n' "$command" >&$fd
    wait_for_count "$file" "$needle" "$((before + 1))" "$pid"
}

send_and_wait_regex() {
    local fd=$1
    local file=$2
    local command=$3
    local pattern=$4
    local pid=$5
    local before
    before=$(count_regex "$file" "$pattern")
    printf '%s\n' "$command" >&$fd
    wait_for_regex_count "$file" "$pattern" "$((before + 1))" "$pid"
}

send_and_wait_count() {
    send_and_wait_literal "$@"
}

setup_demo_network

printf 'DEMO SETUP starting device and core\n'
exec {CORE_FD}<> "$CORE_FIFO"
start_process "$DEVICE_NS" "$DEVICE_LOG" /dev/null "$DEVICE_BIN" \
    --debug --link-bind 192.0.2.2:8724 --link-peer 192.0.2.1:8724 \
    --tun-name schc-device --tun-mtu 1280
DEVICE_PID=$LAST_PID
wait_for_literal "$DEVICE_LOG" "READY device  " "$DEVICE_PID"

start_process "$CORE_NS" "$CORE_LOG" "$CORE_FIFO" "$CORE_BIN" \
    --debug --link-bind 192.0.2.1:8724 --link-peer 192.0.2.2:8724 \
    --tun-name schc-core --tun-mtu 1280
CORE_PID=$LAST_PID
wait_for_literal "$CORE_LOG" "READY core  " "$CORE_PID"

setup_demo_tun_routes

start_process "$DEVICE_NS" "$SERVER_LOG" /dev/null "$SERVER_BIN" \
    --sid "$APP_SID" --data "$APP_DATA" --bind '[2001:db8::1]:5683' --path c
SERVER_PID=$LAST_PID
wait_for_literal "$SERVER_LOG" "READY server  bind=[2001:db8::1]:5683  path=c" "$SERVER_PID"

exec {CLIENT_FD}<> "$CLIENT_FIFO"
start_process "$CLIENT_NS" "$CLIENT_LOG" "$CLIENT_FIFO" "$CLIENT_BIN" \
    --sid "$APP_SID" --server '[2001:db8::1]:5683' --bind '[2001:db8::2]:5683' --path c
CLIENT_PID=$LAST_PID
wait_for_literal "$CLIENT_LOG" "READY client  server=[2001:db8::1]:5683  bind=[2001:db8::2]:5683" "$CLIENT_PID"

printf 'DEMO APP exercising standalone client\n'
send_and_wait_literal "$CLIENT_FD" "$CLIENT_LOG" "discover" '</c>;rt="core.c.ds"' "$CLIENT_PID"
send_and_wait_literal "$CLIENT_FD" "$CLIENT_LOG" "schema demo-data" "/demo-data:config/count" "$CLIENT_PID"
send_and_wait_regex "$CLIENT_FD" "$CLIENT_LOG" "fetch /demo-data:config/count" '^7$' "$CLIENT_PID"
send_and_wait_literal "$CLIENT_FD" "$CLIENT_LOG" "set /demo-data:config/count 42" "OK set" "$CLIENT_PID"
send_and_wait_regex "$CLIENT_FD" "$CLIENT_LOG" "fetch /demo-data:config/count" '^42$' "$CLIENT_PID"
send_and_wait_literal "$CLIENT_FD" "$CLIENT_LOG" "delete /demo-data:config/count" "OK delete" "$CLIENT_PID"
send_and_wait_literal "$CLIENT_FD" "$CLIENT_LOG" "fetch /demo-data:config/count" "not found" "$CLIENT_PID"
send_and_wait_literal "$CLIENT_FD" "$CLIENT_LOG" "set /demo-data:config/count 42" "OK set" "$CLIENT_PID"
send_and_wait_literal "$CLIENT_FD" "$CLIENT_LOG" "help" "Data client commands:" "$CLIENT_PID"

printf 'DEMO MGMT exercising core console\n'
send_and_wait_literal "$CORE_FD" "$CORE_LOG" "context status" "CONTEXT generation=1  rules=9" "$CORE_PID"
send_and_wait_literal "$CORE_FD" "$CORE_LOG" "context check" "OK context check  equal" "$CORE_PID"
send_and_wait_count "$CORE_FD" "$CORE_LOG" "rule list core" "RULE 20/8 nature=compression" "$CORE_PID"
send_and_wait_count "$CORE_FD" "$CORE_LOG" "rule list device" "RULE 20/8 nature=compression" "$CORE_PID"
send_and_wait_count "$CORE_FD" "$CORE_LOG" "rule get core 20/8" "RULE 20/8 nature=compression" "$CORE_PID"
send_and_wait_count "$CORE_FD" "$CORE_LOG" "rule get device 20/8" "RULE 20/8 nature=compression" "$CORE_PID"
send_and_wait_literal "$CORE_FD" "$CORE_LOG" "rule update 20/8 entry=9 tv=6 --if-match" "OK update 20/8 entry=9  device=changed  local=changed" "$CORE_PID"
send_and_wait_literal "$CORE_FD" "$CORE_LOG" "context check" "OK context check  equal" "$CORE_PID"
send_and_wait_literal "$CORE_FD" "$CORE_LOG" "rule duplicate 20/8 22/8 entry=9 tv=2" "OK duplicate 20/8 -> 22/8  local=installed  remote=unacknowledged" "$CORE_PID"
wait_for_literal "$DEVICE_LOG" "OK duplicate  local=installed  response=none" "$DEVICE_PID"
send_and_wait_count "$CORE_FD" "$CORE_LOG" "rule get core 22/8" "RULE 22/8 nature=compression" "$CORE_PID"
send_and_wait_count "$CORE_FD" "$CORE_LOG" "rule get device 22/8" "RULE 22/8 nature=compression" "$CORE_PID"
send_and_wait_literal "$CORE_FD" "$CORE_LOG" "context check" "OK context check  equal" "$CORE_PID"
send_and_wait_literal "$CORE_FD" "$CORE_LOG" "help" "Core commands:" "$CORE_PID"

printf 'DEMO APP proving adaptive request after duplicate\n'
send_and_wait_regex "$CLIENT_FD" "$CLIENT_LOG" "fetch /demo-data:config/count" '^42$' "$CLIENT_PID"
send_and_wait_regex "$CLIENT_FD" "$CLIENT_LOG" "fetch /demo-data:config/count" '^42$' "$CLIENT_PID"
printf '%s\n' quit >&$CLIENT_FD
wait_for_exit "$CLIENT_PID"

printf '%s\n' quit >&$CORE_FD
wait_for_exit "$CORE_PID"
require_alive device "$DEVICE_PID"
require_alive server "$SERVER_PID"

python3 "$ROOT/tools/demo_proof.py" \
    --core-log "$CORE_LOG" --device-log "$DEVICE_LOG" \
    --server-log "$SERVER_LOG" --client-log "$CLIENT_LOG"

exit 0
