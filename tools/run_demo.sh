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

Builds the four endpoint binaries as the invoking user, then prints the exact
sudo command needed for the privileged namespace phase when not already root.
--check performs only unprivileged preflight validation.
--no-build reuses target/debug binaries.
--keep-logs preserves successful-run logs as well as failure logs.
USAGE
}

error() {
    printf 'ERROR %s\n' "$*" >&2
    exit 1
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

if (( EUID == 0 && ! NO_BUILD )); then
    error "refusing to build as root; build as the invoking user, then run with sudo and --no-build"
fi

if (( ! NO_BUILD )); then
    printf 'Building endpoint binaries as uid %s...\n' "$(id -u)" >&2
    (cd "$ROOT" && cargo build -p schc-coreconf --bins)
fi

if (( EUID != 0 )); then
    printf '\nThe binaries were built without privilege. Run the namespace phase interactively with:\n' >&2
    if (( KEEP_LOGS )); then
        printf '  sudo %q --no-build --keep-logs\n' "$SCRIPT_DIR/run_demo.sh" >&2
    else
        printf '  sudo %q --no-build\n' "$SCRIPT_DIR/run_demo.sh" >&2
    fi
    exit 2
fi

for binary in "$CLIENT_BIN" "$SERVER_BIN" "$CORE_BIN" "$DEVICE_BIN"; do
    [[ -x "$binary" ]] || error "missing binary $binary; rerun without --no-build as the invoking user"
done
require_command sysctl

SUFFIX=$(python3 -c 'import os; print(os.urandom(3).hex())')
CLIENT_NS="schc-cl-$SUFFIX"
CORE_NS="schc-co-$SUFFIX"
DEVICE_NS="schc-de-$SUFFIX"
CLIENT_VETH="dc$SUFFIX"
CORE_CLIENT_VETH="cc$SUFFIX"
CORE_DEVICE_VETH="cd$SUFFIX"
DEVICE_VETH="dd$SUFFIX"
CLIENT_IF="cli0"
CORE_CLIENT_IF="ccli0"
CORE_DEVICE_IF="cdev0"
DEVICE_IF="dev0"

for interface_name in "$CLIENT_VETH" "$CORE_CLIENT_VETH" "$CORE_DEVICE_VETH" "$DEVICE_VETH" "$CLIENT_IF" "$CORE_CLIENT_IF" "$CORE_DEVICE_IF" "$DEVICE_IF"; do
    (( ${#interface_name} <= 15 )) || error "interface name is longer than Linux's 15-character limit: $interface_name"
done

TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/schc-coreconf-demo.$SUFFIX.XXXXXX")
LOG_DIR="$TMP_DIR/logs"
mkdir -p "$LOG_DIR"
CORE_LOG="$LOG_DIR/core.log"
DEVICE_LOG="$LOG_DIR/device.log"
SERVER_LOG="$LOG_DIR/server.log"
CLIENT_LOG="$LOG_DIR/client.log"
CORE_FIFO="$TMP_DIR/core.stdin"
CLIENT_FIFO="$TMP_DIR/client.stdin"
mkfifo "$CORE_FIFO" "$CLIENT_FIFO"

PIDS=()
NAMESPACES=()
HOST_LINKS=()
CORE_FD=''
CLIENT_FD=''

owner_uid=${SUDO_UID:-$(id -u)}
owner_gid=${SUDO_GID:-$(id -g)}

cleanup() {
    local status=$?
    set +e
    if ((${#PIDS[@]})); then
        for pid in "${PIDS[@]}"; do
            kill -TERM "$pid" 2>/dev/null || true
        done
        for pid in "${PIDS[@]}"; do
            wait "$pid" 2>/dev/null || true
        done
    fi
    for namespace in "${NAMESPACES[@]}"; do
        ip netns del "$namespace" 2>/dev/null || true
    done
    for link in "${HOST_LINKS[@]}"; do
        ip link del "$link" 2>/dev/null || true
    done
    if [[ -n "$CORE_FD" ]]; then eval "exec ${CORE_FD}>&-" 2>/dev/null || true; fi
    if [[ -n "$CLIENT_FD" ]]; then eval "exec ${CLIENT_FD}>&-" 2>/dev/null || true; fi
    if (( status != 0 || KEEP_LOGS )); then
        chown -R "$owner_uid:$owner_gid" "$TMP_DIR" 2>/dev/null || true
        printf 'DEMO LOGS %s\n' "$LOG_DIR" >&2
    else
        rm -rf "$TMP_DIR"
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

ns_exec() {
    local namespace=$1
    shift
    ip netns exec "$namespace" "$@"
}

count_literal() {
    local file=$1
    local needle=$2
    grep -F -c -- "$needle" "$file" 2>/dev/null || true
}

count_regex() {
    local file=$1
    local pattern=$2
    grep -E -c -- "$pattern" "$file" 2>/dev/null || true
}

wait_for_literal() {
    local file=$1
    local needle=$2
    local pid=$3
    local timeout_seconds=${4:-30}
    local deadline=$((SECONDS + timeout_seconds))
    while (( SECONDS < deadline )); do
        grep -Fq -- "$needle" "$file" 2>/dev/null && return 0
        if ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid" 2>/dev/null || true
            error "process $pid exited before '$needle'; see $file"
        fi
        sleep 0.05
    done
    error "timed out waiting for '$needle'; see $file"
}

wait_for_count() {
    local file=$1
    local needle=$2
    local expected=$3
    local pid=$4
    local timeout_seconds=${5:-30}
    local deadline=$((SECONDS + timeout_seconds))
    while (( SECONDS < deadline )); do
        local count
        count=$(count_literal "$file" "$needle")
        (( count >= expected )) && return 0
        if ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid" 2>/dev/null || true
            error "process $pid exited before count $expected for '$needle'; see $file"
        fi
        sleep 0.05
    done
    error "timed out waiting for count $expected of '$needle'; see $file"
}

wait_for_regex_count() {
    local file=$1
    local pattern=$2
    local expected=$3
    local pid=$4
    local timeout_seconds=${5:-30}
    local deadline=$((SECONDS + timeout_seconds))
    while (( SECONDS < deadline )); do
        local count
        count=$(count_regex "$file" "$pattern")
        (( count >= expected )) && return 0
        if ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid" 2>/dev/null || true
            error "process $pid exited before regex count $expected; see $file"
        fi
        sleep 0.05
    done
    error "timed out waiting for regex count $expected; see $file"
}

wait_for_exit() {
    local pid=$1
    local timeout_seconds=${2:-30}
    local deadline=$((SECONDS + timeout_seconds))
    while (( SECONDS < deadline )); do
        if ! kill -0 "$pid" 2>/dev/null; then
            local exit_status=0
            wait "$pid" 2>/dev/null || exit_status=$?
            (( exit_status == 0 )) || error "process $pid exited with status $exit_status; see logs in $LOG_DIR"
            return 0
        fi
        sleep 0.05
    done
    error "process $pid did not exit; see logs in $LOG_DIR"
}

require_alive() {
    local name=$1
    local pid=$2
    if ! kill -0 "$pid" 2>/dev/null; then
        local exit_status=0
        wait "$pid" 2>/dev/null || exit_status=$?
        error "$name process $pid exited unexpectedly with status $exit_status; see logs in $LOG_DIR"
    fi
}

start_process() {
    local namespace=$1
    local log_file=$2
    local input_file=$3
    shift 3
    stdbuf -oL -eL ip netns exec "$namespace" "$@" <"$input_file" >"$log_file" 2>&1 &
    LAST_PID=$!
    PIDS+=("$LAST_PID")
}

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

printf 'DEMO SETUP namespaces=%s,%s,%s\n' "$CLIENT_NS" "$CORE_NS" "$DEVICE_NS"
for namespace in "$CLIENT_NS" "$CORE_NS" "$DEVICE_NS"; do
    ip netns add "$namespace"
    NAMESPACES+=("$namespace")
    ns_exec "$namespace" ip link set lo up
done

ip link add "$CLIENT_VETH" type veth peer name "$CORE_CLIENT_VETH"
HOST_LINKS+=("$CLIENT_VETH" "$CORE_CLIENT_VETH")
ip link set "$CLIENT_VETH" netns "$CLIENT_NS"
ip link set "$CORE_CLIENT_VETH" netns "$CORE_NS"
ns_exec "$CLIENT_NS" ip link set "$CLIENT_VETH" name "$CLIENT_IF"
ns_exec "$CORE_NS" ip link set "$CORE_CLIENT_VETH" name "$CORE_CLIENT_IF"

ip link add "$CORE_DEVICE_VETH" type veth peer name "$DEVICE_VETH"
HOST_LINKS+=("$CORE_DEVICE_VETH" "$DEVICE_VETH")
ip link set "$CORE_DEVICE_VETH" netns "$CORE_NS"
ip link set "$DEVICE_VETH" netns "$DEVICE_NS"
ns_exec "$CORE_NS" ip link set "$CORE_DEVICE_VETH" name "$CORE_DEVICE_IF"
ns_exec "$DEVICE_NS" ip link set "$DEVICE_VETH" name "$DEVICE_IF"

ns_exec "$CLIENT_NS" ip link set "$CLIENT_IF" up
ns_exec "$CORE_NS" ip link set "$CORE_CLIENT_IF" up
ns_exec "$CORE_NS" ip link set "$CORE_DEVICE_IF" up
ns_exec "$DEVICE_NS" ip link set "$DEVICE_IF" up

ns_exec "$CLIENT_NS" ip -6 addr add fd00:1::2/64 dev "$CLIENT_IF" nodad
ns_exec "$CORE_NS" ip -6 addr add fd00:1::1/64 dev "$CORE_CLIENT_IF" nodad
ns_exec "$CORE_NS" ip addr add 192.0.2.1/30 dev "$CORE_DEVICE_IF"
ns_exec "$DEVICE_NS" ip addr add 192.0.2.2/30 dev "$DEVICE_IF"
ns_exec "$CLIENT_NS" ip -6 addr add 2001:db8::2/128 dev lo nodad
ns_exec "$DEVICE_NS" ip -6 addr add 2001:db8::1/128 dev lo nodad

ns_exec "$CORE_NS" sysctl -q -w net.ipv6.conf.all.forwarding=1
# Linux otherwise assigns random IPv6 flow labels to UDP sockets. The demo
# context deliberately elides the flow label as zero to preserve its measured
# compression cost, so make that traffic property explicit at both producers.
ns_exec "$CLIENT_NS" sysctl -q -w net.ipv6.auto_flowlabels=0
ns_exec "$DEVICE_NS" sysctl -q -w net.ipv6.auto_flowlabels=0
ns_exec "$CLIENT_NS" ip -6 route add 2001:db8::1/128 via fd00:1::1 dev "$CLIENT_IF"
ns_exec "$CORE_NS" ip -6 route add 2001:db8::2/128 via fd00:1::2 dev "$CORE_CLIENT_IF"

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

ns_exec "$CORE_NS" ip -6 route add 2001:db8::1/128 dev schc-core
ns_exec "$DEVICE_NS" ip -6 route add 2001:db8::2/128 dev schc-device

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
send_and_wait_literal "$CLIENT_FD" "$CLIENT_LOG" "discover d=0" '</c>;rt="core.c.ds"' "$CLIENT_PID"
send_and_wait_literal "$CLIENT_FD" "$CLIENT_LOG" "schema demo-data" "/demo-data:config/count" "$CLIENT_PID"
send_and_wait_regex "$CLIENT_FD" "$CLIENT_LOG" "get /demo-data:config/count" '^7$' "$CLIENT_PID"
send_and_wait_regex "$CLIENT_FD" "$CLIENT_LOG" "fetch /demo-data:config/count" '^7$' "$CLIENT_PID"
send_and_wait_literal "$CLIENT_FD" "$CLIENT_LOG" "set /demo-data:config/count 42" "OK set" "$CLIENT_PID"
send_and_wait_regex "$CLIENT_FD" "$CLIENT_LOG" "get /demo-data:config/count" '^42$' "$CLIENT_PID"
send_and_wait_regex "$CLIENT_FD" "$CLIENT_LOG" "fetch /demo-data:config/count" '^42$' "$CLIENT_PID"
send_and_wait_literal "$CLIENT_FD" "$CLIENT_LOG" "delete /demo-data:config/count" "OK delete" "$CLIENT_PID"
send_and_wait_literal "$CLIENT_FD" "$CLIENT_LOG" "fetch /demo-data:config/count" "not found" "$CLIENT_PID"
send_and_wait_literal "$CLIENT_FD" "$CLIENT_LOG" "set /demo-data:config/count 42" "OK set" "$CLIENT_PID"
send_and_wait_literal "$CLIENT_FD" "$CLIENT_LOG" "reload" "OK reload" "$CLIENT_PID"
send_and_wait_regex "$CLIENT_FD" "$CLIENT_LOG" "get /demo-data:config/count" '^42$' "$CLIENT_PID"
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
send_and_wait_regex "$CLIENT_FD" "$CLIENT_LOG" "get /demo-data:config/count" '^42$' "$CLIENT_PID"
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
