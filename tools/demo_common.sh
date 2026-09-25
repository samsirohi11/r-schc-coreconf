#!/usr/bin/env bash

# Shared namespace, resource, process, and readiness primitives for the demo
# entry points. The caller supplies the repository paths and option variables.

if ! declare -p DEMO_IP_COMMAND >/dev/null 2>&1; then
    DEMO_IP_COMMAND=(ip)
fi
if ! declare -p DEMO_PRIVILEGE_COMMAND >/dev/null 2>&1; then
    DEMO_PRIVILEGE_COMMAND=()
fi

demo_ip() {
    "${DEMO_IP_COMMAND[@]}" "$@"
}

demo_privileged() {
    "${DEMO_PRIVILEGE_COMMAND[@]}" "$@"
}

init_demo_resources() {
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
    PIDS=()
    NAMESPACES=()
    HOST_LINKS=()
    CORE_FD=''
    CLIENT_FD=''

    owner_uid=${SUDO_UID:-$(id -u)}
    owner_gid=${SUDO_GID:-$(id -g)}
}

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
    delete_demo_network
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

ns_exec() {
    local namespace=$1
    shift
    demo_ip netns exec "$namespace" "$@"
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
        if [[ -n "$pid" ]] && ! kill -0 "$pid" 2>/dev/null; then
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
    error "timed out waiting for regex count $expected; see logs in $LOG_DIR"
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

kill_demo_namespace_processes() {
    local namespace=$1
    local pid
    local -a pids=()
    mapfile -t pids < <(demo_ip netns pids "$namespace" 2>/dev/null || true)
    for pid in "${pids[@]}"; do
        [[ "$pid" =~ ^[1-9][0-9]*$ ]] && (( pid > 1 )) &&
            demo_privileged kill -TERM "$pid" 2>/dev/null || true
    done
    sleep 0.2
    mapfile -t pids < <(demo_ip netns pids "$namespace" 2>/dev/null || true)
    for pid in "${pids[@]}"; do
        [[ "$pid" =~ ^[1-9][0-9]*$ ]] && (( pid > 1 )) &&
            demo_privileged kill -KILL "$pid" 2>/dev/null || true
    done
}

delete_demo_network() {
    local namespace
    for namespace in "${NAMESPACES[@]}"; do
        demo_ip netns del "$namespace" 2>/dev/null || true
    done
    local link
    for link in "${HOST_LINKS[@]}"; do
        demo_ip link del "$link" 2>/dev/null || true
    done
}

setup_demo_network() {
    printf 'DEMO SETUP namespaces=%s,%s,%s\n' "$CLIENT_NS" "$CORE_NS" "$DEVICE_NS"
    for namespace in "$CLIENT_NS" "$CORE_NS" "$DEVICE_NS"; do
        demo_ip netns add "$namespace"
        NAMESPACES+=("$namespace")
        ns_exec "$namespace" ip link set lo up
    done

    demo_ip link add "$CLIENT_VETH" type veth peer name "$CORE_CLIENT_VETH"
    HOST_LINKS+=("$CLIENT_VETH" "$CORE_CLIENT_VETH")
    demo_ip link set "$CLIENT_VETH" netns "$CLIENT_NS"
    demo_ip link set "$CORE_CLIENT_VETH" netns "$CORE_NS"
    ns_exec "$CLIENT_NS" ip link set "$CLIENT_VETH" name "$CLIENT_IF"
    ns_exec "$CORE_NS" ip link set "$CORE_CLIENT_VETH" name "$CORE_CLIENT_IF"

    demo_ip link add "$CORE_DEVICE_VETH" type veth peer name "$DEVICE_VETH"
    HOST_LINKS+=("$CORE_DEVICE_VETH" "$DEVICE_VETH")
    demo_ip link set "$CORE_DEVICE_VETH" netns "$CORE_NS"
    demo_ip link set "$DEVICE_VETH" netns "$DEVICE_NS"
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
}

setup_demo_tun_routes() {
    ns_exec "$CORE_NS" ip -6 route add 2001:db8::1/128 dev schc-core
    ns_exec "$DEVICE_NS" ip -6 route add 2001:db8::2/128 dev schc-device
}
