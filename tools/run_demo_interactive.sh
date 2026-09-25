#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)
ROLE_HELPER="$SCRIPT_DIR/demo_role.sh"
CLIENT_BIN="$ROOT/target/debug/schc-data-client"
SERVER_BIN="$ROOT/target/debug/schc-data-server"
CORE_BIN="$ROOT/target/debug/schc-coreconf-core"
DEVICE_BIN="$ROOT/target/debug/schc-coreconf-device"
APP_SID="$ROOT/fixtures/demo/demo-data.sid"
APP_DATA="$ROOT/fixtures/demo/app-data.json"

NO_BUILD=0
CHECK_ONLY=0
KEEP_LOGS=0
PRINT_COMMANDS=0
TERMINAL_BIN=''
TERMINAL_KIND=''
NETWORK_ATTEMPTED=0
CLEANUP_DONE=0
DEMO_IP_COMMAND=(sudo ip)
DEMO_PRIVILEGE_COMMAND=(sudo)

usage() {
    cat <<'USAGE'
Usage: tools/run_demo_interactive.sh [--check] [--no-build] [--keep-logs] [--print-commands]

Builds the endpoint binaries as the invoking user, creates the demo network,
and opens four host terminal windows: device, core, server, and client.
Ghostty is preferred; GNOME Terminal is the fallback. Each role command uses
sudo ip netns exec in its own terminal. Set DEMO_TERMINAL to ghostty or
gnome-terminal to choose the terminal explicitly.
USAGE
}

error() {
    printf 'ERROR %s\n' "$*" >&2
    exit 1
}

source "$SCRIPT_DIR/demo_common.sh"

require_command() {
    command -v "$1" >/dev/null 2>&1 || error "missing command '$1'"
}

select_terminal() {
    local requested candidate
    if [[ -n "${DEMO_TERMINAL:-}" ]]; then
        requested=$DEMO_TERMINAL
        command -v "$requested" >/dev/null 2>&1 ||
            error "DEMO_TERMINAL '$requested' was not found on PATH"
        TERMINAL_BIN=$(command -v "$requested")
    else
        for candidate in ghostty gnome-terminal gnome-terminal.wrapper; do
            if command -v "$candidate" >/dev/null 2>&1; then
                TERMINAL_BIN=$(command -v "$candidate")
                break
            fi
        done
        if [[ -z "$TERMINAL_BIN" ]]; then
            printf '%s\n' \
                'ERROR no supported terminal found (Ghostty or GNOME Terminal).' \
                'Install one, or set DEMO_TERMINAL=ghostty or DEMO_TERMINAL=gnome-terminal.' \
                'Role command templates follow; namespace names are examples.' >&2
            print_role_commands
            exit 1
        fi
    fi
    case "$(basename -- "$TERMINAL_BIN")" in
        ghostty) TERMINAL_KIND=ghostty ;;
        gnome-terminal|gnome-terminal.wrapper) TERMINAL_KIND=gnome ;;
        *) error "unsupported terminal '$TERMINAL_BIN'; use Ghostty or GNOME Terminal" ;;
    esac
}

print_argv() {
    local argument
    for argument in "$@"; do
        printf '%q ' "$argument"
    done
    printf '\n'
}

build_role_command() {
    local role=$1
    local log_file=$2
    local status_file=$3
    case "$role" in
        device)
            ROLE_COMMAND=(sudo ip netns exec "$DEVICE_NS" bash "$ROLE_HELPER" --root
                "$log_file" "$status_file" "$DEVICE_BIN" --debug
                --link-bind 192.0.2.2:8724 --link-peer 192.0.2.1:8724
                --tun-name schc-device --tun-mtu 1280)
            ;;
        core)
            ROLE_COMMAND=(sudo ip netns exec "$CORE_NS" bash "$ROLE_HELPER" --root
                "$log_file" "$status_file" "$CORE_BIN" --debug
                --link-bind 192.0.2.1:8724 --link-peer 192.0.2.2:8724
                --tun-name schc-core --tun-mtu 1280)
            ;;
        server)
            ROLE_COMMAND=(sudo ip netns exec "$DEVICE_NS" bash "$ROLE_HELPER"
                --user "$owner_user" "$log_file" "$status_file" "$SERVER_BIN"
                --sid "$APP_SID" --data "$APP_DATA"
                --bind '[2001:db8::1]:5683' --path c)
            ;;
        client)
            ROLE_COMMAND=(sudo ip netns exec "$CLIENT_NS" bash "$ROLE_HELPER"
                --user "$owner_user" "$log_file" "$status_file" "$CLIENT_BIN"
                --sid "$APP_SID" --server '[2001:db8::1]:5683'
                --bind '[2001:db8::2]:5683' --path c)
            ;;
        *) error "unknown demo role $role" ;;
    esac
}

build_terminal_command() {
    local title=$1
    shift
    if [[ "$TERMINAL_KIND" == ghostty ]]; then
        TERMINAL_COMMAND=("$TERMINAL_BIN" "--title=$title" -e "$@")
    else
        TERMINAL_COMMAND=("$TERMINAL_BIN" --window --title "$title" --wait -- "$@")
    fi
}

print_role_commands() {
    local saved_owner=${owner_user:-}
    owner_user=demo-user
    CLIENT_NS=schc-cl-000000
    CORE_NS=schc-co-000000
    DEVICE_NS=schc-de-000000
    APP_SID="$ROOT/fixtures/demo/demo-data.sid"
    APP_DATA="$ROOT/fixtures/demo/app-data.json"
    local role title
    local log_file
    for role in device core server client; do
        case "$role" in
            device) title=Device ;;
            core) title=Core ;;
            server) title=Server ;;
            client) title=Client ;;
        esac
        log_file="/tmp/schc-coreconf-demo-print/$role.log"
        build_role_command "$role" "$log_file" "/tmp/schc-coreconf-demo-print/$role.exit-status"
        printf 'ROLE %s: ' "$role"
        print_argv "${ROLE_COMMAND[@]}"
        if [[ -n "$TERMINAL_KIND" ]]; then
            build_terminal_command "$title" "${ROLE_COMMAND[@]}"
            printf 'WINDOW %s: ' "$role"
            print_argv "${TERMINAL_COMMAND[@]}"
        fi
    done
    owner_user=$saved_owner
}

launch_role() {
    local role=$1
    local title=$2
    local log_file="$LOG_DIR/$role.interactive.log"
    local status_file="$LOG_DIR/$role.exit-status"
    : >"$log_file"
    : >"$status_file"
    ROLE_LOGS["$role"]=$log_file
    ROLE_STATUS["$role"]=$status_file
    build_role_command "$role" "$log_file" "$status_file"
    build_terminal_command "$title" "${ROLE_COMMAND[@]}"
    printf 'DEMO LAUNCH %s: ' "$role"
    print_argv "${TERMINAL_COMMAND[@]}"
    "${TERMINAL_COMMAND[@]}" &
}

wait_for_interactive_role() {
    local role=$1
    local needle=$2
    local deadline=$((SECONDS + 60))
    while (( SECONDS < deadline )); do
        grep -Fq -- "$needle" "${ROLE_LOGS[$role]}" 2>/dev/null && return 0
        if [[ -s "${ROLE_STATUS[$role]}" ]]; then
            local role_status
            role_status=$(<"${ROLE_STATUS[$role]}")
            error "$role role exited with status $role_status before readiness; see ${ROLE_LOGS[$role]}"
        fi
        sleep 0.05
    done
    error "timed out waiting for '$needle'; see ${ROLE_LOGS[$role]}"
}

cleanup_interactive() {
    local status=$1
    (( CLEANUP_DONE )) && return
    CLEANUP_DONE=1
    set +e
    local namespace
    if (( NETWORK_ATTEMPTED )); then
        for namespace in "${NAMESPACES[@]}"; do
            kill_demo_namespace_processes "$namespace"
        done
    fi
    if (( NETWORK_ATTEMPTED )); then
        delete_demo_network
    fi
    if (( status != 0 || KEEP_LOGS )); then
        printf 'DEMO LOGS %s\n' "$LOG_DIR" >&2
    else
        rm -rf "$TMP_DIR"
    fi
    exit "$status"
}

for argument in "$@"; do
    case "$argument" in
        --check) CHECK_ONLY=1 ;;
        --no-build) NO_BUILD=1 ;;
        --keep-logs) KEEP_LOGS=1 ;;
        --print-commands) PRINT_COMMANDS=1 ;;
        -h|--help) usage; exit 0 ;;
        *) error "unknown argument $argument; use --help" ;;
    esac
done

(( EUID != 0 )) || error "run the interactive launcher as an unprivileged user"
select_terminal

if (( PRINT_COMMANDS )); then
    print_role_commands
    exit 0
fi

preflight() {
    local command_name binary
    for command_name in bash ip python3 grep sysctl sudo script runuser; do
        require_command "$command_name"
    done
    [[ -r "$ROLE_HELPER" ]] || error "missing role helper: $ROLE_HELPER"
    if (( ! NO_BUILD && ! CHECK_ONLY )); then
        require_command cargo
    fi
    [[ -e /dev/net/tun ]] || error "missing /dev/net/tun; Linux TUN support is required"
    [[ -r "$APP_SID" ]] || error "missing application SID fixture: $APP_SID"
    [[ -r "$APP_DATA" ]] || error "missing application data fixture: $APP_DATA"
    [[ -r "$ROOT/Cargo.toml" ]] || error "repository root is not a Cargo workspace: $ROOT"
    if (( NO_BUILD || CHECK_ONLY )); then
        for binary in "$CLIENT_BIN" "$SERVER_BIN" "$CORE_BIN" "$DEVICE_BIN"; do
            [[ -x "$binary" ]] ||
                error "missing binary $binary; run cargo build --workspace --bins or omit --no-build"
        done
    fi
    printf 'DEMO CHECK OK terminal=%s tun=present fixtures=present\n' "$TERMINAL_KIND"
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

init_demo_resources
owner_user=$(id -un "$owner_uid")
declare -A ROLE_LOGS ROLE_STATUS
trap 'cleanup_interactive "$?"' EXIT
trap 'exit 130' INT TERM

sudo -v
NETWORK_ATTEMPTED=1
setup_demo_network

launch_role device Device
wait_for_interactive_role device "READY device  "

launch_role core Core
wait_for_interactive_role core "READY core  "

setup_demo_tun_routes

launch_role server Server
wait_for_interactive_role server \
    "READY server  bind=[2001:db8::1]:5683  path=c"

launch_role client Client
wait_for_interactive_role client \
    "READY client  server=[2001:db8::1]:5683  bind=[2001:db8::2]:5683"

printf 'DEMO READY interactive\n'
printf 'Use the Client and Core windows for commands; Device and Server show logs.\n'
while :; do
    sleep 1
    for role in device core server client; do
        if [[ -s "${ROLE_STATUS[$role]}" ]]; then
            role_status=$(<"${ROLE_STATUS[$role]}")
            error "$role role exited with status $role_status; see ${ROLE_LOGS[$role]}"
        fi
    done
done
