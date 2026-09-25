#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

usage() {
    printf 'Usage: demo_role.sh (--root | --user USER) LOG_FILE STATUS_FILE PROGRAM [ARG ...]\n' >&2
    exit 2
}

[[ $# -ge 4 ]] || usage
drop_user=''
case "$1" in
    --root)
        shift
        ;;
    --as-user)
        shift
        ;;
    --user)
        [[ $# -ge 4 ]] || usage
        drop_user=$2
        shift 2
        ;;
    *)
        usage
        ;;
esac

[[ $# -ge 2 ]] || usage
log_file=$1
shift
status_file=$1
shift

if [[ -n "$drop_user" ]]; then
    exec runuser -u "$drop_user" -- bash "$0" --as-user "$log_file" "$status_file" "$@"
fi

[[ $# -ge 1 ]] || usage
role_command=''
printf -v role_command '%q ' "$@"
role_command=${role_command% }
role_status=0
if script -qefc "$role_command" "$log_file"; then
    role_status=0
else
    role_status=$?
fi
printf '%s\n' "$role_status" >"$status_file"
exit "$role_status"
