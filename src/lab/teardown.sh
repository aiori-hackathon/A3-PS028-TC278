#!/usr/bin/env bash
# Remove the HappyLab lab completely, then verify nothing is left.
#
#   sudo src/lab/teardown.sh
#
# Idempotent: safe to run when the lab is partly or fully gone.
# Deleting a namespace also deletes its veths, qdiscs, routes and neighbour entries.
# Only files written by setup.sh are removed; it never uses rm -r.
set -euo pipefail

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
need_root

echo "== HappyLab teardown: $(date -u +%Y-%m-%dT%H:%M:%SZ) =="

stop_processes() {  # stop_processes NS: TERM, wait up to 2 s, then KILL
    local ns=$1 pids i
    pids=$(ip netns pids "$ns" 2>/dev/null || true)
    if [[ -z $pids ]]; then
        echo "none: processes in $ns"
        return 0
    fi
    # shellcheck disable=SC2086  # word splitting of the PID list is intended
    run kill $pids || true
    for i in 1 2 3 4 5 6 7 8 9 10; do
        pids=$(ip netns pids "$ns" 2>/dev/null || true)
        [[ -z $pids ]] && return 0
        sleep 0.2
    done
    # shellcheck disable=SC2086
    run kill -9 $pids || true
}

for ns in "$NS_CLIENT" "$NS_SERVER"; do
    if ns_exists "$ns"; then
        stop_processes "$ns"
        run ip netns del "$ns"
    else
        echo "absent: namespace $ns"
    fi
done

for f in resolv.conf gai.conf; do
    if [[ -e $NETNS_ETC/$f ]]; then
        run rm -f "$NETNS_ETC/$f"
    else
        echo "absent: $NETNS_ETC/$f"
    fi
done

remove_dir_if_empty() {
    if [[ ! -d $1 ]]; then
        echo "absent: $1"
    elif [[ -z $(ls -A "$1") ]]; then
        run rmdir "$1"
    else
        echo "WARNING: $1 is not empty, left in place:" >&2
        ls -A "$1" >&2
    fi
}
remove_dir_if_empty "$NETNS_ETC"
remove_dir_if_empty "$(dirname "$NETNS_ETC")"

echo "== teardown done; verifying =="
exec "$HL_LAB_DIR/verify.sh" down
