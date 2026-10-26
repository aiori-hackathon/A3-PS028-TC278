#!/usr/bin/env bash
# Set the impairment on one lab link, equally in both directions.
#
#   sudo src/lab/netem.sh FAMILY DELAY_MS_EACH_WAY LOSS_PCT
#   sudo src/lab/netem.sh v6 10 100     # S1: IPv6 blackhole
#   sudo src/lab/netem.sh v6 10 0       # restore v6 to baseline
#
# Changes only qdiscs on the server end and its ifb device inside hl-server
# (see hl_set_link in lib.sh). Always follow with verify.sh and the matching targets.
set -euo pipefail

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
need_root

if [[ $# -ne 3 ]]; then
    echo "usage: $0 v4|v6 DELAY_MS_EACH_WAY LOSS_PCT" >&2
    exit 2
fi
if ! ns_exists "$NS_SERVER"; then
    echo "error: lab is not set up (run src/lab/setup.sh first)" >&2
    exit 1
fi

echo "== HappyLab netem: $(date -u +%Y-%m-%dT%H:%M:%SZ) $1 delay=${2}ms each way, loss=${3}% each way =="
hl_set_link "$1" "$2" "$3"
echo "next: sudo src/lab/verify.sh up <v4 target> <v6 target>"
