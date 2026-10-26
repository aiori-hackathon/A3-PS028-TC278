#!/usr/bin/env bash
# Verify the HappyLab lab. Read-only: it changes nothing.
#
#   sudo src/lab/verify.sh up [V4_TARGET V6_TARGET]   # lab present, RTT on target
#   sudo src/lab/verify.sh down                       # nothing of the lab left
#
# V4_TARGET / V6_TARGET: expected RTT in ms (default: BASELINE_RTT_MS from lab.env),
# or "blackhole" when 100% loss is expected.
# Every check prints PASS or FAIL; all checks run, then the script exits 1 if any failed.
# RTT lines are measured with ping from inside hl-client (packet-level evidence);
# netem lines are configuration only, not ground truth.
set -euo pipefail

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
need_root

mode=${1:-up}
checks=0
fails=0

pass() { checks=$((checks + 1)); printf 'PASS %s\n' "$*"; }
fail() { checks=$((checks + 1)); fails=$((fails + 1)); printf 'FAIL %s\n' "$*"; }
info() { printf 'INFO %s\n' "$*"; }

# expect DESCRIPTION TEXT NEEDLE...: pass if TEXT contains every NEEDLE
expect() {
    local desc=$1 text=$2 needle
    shift 2
    for needle in "$@"; do
        if [[ $text != *"$needle"* ]]; then
            fail "$desc (missing: $needle)"
            return 0
        fi
    done
    pass "$desc"
}

# expect_empty DESCRIPTION TEXT
expect_empty() {
    if [[ -z $2 ]]; then pass "$1"; else fail "$1 (found: ${2//$'\n'/ | })"; fi
}

# --- host-namespace safety (read-only) ---------------------------------------
host_checks() {
    local links routes
    links=$(ip -o link show | awk -F': ' '{print $2}' | sed 's/@.*//' | grep -E '^hl-' || true)
    expect_empty "host: no hl-* interfaces in the host namespace" "$links"
    routes=$( { ip -4 route show table all; ip -6 route show table all; } 2>/dev/null \
              | grep -E "$HL_HOST_LAB_RE" || true)
    expect_empty "host: no lab prefixes in host routes" "$routes"
    if [[ -n $(ip -4 route show default) ]]; then
        pass "host: IPv4 default route present ($(ip -4 route show default | head -1))"
    else
        fail "host: IPv4 default route missing (also happens if Wi-Fi is down)"
    fi
    info "host IPv6 default: $(ip -6 route show default | head -1)"
    if grep -q 'hl\.test' /etc/hosts; then
        fail "host: /etc/hosts must not mention hl.test"
    else
        pass "host: /etc/hosts does not mention hl.test"
    fi
}

# --- one interface end -------------------------------------------------------
# check_end NS IF MAC FAMILY ADDR/LEN
check_end() {
    local ns=$1 dev=$2 mac=$3 family=$4 addr=$5 link a4 a6
    link=$(ip -n "$ns" -o link show dev "$dev" 2>&1 || true)
    expect "$ns/$dev: up, MAC $mac" "$link" "state UP" "link/ether $mac"
    a4=$(ip -n "$ns" -o -4 addr show dev "$dev" 2>/dev/null || true)
    a6=$(ip -n "$ns" -o -6 addr show dev "$dev" 2>/dev/null || true)
    if [[ $family == 4 ]]; then
        expect "$ns/$dev: has $addr" "$a4" "inet $addr "
        expect_empty "$ns/$dev: no IPv6 address" "$a6"
    else
        expect "$ns/$dev: has $addr" "$a6" "inet6 $addr "
        expect_empty "$ns/$dev: no IPv4 address" "$a4"
        local line
        line=$(grep -F "inet6 $addr " <<<"$a6" || true)
        if [[ -z $line || $line == *tentative* || $line == *dadfailed* ]]; then
            fail "$ns/$dev: IPv6 address is tentative or failed DAD"
        else
            pass "$ns/$dev: IPv6 address usable (not tentative)"
        fi
    fi
}

# check_neigh NS IF ADDR MAC
check_neigh() {
    local out
    out=$(ip -n "$1" neigh show "$3" dev "$2" 2>&1 || true)
    expect "$1/$2: static neighbour $3" "$out" "lladdr $4" "PERMANENT"
}

# check_netem NS IF: present on impaired links; printed as configuration only
check_netem() {
    local out
    out=$(tc -n "$1" qdisc show dev "$2" 2>&1 || true)
    expect "$1/$2: netem qdisc present" "$out" "qdisc netem"
    info "$1/$2 netem config (not ground truth): $(grep netem <<<"$out" || true)"
}

# check_file_in_ns DESCRIPTION PATH EXPECTED: what hl-client actually sees at PATH
check_file_in_ns() {
    local seen
    seen=$(ip netns exec "$NS_CLIENT" cat "$2" 2>&1 || true)
    if [[ $seen == "$3" ]]; then
        pass "$1"
    else
        fail "$1 (hl-client sees: ${seen//$'\n'/ | })"
    fi
}

# rtt LABEL NS FAMILY DST TARGET: measure real RTT with ping and compare to TARGET
rtt() {
    local label=$1 ns=$2 family=$3 dst=$4 target=$5 out stats verdict
    out=$(LC_ALL=C ip netns exec "$ns" ping "-$family" -n -c "$PING_COUNT" \
          -i "$PING_INTERVAL_S" -W "$PING_WAIT_S" "$dst" 2>&1 || true)
    if ! stats=$(hl_rtt_stats <<<"$out"); then
        fail "RTT $label: could not read ping output"
        sed 's/^/  | /' <<<"$out"
        return 0
    fi
    if verdict=$(hl_rtt_check "$target" "$stats"); then
        pass "RTT $label $stats $verdict"
    else
        fail "RTT $label $stats $verdict"
    fi
}

valid_target() {
    [[ $1 == blackhole || $1 =~ ^[0-9]+(\.[0-9]+)?$ ]]
}

verify_up() {
    local v4_target=${1:-$BASELINE_RTT_MS} v6_target=${2:-$BASELINE_RTT_MS} ns
    for t in "$v4_target" "$v6_target"; do
        valid_target "$t" || { echo "error: bad target '$t' (use a number in ms or 'blackhole')" >&2; exit 2; }
    done
    echo "== HappyLab verify up: $(date -u +%Y-%m-%dT%H:%M:%SZ) targets v4=$v4_target v6=$v6_target =="

    for ns in "$NS_CLIENT" "$NS_SERVER"; do
        if ns_exists "$ns"; then pass "namespace $ns exists"; else fail "namespace $ns exists"; fi
    done

    check_end "$NS_CLIENT" "$V4_IF_C"  "$V4_MAC_C"  4 "$V4_ADDR_C/$V4_PREFIX_LEN"
    check_end "$NS_SERVER" "$V4_IF_S"  "$V4_MAC_S"  4 "$V4_ADDR_S/$V4_PREFIX_LEN"
    check_end "$NS_CLIENT" "$V6_IF_C"  "$V6_MAC_C"  6 "$V6_ADDR_C/$V6_PREFIX_LEN"
    check_end "$NS_SERVER" "$V6_IF_S"  "$V6_MAC_S"  6 "$V6_ADDR_S/$V6_PREFIX_LEN"
    check_end "$NS_CLIENT" "$CTL_IF_C" "$CTL_MAC_C" 4 "$CTL_ADDR_C/$CTL_PREFIX_LEN"
    check_end "$NS_SERVER" "$CTL_IF_S" "$CTL_MAC_S" 4 "$CTL_ADDR_S/$CTL_PREFIX_LEN"

    check_neigh "$NS_CLIENT" "$V4_IF_C" "$V4_ADDR_S" "$V4_MAC_S"
    check_neigh "$NS_SERVER" "$V4_IF_S" "$V4_ADDR_C" "$V4_MAC_C"
    check_neigh "$NS_CLIENT" "$V6_IF_C" "$V6_ADDR_S" "$V6_MAC_S"
    check_neigh "$NS_SERVER" "$V6_IF_S" "$V6_ADDR_C" "$V6_MAC_C"

    expect "$NS_CLIENT: IPv4 default route via v4 link" \
        "$(ip -n "$NS_CLIENT" -4 route show default 2>&1 || true)" "via $V4_ADDR_S dev $V4_IF_C"
    expect "$NS_CLIENT: IPv6 default route via v6 link" \
        "$(ip -n "$NS_CLIENT" -6 route show default 2>&1 || true)" "via $V6_ADDR_S dev $V6_IF_C"

    local port_start
    port_start=$(ip netns exec "$NS_SERVER" sysctl -n net.ipv4.ip_unprivileged_port_start 2>&1 || true)
    if [[ $port_start == 0 ]]; then
        pass "$NS_SERVER: unprivileged ports start at 0"
    else
        fail "$NS_SERVER: unprivileged ports start at 0 (got $port_start)"
    fi

    check_netem "$NS_CLIENT" "$V4_IF_C"
    check_netem "$NS_SERVER" "$V4_IF_S"
    check_netem "$NS_CLIENT" "$V6_IF_C"
    check_netem "$NS_SERVER" "$V6_IF_S"
    local q
    for q in "$NS_CLIENT:$CTL_IF_C" "$NS_SERVER:$CTL_IF_S"; do
        if tc -n "${q%%:*}" qdisc show dev "${q#*:}" 2>/dev/null | grep -q netem; then
            fail "${q%%:*}/${q#*:}: ctl link must not be impaired"
        else
            pass "${q%%:*}/${q#*:}: no netem on ctl link"
        fi
    done

    check_file_in_ns "$NS_CLIENT sees lab resolv.conf (bind mount works)" /etc/resolv.conf "$(hl_resolv_conf)"
    check_file_in_ns "$NS_CLIENT sees lab gai.conf (bind mount works)" /etc/gai.conf "$(hl_gai_conf)"

    host_checks

    rtt v4  "$NS_CLIENT" 4 "$V4_ADDR_S"  "$v4_target"
    rtt v6  "$NS_CLIENT" 6 "$V6_ADDR_S"  "$v6_target"
    rtt ctl "$NS_CLIENT" 4 "$CTL_ADDR_S" "max:$CTL_MAX_RTT_MS"
}

verify_down() {
    echo "== HappyLab verify down: $(date -u +%Y-%m-%dT%H:%M:%SZ) =="
    local ns
    for ns in "$NS_CLIENT" "$NS_SERVER"; do
        if ns_exists "$ns"; then fail "namespace $ns removed"; else pass "namespace $ns removed"; fi
    done
    local left
    left=$(ip netns list 2>/dev/null | awk '{print $1}' | grep -E '^hl-' || true)
    expect_empty "no hl-* namespaces left" "$left"
    if [[ -e $NETNS_ETC ]]; then
        fail "$NETNS_ETC removed"
    else
        pass "$NETNS_ETC removed"
    fi
    host_checks
}

case $mode in
    up)   shift || true; verify_up "$@" ;;
    down) verify_down ;;
    *)    echo "usage: $0 up [V4_TARGET V6_TARGET] | down" >&2; exit 2 ;;
esac

if ((fails == 0)); then
    echo "VERIFY $mode: PASS ($checks checks)"
else
    echo "VERIFY $mode: FAIL ($fails of $checks failed)"
    exit 1
fi
