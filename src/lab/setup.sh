#!/usr/bin/env bash
# Bring the HappyLab lab to its baseline state, then verify it.
#
#   sudo src/lab/setup.sh
#
# Idempotent: it converges to the target state, so running it again (or after a
# half-finished run) completes the lab instead of failing or duplicating anything.
# Touches only the hl-client and hl-server namespaces and /etc/netns/hl-client/.
# Nothing is created in the host namespace: veths are created directly inside the namespaces.
# Undo with src/lab/teardown.sh.
set -euo pipefail

# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
need_root

echo "== HappyLab setup: $(date -u +%Y-%m-%dT%H:%M:%SZ) =="

# Load netem now so a missing module fails here, with a clear message, not halfway through.
run modprobe sch_netem

# --- namespaces --------------------------------------------------------------
for ns in "$NS_CLIENT" "$NS_SERVER"; do
    if ns_exists "$ns"; then
        echo "exists: namespace $ns"
    else
        run ip netns add "$ns"
    fi
    run ip -n "$ns" link set dev lo up
    # Per-namespace only. No duplicate-address detection or router adverts in the lab:
    # DAD would leave IPv6 addresses "tentative" for about a second after setup.
    run ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.accept_dad=0 net.ipv6.conf.default.accept_dad=0
    run ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.accept_ra=0 net.ipv6.conf.default.accept_ra=0
done

# --- veth pairs (client end in hl-client, server end in hl-server) -----------
make_link() {  # make_link CLIENT_IF SERVER_IF
    if ip -n "$NS_CLIENT" link show dev "$1" >/dev/null 2>&1; then
        echo "exists: veth $1 <-> $2"
    else
        run ip link add "$1" netns "$NS_CLIENT" type veth peer name "$2" netns "$NS_SERVER"
    fi
}

# configure_end NS IF MAC FAMILY ADDR/LEN
configure_end() {
    local ns=$1 dev=$2 mac=$3 family=$4 addr=$5 current
    current=$(ip -n "$ns" -o link show dev "$dev" | awk '{for (i = 1; i < NF; i++) if ($i == "link/ether") print $(i + 1)}')
    if [[ $current != "$mac" ]]; then
        run ip -n "$ns" link set dev "$dev" down
        run ip -n "$ns" link set dev "$dev" address "$mac"
    fi
    if [[ $family == 4 ]]; then
        run ip netns exec "$ns" sysctl -qw "net.ipv6.conf.$dev.disable_ipv6=1"
        run ip -n "$ns" addr replace "$addr" dev "$dev"
    else
        run ip netns exec "$ns" sysctl -qw "net.ipv6.conf.$dev.disable_ipv6=0"
        run ip netns exec "$ns" sysctl -qw "net.ipv6.conf.$dev.accept_dad=0"
        run ip netns exec "$ns" sysctl -qw "net.ipv6.conf.$dev.accept_ra=0"
        run ip -n "$ns" addr replace "$addr" dev "$dev" nodad
    fi
    run ip -n "$ns" link set dev "$dev" up
}

make_link "$V4_IF_C" "$V4_IF_S"
make_link "$V6_IF_C" "$V6_IF_S"
make_link "$CTL_IF_C" "$CTL_IF_S"

configure_end "$NS_CLIENT" "$V4_IF_C"  "$V4_MAC_C"  4 "$V4_ADDR_C/$V4_PREFIX_LEN"
configure_end "$NS_SERVER" "$V4_IF_S"  "$V4_MAC_S"  4 "$V4_ADDR_S/$V4_PREFIX_LEN"
configure_end "$NS_CLIENT" "$V6_IF_C"  "$V6_MAC_C"  6 "$V6_ADDR_C/$V6_PREFIX_LEN"
configure_end "$NS_SERVER" "$V6_IF_S"  "$V6_MAC_S"  6 "$V6_ADDR_S/$V6_PREFIX_LEN"
configure_end "$NS_CLIENT" "$CTL_IF_C" "$CTL_MAC_C" 4 "$CTL_ADDR_C/$CTL_PREFIX_LEN"
configure_end "$NS_SERVER" "$CTL_IF_S" "$CTL_MAC_S" 4 "$CTL_ADDR_S/$CTL_PREFIX_LEN"

# --- static neighbours on the impaired links ----------------------------------
# With permanent entries, a later "netem loss 100%" drops data only: ARP/ND cannot
# fail, so a blackhole stays silent instead of turning into "host unreachable".
run ip -n "$NS_CLIENT" neigh replace "$V4_ADDR_S" lladdr "$V4_MAC_S" dev "$V4_IF_C" nud permanent
run ip -n "$NS_SERVER" neigh replace "$V4_ADDR_C" lladdr "$V4_MAC_C" dev "$V4_IF_S" nud permanent
run ip -n "$NS_CLIENT" neigh replace "$V6_ADDR_S" lladdr "$V6_MAC_S" dev "$V6_IF_C" nud permanent
run ip -n "$NS_SERVER" neigh replace "$V6_ADDR_C" lladdr "$V6_MAC_C" dev "$V6_IF_S" nud permanent

# --- client default routes ---------------------------------------------------
# Chromium decides whether IPv6 is usable by looking up a route to a global
# address, so the client needs an IPv6 default route, not just the on-link /64.
run ip -n "$NS_CLIENT" -4 route replace default via "$V4_ADDR_S" dev "$V4_IF_C"
run ip -n "$NS_CLIENT" -6 route replace default via "$V6_ADDR_S" dev "$V6_IF_C"

# nginx and the DNS server run as the normal user inside hl-server on ports 80 and 53.
run ip netns exec "$NS_SERVER" sysctl -qw net.ipv4.ip_unprivileged_port_start=0

# --- baseline impairment (v4 and v6 links only; ctl is never impaired) -------
for pair in "$NS_CLIENT:$V4_IF_C" "$NS_SERVER:$V4_IF_S" "$NS_CLIENT:$V6_IF_C" "$NS_SERVER:$V6_IF_S"; do
    run tc -n "${pair%%:*}" qdisc replace dev "${pair#*:}" root netem delay "${BASELINE_DELAY_MS}ms"
done

# --- lab-only resolver and address-selection policy for hl-client -------------
write_file() {  # write_file PATH (contents on stdin), mode 0644, atomic
    printf '+ write %s\n' "$1"
    cat > "$1.tmp"
    chmod 0644 "$1.tmp"
    mv -f "$1.tmp" "$1"
}
run install -d -m 0755 "$NETNS_ETC"
hl_resolv_conf | write_file "$NETNS_ETC/resolv.conf"
hl_gai_conf | write_file "$NETNS_ETC/gai.conf"

echo "== setup done; verifying =="
exec "$HL_LAB_DIR/verify.sh" up "$BASELINE_RTT_MS" "$BASELINE_RTT_MS"
