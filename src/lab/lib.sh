# shellcheck shell=bash
# Shared helpers for the HappyLab lab scripts. Sourced, never executed.
# The RTT helpers (hl_rtt_stats, hl_rtt_check) are pure text functions,
# so they are tested without sudo in src/tests/test_lab_lib.py.

HL_LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lab.env
source "$HL_LAB_DIR/lab.env"

# Host routes must never mention these lab prefixes.
HL_HOST_LAB_RE='192\.0\.2\.|198\.51\.100\.|2001:db8:28:'

# Print a command, then run it.
run() {
    printf '+ %s\n' "$*"
    "$@"
}

need_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "error: run this with sudo (plain sudo, never sudo -E)" >&2
        exit 1
    fi
}

ns_exists() {
    [[ -e "/run/netns/$1" ]]
}

# Contents of the lab-only files in /etc/netns/hl-client/.
hl_resolv_conf() {
    printf '# HappyLab lab-only resolver for %s (written by src/lab/setup.sh)\n' "$NS_CLIENT"
    printf 'nameserver %s\n' "$DNS_ADDR"
}

hl_gai_conf() {
    printf '# HappyLab lab-only gai.conf for %s (written by src/lab/setup.sh).\n' "$NS_CLIENT"
    printf '# Intentionally has no rules: the glibc built-in default address-selection policy applies.\n'
}

# Read iputils ping output on stdin. Print one line:
#   median_ms=X min_ms=X max_ms=X loss_pct=X sent=N received=N
# (median/min/max are NA when no replies arrived). Exit 1 if there is no summary line.
# Loss is computed from the transmitted/received counts, not ping's own percentage.
hl_rtt_stats() {
    awk '
        match($0, /time=[0-9.]+/) { t[++n] = substr($0, RSTART + 5, RLENGTH - 5) + 0 }
        /packets transmitted/ {
            sent = $1 + 0
            for (i = 2; i <= NF; i++) if ($i == "received," || $i == "received") recv = $(i - 1) + 0
            seen = 1
        }
        END {
            if (!seen || sent == 0) { print "error=no_ping_summary"; exit 1 }
            for (i = 2; i <= n; i++) {          # insertion sort of the RTT samples
                v = t[i]; j = i - 1
                while (j > 0 && t[j] > v) { t[j + 1] = t[j]; j-- }
                t[j + 1] = v
            }
            if (n == 0) printf "median_ms=NA min_ms=NA max_ms=NA"
            else {
                med = (n % 2) ? t[(n + 1) / 2] : (t[n / 2] + t[n / 2 + 1]) / 2
                printf "median_ms=%.2f min_ms=%.2f max_ms=%.2f", med, t[1], t[n]
            }
            printf " loss_pct=%g sent=%d received=%d\n", 100 * (sent - recv) / sent, sent, recv
        }'
}

# hl_rtt_check TARGET STATS
# TARGET is an RTT in ms, "blackhole" (100% loss expected) or "max:N" (below N ms, no loss).
# A numeric target passes when loss is 0 and |median - target| <= max(2 ms, 10% of target).
# Prints the target and verdict; exit 0 on PASS, 1 on FAIL, 2 on a bad TARGET.
hl_rtt_check() {
    awk -v target="$1" -v stats="$2" '
        BEGIN {
            n = split(stats, kv, " ")
            for (i = 1; i <= n; i++) { split(kv[i], p, "="); s[p[1]] = p[2] }
            loss = s["loss_pct"] + 0
            med = s["median_ms"]
            if (target == "blackhole") {
                if (loss == 100) { print "target=blackhole PASS"; exit 0 }
                printf "target=blackhole FAIL (expected 100%% loss, got %g%%)\n", loss; exit 1
            }
            if (target ~ /^max:[0-9]+(\.[0-9]+)?$/) {
                lim = substr(target, 5) + 0
                if (loss == 0 && med != "NA" && med + 0 < lim) { printf "target_ms=<%g PASS\n", lim; exit 0 }
                printf "target_ms=<%g FAIL (median %s, loss %g%%)\n", lim, med, loss; exit 1
            }
            if (target !~ /^[0-9]+(\.[0-9]+)?$/) { printf "error: bad target %s\n", target; exit 2 }
            t = target + 0
            tol = t * 0.10; if (tol < 2) tol = 2
            if (loss != 0 || med == "NA") {
                printf "target_ms=%g tol_ms=%.1f FAIL (loss %g%%)\n", t, tol, loss; exit 1
            }
            d = med - t; if (d < 0) d = -d
            if (d <= tol) { printf "target_ms=%g tol_ms=%.1f PASS\n", t, tol; exit 0 }
            printf "target_ms=%g tol_ms=%.1f FAIL (median outside %.1f-%.1f)\n", t, tol, t - tol, t + tol
            exit 1
        }'
}
