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

# hl_set_link FAMILY DELAY_MS LOSS_PCT [JITTER_MS]
# JITTER_MS (optional, default 0) adds netem delay variation with the distribution named
# explicitly ("distribution normal"; tc-netem(8): JITTER is the spread around DELAY), so the
# result never depends on netem's default. With JITTER_MS 0 or absent the netem arguments are
# exactly what they were before jitter existed (C0 and S1-S6 are pinned by a test).
# Impair one link (v4 or v6) equally in both directions, without touching the client:
#   server->client: netem on the server end's egress (hl-v4s / hl-v6s)
#   client->server: netem on the ifb device that receives the server end's ingress
# The client interfaces stay qdisc-free, so a capture in hl-client sees every packet
# the client sends, at the time it sends it (egress qdiscs act before tcpdump sees a packet).
# Arguments are validated before anything is changed; exit 2 on bad input.
hl_set_link() {
    local family=$1 delay=$2 loss=$3 jitter=${4:-0} dev ifb
    case $family in
        v4) dev=$V4_IF_S ifb=$V4_IFB ;;
        v6) dev=$V6_IF_S ifb=$V6_IFB ;;
        *) echo "error: family must be v4 or v6, got '$family'" >&2; return 2 ;;
    esac
    # Whole ms, or a half ms (an odd "+N ms RTT" splits into N/2 each way, e.g. 72.5); tc takes "72.5ms".
    if [[ ! $delay =~ ^[0-9]+(\.5)?$ ]]; then
        echo "error: delay must be whole ms or end in .5, got '$delay'" >&2; return 2
    fi
    if [[ ! $loss =~ ^[0-9]+$ ]] || ((loss > 100)); then
        echo "error: loss must be 0-100 (%), got '$loss'" >&2; return 2
    fi
    if [[ ! $jitter =~ ^[0-9]+$ ]]; then
        echo "error: jitter must be whole ms, got '$jitter'" >&2; return 2
    fi
    local netem=(netem delay "${delay}ms")
    if ((jitter > 0)); then netem+=("${jitter}ms" distribution normal); fi
    if ((loss > 0)); then netem+=(loss "${loss}%"); fi
    run tc -n "$NS_SERVER" qdisc replace dev "$dev" root "${netem[@]}"
    run tc -n "$NS_SERVER" qdisc replace dev "$ifb" root "${netem[@]}"
}

# hl_rtt_stats [sd]
# Read iputils ping output on stdin. Print one line:
#   median_ms=X min_ms=X max_ms=X loss_pct=X sent=N received=N errors=N
# (median/min/max are NA when no replies arrived). Exit 1 if there is no summary line.
# With the argument "sd" (band verify only), " sd_ms=X" (population standard deviation of the
# RTT samples, NA with fewer than 2) is appended; without it the line is exactly as before.
# Loss is computed from the transmitted/received counts, not ping's own percentage.
# errors counts ICMP errors such as "Destination Host Unreachable" (0 for a silent blackhole).
hl_rtt_stats() {
    awk -v want_sd="${1:-}" '
        match($0, /time=[0-9.]+/) { t[++n] = substr($0, RSTART + 5, RLENGTH - 5) + 0 }
        /packets transmitted/ {
            sent = $1 + 0
            for (i = 2; i <= NF; i++) {
                if ($i == "received," || $i == "received") recv = $(i - 1) + 0
                if ($i ~ /^\+[0-9]+$/ && $(i + 1) ~ /^errors/) errs = substr($i, 2) + 0
            }
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
            printf " loss_pct=%g sent=%d received=%d errors=%d", 100 * (sent - recv) / sent, sent, recv, errs
            if (want_sd == "sd") {
                if (n < 2) printf " sd_ms=NA"
                else {
                    for (i = 1; i <= n; i++) sum += t[i]
                    mean = sum / n
                    for (i = 1; i <= n; i++) ss += (t[i] - mean) ^ 2
                    printf " sd_ms=%.2f", sqrt(ss / n)
                }
            }
            printf "\n"
        }'
}

# hl_band_pings TARGET: number of pings a band target asks for (its last field); empty otherwise.
hl_band_pings() {
    case $1 in
        band:loss:*|band:jitter:*) printf '%s\n' "${1##*:}" ;;
    esac
}

# hl_rtt_check TARGET STATS
# TARGET is an RTT in ms, "blackhole" (100% loss and no ICMP errors: a silent drop)
# or "max:N" (below N ms, no loss).
# A numeric target passes when loss is 0 and |median - target| <= max(2 ms, 10% of target).
# This point check is the default and is unchanged. Band targets are for links where a point
# check is meaningless; the scenario declares the band (src/runner/scenario_grid.py):
#   band:loss:EXPECT_PCT:TOL_PCT:RTT_MS:N   round-trip ping loss within EXPECT +/- TOL percentage
#       points, no ICMP errors, and the median of the replies within the numeric tolerance of RTT
#   band:jitter:MED_LO:MED_HI:SD_LO:SD_HI:N   no loss, median RTT in [MED_LO, MED_HI] and the
#       RTT standard deviation (needs STATS from "hl_rtt_stats sd") in [SD_LO, SD_HI]
# N is the number of pings (used by verify.sh, not here). Every verdict prints the observed values.
# Verdict keys must never reuse a hl_rtt_stats key (median_ms, sd_ms, ...): verify.sh prints both on
# one line and the orchestrator's parser keeps the last value of a key.
# Prints the target and verdict; exit 0 on PASS, 1 on FAIL, 2 on a bad TARGET.
hl_rtt_check() {
    awk -v target="$1" -v stats="$2" '
        BEGIN {
            n = split(stats, kv, " ")
            for (i = 1; i <= n; i++) { split(kv[i], p, "="); s[p[1]] = p[2] }
            loss = s["loss_pct"] + 0
            med = s["median_ms"]
            if (target == "blackhole") {
                errs = s["errors"] + 0
                if (loss == 100 && errs == 0) { print "target=blackhole PASS"; exit 0 }
                if (loss != 100) { printf "target=blackhole FAIL (expected 100%% loss, got %g%%)\n", loss; exit 1 }
                printf "target=blackhole FAIL (%d ICMP errors: drop is not silent)\n", errs; exit 1
            }
            if (target ~ /^max:[0-9]+(\.[0-9]+)?$/) {
                lim = substr(target, 5) + 0
                if (loss == 0 && med != "NA" && med + 0 < lim) { printf "target_ms=<%g PASS\n", lim; exit 0 }
                printf "target_ms=<%g FAIL (median %s, loss %g%%)\n", lim, med, loss; exit 1
            }
            num = "[0-9]+(\\.[0-9]+)?"
            if (target ~ ("^band:loss:" num ":" num ":" num ":[0-9]+$")) {
                split(target, b, ":"); exp_l = b[3] + 0; tl = b[4] + 0; rt = b[5] + 0
                errs = s["errors"] + 0
                rtol = rt * 0.10; if (rtol < 2) rtol = 2
                head = sprintf("target=band:loss expect_loss_pct=%g tol_pct=%g rtt_ms=%g rtt_tol_ms=%.1f observed_loss_pct=%g observed_median_ms=%s", exp_l, tl, rt, rtol, loss, med)
                dl = loss - exp_l; if (dl < 0) dl = -dl
                if (dl > tl) { printf "%s FAIL (loss outside %g-%g%%)\n", head, exp_l - tl, exp_l + tl; exit 1 }
                if (errs != 0) { printf "%s FAIL (%d ICMP errors: drops are not silent)\n", head, errs; exit 1 }
                if (med == "NA") { printf "%s FAIL (no replies)\n", head; exit 1 }
                dr = med - rt; if (dr < 0) dr = -dr
                if (dr > rtol) { printf "%s FAIL (median outside %.1f-%.1f)\n", head, rt - rtol, rt + rtol; exit 1 }
                printf "%s PASS\n", head; exit 0
            }
            if (target ~ ("^band:jitter:" num ":" num ":" num ":" num ":[0-9]+$")) {
                split(target, b, ":"); mlo = b[3] + 0; mhi = b[4] + 0; slo = b[5] + 0; shi = b[6] + 0
                sd = s["sd_ms"]
                head = sprintf("target=band:jitter band_median_ms=%g-%g band_sd_ms=%g-%g observed_median_ms=%s observed_sd_ms=%s observed_loss_pct=%g", mlo, mhi, slo, shi, med, sd, loss)
                if (loss != 0) { printf "%s FAIL (loss %g%%)\n", head, loss; exit 1 }
                if (med == "NA" || sd == "" || sd == "NA") { printf "%s FAIL (no median or spread)\n", head; exit 1 }
                if (med + 0 < mlo || med + 0 > mhi) { printf "%s FAIL (median outside band)\n", head; exit 1 }
                if (sd + 0 < slo || sd + 0 > shi) { printf "%s FAIL (spread outside band)\n", head; exit 1 }
                printf "%s PASS\n", head; exit 0
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
