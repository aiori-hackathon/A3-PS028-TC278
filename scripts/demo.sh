#!/usr/bin/env bash
# make demo: one live run for the presentation, start to finish, in under a minute of machine time.
#
#   make demo                          # S1 (IPv6 blackhole) with curl
#   make demo SCENARIO=S4 CLIENT=chromium
#   DEMO_OPEN=0 make demo              # do not open the timeline in a browser
#
# Run as your normal user (never with sudo): it asks for the sudo password once, up front, then uses
# `sudo -n` only, so nothing can stop and wait for a password halfway.
#
#   1. lab: bring it up if it is not (src/lab/setup.sh), or verify it if it is (src/lab/verify.sh); PASS/FAIL
#   2. run: one repetition of SCENARIO with CLIENT (orchestrate.py --demo: apply, verify, capture, client,
#      restore baseline, verify again)
#   3. parse: re-read the capture and check it against the record; write the race timeline page
#   4. open: the timeline page in the browser
#   5. leave the lab up at baseline, then print the numbers to talk over
#
# Demo runs are written only to data/demo/ (gitignored) with a "demo-" session ID, so no dataset manifest,
# summary or batch check can pick them up (see `make demo-isolation-check`).
#
# On any error, timeout or Ctrl-C: leftover lab processes are stopped, both links are set back to the
# baseline and verified. If that verify fails, setup.sh converges the lab; if that fails too, teardown.sh
# removes it, so the lab is never left half-impaired. Every step has a time limit: nothing waits forever.
set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO"

SCENARIO=${SCENARIO:-S1}
CLIENT=${CLIENT:-curl}
DEMO_OPEN=${DEMO_OPEN:-1}
BUDGET_S=60
PY=(env -u PYTHONPATH -u LD_LIBRARY_PATH "$REPO/.venv/bin/python")
LAB_DIR=src/lab
DEMO_DIR=data/demo
# shellcheck source=../src/lab/lab.env
source "$LAB_DIR/lab.env"

if [[ $EUID -eq 0 ]]; then
    echo "error: run make demo as your normal user, not with sudo (it calls sudo itself)" >&2
    exit 2
fi

# --- output for a room ---------------------------------------------------------------------
if [[ -t 1 && -z ${NO_COLOR:-} ]]; then
    B=$'\e[1m' G=$'\e[1;32m' RD=$'\e[1;31m' Y=$'\e[1;33m' D=$'\e[2m' R=$'\e[0m'
else
    B="" G="" RD="" Y="" D="" R=""
fi
step_no=0
step() {   # step TITLE: a numbered heading with the elapsed time
    step_no=$((step_no + 1))
    printf '\n%s[%d/5] %s%s %s(t=%ds)%s\n' "$B" "$step_no" "$1" "$R" "$D" "$SECONDS" "$R"
}
say() { printf '  %s\n' "$*"; }
big_pass() {
    printf '%s' "$G"
    printf '  %s\n' '██▀▀██  ██▀▀██  ██▀▀▀▀  ██▀▀▀▀' '██▀▀▀▀  ██▀▀██  ▀▀▀▀██  ▀▀▀▀██' '▀▀      ▀▀  ▀▀  ▀▀▀▀▀▀  ▀▀▀▀▀▀'
    printf '%s  %s\n' "$R" "$*"
}
big_fail() {
    printf '%s' "$RD"
    printf '  %s\n' '██▀▀▀▀  ██▀▀██  ▀▀██▀▀  ██    ' '██▀▀    ██▀▀██    ██    ██    ' '▀▀      ▀▀  ▀▀  ▀▀▀▀▀▀  ▀▀▀▀▀▀'
    printf '%s  %s%s%s\n' "$R" "$RD" "$*" "$R"
}

mkdir -p "$DEMO_DIR/lab"
LOG="$DEMO_DIR/lab/demo_$(date -u +%Y%m%dT%H%M%SZ).log"
: >"$LOG"

# run_step LIMIT_S FILTER CMD...: run CMD with a time limit, the full output to $LOG, and the lines matching
# the awk FILTER on screen. Returns CMD's exit status (124 on timeout). The tee/awk side ignores Ctrl-C, so
# an interrupted command can still print its clean-up messages instead of dying on a closed pipe.
run_step() {
    local limit=$1 filter=$2
    shift 2
    printf '\n$ %s\n' "$*" >>"$LOG"
    set +e
    timeout --foreground -s INT -k 10 "$limit" "$@" 2>&1 \
        | ( trap '' INT; tee -a "$LOG" | awk "$filter { print \"  \" \$0; fflush() }" )
    local rc=${PIPESTATUS[0]}
    set -e
    if ((rc == 124)); then
        say "${RD}TIMED OUT after ${limit} s: $*${R}"
    fi
    return "$rc"
}

lab_present() { [[ -e /run/netns/$NS_CLIENT || -e /run/netns/$NS_SERVER ]]; }
lab_complete() { [[ -e /run/netns/$NS_CLIENT && -e /run/netns/$NS_SERVER ]]; }

# --- clean-up: on error, timeout or Ctrl-C ------------------------------------------------------
stop_lab_processes() {
    local ns pids
    for ns in "$NS_CLIENT" "$NS_SERVER"; do
        [[ -e /run/netns/$ns ]] || continue
        pids=$(timeout 5 sudo -n ip netns pids "$ns" 2>/dev/null | tr '\n' ' ' || true)
        if [[ -n ${pids// /} ]]; then
            say "stopping processes left in $ns: $pids"
            # shellcheck disable=SC2086  # the PID list is meant to split
            timeout 5 sudo -n kill $pids 2>/dev/null || true
            sleep 1
            pids=$(timeout 5 sudo -n ip netns pids "$ns" 2>/dev/null | tr '\n' ' ' || true)
            # shellcheck disable=SC2086
            [[ -n ${pids// /} ]] && { timeout 5 sudo -n kill -9 $pids 2>/dev/null || true; }
        fi
    done
}

restore_lab() {   # set both links to the baseline and verify; converge or remove the lab if that fails
    if ! timeout 5 sudo -n true 2>/dev/null; then
        big_fail "sudo needs a password again, so the lab could not be restored automatically."
        say "Run:  sudo src/lab/netem.sh v4 $BASELINE_DELAY_MS 0 && sudo src/lab/netem.sh v6 $BASELINE_DELAY_MS 0"
        say "then: sudo src/lab/verify.sh up   (or make lab-down to remove the lab)"
        return 1
    fi
    if ! lab_present; then
        say "the lab is not up, so there is nothing to restore"
        return 0
    fi
    stop_lab_processes
    if lab_complete; then
        say "restoring the baseline (${BASELINE_DELAY_MS} ms each way on both links) and verifying it"
        if run_step 15 '/^\+ tc/' sudo -n "$LAB_DIR/netem.sh" v4 "$BASELINE_DELAY_MS" 0 \
            && run_step 15 '/^\+ tc/' sudo -n "$LAB_DIR/netem.sh" v6 "$BASELINE_DELAY_MS" 0 \
            && run_step 40 '/^(PASS RTT|FAIL|VERIFY)/' sudo -n "$LAB_DIR/verify.sh" up "$BASELINE_RTT_MS" "$BASELINE_RTT_MS"; then
            big_pass "lab restored to baseline and verified; it is still up, so make demo can run again"
            return 0
        fi
    fi
    say "${Y}the lab is not at a verified baseline: rebuilding it with setup.sh${R}"
    if run_step 60 '/^(PASS RTT|FAIL|VERIFY)/' sudo -n "$LAB_DIR/setup.sh"; then
        big_pass "lab rebuilt and verified at baseline; make demo can run again"
        return 0
    fi
    say "${RD}setup.sh could not bring the lab to a verified baseline: removing it with teardown.sh${R}"
    if run_step 40 '/^(PASS|FAIL|VERIFY)/' sudo -n "$LAB_DIR/teardown.sh"; then
        big_fail "the lab was removed (nothing of it is left); make demo will rebuild it. Full log: $LOG"
    else
        big_fail "teardown did not verify. Run sudo src/lab/teardown.sh by hand. Full log: $LOG"
    fi
    return 1
}

interrupted=0
finished=0
on_exit() {
    local rc=$?
    trap '' INT TERM   # clean-up must finish; commands started from here inherit the ignore
    ((rc == 0)) && return 0
    if ((finished)); then   # the lab is verified at baseline; only the numbers are in question
        say "${RD}exit $rc: the run's numbers are flagged above; do not quote them. The lab is up at baseline.${R}"
        return 0
    fi
    if ((!lab_touched)); then   # stopped before the lab was touched: the reason is already on screen
        exit "$rc"
    fi
    printf '\n'
    if ((interrupted)); then
        big_fail "make demo was interrupted (Ctrl-C) at t=${SECONDS}s"
    else
        big_fail "make demo stopped at step $step_no (exit $rc) at t=${SECONDS}s. Full log: $LOG"
    fi
    if ((lab_touched)); then
        restore_lab || true
    fi
    say "Fallback: the committed example runs in examples/ (README there)."
    exit "$rc"
}
lab_touched=0
trap on_exit EXIT
trap 'interrupted=1; exit 130' INT
trap 'exit 143' TERM

printf '%sHappyLab live demo: %s with %s%s  %s(machine-time budget %d s; full log %s)%s\n' \
    "$B" "$SCENARIO" "$CLIENT" "$R" "$D" "$BUDGET_S" "$LOG" "$R"

# --- 0. arguments and sudo, before anything changes -------------------------------------------
if ! out=$("${PY[@]}" src/runner/orchestrate.py --demo --dry-run --scenario "$SCENARIO" --client "$CLIENT" 2>&1); then
    big_fail "SCENARIO=$SCENARIO CLIENT=$CLIENT is not a valid demo cell; nothing was changed"
    printf '%s\n' "$out" | grep -E 'error|ERROR|invalid' | sed 's/^/  /' || true
    exit 2
fi
if ! timeout 5 sudo -n true 2>/dev/null; then
    say "sudo: asking for your password once (every later sudo call is non-interactive)"
    if ! timeout --foreground 60 sudo -v; then
        big_fail "sudo was not granted; nothing was changed"
        exit 1
    fi
fi

# --- 1. lab ---------------------------------------------------------------------------------
lab_touched=1
if lab_complete; then
    step "Lab is up: verifying it (real RTT by ping on every link, interfaces, routes, qdiscs)"
    if ! run_step 40 '/^(PASS RTT|FAIL|VERIFY)/' sudo -n "$LAB_DIR/verify.sh" up "$BASELINE_RTT_MS" "$BASELINE_RTT_MS"; then
        say "${Y}verify failed: converging the lab with setup.sh (idempotent)${R}"
        run_step 60 '/^(PASS RTT|FAIL|VERIFY)/' sudo -n "$LAB_DIR/setup.sh"
    fi
else
    step "Lab is down: building it (namespaces, veths, netem baseline, lab DNS files) and verifying it"
    run_step 60 '/^(PASS RTT|FAIL|VERIFY)/' sudo -n "$LAB_DIR/setup.sh"
fi
checks=$(grep -Eo 'VERIFY up: PASS \([0-9]+ checks\)' "$LOG" | tail -1 || true)
big_pass "lab verified at baseline: ${checks#VERIFY up: PASS }"

# --- 2. one run -------------------------------------------------------------------------------
step "Running $SCENARIO once with $CLIENT (scenario applied, verified, captured, then baseline restored)"
# awk here may be mawk: no {n} intervals in the patterns
orch_rc=0
run_step 90 '/^  \[orchestrator\]|^(STOPPED|ERROR|  CONFLICT|WARNING)|^[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T/' \
    sudo -n "${PY[@]}" src/runner/orchestrate.py --demo --scenario "$SCENARIO" --client "$CLIENT" || orch_rc=$?
# exit 3: the run finished and the lab was restored, but the client log and the capture disagree. The numbers
# are still shown, flagged; anything else is a failure.
if ((orch_rc != 0 && orch_rc != 3)); then
    exit "$orch_rc"
fi
run_id=$(grep -Eo '^DEMO_RUN_ID=[^[:space:]]+' "$LOG" | tail -1 | cut -d= -f2 || true)
if [[ -z $run_id ]]; then
    echo "error: the orchestrator finished without naming its run" >&2
    exit 1
fi
say "${G}record written:${R} $DEMO_DIR/runs/$run_id.json"

# --- 3. parse -----------------------------------------------------------------------------------
step "Parsing the capture again and checking it against the record"
page_file=$(mktemp)
run_step 60 '1' "${PY[@]}" src/analysis/demo_report.py "$run_id" --parse-only --page-path-file "$page_file"
page=$(cat "$page_file")
rm -f "$page_file"

# --- 4. timeline --------------------------------------------------------------------------------
step "Opening the connection race timeline"
if [[ $DEMO_OPEN == 1 && -n ${DISPLAY:-}${WAYLAND_DISPLAY:-} ]] && command -v xdg-open >/dev/null; then
    setsid xdg-open "$page" >/dev/null 2>&1 </dev/null &
    say "opened in your browser: $page"
else
    say "${Y}not opened automatically${R} (DEMO_OPEN=$DEMO_OPEN, no display, or no xdg-open). Open: $page"
fi

# --- 5. lab stays up --------------------------------------------------------------------------------
step "Leaving the lab up at baseline for the next run"
# The orchestrator has stopped nginx and the DNS server, so anything still running in the namespaces was left
# by the run (a browser helper, say): name it and stop it, so the next run starts from the same state.
pids=$( { timeout 5 sudo -n ip netns pids "$NS_CLIENT"; timeout 5 sudo -n ip netns pids "$NS_SERVER"; } 2>/dev/null || true)
if [[ -n ${pids//[[:space:]]/} ]]; then
    say "${Y}left by the run:${R} $(ps -o comm= -p "$(tr -s '[:space:]' ',' <<<"$pids" | sed 's/^,//; s/,$//')" 2>/dev/null | tr '\n' ' ')"
    stop_lab_processes
fi
qd=$(timeout 10 sudo -n tc -n "$NS_SERVER" qdisc show 2>/dev/null | grep netem || true)
# baseline: exactly "delay 10ms" at the end of all four netem lines (no jitter, no loss)
at_base=$(grep -cE "delay ${BASELINE_DELAY_MS}ms *\$" <<<"$qd" || true)
if [[ $at_base -eq 4 && $(grep -c netem <<<"$qd" || true) -eq 4 ]]; then
    say "PASS netem back to ${BASELINE_DELAY_MS} ms each way, no loss, on all four impaired qdiscs; nothing left running in the lab"
    say "(the orchestrator's post-run verify measured the baseline RTT, above)"
else
    say "${RD}FAIL the netem configuration is not the baseline after the run:${R}"
    printf '%s\n' "${qd:-  (no netem qdiscs found)}" | sed 's/^/  /'
    exit 1
fi
finished=1

elapsed=$SECONDS
printf '\n'
report_rc=0
"${PY[@]}" src/analysis/demo_report.py "$run_id" --numbers-only || report_rc=$?

printf '\n'
if ((elapsed <= BUDGET_S)); then
    say "${G}machine time ${elapsed} s${R} (budget ${BUDGET_S} s). Lab still up. Next: make demo SCENARIO=... CLIENT=..."
else
    say "${RD}WARNING: machine time ${elapsed} s is over the ${BUDGET_S} s budget${R}. Lab still up."
fi
exit "$report_rc"
