#!/usr/bin/env bash
# make demo-check: can this machine run `make demo`? A pre-flight for the venue. It changes nothing:
# no sudo prompt (only `sudo -n`, which never asks), no module loading, no namespace, no file written,
# no client started (the Chromium build is checked on disk, not launched).
#
#   make demo-check
#
# Each check prints PASS, WARN or FAIL. WARN means the demo can run but something needs attention (for
# example sudo will ask for a password, or the timeline cannot open by itself). Exit 1 if anything FAILs.
#
# The expected client versions are the ones every certified run recorded (README.md, client table;
# docs/report.md). A different version still runs, but its numbers are not comparable, so it is a FAIL.
set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO"

EXPECT_CURL="8.5.0"
EXPECT_PLAYWRIGHT="1.64.1"
EXPECT_CHROMIUM="156.0.8078.4"
MIN_FREE_MB=500          # a demo run writes about 5 MB (record, pcap, logs, timeline page)
MODULES=(sch_netem ifb sch_ingress cls_matchall act_mirred veth)
VENV_PY="$REPO/.venv/bin/python"
PY=(env -u PYTHONPATH -u LD_LIBRARY_PATH "$VENV_PY")

checks=0 fails=0 warns=0
pass() { checks=$((checks + 1)); printf 'PASS %s\n' "$*"; }
warn() { checks=$((checks + 1)); warns=$((warns + 1)); printf 'WARN %s\n' "$*"; }
fail() { checks=$((checks + 1)); fails=$((fails + 1)); printf 'FAIL %s\n' "$*"; }
info() { printf 'INFO %s\n' "$*"; }

echo "== HappyLab demo-check: $(date -u +%Y-%m-%dT%H:%M:%SZ) on $(uname -n), kernel $(uname -r) =="

# --- kernel ------------------------------------------------------------------------------------
kver=$(uname -r)
builtin_list="/lib/modules/$kver/modules.builtin"
for m in "${MODULES[@]}"; do
    if grep -q "^$m " /proc/modules 2>/dev/null; then
        pass "kernel module $m: loaded"
    elif modinfo -n "$m" >/dev/null 2>&1; then
        pass "kernel module $m: available ($(modinfo -n "$m" 2>/dev/null)); setup.sh loads it"
    elif [[ -r $builtin_list ]] && grep -q "/$m\.ko" "$builtin_list"; then
        pass "kernel module $m: built into the kernel"
    else
        fail "kernel module $m: not found for kernel $kver (install linux-modules-extra-$kver?)"
    fi
done

# --- namespaces -----------------------------------------------------------------------------------
if [[ -e /proc/self/ns/net ]]; then
    pass "network namespaces: supported by this kernel (/proc/self/ns/net)"
else
    fail "network namespaces: /proc/self/ns/net missing (kernel without CONFIG_NET_NS)"
fi
cfg="/boot/config-$kver"
if [[ -r $cfg ]]; then
    for opt in CONFIG_NET_NS CONFIG_VETH CONFIG_NET_SCH_NETEM CONFIG_IFB; do
        val=$(grep -E "^$opt=" "$cfg" | cut -d= -f2 || true)
        if [[ $val == y || $val == m ]]; then pass "kernel config $opt=$val"; else fail "kernel config $opt is ${val:-not set}"; fi
    done
else
    info "kernel config $cfg not readable; relying on the module checks above"
fi
if ip netns list >/dev/null 2>&1; then
    pass "ip netns: works ($(ip -V 2>&1 | head -1))"
else
    fail "ip netns list failed"
fi
if [[ -e /run/netns/hl-client || -e /run/netns/hl-server ]]; then
    if [[ -e /run/netns/hl-client && -e /run/netns/hl-server ]]; then
        info "lab: up (hl-client and hl-server exist); make demo will verify it before the run"
    else
        warn "lab: only one of hl-client/hl-server exists (a half-built lab); make demo will converge it with setup.sh"
    fi
else
    info "lab: down; make demo will build it (setup.sh, about 10 s)"
fi

# --- tools ----------------------------------------------------------------------------------------
for t in ip tc ping tcpdump nginx runuser timeout setsid sudo modprobe; do
    if p=$(command -v "$t" 2>/dev/null) || p=$(PATH=$PATH:/usr/sbin:/sbin command -v "$t" 2>/dev/null); then
        pass "tool $t: $p"
    else
        fail "tool $t: not found"
    fi
done
if tcpdump --help 2>&1 | grep -q -- '--immediate-mode'; then
    pass "tcpdump supports --immediate-mode"
else
    fail "tcpdump has no --immediate-mode (short captures could be written empty)"
fi

# --- sudo (never prompts) -----------------------------------------------------------------------
if [[ $EUID -eq 0 ]]; then
    fail "run make demo-check (and make demo) as your normal user, not as root"
elif sudo -n true 2>/dev/null; then
    pass "sudo: works without a prompt right now"
elif id -nG | tr ' ' '\n' | grep -qxE 'sudo|admin|wheel'; then
    warn "sudo: you are in an admin group, but sudo will ask for your password once at the start of make demo (run sudo -v just before presenting to avoid the prompt on screen)"
else
    fail "sudo: not available without a password and you are not in sudo/admin/wheel"
fi
if [[ -n ${PYTHONPATH:-}${LD_LIBRARY_PATH:-} ]]; then
    info "PYTHONPATH/LD_LIBRARY_PATH are set in this shell (ROS); make demo strips them from everything it starts"
fi

# --- clients ----------------------------------------------------------------------------------------
if v=$(curl --version 2>/dev/null | head -1); then
    if [[ $v == "curl $EXPECT_CURL "* ]]; then
        pass "curl $EXPECT_CURL (the version every certified run recorded)"
    else
        fail "curl: found '${v%% (*}', expected curl $EXPECT_CURL"
    fi
else
    fail "curl: not found"
fi

if [[ -x $VENV_PY ]]; then
    pass "python venv: $VENV_PY ($("${PY[@]}" -c 'import platform; print(platform.python_version())' 2>/dev/null || echo '?'))"
    if missing=$("${PY[@]}" -c '
import importlib.util as u
print(" ".join(m for m in ("dnslib", "plotly", "playwright", "yaml") if u.find_spec(m) is None))' 2>/dev/null) \
        && [[ -z $missing ]]; then
        pass "python packages: dnslib, plotly, playwright, yaml importable"
    else
        fail "python packages missing: ${missing:-could not run the venv python}"
    fi
    pw=$("${PY[@]}" -c 'import importlib.metadata as m; print(m.version("playwright"))' 2>/dev/null || true)
    if [[ $pw == "$EXPECT_PLAYWRIGHT" ]]; then
        pass "Playwright $pw"
    else
        fail "Playwright: found '${pw:-none}', expected $EXPECT_PLAYWRIGHT"
    fi
    # The Chromium build Playwright will launch, from its own browsers.json; checked on disk, not started.
    read -r rev bver < <("${PY[@]}" -c '
import json, pathlib, playwright
p = pathlib.Path(playwright.__file__).parent / "driver" / "package" / "browsers.json"
b = next(x for x in json.loads(p.read_text())["browsers"] if x["name"] == "chromium")
print(b["revision"], b["browserVersion"])' 2>/dev/null || echo "? ?")
    root=${PLAYWRIGHT_BROWSERS_PATH:-$HOME/.cache/ms-playwright}
    exe="$root/chromium-$rev/chrome-linux64/chrome"
    if [[ $bver != "$EXPECT_CHROMIUM" ]]; then
        fail "Chromium: Playwright expects build $bver, the certified runs used $EXPECT_CHROMIUM"
    elif [[ -x $exe && -e $root/chromium-$rev/INSTALLATION_COMPLETE ]]; then
        pass "Chromium $bver: $exe (installed, not launched by this check)"
    else
        fail "Chromium $bver: not installed at $exe (.venv/bin/python -m playwright install chromium)"
    fi
else
    fail "python venv: $VENV_PY missing (make setup)"
fi

# --- disk, output, terminal ------------------------------------------------------------------------
free_mb=$(df -Pm "$REPO" | awk 'NR == 2 { print $4 }')
if ((free_mb >= MIN_FREE_MB)); then
    pass "disk: ${free_mb} MB free on $(df -P "$REPO" | awk 'NR == 2 { print $6 }') (need ${MIN_FREE_MB} MB)"
else
    fail "disk: only ${free_mb} MB free (need ${MIN_FREE_MB} MB)"
fi
if [[ -e data/demo ]]; then
    if [[ -w data/demo && -O data/demo ]]; then pass "data/demo/ exists and is yours"
    else fail "data/demo/ is not owned by $(id -un) or not writable (fix: sudo chown -R $(id -un): data/demo)"; fi
elif [[ -w data || ( ! -e data && -w . ) ]]; then
    pass "data/demo/ can be created"
else
    fail "data/demo/ cannot be created (data/ not writable)"
fi
if git check-ignore -q data/demo/x 2>/dev/null; then
    pass "data/demo/ is gitignored (demo runs cannot be committed by accident)"
else
    fail "data/demo/ is not gitignored"
fi
if [[ -n ${DISPLAY:-}${WAYLAND_DISPLAY:-} ]] && command -v xdg-open >/dev/null; then
    pass "display: xdg-open can open the timeline page"
else
    warn "display: no DISPLAY/WAYLAND_DISPLAY or no xdg-open; make demo will print the page path instead"
fi
if [[ -t 1 ]]; then
    cols=$(tput cols 2>/dev/null || echo 80) rows=$(tput lines 2>/dev/null || echo 24)
    if ((cols >= 80 && rows >= 40)); then
        pass "terminal: ${cols}x${rows} (the numbers need 80x40 to stay on one screen)"
    else
        warn "terminal: ${cols}x${rows}; the numbers need about 80x40 to stay on one screen (zoom out or enlarge)"
    fi
fi

echo
if ((fails == 0)); then
    echo "DEMO-CHECK: PASS ($checks checks, $warns warning(s)); nothing was changed"
else
    echo "DEMO-CHECK: FAIL ($fails of $checks failed, $warns warning(s)); nothing was changed"
    exit 1
fi
