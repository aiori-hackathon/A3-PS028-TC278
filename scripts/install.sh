#!/usr/bin/env bash
# Prepare a host for HappyLab: check it, install the apt and pip dependencies, create .venv.
#
#   scripts/install.sh --check   # report only: changes nothing, never calls sudo, apt, pip or modprobe
#   scripts/install.sh           # install what is missing (calls sudo for apt-get only)
#
# Run as your normal user, not with sudo: .venv must belong to you. Never use sudo -E.
#
# What it checks (PASS / WARN / FAIL per line):
#   host      Ubuntu 24.04; network namespace support; kernel modules sch_netem, ifb, veth, plus
#             act_mirred and cls_matchall (used by the ifb redirect). Modules are checked for
#             availability (loaded, built in, or found by modinfo); none is loaded here, setup.sh does that.
#   apt       iproute2 iputils-ping tcpdump nginx curl kmod python3.12-venv
#   python    .venv (Python 3.12), the pinned packages in requirements.txt, Playwright's Chromium
#   versions  WARN if curl is not 8.5.0 or Chromium is not 156.0.8078.4, the versions the core
#             dataset was measured with. Other versions work, but their results are not comparable.
#
# What it never does: touch the lab namespaces, routes, interfaces, firewall or /etc/gai.conf,
# load kernel modules, or change services. If the host's nginx service is running it prints the
# command to stop it (the lab runs its own nginx inside hl-server) and leaves it alone.
# An existing .venv is reused; a .venv that is a symlink (a git worktree sharing the main
# checkout's) is checked but never installed into.
# The Chromium version check starts headless Chromium once with no page (client_chromium.py
# --version, the same probe the orchestrator records), and is the only process it starts besides
# version queries.
#
# Exit status: 0 if nothing FAILed (WARNs allowed), 1 otherwise, 2 for a usage error.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="$REPO/.venv"
WANT_UBUNTU=24.04
WANT_CURL=8.5.0
WANT_CHROMIUM=156.0.8078.4
APT_PACKAGES=(iproute2 iputils-ping tcpdump nginx curl kmod python3.12-venv)
MODULES=(sch_netem ifb veth act_mirred cls_matchall)

mode=install
case "${1:-}" in
    "") ;;
    --check) mode=check ;;
    -h | --help) sed -n '2,27p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "usage: $0 [--check]" >&2; exit 2 ;;
esac
[[ $# -le 1 ]] || { echo "usage: $0 [--check]" >&2; exit 2; }

passes=0 warns=0 fails=0
pass() { passes=$((passes + 1)); printf 'PASS %s\n' "$*"; }
warn() { warns=$((warns + 1)); printf 'WARN %s\n' "$*"; }
fail() { fails=$((fails + 1)); printf 'FAIL %s\n' "$*"; }
info() { printf 'INFO %s\n' "$*"; }
run() { printf '+ %s\n' "$*"; "$@"; }

# Python without the ROS (or any other) PYTHONPATH / LD_LIBRARY_PATH; -B writes no __pycache__.
py() { env -u PYTHONPATH -u LD_LIBRARY_PATH "$VENV/bin/python" -B "$@"; }

if [[ $EUID -eq 0 ]]; then
    if [[ $mode == install ]]; then
        echo "error: run as your normal user (it calls sudo for apt-get itself); .venv must not belong to root" >&2
        exit 1
    fi
    warn "running as root: --check works, but run the install as your normal user"
fi

echo "== HappyLab install ($mode): $(date -u +%Y-%m-%dT%H:%M:%SZ) =="

# --- host ----------------------------------------------------------------------------------
echo "-- host"
os_id=$(. /etc/os-release 2>/dev/null && echo "${ID:-?} ${VERSION_ID:-?}") || os_id="unknown"
if [[ $os_id == "ubuntu $WANT_UBUNTU" ]]; then
    pass "OS: Ubuntu $WANT_UBUNTU"
else
    fail "OS: $os_id (HappyLab is tested on Ubuntu $WANT_UBUNTU only)"
fi
info "kernel: $(uname -r)"

if [[ -e /proc/self/ns/net ]]; then
    pass "network namespaces: supported by the kernel (/proc/self/ns/net)"
else
    fail "network namespaces: /proc/self/ns/net missing (kernel without CONFIG_NET_NS?)"
fi

module_state() {  # prints loaded / built-in / available, or nothing
    local m=$1 builtin="/lib/modules/$(uname -r)/modules.builtin"
    if [[ -d /sys/module/$m ]]; then
        echo loaded
    elif [[ -r $builtin ]] && grep -qE "/$m\.ko(\.[a-z]+)?$" "$builtin"; then
        echo built-in
    elif command -v modinfo >/dev/null && modinfo -n "$m" >/dev/null 2>&1; then
        echo available
    fi
}
for m in "${MODULES[@]}"; do
    state=$(module_state "$m")
    if [[ -n $state ]]; then
        pass "kernel module $m: $state"
    else
        fail "kernel module $m: not found for $(uname -r) (install the kernel's modules package, e.g. linux-modules-extra-$(uname -r))"
    fi
done
host_fails=$fails

# --- apt -----------------------------------------------------------------------------------
echo "-- apt packages"
missing=()
for p in "${APT_PACKAGES[@]}"; do
    if [[ $(dpkg-query -W -f='${Status}' "$p" 2>/dev/null || true) == "install ok installed" ]]; then
        pass "apt: $p $(dpkg-query -W -f='${Version}' "$p")"
    else
        missing+=("$p")
    fi
done
if ((${#missing[@]})); then
    if [[ $mode == check ]]; then
        for p in "${missing[@]}"; do fail "apt: $p not installed (install.sh would install it)"; done
    elif ((host_fails)); then
        for p in "${missing[@]}"; do fail "apt: $p not installed"; done
        echo "stopping: the host checks above failed, so nothing is installed" >&2
    else
        run sudo apt-get update
        run sudo apt-get install -y "${missing[@]}"
        for p in "${missing[@]}"; do pass "apt: $p installed"; done
    fi
fi

if command -v systemctl >/dev/null && systemctl is-active --quiet nginx 2>/dev/null; then
    warn "host nginx service is running; the lab never uses it. To stop it: sudo systemctl disable --now nginx"
fi

# --- python environment --------------------------------------------------------------------
echo "-- python environment"
shared_venv=false
if [[ -L $VENV ]]; then
    shared_venv=true
    info ".venv is a symlink to $(readlink -f "$VENV"): checked only, never installed into"
fi
if [[ ! -x $VENV/bin/python ]]; then
    if [[ $shared_venv == true ]]; then
        fail ".venv: symlink target has no bin/python (broken symlink?)"
    elif [[ $mode == check ]]; then
        fail ".venv: missing (install.sh would create it)"
    elif ((host_fails)); then
        fail ".venv: missing (not created: the host checks failed)"
    else
        command -v python3.12 >/dev/null || { fail "python3.12 not found"; exit 1; }
        run env -u PYTHONPATH -u LD_LIBRARY_PATH python3.12 -m venv "$VENV"
    fi
fi

if [[ -x $VENV/bin/python ]]; then
    pyver=$(py -c 'import platform; print(platform.python_version())')
    if [[ $pyver == 3.12.* ]]; then pass ".venv: Python $pyver"; else warn ".venv: Python $pyver (tested with 3.12)"; fi

    if [[ $mode == install && $shared_venv == false ]] && ((host_fails == 0)); then
        run env -u PYTHONPATH -u LD_LIBRARY_PATH "$VENV/bin/python" -m pip install -r "$REPO/requirements.txt"
        run env -u PYTHONPATH -u LD_LIBRARY_PATH "$VENV/bin/python" -m playwright install chromium
    fi

    # pinned packages: name==version lines of requirements.txt
    while read -r name want; do
        got=$(py -c 'import importlib.metadata as m, sys
try: print(m.version(sys.argv[1]))
except m.PackageNotFoundError: pass' "$name")
        if [[ -z $got ]]; then
            fail "pip: $name not installed (want $want)"
        elif [[ $got == "$want" ]]; then
            pass "pip: $name $got"
        else
            warn "pip: $name $got (requirements.txt pins $want)"
        fi
    done < <(sed -nE 's/^([A-Za-z0-9_.-]+)==([^ #]+).*/\1 \2/p' "$REPO/requirements.txt")
fi

# --- client versions -----------------------------------------------------------------------
echo "-- client versions"
if command -v curl >/dev/null; then
    curl_line=$(env -u PYTHONPATH -u LD_LIBRARY_PATH curl --version | head -n 1)
    curl_ver=$(awk '{print $2}' <<<"$curl_line")
    if [[ $curl_ver == "$WANT_CURL" ]]; then
        pass "curl $curl_ver"
    else
        warn "curl $curl_ver: the dataset used curl $WANT_CURL; results are not directly comparable"
    fi
else
    fail "curl: not installed"
fi

if [[ -x $VENV/bin/python ]] && py -c 'import playwright' 2>/dev/null; then
    if out=$(timeout 60 env -u PYTHONPATH -u LD_LIBRARY_PATH "$VENV/bin/python" -B \
             "$REPO/src/runner/client_chromium.py" --version 2>&1); then
        chromium_ver=$(py -c 'import json, sys
print(json.loads(sys.argv[1].strip().splitlines()[-1]).get("browser_version") or "")' "$out" 2>/dev/null || true)
    else
        chromium_ver=""
    fi
    if [[ -z $chromium_ver ]]; then
        fail "Chromium: Playwright could not start it (run: .venv/bin/python -m playwright install chromium)"
    elif [[ $chromium_ver == "$WANT_CHROMIUM" ]]; then
        pass "Chromium $chromium_ver (Playwright)"
    else
        warn "Chromium $chromium_ver: the dataset used Chromium $WANT_CHROMIUM; results are not directly comparable"
    fi
else
    fail "Chromium: Playwright not installed in .venv"
fi

# --- summary -------------------------------------------------------------------------------
echo "== $passes passed, $warns warnings, $fails failed =="
if [[ $mode == check ]]; then
    echo "check mode: nothing was changed"
fi
if ((fails)); then
    exit 1
fi
if [[ $mode == install ]]; then
    echo "next: scripts/test.sh, then read src/lab/setup.sh and run: sudo src/lab/setup.sh"
fi
