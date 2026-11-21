"""Client and scenario names: what is allowed, and how a name appears in file names. Standard library only.

Clients
-------
A client label is an implementation, optionally with a variant:

    curl            curl as installed, no Happy Eyeballs option given ("default (not set)")
    curl@he<N>      curl with --happy-eyeballs-timeout-ms N (N a whole number, 1-60000, no leading zero)
    chromium        Chromium via Playwright (takes no variants)

A variant is a configuration of an implementation, not another client: PS-028's "2 client
implementations or versions" are curl and Chromium. Records keep the two apart (client.name is the
implementation, client.variant the variant), and summaries group variants under their implementation.

Sanitisation rule (one rule, used for every path): in a file name, a client label appears with "@"
replaced by "-", e.g. curl@he200 -> curl-he200. Run IDs use that form, so pcaps, records, client logs
and NetLogs (all named after the run ID) follow it. The mapping is reversible because implementation
names contain no "-" and the variant grammar is fixed.

Scenarios
---------
CORE_SCENARIOS (C0 and S1-S6) are the baseline and PS-028's six required scenarios, defined in
src/config/scenarios.yaml. Generated scenarios (src/config/scenarios_generated.yaml, written by
src/runner/scenario_grid.py) are extensions with IDs like Gv6d200 (IPv6 +200 ms RTT) or Gv6l5 (IPv6 5%
loss): always a "G" prefix, so they cannot be confused with the core set.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

IMPLEMENTATIONS = ("curl", "chromium")
HE_TIMEOUT_MIN_MS, HE_TIMEOUT_MAX_MS = 1, 60_000
_VARIANT_RE = re.compile(r"he([1-9]\d*)")
VARIANT_PATTERN = r"he[1-9]\d*"                 # for building other regexes
CLIENT_LABEL_PATTERN = rf"curl(?:@{VARIANT_PATTERN})?|chromium"
FILE_TOKEN_PATTERN = rf"curl(?:-{VARIANT_PATTERN})?|chromium"

CORE_SCENARIOS = ("C0", "S1", "S2", "S3", "S4", "S5", "S6")
OTHER_DEFINED_SCENARIOS = ("X1", "harness-test")   # reserved IDs that are not generated
GENERATED_ID_PATTERN = r"G(?:v4|v6)(?:d|l)[1-9]\d*"
_GENERATED_ID_RE = re.compile(GENERATED_ID_PATTERN)
_CORE_LIKE_RE = re.compile(r"[CSX]\d+")


class InvalidName(ValueError):
    """A client label or scenario ID that is not allowed."""


@dataclass(frozen=True)
class ClientName:
    implementation: str
    variant: str | None = None
    he_timeout_ms: int | None = None

    @property
    def label(self) -> str:
        return self.implementation + (f"@{self.variant}" if self.variant else "")

    @property
    def file_token(self) -> str:
        return file_token(self.label)


def parse_client(label: str) -> ClientName:
    """'curl', 'curl@he200' or 'chromium' -> ClientName; anything else raises InvalidName."""
    if not isinstance(label, str):
        raise InvalidName(f"client label must be a string, got {label!r}")
    impl, sep, variant = label.partition("@")
    if impl not in IMPLEMENTATIONS:
        raise InvalidName(f"unknown client implementation {impl!r} in {label!r}; known: {', '.join(IMPLEMENTATIONS)}")
    if not sep:
        return ClientName(impl)
    if impl != "curl":
        raise InvalidName(f"{label!r}: {impl} takes no variants (only curl does, e.g. curl@he200)")
    m = _VARIANT_RE.fullmatch(variant)
    if not m:
        raise InvalidName(f"{label!r}: unknown variant {variant!r}; use he<N> for --happy-eyeballs-timeout-ms N")
    ms = int(m[1])
    if not HE_TIMEOUT_MIN_MS <= ms <= HE_TIMEOUT_MAX_MS:
        raise InvalidName(f"{label!r}: Happy Eyeballs timeout must be {HE_TIMEOUT_MIN_MS}-{HE_TIMEOUT_MAX_MS} ms")
    return ClientName(impl, variant, ms)


def file_token(label: str) -> str:
    """The sanitisation rule: '@' -> '-' (after checking the label is valid)."""
    return parse_client(label).label.replace("@", "-")


def label_from_file_token(token: str) -> str:
    label = token.replace("-", "@", 1)
    if file_token(label) != token:
        raise InvalidName(f"{token!r} is not a client file token")
    return label


def label_of(client_block: dict) -> str:
    """Client label of a run record's client block (client.name plus client.variant, if any)."""
    variant = client_block.get("variant")
    return client_block["name"] + (f"@{variant}" if variant else "")


def implementation_of(label: str) -> str:
    return parse_client(label).implementation


def client_sort_key(label: str) -> tuple:
    """Implementations in IMPLEMENTATIONS order; within one, the plain client first, then variants by value."""
    c = parse_client(label)
    return (IMPLEMENTATIONS.index(c.implementation), c.variant is not None, c.he_timeout_ms or 0)


def group_by_implementation(labels) -> dict[str, list[str]]:
    """{implementation: [labels]} in client_sort_key order; variants are listed under their implementation."""
    out: dict[str, list[str]] = {}
    for lb in sorted(labels, key=client_sort_key):
        out.setdefault(implementation_of(lb), []).append(lb)
    return out


def is_generated_id(sid: str) -> bool:
    return isinstance(sid, str) and bool(_GENERATED_ID_RE.fullmatch(sid))


def check_generated_id(sid: str, defined: set[str] | frozenset[str] = frozenset()) -> None:
    """Reject a generated scenario ID that collides with, or looks like, a core or other defined ID."""
    if sid in CORE_SCENARIOS:
        raise InvalidName(f"generated scenario ID {sid!r} collides with a core scenario ID "
                         f"({', '.join(CORE_SCENARIOS)}); core scenarios are never generated")
    if sid in defined or sid in OTHER_DEFINED_SCENARIOS:
        raise InvalidName(f"generated scenario ID {sid!r} is already defined in src/config/scenarios.yaml")
    if _CORE_LIKE_RE.fullmatch(str(sid)):
        raise InvalidName(f"generated scenario ID {sid!r} looks like a core ID; generated IDs start with 'G'")
    if not is_generated_id(sid):
        raise InvalidName(f"generated scenario ID {sid!r} does not match {GENERATED_ID_PATTERN}")
