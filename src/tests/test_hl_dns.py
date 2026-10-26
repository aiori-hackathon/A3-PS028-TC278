"""Tests for the test-zone DNS server (src/dns/hl_dns.py)."""

import asyncio
import importlib.util
import io
import json
import socket
import sys
import time
from pathlib import Path

import pytest
from dnslib import QTYPE, RCODE, DNSRecord

SRC = Path(__file__).resolve().parents[1]
# Loaded by path: a package named "dns" would clash with dnspython if that is ever installed.
_spec = importlib.util.spec_from_file_location("hl_dns", SRC / "dns" / "hl_dns.py")
hl_dns = importlib.util.module_from_spec(_spec)
sys.modules["hl_dns"] = hl_dns  # dataclasses look the module up here
_spec.loader.exec_module(hl_dns)


def ask(name, qtype, zone=None):
    reply, delay, info = hl_dns.answer(DNSRecord.question(name, qtype).pack(), zone or hl_dns.Zone())
    return DNSRecord.parse(reply), delay, info


def test_a_record():
    r, delay, info = ask("www.hl.test", "A")
    assert r.header.rcode == RCODE.NOERROR and r.header.aa == 1
    assert [str(rr.rdata) for rr in r.rr] == ["192.0.2.2"]
    assert r.rr[0].ttl == 0 and delay == 0
    assert info["qtype"] == "A" and info["answers"] == ["192.0.2.2"]


def test_aaaa_record():
    r, _, _ = ask("www.hl.test", "AAAA")
    assert [str(rr.rdata) for rr in r.rr] == ["2001:db8:28:6::2"]


def test_case_insensitive_and_trailing_dot():
    r, _, _ = ask("WWW.HL.TEST.", "A")
    assert [str(rr.rdata) for rr in r.rr] == ["192.0.2.2"]


def test_other_type_is_nodata():
    r, delay, _ = ask("www.hl.test", "HTTPS")
    assert r.header.rcode == RCODE.NOERROR and r.rr == []
    assert r.auth and r.auth[0].rtype == QTYPE.SOA
    assert delay == 0


def test_unknown_name_in_zone_is_nxdomain():
    r, _, _ = ask("nope.hl.test", "A")
    assert r.header.rcode == RCODE.NXDOMAIN


def test_outside_zone_is_refused():
    r, _, _ = ask("example.com", "A")
    assert r.header.rcode == RCODE.REFUSED and r.rr == []


def test_reply_keeps_query_id():
    q = DNSRecord.question("www.hl.test", "A")
    reply, _, _ = hl_dns.answer(q.pack(), hl_dns.Zone())
    assert DNSRecord.parse(reply).header.id == q.header.id


def test_garbage_is_dropped():
    reply, delay, info = hl_dns.answer(b"\x00\x01", hl_dns.Zone())
    assert reply is None and "error" in info


def test_delay_applies_only_to_configured_type():
    zone = hl_dns.Zone(delay_ms={"AAAA": 300})
    assert ask("www.hl.test", "AAAA", zone)[1] == 300
    assert ask("www.hl.test", "A", zone)[1] == 0
    assert ask("nope.hl.test", "AAAA", zone)[1] == 0  # errors are never delayed


@pytest.mark.parametrize("items,expected", [
    ([], {}), (["AAAA=300"], {"AAAA": 300}), (["a=5", "AAAA=0"], {"A": 5, "AAAA": 0}),
])
def test_parse_delay(items, expected):
    assert hl_dns.parse_delay(items) == expected


@pytest.mark.parametrize("item", ["AAAA", "MX=5", "AAAA=-1", "AAAA=fast"])
def test_parse_delay_rejects(item):
    with pytest.raises(ValueError):
        hl_dns.parse_delay([item])


def test_delayed_aaaa_does_not_block_a(tmp_path):
    """Send AAAA then A on one socket, like glibc. A must come back first; AAAA after >= 300 ms."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    log = io.StringIO()

    async def scenario():
        loop = asyncio.get_running_loop()
        zone = hl_dns.Zone(delay_ms={"AAAA": 300})
        transport, _ = await loop.create_datagram_endpoint(
            lambda: hl_dns._Protocol(zone, out=log), local_addr=("127.0.0.1", port))
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.setblocking(False)
            client.connect(("127.0.0.1", port))
            start = time.monotonic()
            client.send(DNSRecord.question("www.hl.test", "AAAA").pack())
            client.send(DNSRecord.question("www.hl.test", "A").pack())
            got = []
            for _ in range(2):
                data = await asyncio.wait_for(loop.sock_recv(client, 512), timeout=3)
                got.append((QTYPE[DNSRecord.parse(data).q.qtype], time.monotonic() - start))
            client.close()
            return got
        finally:
            transport.close()

    got = asyncio.run(scenario())
    assert [qtype for qtype, _ in got] == ["A", "AAAA"]
    assert got[0][1] < 0.1
    assert got[1][1] >= 0.3
    lines = [json.loads(line) for line in log.getvalue().splitlines()]
    aaaa = next(x for x in lines if x["qtype"] == "AAAA")
    assert aaaa["delay_ms"] == 300 and aaaa["sent_ns"] - aaaa["recv_ns"] >= 300_000_000
