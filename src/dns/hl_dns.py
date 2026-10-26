"""HappyLab test-zone DNS server (UDP).

Serves the zone hl.test from inside hl-server, on the unimpaired ctl link:
    www.hl.test  A     192.0.2.2         (hl-server, v4 link)
    www.hl.test  AAAA  2001:db8:28:6::2  (hl-server, v6 link)

Each record type can have an extra answer delay, 0 ms by default (S6 delays AAAA).
Delays are per query and non-blocking: a delayed AAAA answer never holds up the A
answer that glibc asks for in parallel on the same socket.

Answers:
    www.hl.test, A or AAAA            -> the record (TTL 0, so nothing is cached between runs)
    www.hl.test, any other type       -> NOERROR with no answer (e.g. HTTPS/SVCB queries)
    other names inside hl.test        -> NXDOMAIN
    names outside hl.test             -> REFUSED
Every query is logged to stdout as one JSON line (receive and send times in ns).

Usage (inside hl-server, as the normal user; see docs for the full command):
    python src/dns/hl_dns.py --listen 198.51.100.53 [--port 53] [--delay AAAA=300]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from dataclasses import dataclass, field

from dnslib import AAAA, QTYPE, RCODE, RR, SOA, A, DNSLabel, DNSRecord

ZONE = DNSLabel("hl.test.")
HOST = DNSLabel("www.hl.test.")
DEFAULT_A = "192.0.2.2"
DEFAULT_AAAA = "2001:db8:28:6::2"
TTL = 0


@dataclass
class Zone:
    a: str = DEFAULT_A
    aaaa: str = DEFAULT_AAAA
    delay_ms: dict[str, int] = field(default_factory=dict)  # e.g. {"AAAA": 300}

    def delay_for(self, qtype: str) -> int:
        return self.delay_ms.get(qtype, 0)


def _soa() -> RR:
    return RR(ZONE, QTYPE.SOA, ttl=TTL,
              rdata=SOA("ns.hl.test.", "hostmaster.hl.test.", (1, 60, 60, 60, 0)))


def answer(data: bytes, zone: Zone) -> tuple[bytes | None, int, dict]:
    """Build the reply for one query. Returns (reply bytes or None, delay_ms, log info).

    Pure function: no sockets, no sleeping, so it is tested directly.
    """
    try:
        request = DNSRecord.parse(data)
    except Exception as exc:  # noqa: BLE001 - any parse failure means "drop it"
        return None, 0, {"error": f"unparseable query: {exc}"}
    if not request.questions:
        reply = request.reply()
        reply.header.rcode = RCODE.FORMERR
        return reply.pack(), 0, {"rcode": "FORMERR"}

    q = request.questions[0]
    qname, qtype = q.qname, QTYPE.get(q.qtype, str(q.qtype))
    reply = request.reply()  # copies id and question, sets QR, AA, RA
    info = {"id": request.header.id, "qname": str(qname), "qtype": qtype}

    if not qname.matchSuffix(ZONE):
        reply.header.aa = 0
        reply.header.rcode = RCODE.REFUSED
    elif qname == HOST and qtype == "A":
        reply.add_answer(RR(qname, QTYPE.A, ttl=TTL, rdata=A(zone.a)))
    elif qname == HOST and qtype == "AAAA":
        reply.add_answer(RR(qname, QTYPE.AAAA, ttl=TTL, rdata=AAAA(zone.aaaa)))
    elif qname == HOST:
        reply.add_auth(_soa())  # NOERROR, no data
    else:
        reply.header.rcode = RCODE.NXDOMAIN
        reply.add_auth(_soa())

    info["rcode"] = RCODE.get(reply.header.rcode)
    info["answers"] = [str(rr.rdata) for rr in reply.rr]
    delay = zone.delay_for(qtype) if reply.header.rcode == RCODE.NOERROR else 0
    info["delay_ms"] = delay
    return reply.pack(), delay, info


class _Protocol(asyncio.DatagramProtocol):
    def __init__(self, zone: Zone, out=sys.stdout):
        self.zone, self.out = zone, out
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        recv_ns = time.time_ns()
        reply, delay_ms, info = answer(data, self.zone)
        info.update(client=f"{addr[0]}:{addr[1]}", recv_ns=recv_ns)
        if reply is None:
            self._log(info)
            return
        loop = asyncio.get_running_loop()
        loop.call_later(delay_ms / 1000, self._send, reply, addr, info)

    def _send(self, reply, addr, info):
        self.transport.sendto(reply, addr)
        info["sent_ns"] = time.time_ns()
        self._log(info)

    def _log(self, info):
        self.out.write(json.dumps(info) + "\n")
        self.out.flush()


async def serve(listen: str, port: int, zone: Zone) -> None:
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(lambda: _Protocol(zone),
                                                       local_addr=(listen, port))
    print(json.dumps({"event": "listening", "addr": f"{listen}:{port}", "a": zone.a,
                      "aaaa": zone.aaaa, "delay_ms": zone.delay_ms, "ttl": TTL}), flush=True)
    try:
        await asyncio.Event().wait()
    finally:
        transport.close()


def parse_delay(items: list[str]) -> dict[str, int]:
    delays: dict[str, int] = {}
    for item in items:
        qtype, sep, ms = item.partition("=")
        qtype = qtype.strip().upper()
        if not sep or qtype not in ("A", "AAAA") or not ms.strip().isdigit():
            raise ValueError(f"bad --delay {item!r}: use A=<ms> or AAAA=<ms>")
        delays[qtype] = int(ms)
    return delays


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--listen", default="198.51.100.53")
    p.add_argument("--port", type=int, default=53)
    p.add_argument("--a", default=DEFAULT_A, help="A record for www.hl.test")
    p.add_argument("--aaaa", default=DEFAULT_AAAA, help="AAAA record for www.hl.test")
    p.add_argument("--delay", action="append", default=[], metavar="TYPE=MS",
                   help="extra answer delay per record type, e.g. --delay AAAA=300 (default 0)")
    args = p.parse_args(argv)
    try:
        zone = Zone(a=args.a, aaaa=args.aaaa, delay_ms=parse_delay(args.delay))
    except ValueError as exc:
        p.error(str(exc))
    try:
        asyncio.run(serve(args.listen, args.port, zone))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
