"""Read a tcpdump pcap and reconstruct what happened on the wire (packet-level facts only).

Supported: classic pcap (micro- or nanosecond, either byte order) with link types
Ethernet (1), raw IP (101), Linux cooked v1 (113) and v2 (276, what `tcpdump -i any` writes).
pcapng is rejected with a clear error.

This module reports facts: packets, TCP connection attempts, DNS exchanges, ICMP errors
and neighbour-discovery traffic. Deciding which attempt "won" and computing the metrics
is done in analysis/metrics.py, so the interpretation rules live in one place.

Standard library only, plus dnslib to decode DNS payloads.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field
from pathlib import Path

from dnslib import QTYPE, RCODE, DNSRecord

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_LINUX_SLL2 = 276
PACKET_OUTGOING = 4  # Linux cooked-capture packet type for packets this host sent

_MAGICS = {
    bytes.fromhex("d4c3b2a1"): ("<", 1000),  # little-endian, microseconds
    bytes.fromhex("a1b2c3d4"): (">", 1000),
    bytes.fromhex("4d3cb2a1"): ("<", 1),     # little-endian, nanoseconds
    bytes.fromhex("a1b23c4d"): (">", 1),
}


class PcapError(Exception):
    pass


@dataclass(frozen=True)
class Packet:
    ts_ns: int
    proto: str                    # tcp, udp, icmp, icmp6, arp, fragment, other
    family: str | None = None     # v4 or v6 (None for ARP and non-IP)
    src: str | None = None
    dst: str | None = None
    sport: int | None = None
    dport: int | None = None
    flags: int = 0                # TCP flags
    seq: int = 0
    ack: int = 0
    payload: bytes = b""
    icmp_type: int | None = None
    icmp_code: int | None = None
    ifindex: int | None = None    # Linux cooked v2 only
    outgoing: bool | None = None  # Linux cooked captures only


# --- reading ---------------------------------------------------------------------

def read_pcap(path: str | Path) -> tuple[int, list[Packet]]:
    """Return (link type, packets in file order)."""
    data = Path(path).read_bytes()
    if len(data) < 24:
        raise PcapError(f"{path}: too short for a pcap header")
    magic = data[:4]
    if magic == bytes.fromhex("0a0d0d0a"):
        raise PcapError(f"{path}: pcapng is not supported; capture with `tcpdump -w` (classic pcap)")
    if magic not in _MAGICS:
        raise PcapError(f"{path}: not a pcap file")
    endian, ns_per_unit = _MAGICS[magic]
    linktype = struct.unpack(endian + "I", data[20:24])[0] & 0x0FFFFFFF
    if linktype not in (LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_LINUX_SLL, LINKTYPE_LINUX_SLL2):
        raise PcapError(f"{path}: unsupported link type {linktype}")

    packets: list[Packet] = []
    off = 24
    while off + 16 <= len(data):
        sec, frac, incl, _orig = struct.unpack(endian + "IIII", data[off:off + 16])
        frame = data[off + 16:off + 16 + incl]
        if len(frame) < incl:
            raise PcapError(f"{path}: truncated record at byte {off}")
        off += 16 + incl
        pkt = _decode_link(linktype, sec * 1_000_000_000 + frac * ns_per_unit, frame)
        if pkt is not None:
            packets.append(pkt)
    return linktype, packets


def _decode_link(linktype: int, ts_ns: int, frame: bytes) -> Packet | None:
    ifindex = outgoing = None
    if linktype == LINKTYPE_ETHERNET:
        if len(frame) < 14:
            return None
        ethertype, body = struct.unpack(">H", frame[12:14])[0], frame[14:]
        if ethertype == 0x8100 and len(body) >= 4:  # 802.1Q tag
            ethertype, body = struct.unpack(">H", body[2:4])[0], body[4:]
    elif linktype == LINKTYPE_LINUX_SLL:
        if len(frame) < 16:
            return None
        outgoing = struct.unpack(">H", frame[0:2])[0] == PACKET_OUTGOING
        ethertype, body = struct.unpack(">H", frame[14:16])[0], frame[16:]
    elif linktype == LINKTYPE_LINUX_SLL2:
        if len(frame) < 20:
            return None
        ethertype = struct.unpack(">H", frame[0:2])[0]
        ifindex = struct.unpack(">I", frame[4:8])[0]
        outgoing = frame[10] == PACKET_OUTGOING
        body = frame[20:]
    else:  # raw IP
        if not frame:
            return None
        ethertype, body = (0x0800 if frame[0] >> 4 == 4 else 0x86DD), frame

    meta = {"ts_ns": ts_ns, "ifindex": ifindex, "outgoing": outgoing}
    if ethertype == 0x0806:
        return Packet(proto="arp", **meta)
    if ethertype == 0x0800:
        return _decode_ipv4(body, meta)
    if ethertype == 0x86DD:
        return _decode_ipv6(body, meta)
    return Packet(proto="other", **meta)


def _decode_ipv4(b: bytes, meta: dict) -> Packet | None:
    if len(b) < 20:
        return None
    ihl = (b[0] & 0x0F) * 4
    total = struct.unpack(">H", b[2:4])[0]
    proto = b[9]
    src, dst = str(ipaddress.IPv4Address(b[12:16])), str(ipaddress.IPv4Address(b[16:20]))
    ip = {"family": "v4", "src": src, "dst": dst, **meta}
    if struct.unpack(">H", b[6:8])[0] & 0x1FFF:  # non-first fragment
        return Packet(proto="fragment", **ip)
    return _decode_l4(proto, b[ihl:total], ip, icmp_proto=1)


def _decode_ipv6(b: bytes, meta: dict) -> Packet | None:
    if len(b) < 40:
        return None
    plen = struct.unpack(">H", b[4:6])[0]
    nh = b[6]
    src, dst = str(ipaddress.IPv6Address(b[8:24])), str(ipaddress.IPv6Address(b[24:40]))
    ip = {"family": "v6", "src": src, "dst": dst, **meta}
    l4 = b[40:40 + plen]
    while nh in (0, 43, 44, 60) and len(l4) >= 8:  # extension headers
        if nh == 44:
            if struct.unpack(">H", l4[2:4])[0] & 0xFFF8:  # non-first fragment
                return Packet(proto="fragment", **ip)
            nh, l4 = l4[0], l4[8:]
        else:
            nh, l4 = l4[0], l4[(l4[1] + 1) * 8:]
    return _decode_l4(nh, l4, ip, icmp_proto=58)


def _decode_l4(proto: int, l4: bytes, ip: dict, icmp_proto: int) -> Packet:
    if proto == 6 and len(l4) >= 20:
        sport, dport, seq, ack = struct.unpack(">HHII", l4[0:12])
        off = (l4[12] >> 4) * 4
        return Packet(proto="tcp", sport=sport, dport=dport, seq=seq, ack=ack,
                      flags=l4[13], payload=bytes(l4[off:]), **ip)
    if proto == 17 and len(l4) >= 8:
        sport, dport, length = struct.unpack(">HHH", l4[0:6])
        return Packet(proto="udp", sport=sport, dport=dport, payload=bytes(l4[8:length]), **ip)
    if proto == icmp_proto and len(l4) >= 2:
        return Packet(proto="icmp" if icmp_proto == 1 else "icmp6",
                      icmp_type=l4[0], icmp_code=l4[1], **ip)
    return Packet(proto="other", **ip)


# --- reconstruction ----------------------------------------------------------------

@dataclass
class Attempt:
    """One TCP connection attempt, keyed by the client's SYN (client = side that sent the SYN)."""
    family: str
    src: str
    sport: int
    dst: str
    dport: int
    first_syn_ns: int
    client_isn: int
    syn_count: int = 1
    synack_ns: int | None = None
    server_isn: int | None = None
    handshake_ack_ns: int | None = None   # client ACK completing the three-way handshake
    server_rst_ns: int | None = None
    client_rst_ns: int | None = None
    client_data_bytes: int = 0
    first_client_data_ns: int | None = None
    http_status: int | None = None        # from the first server segment starting with "HTTP/"

    @property
    def syn_retransmits(self) -> int:
        return self.syn_count - 1

    @property
    def handshake_completed(self) -> bool:
        return self.handshake_ack_ns is not None


@dataclass
class DnsExchange:
    client: str            # address:port that sent the query
    server: str
    id: int
    qname: str
    qtype: str
    query_ns: int
    response_ns: int | None = None
    rcode: str | None = None
    answers: list[str] = field(default_factory=list)


@dataclass
class Timeline:
    linktype: int
    window: tuple[int, int] | None
    packet_count: int                      # packets inside the window
    attempts: list[Attempt]
    dns: list[DnsExchange]
    icmp_errors: list[Packet]              # destination unreachable and similar
    neighbour_packets: int                 # ARP plus IPv6 neighbour solicitation/advertisement
    anomalies: list[str]
    other_udp: list[Packet] = field(default_factory=list)  # UDP not on port 53 (e.g. QUIC on 443)


_ICMP4_ERRORS = {3, 11, 12}      # unreachable, time exceeded, parameter problem
_ICMP6_ERRORS = {1, 2, 3, 4}     # unreachable, too big, time exceeded, parameter problem
_ICMP6_ND = {133, 134, 135, 136, 137}


def analyse(linktype: int, packets: list[Packet], window: tuple[int, int] | None = None) -> Timeline:
    """Rebuild attempts and DNS exchanges from packets. `window` = (start_ns, end_ns), inclusive."""
    if window is not None:
        packets = [p for p in packets if window[0] <= p.ts_ns <= window[1]]
    packets = sorted(packets, key=lambda p: p.ts_ns)  # stable: keeps file order for equal times

    attempts: dict[tuple, Attempt] = {}
    dns: list[DnsExchange] = []
    icmp_errors: list[Packet] = []
    neighbour = 0
    unmatched_tcp = 0
    anomalies: list[str] = []
    other_udp: list[Packet] = []

    for p in packets:
        if p.proto == "arp" or (p.proto == "icmp6" and p.icmp_type in _ICMP6_ND):
            neighbour += 1
        elif (p.proto == "icmp" and p.icmp_type in _ICMP4_ERRORS) or (
                p.proto == "icmp6" and p.icmp_type in _ICMP6_ERRORS):
            icmp_errors.append(p)
        elif p.proto == "tcp":
            if not _track_tcp(p, attempts):
                unmatched_tcp += 1
        elif p.proto == "udp" and 53 in (p.sport, p.dport):
            _track_dns(p, dns, anomalies)
        elif p.proto == "udp":
            other_udp.append(p)

    if unmatched_tcp:
        anomalies.append(f"{unmatched_tcp} TCP packets not belonging to any SYN seen in the window")
    for ex in dns:
        if ex.response_ns is None:
            anomalies.append(f"DNS {ex.qtype} query for {ex.qname} (id {ex.id}) got no response")
    return Timeline(linktype=linktype, window=window, packet_count=len(packets),
                    attempts=sorted(attempts.values(), key=lambda a: a.first_syn_ns),
                    dns=dns, icmp_errors=icmp_errors, neighbour_packets=neighbour,
                    anomalies=anomalies, other_udp=other_udp)


def _track_tcp(p: Packet, attempts: dict[tuple, Attempt]) -> bool:
    fwd = (p.src, p.sport, p.dst, p.dport)
    rev = (p.dst, p.dport, p.src, p.sport)
    syn, ack = bool(p.flags & SYN), bool(p.flags & ACK)

    if syn and not ack:
        a = attempts.get(fwd)
        if a is None:
            attempts[fwd] = Attempt(family=p.family, src=p.src, sport=p.sport, dst=p.dst,
                                    dport=p.dport, first_syn_ns=p.ts_ns, client_isn=p.seq)
        else:
            a.syn_count += 1
        return True

    if fwd in attempts:  # client -> server
        a = attempts[fwd]
        if (ack and a.synack_ns is not None and a.handshake_ack_ns is None
                and p.ack == (a.server_isn + 1) % 2**32):
            a.handshake_ack_ns = p.ts_ns
        if p.payload:
            a.client_data_bytes += len(p.payload)
            if a.first_client_data_ns is None:
                a.first_client_data_ns = p.ts_ns
        if p.flags & RST and a.client_rst_ns is None:
            a.client_rst_ns = p.ts_ns
        return True

    if rev in attempts:  # server -> client
        a = attempts[rev]
        if syn and ack:
            if a.synack_ns is None and p.ack == (a.client_isn + 1) % 2**32:
                a.synack_ns, a.server_isn = p.ts_ns, p.seq
        elif p.flags & RST and a.server_rst_ns is None:
            a.server_rst_ns = p.ts_ns
        if a.http_status is None and p.payload.startswith(b"HTTP/"):
            parts = p.payload.split(b" ", 2)
            if len(parts) > 1 and parts[1].isdigit():
                a.http_status = int(parts[1])
        return True

    return False


def _track_dns(p: Packet, dns: list[DnsExchange], anomalies: list[str]) -> None:
    try:
        rec = DNSRecord.parse(p.payload)
    except Exception:  # noqa: BLE001
        anomalies.append(f"undecodable DNS packet at {p.ts_ns}")
        return
    if not rec.questions:
        return
    q = rec.questions[0]
    qname, qtype = str(q.qname), QTYPE.get(q.qtype, str(q.qtype))
    if not rec.header.qr:
        dns.append(DnsExchange(client=f"{p.src}:{p.sport}", server=p.dst, id=rec.header.id,
                               qname=qname, qtype=qtype, query_ns=p.ts_ns))
        return
    client = f"{p.dst}:{p.dport}"
    for ex in dns:
        if ex.client == client and ex.id == rec.header.id and ex.response_ns is None:
            ex.response_ns = p.ts_ns
            ex.rcode = RCODE.get(rec.header.rcode)
            ex.answers = [str(rr.rdata) for rr in rec.rr]
            return
    anomalies.append(f"DNS response id {rec.header.id} with no matching query")


def parse(path: str | Path, window: tuple[int, int] | None = None) -> Timeline:
    linktype, packets = read_pcap(path)
    return analyse(linktype, packets, window)
