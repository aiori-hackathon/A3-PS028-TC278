"""Build tiny synthetic pcap files (raw-IP link type) for parser edge-case tests."""

from __future__ import annotations

import ipaddress
import struct

from analysis.parse_pcap import ACK, FIN, RST, SYN  # noqa: F401  (re-exported for tests)

LINKTYPE_RAW = 101


def ip_tcp(src: str, dst: str, sport: int, dport: int, flags: int, seq: int = 0, ack: int = 0,
           payload: bytes = b"") -> bytes:
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
    return _ip(src, dst, 6, tcp)


def ip_icmp(src: str, dst: str, icmp_type: int, code: int = 0) -> bytes:
    v6 = ":" in src
    return _ip(src, dst, 58 if v6 else 1, bytes([icmp_type, code, 0, 0, 0, 0, 0, 0]))


def _ip(src: str, dst: str, proto: int, l4: bytes) -> bytes:
    s, d = ipaddress.ip_address(src), ipaddress.ip_address(dst)
    if s.version == 4:
        return struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 0, 0, 64, proto, 0,
                           s.packed, d.packed) + l4
    return struct.pack(">IHBB16s16s", 6 << 28, len(l4), proto, 64, s.packed, d.packed) + l4


def pcap(frames: list[tuple[int, bytes]], nanosecond: bool = False) -> bytes:
    """frames: [(timestamp_ns, raw IP packet)] -> pcap bytes (little-endian)."""
    magic = bytes.fromhex("4d3cb2a1") if nanosecond else bytes.fromhex("d4c3b2a1")
    out = bytearray(magic + struct.pack("<HHiIII", 2, 4, 0, 0, 262144, LINKTYPE_RAW))
    for ts, frame in frames:
        sec, rem = divmod(ts, 1_000_000_000)
        frac = rem if nanosecond else rem // 1000
        out += struct.pack("<IIII", sec, frac, len(frame), len(frame)) + frame
    return bytes(out)


MS = 1_000_000
C4, S4 = "192.0.2.1", "192.0.2.2"
C6, S6 = "2001:db8:28:6::1", "2001:db8:28:6::2"


def handshake(t0: int, c: str, s: str, sport: int, rtt_ms: int = 20, data: bool = True,
              isn: int = 1000, server_isn: int = 5000) -> list[tuple[int, bytes]]:
    """SYN at t0, SYN-ACK at t0+rtt, ACK right after, then optional GET and HTTP 200."""
    t_sa = t0 + rtt_ms * MS
    frames = [
        (t0, ip_tcp(c, s, sport, 80, SYN, seq=isn)),
        (t_sa, ip_tcp(s, c, 80, sport, SYN | ACK, seq=server_isn, ack=isn + 1)),
        (t_sa + 30_000, ip_tcp(c, s, sport, 80, ACK, seq=isn + 1, ack=server_isn + 1)),
    ]
    if data:
        frames += [
            (t_sa + 60_000, ip_tcp(c, s, sport, 80, ACK | 0x08, seq=isn + 1, ack=server_isn + 1,
                                   payload=b"GET / HTTP/1.1\r\n\r\n")),
            (t_sa + rtt_ms * MS, ip_tcp(s, c, 80, sport, ACK | 0x08, seq=server_isn + 1, ack=isn + 19,
                                        payload=b"HTTP/1.1 200 OK\r\n\r\nHappyLab\n")),
        ]
    return frames
