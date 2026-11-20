"""Read IPv4 TCP/UDP packets from a pcap or pcapng file into the packet table of
``exporter``, and write such a table back to a pcap for other exporters to read."""

from __future__ import annotations

import socket
from pathlib import Path

import numpy as np
import pandas as pd

from .exporter import COLUMNS


def read(path: Path, hosts: set[str] | None = None, t0: float | None = None,
         t1: float | None = None, max_packets: int | None = None) -> pd.DataFrame:
    """Packets with ``src`` or ``dst`` in ``hosts`` (all if None) and time in [t0, t1).
    ``size`` is the IP payload length (transport header plus data)."""
    import dpkt

    rows: dict[str, list] = {c: [] for c in COLUMNS}
    with open(path, "rb") as fh:
        ng = fh.read(4) == b"\x0a\x0d\x0d\x0a"  # pcapng section header block
        fh.seek(0)
        reader = dpkt.pcapng.Reader(fh) if ng else dpkt.pcap.Reader(fh)
        for ts, buf in reader:
            if t0 is not None and ts < t0:
                continue
            if t1 is not None and ts >= t1:
                break
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except (dpkt.UnpackError, ValueError):
                continue
            ip = eth.data
            if not isinstance(ip, dpkt.ip.IP):
                continue
            l4 = ip.data
            if not isinstance(l4, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                continue
            s, d = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)
            if hosts is not None and s not in hosts and d not in hosts:
                continue
            rows["ts"].append(ts)
            rows["src"].append(s)
            rows["dst"].append(d)
            rows["sport"].append(l4.sport)
            rows["dport"].append(l4.dport)
            rows["proto"].append(ip.p)
            rows["size"].append(max(ip.len - ip.hl * 4, 0))
            rows["flags"].append(l4.flags if isinstance(l4, dpkt.tcp.TCP) else 0)
            if max_packets is not None and len(rows["ts"]) >= max_packets:
                break
    df = pd.DataFrame(rows)
    for c, t in (("sport", np.int32), ("dport", np.int32), ("proto", np.int16),
                 ("size", np.int64), ("flags", np.int16)):
        df[c] = df[c].astype(t)
    return df


def write(pk: pd.DataFrame, path: Path) -> None:
    """The packet table ``pk`` as a pcap of Ethernet/IPv4 frames: every packet with its
    time, addresses, ports, TCP flags and IP payload length (zeros as data), which is
    all a flow exporter accounts. UDP packets get their 8-byte header, TCP ones a
    20-byte header; a ``size`` below the header is written as a bare header."""
    import dpkt

    pk = pk.sort_values("ts", kind="stable")
    mac = b"\x02\x00\x00\x00\x00\x01"
    with open(path, "wb") as fh:
        out = dpkt.pcap.Writer(fh, snaplen=65535)
        for ts, src, dst, sport, dport, proto, size, flags in zip(
                pk["ts"].to_numpy(np.float64), pk["src"], pk["dst"], pk["sport"].to_numpy(),
                pk["dport"].to_numpy(), pk["proto"].to_numpy(), pk["size"].to_numpy(),
                pk["flags"].to_numpy(), strict=True):
            if proto == dpkt.ip.IP_PROTO_TCP:
                l4 = dpkt.tcp.TCP(sport=int(sport), dport=int(dport), flags=int(flags),
                                  data=bytes(max(int(size) - 20, 0)))
            else:
                l4 = dpkt.udp.UDP(sport=int(sport), dport=int(dport),
                                  data=bytes(max(int(size) - 8, 0)))
                l4.ulen = len(l4)
            ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=int(proto),
                            data=l4)
            ip.len = len(ip)
            out.writepkt(bytes(dpkt.ethernet.Ethernet(src=mac, dst=mac, data=ip)), ts=float(ts))
