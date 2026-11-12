"""Read IPv4 TCP/UDP packets from a pcap or pcapng file into the packet table of
``exporter``."""

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
