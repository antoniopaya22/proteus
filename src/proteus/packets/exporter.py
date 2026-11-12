"""Packets to flow records, as a NetFlow/IPFIX-style exporter would produce them.

Packets are a table with columns ``ts`` (seconds), ``src``, ``dst`` (strings),
``sport``, ``dport``, ``proto``, ``size`` (bytes counted for the flow: IP payload)
and ``flags`` (TCP flags byte, 0 for other protocols).

A flow is bidirectional and keyed by its 5-tuple; its initiator (the ``src`` of the
record) is the sender of its first packet. A record is exported, and the next packet
of the same 5-tuple starts a new flow, when

* the flow has been active for ``active_s`` (active timeout Δ),
* no packet was seen for ``idle_s`` (idle timeout), or
* a RST is seen, or both sides have sent a FIN (the closing packet belongs to the
  flow).

Every packet is therefore accounted in a record whose ``t_end`` lies between the
packet's time and Δ after it, which is the property the certificate relies on
(``proteus.core.certify``).
"""

from __future__ import annotations

import numpy as np
import pandas as pd

FIN, SYN, RST = 0x01, 0x02, 0x04
COLUMNS = ["ts", "src", "dst", "sport", "dport", "proto", "size", "flags"]


def export(pk: pd.DataFrame, active_s: float = 120.0, idle_s: float = 60.0) -> pd.DataFrame:
    pk = pk.sort_values("ts", kind="stable")
    ts = pk["ts"].to_numpy(np.float64)
    src = pk["src"].to_numpy(object)
    dst = pk["dst"].to_numpy(object)
    sp = pk["sport"].to_numpy(np.int64)
    dp = pk["dport"].to_numpy(np.int64)
    pr = pk["proto"].to_numpy(np.int64)
    sz = pk["size"].to_numpy(np.int64)
    fl = pk["flags"].to_numpy(np.int64)
    live: dict = {}
    out: list[tuple] = []

    def close(key):
        f = live.pop(key)
        out.append((f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8], f[9], f[10],
                    f[11]))

    for i in range(len(ts)):
        a, b = (src[i], sp[i]), (dst[i], dp[i])
        key = (min(a, b), max(a, b), pr[i])
        f = live.get(key)
        if f is not None and (ts[i] - f[0] >= active_s or ts[i] - f[12] > idle_s):
            close(key)
            f = None
        if f is None:
            # [t_start, t_end, src, sport, dst, dport, proto, fpk, bpk, fby, bby, bwd_rst,
            #  last, fin_fwd, fin_bwd]
            f = [ts[i], ts[i], src[i], sp[i], dst[i], dp[i], pr[i], 0, 0, 0, 0, 0,
                 ts[i], False, False]
            live[key] = f
        fwd = src[i] == f[2] and sp[i] == f[3]
        if fwd:
            f[7] += 1
            f[9] += sz[i]
            f[13] = f[13] or bool(fl[i] & FIN)
        else:
            f[8] += 1
            f[10] += sz[i]
            f[14] = f[14] or bool(fl[i] & FIN)
            if fl[i] & RST:
                f[11] += 1
        f[1] = ts[i]
        f[12] = ts[i]
        if fl[i] & RST or (f[13] and f[14]):
            close(key)
    for key in list(live):
        close(key)
    df = pd.DataFrame(out, columns=["t0", "t1", "src_ip", "src_port", "dst_ip", "dst_port",
                                    "proto", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes",
                                    "bwd_rst"])
    df["t_start"] = pd.to_datetime(df.pop("t0"), unit="s").astype("datetime64[us]")
    df["t_end"] = pd.to_datetime(df.pop("t1"), unit="s").astype("datetime64[us]")
    df["duration_us"] = (df["t_end"] - df["t_start"]).dt.total_seconds().mul(1e6).astype(np.int64)
    df["f_bwd_rst_flags"] = df.pop("bwd_rst").astype(np.float32)
    for c in ("src_ip", "dst_ip"):
        df[c] = df[c].astype("string")
    df["src_port"] = df["src_port"].astype(np.int32)
    df["dst_port"] = df["dst_port"].astype(np.int32)
    df["proto"] = df["proto"].astype(np.int16)
    return df.sort_values("t_end", kind="stable").reset_index(drop=True)
