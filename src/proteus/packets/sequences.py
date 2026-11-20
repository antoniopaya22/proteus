"""Packets to per-flow packet sequences, the input of sequence classifiers of traffic
(the DF, kFP and Whisper models that CertTA certifies, for instance).

The flows are those of ``exporter.export``: bidirectional 5-tuple, initiator = sender
of the first packet, a flow ends at the active timeout, the idle timeout, a RST, or
once both sides have sent a FIN (the closing packet belongs to the flow). Instead of
counters, every flow keeps its packets in time order: their times relative to the
first one and their signed sizes (+ from the initiator, - from the responder).
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from .exporter import FIN, RST


def assign(pk: pd.DataFrame, active_s: float = 120.0, idle_s: float = 60.0) -> np.ndarray:
    """Flow of every packet of ``pk`` (in its row order), flows numbered by their
    first packet, with the rules of ``exporter.export``."""
    order = np.argsort(pk["ts"].to_numpy(np.float64), kind="stable")
    ts = pk["ts"].to_numpy(np.float64)[order]
    src = pk["src"].to_numpy(object)[order]
    dst = pk["dst"].to_numpy(object)[order]
    sp = pk["sport"].to_numpy(np.int64)[order]
    dp = pk["dport"].to_numpy(np.int64)[order]
    pr = pk["proto"].to_numpy(np.int64)[order]
    fl = pk["flags"].to_numpy(np.int64)[order]
    fid = np.empty(len(ts), dtype=np.int64)
    live: dict = {}
    n = 0
    for i in range(len(ts)):
        a, b = (src[i], sp[i]), (dst[i], dp[i])
        key = (min(a, b), max(a, b), pr[i])
        f = live.get(key)
        if f is not None and (ts[i] - f[1] >= active_s or ts[i] - f[2] > idle_s):
            del live[key]
            f = None
        if f is None:
            # [id, t_start, last, initiator, fin_fwd, fin_bwd]
            f = [n, ts[i], ts[i], a, False, False]
            live[key] = f
            n += 1
        fid[i] = f[0]
        if a == f[3]:
            f[4] = f[4] or bool(fl[i] & FIN)
        else:
            f[5] = f[5] or bool(fl[i] & FIN)
        f[2] = ts[i]
        if fl[i] & RST or (f[4] and f[5]):
            del live[key]
    out = np.empty(len(ts), dtype=np.int64)
    out[order] = fid
    return out


def sequences(pk: pd.DataFrame, active_s: float = 120.0, idle_s: float = 60.0) -> pd.DataFrame:
    """One row per flow, in the order of their first packet: initiator ``src``/``sport``,
    ``dst``/``dport``, ``proto``, ``t_start`` (s), ``packets``, ``ts`` (times relative to
    the first packet, s), ``length`` (signed sizes) and ``rows`` (positions of the
    flow's packets in ``pk``), the last three as arrays in time order."""
    fid = assign(pk, active_s, idle_s)
    ts = pk["ts"].to_numpy(np.float64)
    order = np.lexsort((ts, fid))
    bounds = np.flatnonzero(np.diff(fid[order])) + 1
    groups = np.split(order, bounds) if len(order) else []
    src = pk["src"].to_numpy(object)
    sp = pk["sport"].to_numpy(np.int64)
    dst = pk["dst"].to_numpy(object)
    dp = pk["dport"].to_numpy(np.int64)
    pr = pk["proto"].to_numpy(np.int64)
    sz = pk["size"].to_numpy(np.int64)
    recs = []
    for g in groups:
        first = g[0]
        fwd = (src[g] == src[first]) & (sp[g] == sp[first])
        recs.append((src[first], int(sp[first]), dst[first], int(dp[first]), int(pr[first]),
                     float(ts[first]), len(g), ts[g] - ts[first], np.where(fwd, sz[g], -sz[g]),
                     g))
    return pd.DataFrame(recs, columns=["src", "sport", "dst", "dport", "proto", "t_start",
                                       "packets", "ts", "length", "rows"])
