"""Attacker operations on flow records (traffic-space transformation model, doc 04 §4.3).

Every operator takes a flow table in the common schema and returns a new table.
Original rows keep their position in ``orig_id``; rows created by the operator get
``orig_id = -1``. Selection ``sel`` is a boolean mask of the flows the attacker
controls (its own flows).

Free operations, by effect on evidence timing:

* No re-timing (exact guarantee): ``pad``, ``insert_packets`` without extension,
  ``add_decoys``, ``change_src_ports``.
* Re-timing bounded by the exporter timeout Δ (guarantee with slack 2Δ/τ, see
  ``proteus.core.certify``): ``split_flows``, ``insert_packets`` with extension.

Costly operations (reduce attack effectiveness; used for the harm frontier):
``slow_down``.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

US = 1_000_000


def _with_ids(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    if "orig_id" not in out.columns:
        out["orig_id"] = np.arange(len(out))
    return out


def pad(df: pd.DataFrame, sel: np.ndarray, bytes_per_pkt: int) -> pd.DataFrame:
    """Add ``bytes_per_pkt`` padding to every forward packet of the selected flows."""
    out = _with_ids(df)
    out.loc[sel, "fwd_bytes"] += bytes_per_pkt * out.loc[sel, "fwd_pkts"]
    return out


def insert_packets(df: pd.DataFrame, sel: np.ndarray, k: int, size: int,
                   extend_s: float = 0.0, timeout_s: float = 120.0) -> pd.DataFrame:
    """Insert ``k`` forward packets of ``size`` bytes into each selected flow.

    With ``extend_s > 0`` the packets are sent after the flow's last packet, which
    delays its export by up to the exporter timeout.
    """
    out = _with_ids(df)
    out.loc[sel, "fwd_pkts"] += k
    out.loc[sel, "fwd_bytes"] += k * size
    if extend_s > 0:
        dur = out.loc[sel, "duration_us"].to_numpy()
        ext = np.minimum(extend_s * US, np.maximum(timeout_s * US - dur, 0)).astype(np.int64)
        out.loc[sel, "duration_us"] = dur + ext
        out.loc[sel, "t_end"] = out.loc[sel, "t_end"] + pd.to_timedelta(ext, unit="us")
    return out


def change_src_ports(df: pd.DataFrame, sel: np.ndarray, rng: np.random.Generator) -> pd.DataFrame:
    out = _with_ids(df)
    out.loc[sel, "src_port"] = rng.integers(1024, 65536, int(sel.sum())).astype(np.int32)
    return out


def add_decoys(df: pd.DataFrame, n: int, rng: np.random.Generator, src_ips, dst_ips, dst_ports,
               proto: int = 6, pkts: int = 3, bytes_per_pkt: int = 60) -> pd.DataFrame:
    """Append ``n`` short decoy flows from attacker sources to arbitrary destinations,
    spread uniformly over the trace."""
    out = _with_ids(df)
    t0 = out["t_start"].min().value
    t1 = out["t_end"].max().value
    start = rng.integers(t0, max(t1, t0 + 1), n)
    dur = rng.integers(0, 1_000_000, n)
    rows = pd.DataFrame({
        "t_start": pd.to_datetime(start, unit="ns").astype("datetime64[us]"),
        "t_end": pd.to_datetime(start + dur * 1000, unit="ns").astype("datetime64[us]"),
        "duration_us": dur.astype(np.int64),
        "src_ip": rng.choice(np.asarray(src_ips, dtype=object), n),
        "src_port": rng.integers(1024, 65536, n).astype(np.int32),
        "dst_ip": rng.choice(np.asarray(dst_ips, dtype=object), n),
        "dst_port": rng.choice(np.asarray(dst_ports), n).astype(np.int32),
        "proto": np.full(n, proto, dtype=np.int16),
        "fwd_pkts": np.full(n, pkts, dtype=np.int64),
        "bwd_pkts": np.zeros(n, dtype=np.int64),
        "fwd_bytes": np.full(n, pkts * bytes_per_pkt, dtype=np.int64),
        "bwd_bytes": np.zeros(n, dtype=np.int64),
        "f_bwd_rst_flags": np.zeros(n, dtype=np.float32),
        "orig_id": np.full(n, -1),
    })
    for c in out.columns:
        if c not in rows.columns:
            rows[c] = "decoy" if out[c].dtype == object or str(out[c].dtype) in (
                "string", "category") else 0
    rows["src_ip"] = rows["src_ip"].astype(out["src_ip"].dtype)
    rows["dst_ip"] = rows["dst_ip"].astype(out["dst_ip"].dtype)
    return pd.concat([out, rows[out.columns]], ignore_index=True)


def split_flows(df: pd.DataFrame, sel: np.ndarray, parts: int,
                rng: np.random.Generator) -> pd.DataFrame:
    """Split each selected flow into up to ``parts`` consecutive flows with new source
    ports. Packets, bytes and connection time are conserved; a flow with fewer
    forward packets than ``parts`` is split into as many flows as it has packets."""
    out = _with_ids(df)
    keep = out[~sel]
    pieces = [keep]
    src = out[sel]
    for _, r in src.iterrows():
        k = int(max(1, min(parts, r["fwd_pkts"])))
        if k == 1:
            pieces.append(r.to_frame().T)
            continue
        edges = np.linspace(0, r["duration_us"], k + 1).astype(np.int64)
        fp = np.full(k, r["fwd_pkts"] // k)
        fp[: r["fwd_pkts"] % k] += 1
        bp = np.full(k, r["bwd_pkts"] // k)
        bp[: r["bwd_pkts"] % k] += 1
        fb = np.floor(r["fwd_bytes"] * fp / max(r["fwd_pkts"], 1)).astype(np.int64)
        fb[-1] += r["fwd_bytes"] - fb.sum()
        bb = np.floor(r["bwd_bytes"] * bp / max(r["bwd_pkts"], 1)).astype(np.int64)
        bb[-1] += r["bwd_bytes"] - bb.sum()
        t0 = r["t_start"]
        rows = pd.DataFrame([r] * k).reset_index(drop=True)
        rows["t_start"] = [t0 + pd.Timedelta(microseconds=int(e)) for e in edges[:-1]]
        rows["t_end"] = [t0 + pd.Timedelta(microseconds=int(e)) for e in edges[1:]]
        rows["duration_us"] = np.diff(edges)
        rows["fwd_pkts"], rows["bwd_pkts"] = fp, bp
        rows["fwd_bytes"], rows["bwd_bytes"] = fb, bb
        rows["src_port"] = rng.integers(1024, 65536, k)
        # A responder RST closes the original connection: keep it on the last piece.
        rst = r.get("f_bwd_rst_flags", 0)
        rows["f_bwd_rst_flags"] = [0.0] * (k - 1) + [rst]
        rows["orig_id"] = [-1] * (k - 1) + [r["orig_id"]]
        pieces.append(rows)
    res = pd.concat(pieces, ignore_index=True)
    return res.astype({c: df[c].dtype for c in df.columns if c in res.columns})


def slow_down(df: pd.DataFrame, sel: np.ndarray, factor: float) -> pd.DataFrame:
    """Stretch the selected flows in time by ``factor`` (> 1) around their first start:
    the same work at a lower rate. Costly: it reduces the attack's effect."""
    out = _with_ids(df)
    t0 = out.loc[sel, "t_start"].min()
    for c in ("t_start", "t_end"):
        out.loc[sel, c] = t0 + (out.loc[sel, c] - t0) * factor
    out.loc[sel, "duration_us"] = (out.loc[sel, "duration_us"] * factor).astype(np.int64)
    return out
