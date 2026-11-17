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


# Fewest payload bytes that a request of each service can carry (destination port ->
# bytes): an HTTP/1.0 request line, a USER and a PASS command, the smallest SSH key
# exchange and one authentication attempt. Other services are left as they are.
MIN_REQUEST_BYTES = {80: 18, 8080: 18, 21: 24, 22: 500}


def shrink_requests(df: pd.DataFrame, sel: np.ndarray,
                    floors: dict[int, int] | None = None) -> pd.DataFrame:
    """Send the request of each selected TCP flow with as few payload bytes as its service
    allows (``floors``, by destination port; default ``MIN_REQUEST_BYTES``). The number
    of requests, connections and packets does not change, so the attack does the same
    work: unlike padding, this lowers evidence, and no certificate covers it."""
    floors = MIN_REQUEST_BYTES if floors is None else floors
    out = _with_ids(df)
    # Only requests over TCP: the bytes of a UDP flood are its harm, not a disguise.
    sel = np.asarray(sel) & (out["proto"].to_numpy() == 6)
    floor = out.loc[sel, "dst_port"].map(floors)
    cur = out.loc[sel, "fwd_bytes"]
    out.loc[sel, "fwd_bytes"] = np.minimum(cur, floor.fillna(cur)).astype(cur.dtype)
    return out


def split_flows(df: pd.DataFrame, sel: np.ndarray, parts: int,
                rng: np.random.Generator) -> pd.DataFrame:
    """Split each selected flow into up to ``parts`` consecutive flows with new source
    ports. Packets, bytes and connection time are conserved; a flow with fewer
    forward packets than ``parts`` is split into as many flows as it has packets."""
    out = _with_ids(df)
    src = out[sel]
    k = np.clip(src["fwd_pkts"].to_numpy(np.int64), 1, max(int(parts), 1))
    if not (k > 1).any():
        return pd.concat([out[~sel], src], ignore_index=True)
    first = np.cumsum(k) - k  # row of the first piece of every flow
    rep = np.repeat(np.arange(len(src)), k)
    j = np.arange(len(rep)) - first[rep]  # piece number within its flow
    kk = k[rep]
    multi, last = kk > 1, j == kk - 1
    rows = src.iloc[rep].reset_index(drop=True)

    def total(col: str) -> np.ndarray:
        return src[col].to_numpy(np.int64)[rep]

    def share(col: str) -> np.ndarray:  # equal parts, the remainder to the first pieces
        return total(col) // kk + (j < total(col) % kk)

    def weighted(col: str, part: np.ndarray, whole: str) -> np.ndarray:
        """Bytes in proportion to the packets of each piece; the rounding to the last."""
        b = np.floor(total(col) * part / np.maximum(total(whole), 1)).astype(np.int64)
        b[first + k - 1] += src[col].to_numpy(np.int64) - np.add.reduceat(b, first)
        return b

    d = total("duration_us")
    lo = (j * (d / kk)).astype(np.int64)
    hi = np.where(last, d, ((j + 1) * (d / kk)).astype(np.int64))
    t0 = rows["t_start"]
    rows["t_end"] = (t0 + pd.to_timedelta(hi, unit="us")).where(multi, rows["t_end"])
    rows["t_start"] = t0 + pd.to_timedelta(np.where(multi, lo, 0), unit="us")
    rows["duration_us"] = np.where(multi, hi - lo, d)
    fp, bp = share("fwd_pkts"), share("bwd_pkts")
    rows["fwd_bytes"] = weighted("fwd_bytes", fp, "fwd_pkts")
    rows["bwd_bytes"] = weighted("bwd_bytes", bp, "bwd_pkts")
    rows["fwd_pkts"], rows["bwd_pkts"] = fp, bp
    port = rows["src_port"].to_numpy().copy()
    port[multi] = rng.integers(1024, 65536, int(multi.sum()))
    rows["src_port"] = port
    # A responder RST closes the original connection: keep it on the last piece.
    if "f_bwd_rst_flags" in rows.columns:
        rows["f_bwd_rst_flags"] = rows["f_bwd_rst_flags"].where(~multi | last, 0.0)
    else:
        rows["f_bwd_rst_flags"] = np.where(multi, 0.0, np.nan)
    rows["orig_id"] = rows["orig_id"].where(~multi | last, -1)
    res = pd.concat([out[~sel], rows], ignore_index=True)
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


def reuse_connections(df: pd.DataFrame, sel: np.ndarray, k: int, timeout_s: float,
                      saved_pkts: int = 4) -> pd.DataFrame:
    """Carry up to ``k`` consecutive selected flows of the same source and service in
    one connection (HTTP keep-alive, several attempts per session). The merged record
    keeps the payload bytes and the requests' packets, saves ``saved_pkts`` forward
    packets (handshake and teardown) per merged flow, and never spans more than the
    exporter's active timeout. Per-connection counts (flows, resets, unanswered) drop."""
    if k <= 1 or not sel.any():
        return df
    out = _with_ids(df)
    a = out[sel].sort_values("t_start", kind="stable")
    slot = (a["t_start"].astype("int64") // int(timeout_s * 1e6)).to_numpy()
    grp = a.groupby([a["src_ip"].astype(str), a["dst_ip"].astype(str), a["dst_port"],
                     a["proto"], slot], sort=False).cumcount() // k
    keys = [a["src_ip"].astype(str), a["dst_ip"].astype(str), a["dst_port"], a["proto"],
            pd.Series(slot, index=a.index), grp]
    g = a.groupby(keys, sort=False)
    first = g.head(1).copy()
    n = g["fwd_pkts"].transform("size").loc[first.index].to_numpy()
    agg = g.agg(t_start=("t_start", "min"), t_end=("t_end", "max"),
                fwd_pkts=("fwd_pkts", "sum"), bwd_pkts=("bwd_pkts", "sum"),
                fwd_bytes=("fwd_bytes", "sum"), bwd_bytes=("bwd_bytes", "sum"),
                rst=("f_bwd_rst_flags", "max"))
    first["t_start"], first["t_end"] = agg["t_start"].to_numpy(), agg["t_end"].to_numpy()
    first["duration_us"] = (first["t_end"] - first["t_start"]).dt.total_seconds().mul(1e6) \
        .astype(np.int64)
    first["fwd_pkts"] = np.maximum(agg["fwd_pkts"].to_numpy() - saved_pkts * (n - 1), n)
    first["bwd_pkts"] = agg["bwd_pkts"].to_numpy()
    first["fwd_bytes"], first["bwd_bytes"] = agg["fwd_bytes"].to_numpy(), agg["bwd_bytes"].to_numpy()
    first["f_bwd_rst_flags"] = agg["rst"].to_numpy()
    return pd.concat([out[~sel], first], ignore_index=True)


def spread_sources(df: pd.DataFrame, sel: np.ndarray, n: int,
                   rng: np.random.Generator) -> pd.DataFrame:
    """Send the selected flows from ``n`` sources (a costly operation: it needs the
    hosts). Destination-side evidence is unchanged, source-side evidence is divided."""
    out = df.copy()
    srcs = np.array([f"198.18.{i // 250}.{i % 250 + 1}" for i in range(n)])  # benchmark net
    out.loc[sel, "src_ip"] = pd.array(rng.choice(srcs, int(sel.sum())),
                                      dtype=out["src_ip"].dtype)
    return out


def pulse(df: pd.DataFrame, sel: np.ndarray, period_s: float, duty: float) -> pd.DataFrame:
    """Send the selected flows in bursts: the same flows and the same mean rate, but
    only during the first ``duty`` fraction of every ``period_s`` (each flow moves
    earlier within its period)."""
    out = df.copy()
    t = out.loc[sel, "t_start"].astype("int64").to_numpy()
    t0 = int(t.min()) if len(t) else 0
    per = int(period_s * 1e6)
    phase = (t - t0) % per
    new = t - phase + (phase * duty).astype(np.int64)
    out.loc[sel, "t_start"] = pd.to_datetime(new, unit="us").astype(out["t_start"].dtype)
    out.loc[sel, "t_end"] = (out.loc[sel, "t_start"]
                             + pd.to_timedelta(out.loc[sel, "duration_us"], unit="us"))
    return out
