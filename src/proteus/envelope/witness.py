"""Harm witnesses per victim and window, from flow records.

A witness is a total at the victim that an attack cannot lower without lowering its
harm, whatever it does with its own packets and however many sources it uses:

* ``conc``  peak number of connections open at once to a service (slots held);
* ``conn``  connections started to a service (a brute force gets a bounded number of
  attempts out of each);
* ``pkts``, ``bytes``  packets and bytes sent to a service (work asked of it);
* ``ports`` distinct ports contacted on a host (what a vertical scan learns).

Services are (destination host, port, protocol); entities are keyed by a stable 64-bit
hash so that tables of different days and chunks line up. Windows are indexed by
``t_start // window``. A flow counts in the window where it starts for ``conn``,
``pkts``, ``bytes`` and ``ports``, and in every window it overlaps for ``conc``.
Entity-windows where every witness is under its floor are not stored: they can never
alert, and a missing window reads as zero.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

SERVICE = ["dst_ip", "dst_port", "proto"]
HOST = ["dst_ip", "proto"]
SERVICE_WITNESSES = ("conc", "conn", "pkts", "bytes")
HOST_WITNESSES = ("ports",)
FLOORS = {"conc": 8.0, "conn": 20.0, "pkts": 200.0, "bytes": 2e5, "ports": 8.0}
MAX_SPAN = 6  # windows a single record may cover; longer records are cut


def _us(t: pd.Series) -> np.ndarray:
    return t.to_numpy().astype("datetime64[us]").astype(np.int64)


def entity_key(df: pd.DataFrame, cols: list[str]) -> np.ndarray:
    """Stable int64 key of the entity of each row (same value in every table)."""
    k = pd.DataFrame({c: df[c].astype(str) if c == "dst_ip" else df[c].astype(np.int64)
                      for c in cols})
    return pd.util.hash_pandas_object(k, index=False).to_numpy().view(np.int64)


def peak_concurrency(key: np.ndarray, ts: np.ndarray, te: np.ndarray, window_us: int,
                     keep: tuple[int, int] | None = None,
                     flag: np.ndarray | None = None) -> pd.DataFrame:
    """Peak number of records of each key open at once in each window they overlap
    (``key``, ``win``, ``conc``, ``dirty``: any flagged record among them)."""
    te = np.maximum(te, ts)
    w0 = ts // window_us
    n = np.minimum(te // window_us - w0, MAX_SPAN - 1) + 1
    idx = np.repeat(np.arange(len(ts)), n)
    win = w0[idx] + (np.arange(len(idx)) - np.repeat(np.cumsum(n) - n, n))
    if keep is not None:
        m = (win >= keep[0]) & (win < keep[1])
        idx, win = idx[m], win[m]
    if not len(idx):
        return pd.DataFrame({"key": np.array([], np.int64), "win": np.array([], np.int64),
                             "conc": np.array([], np.float64), "dirty": np.array([], bool)})
    a = np.maximum(ts[idx], win * window_us)
    b = np.minimum(te[idx], (win + 1) * window_us - 1)
    m = len(idx)
    kk, ww = np.concatenate([key[idx]] * 2), np.concatenate([win] * 2)
    tt = np.concatenate([a, b])
    dd = np.concatenate([np.ones(m, np.int64), -np.ones(m, np.int64)])
    ff = np.concatenate([flag[idx]] * 2) if flag is not None else np.zeros(2 * m, bool)
    o = np.lexsort((-dd, tt, ww, kk))  # openings before closings at the same instant
    kk, ww, dd, ff = kk[o], ww[o], dd[o], ff[o]
    st = np.flatnonzero(np.r_[True, (kk[1:] != kk[:-1]) | (ww[1:] != ww[:-1])])
    c = np.cumsum(dd)
    run = c - np.repeat(c[st] - dd[st], np.diff(np.r_[st, len(kk)]))
    return pd.DataFrame({"key": kk[st], "win": ww[st],
                         "conc": np.maximum.reduceat(run, st).astype(np.float64),
                         "dirty": np.maximum.reduceat(ff, st)})


def _labels(flows: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    att = (flows["is_attack"].to_numpy().astype(bool) if "is_attack" in flows
           else np.zeros(len(flows), bool))
    name = (flows["attack"].astype(str).to_numpy() if "attack" in flows
            else np.full(len(flows), "", dtype=object))
    return att, np.where(att, name, "")


def _finish(out: pd.DataFrame, names: pd.DataFrame, cols: list[str], witnesses,
            floors: dict[str, float]) -> pd.DataFrame:
    big = np.zeros(len(out), bool)
    for w in witnesses:
        big |= out[w].to_numpy() >= floors[w]
    out = out[big].merge(names, on="key", how="left")
    out["attack"] = out["attack"].fillna("")
    return out[["key", *cols, "win", *witnesses, "dirty", "attack"]].reset_index(drop=True)


def service_windows(flows: pd.DataFrame, window_s: float = 600.0,
                    keep: tuple[int, int] | None = None,
                    floors: dict[str, float] = FLOORS) -> pd.DataFrame:
    """One row per (service, window) with the four service witnesses, ``dirty`` (an
    attack flow counts in it) and the name of that attack. ``keep`` restricts the
    windows written, for chunked reading: pass every record that overlaps them."""
    W = int(window_s * 1e6)
    ts, te = _us(flows["t_start"]), _us(flows["t_end"])
    key = entity_key(flows, SERVICE)
    win = ts // W
    att, name = _labels(flows)
    own = np.ones(len(flows), bool) if keep is None else (win >= keep[0]) & (win < keep[1])
    base = pd.DataFrame({"key": key[own], "win": win[own],
                         "pkts": flows["fwd_pkts"].to_numpy(np.float64)[own],
                         "bytes": flows["fwd_bytes"].to_numpy(np.float64)[own],
                         "dirty": att[own], "attack": name[own]})
    g = base.groupby(["key", "win"], sort=False).agg(
        conn=("pkts", "size"), pkts=("pkts", "sum"), bytes=("bytes", "sum"),
        dirty=("dirty", "max"), attack=("attack", "max"))
    conc = peak_concurrency(key, ts, te, W, keep, att).rename(columns={"dirty": "dirty_c"})
    out = g.join(conc.set_index(["key", "win"]), how="outer")
    out["dirty"] = out["dirty"].fillna(False).astype(bool) | out["dirty_c"].fillna(False).astype(bool)
    out = out.drop(columns="dirty_c").fillna({"conn": 0.0, "pkts": 0.0, "bytes": 0.0,
                                               "conc": 0.0}).reset_index()
    out["conn"] = out["conn"].astype(np.float64)
    names = pd.DataFrame({"key": key, **{c: flows[c].to_numpy() for c in SERVICE}}
                         ).drop_duplicates("key")
    return _finish(out, names, SERVICE, SERVICE_WITNESSES, floors)


def host_windows(flows: pd.DataFrame, window_s: float = 600.0,
                 keep: tuple[int, int] | None = None,
                 floors: dict[str, float] = FLOORS) -> pd.DataFrame:
    """One row per (destination host, protocol, window): distinct ports contacted."""
    W = int(window_s * 1e6)
    win = _us(flows["t_start"]) // W
    key = entity_key(flows, HOST)
    att, name = _labels(flows)
    own = np.ones(len(flows), bool) if keep is None else (win >= keep[0]) & (win < keep[1])
    base = pd.DataFrame({"key": key[own], "win": win[own],
                         "port": flows["dst_port"].to_numpy(np.int64)[own],
                         "dirty": att[own], "attack": name[own]})
    g = base.groupby(["key", "win"], sort=False).agg(
        ports=("port", "nunique"), dirty=("dirty", "max"), attack=("attack", "max")).reset_index()
    g["ports"] = g["ports"].astype(np.float64)
    names = pd.DataFrame({"key": key, **{c: flows[c].to_numpy() for c in HOST}}
                         ).drop_duplicates("key")
    return _finish(g, names, HOST, HOST_WITNESSES, floors)
