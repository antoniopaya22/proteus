"""Evidence counters computed window by window with their state carried over.

``proteus.evidence.chunked`` recomputes each window from a warm-up of earlier flows,
which cannot reach long time scales: a 6-hour counter would need hours of warm-up per
window. ``StreamingEvidence`` instead keeps, per counter, the state of every entity
(its decayed values and the time of its last event) and, for distinct counts, the last
time each (entity, item) pair was seen. Windows must be fed in time order; each
window's flows are scored exactly as ``features.build`` would score them on the whole
stream, up to pruning:

* an entity idle for more than ``horizon_s`` is dropped, which lowers its counters by
  at most exp(-horizon/τ) of their value (≤ e⁻³ at the longest scale with the default
  horizon of 3·τ_max), like the warm-up bound of ``chunked``;
* an (entity, item) pair idle for more than ``horizon_s`` is forgotten, so if the item
  comes back its old, decayed contribution (≤ exp(-horizon/τ)) is not subtracted: a
  distinct count can exceed the exact one by that much per return. A forgotten item
  returns at most once per horizon, so with horizon ≥ 3·τ the excess per item stays
  below e⁻³/(1 - e⁻³) ≈ 0.05 of one item;
* light entities are dropped sooner: an entity idle for more than ``recent_s`` whose
  counter at the longest scale is below ``min_value`` (most pairs of an ISP, seen once)
  is dropped together with its items. Its counters restart from zero if it comes back,
  so they can only be lower than the exact ones, by less than ``min_value`` per drop. Without
  this a day of UGR'16 needs hundreds of millions of entries.

Identifiers are 64-bit hashes of the entity columns, stable across windows.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from numba import njit

from .features import (
    EVIDENCE_VERSION,
    FeatureSpec,
    add_columns,
    counters,
    plan,
    taus_for,
)

PROBE_BASE = np.uint64(1) << np.uint64(63)


def hkeys(*cols: pd.Series) -> np.ndarray:
    """Stable 64-bit identifiers of the rows of ``cols`` (hashes)."""
    df = pd.DataFrame({i: c.to_numpy() if hasattr(c, "to_numpy") else c
                       for i, c in enumerate(cols)})
    return pd.util.hash_pandas_object(df, index=False).to_numpy().astype(np.uint64)


def _probe(n: int) -> np.ndarray:
    return PROBE_BASE + np.arange(n, dtype=np.uint64)


@njit(cache=True)
def _kernel_carry(t, ent, w, prev, taus, s0, t0, has0, out):
    n = t.shape[0]
    k = taus.shape[0]
    state = np.zeros(k)
    for i in range(n):
        if i == 0 or ent[i] != ent[i - 1]:
            for j in range(k):
                state[j] = s0[i, j] * np.exp(-(t[i] - t0[i]) / taus[j]) if has0[i] else 0.0
            dt = 0.0
        else:
            dt = t[i] - t[i - 1]
        for j in range(k):
            s = state[j] * np.exp(-dt / taus[j]) + w[i]
            if prev[i] == prev[i]:  # not NaN: same item seen before
                s -= np.exp(-(t[i] - prev[i]) / taus[j])
            s = max(s, 0.0)
            state[j] = s
            out[i, j] = s


class _Table:
    """Sorted uint64 keys with a time and optional values (k columns)."""

    def __init__(self, k: int = 0):
        self.keys = np.empty(0, dtype=np.uint64)
        self.t = np.empty(0, dtype=np.float64)
        self.v = np.empty((0, k), dtype=np.float32)  # state kept in float32
        self.e = np.empty(0, dtype=np.uint64)  # item tables: entity of each pair

    def lookup(self, q: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """Index into the table and found mask for each query key."""
        if len(self.keys) == 0:
            return np.zeros(len(q), dtype=np.int64), np.zeros(len(q), dtype=bool)
        i = np.searchsorted(self.keys, q)
        i = np.minimum(i, len(self.keys) - 1)
        return i, self.keys[i] == q

    def update(self, keys: np.ndarray, t: np.ndarray, v: np.ndarray | None = None,
               e: np.ndarray | None = None) -> None:
        """Insert or overwrite (keys must be unique)."""
        keep = ~np.isin(self.keys, keys, assume_unique=True)
        K = np.concatenate([self.keys[keep], keys])
        T = np.concatenate([self.t[keep], t])
        o = np.argsort(K, kind="stable")
        self.keys, self.t = K[o], T[o]
        if v is not None:
            self.v = np.concatenate([self.v[keep], v.astype(np.float32)])[o]
        if e is not None:
            self.e = np.concatenate([self.e[keep], e])[o]

    def select(self, m: np.ndarray) -> None:
        self.keys, self.t = self.keys[m], self.t[m]
        if self.v.shape[0]:
            self.v = self.v[m]
        if self.e.shape[0]:
            self.e = self.e[m]

    def __len__(self) -> int:
        return len(self.keys)


def _last_per_key(sorted_keys: np.ndarray) -> np.ndarray:
    """Positions of the last occurrence of each key in an array sorted by key."""
    last = np.ones(len(sorted_keys), dtype=bool)
    last[:-1] = sorted_keys[1:] != sorted_keys[:-1]
    return np.flatnonzero(last)


class StreamingEvidence:
    def __init__(self, taus=None, version: str | None = None,
                 horizon_s: float | None = None, recent_s: float | None = None,
                 min_value: float = 1.5):
        self.version = version or EVIDENCE_VERSION
        self.taus = np.asarray(tuple(taus) if taus is not None else taus_for(self.version),
                               dtype=np.float64)
        self.horizon_s = 3 * float(self.taus.max()) if horizon_s is None else horizon_s
        if recent_s is None:
            recent_s = self.horizon_s if np.isinf(self.horizon_s) else min(
                self.horizon_s, 6 * float(min(self.taus.max(), 600.0)))
        self.recent_s, self.min_value = recent_s, min_value
        self.ent: dict[str, _Table] = {}
        self.items: dict[str, _Table] = {}
        self.t_last = -np.inf

    def _carry(self, name: str, t, ent, w, prev) -> np.ndarray:
        k = len(self.taus)
        table = self.ent.setdefault(name, _Table(k))
        o = np.lexsort((t, ent))
        ts, es = t[o], ent[o]
        first = np.ones(len(o), dtype=bool)
        first[1:] = es[1:] != es[:-1]
        s0 = np.zeros((len(o), k))
        t0 = np.zeros(len(o))
        has0 = np.zeros(len(o), dtype=bool)
        fi = np.flatnonzero(first)
        idx, found = table.lookup(es[fi])
        has0[fi[found]] = True
        s0[fi[found]] = table.v[idx[found]].astype(np.float64)
        t0[fi[found]] = table.t[idx[found]]
        out = np.empty((len(o), k))
        _kernel_carry(ts, es, w[o].astype(np.float64), prev[o], self.taus, s0, t0, has0, out)
        last = _last_per_key(es)
        table.update(es[last], ts[last], out[last])
        res = np.empty_like(out)
        res[o] = out
        return res

    def _prev(self, name: str, t, ent, item, w) -> np.ndarray:
        """Previous time each (entity, item) pair was seen, within or before the window."""
        n = len(t)
        o2 = np.lexsort((t, item, ent))
        e2, i2, t2 = ent[o2], item[o2], t[o2]
        same = np.zeros(n, dtype=bool)
        same[1:] = (e2[1:] == e2[:-1]) & (i2[1:] == i2[:-1])
        prev_sorted = np.full(n, np.nan)
        prev_sorted[1:][same[1:]] = t2[:-1][same[1:]]
        pair = e2 * np.uint64(0x9E3779B97F4A7C15) ^ i2  # wraps around (uint64)
        real = w[o2] > 0
        table = self.items.setdefault(name, _Table())
        first = ~same & real
        fi = np.flatnonzero(first)
        idx, found = table.lookup(pair[fi])
        prev_sorted[fi[found]] = table.t[idx[found]]
        # remember the last time of every real pair
        po = np.flatnonzero(real)
        if len(po):
            pk, pt = pair[po], t2[po]
            oo = np.lexsort((pt, pk))
            last = _last_per_key(pk[oo])
            ek = e2[po][oo][last]
            table.update(pk[oo][last], pt[oo][last], e=ek)
        prev = np.empty(n)
        prev[o2] = prev_sorted
        return prev

    def build(self, df: pd.DataFrame) -> tuple[pd.DataFrame, list[FeatureSpec]]:
        """Features of a window's flows (``df`` sorted by ``t_end``, after every earlier
        window). Updates the carried state."""
        if len(df) == 0:
            return pd.DataFrame(index=df.index), []
        t = df["t_end"].astype("int64").to_numpy().astype(np.float64) / 1e6
        if t[0] < self.t_last:
            raise ValueError("windows must be fed in time order")
        with np.errstate(over="ignore"):
            p = plan(df, self.version, keys=hkeys, probe=_probe)
            cols: dict[str, np.ndarray] = {}
            specs: list[FeatureSpec] = []
            for name, codes, w, cons, kind in counters(p):
                if kind == "sum":
                    v = self._carry(name, t, codes, w, np.full(len(t), np.nan))
                else:
                    iw = p["item_w"].get(w)
                    iw = np.ones(len(t)) if iw is None else iw
                    prev = self._prev(name, t, codes, p["item"][w], iw)
                    v = self._carry(name, t, codes, iw, prev)
                add_columns(cols, specs, name, v, cons, tuple(self.taus))
        self.t_last = float(t[-1])
        self._prune()
        return pd.DataFrame(cols, index=df.index), specs

    def _prune(self) -> None:
        now, tmax = self.t_last, float(self.taus.max())
        for name, table in self.ent.items():
            age = now - table.t
            heavy = table.v[:, -1] * np.exp(-age / tmax) >= self.min_value
            table.select((age <= self.horizon_s) & ((age <= self.recent_s) | heavy))
            items = self.items.get(name)
            if items is not None and len(items):
                age_i = now - items.t
                kept = np.isin(items.e, table.keys)
                items.select((age_i <= self.horizon_s) & ((age_i <= self.recent_s) | kept))

    def size(self) -> int:
        """Entries held (entities and pairs), for memory monitoring."""
        return sum(len(x) for x in (*self.ent.values(), *self.items.values()))
