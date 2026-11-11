"""Exponentially decayed additive counters per entity.

Every counter is evaluated at each event of its entity (after including the event),
so a flow record "sees" the evidence accumulated up to the moment it is exported.

* ``decayed_sum``: C(t) = sum_i w_i * exp(-(t - t_i) / tau) over the entity's events
  with t_i <= t. Non-negative weights make C non-decreasing under event insertion.
* ``decayed_distinct``: D(t) = sum_j exp(-(t - last_j(t)) / tau) over the distinct
  items j (ports, peers, ...) the entity touched, where last_j(t) is the latest time
  item j was seen. Inserting events only moves last_j later or adds items, so D is
  also non-decreasing under insertion. It counts each item once, so repeating an
  item does not inflate it.
"""

from __future__ import annotations

import numpy as np
from numba import njit


@njit(cache=True)
def _kernel(t, ent, w, prev, taus, out):
    n = t.shape[0]
    k = taus.shape[0]
    state = np.zeros(k)
    for i in range(n):
        if i == 0 or ent[i] != ent[i - 1]:
            for j in range(k):
                state[j] = 0.0
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


def _order(t: np.ndarray, ent: np.ndarray) -> np.ndarray:
    return np.lexsort((t, ent))


def decayed_sum(t: np.ndarray, ent: np.ndarray, w: np.ndarray, taus) -> np.ndarray:
    """Decayed sum of ``w`` per entity. Returns (n, len(taus)) in input order."""
    taus = np.asarray(taus, dtype=np.float64)
    o = _order(t, ent)
    out = np.empty((t.shape[0], taus.shape[0]))
    prev = np.full(t.shape[0], np.nan)
    _kernel(t[o].astype(np.float64), ent[o], w[o].astype(np.float64), prev, taus, out)
    res = np.empty_like(out)
    res[o] = out
    return res


def decayed_distinct(t: np.ndarray, ent: np.ndarray, item: np.ndarray, taus,
                     w: np.ndarray | None = None) -> np.ndarray:
    """Decayed number of distinct ``item`` values per entity, in input order.

    ``w`` (default 1) lets zero-weight probe events read the state without
    changing it; they must carry items no real event uses.
    """
    taus = np.asarray(taus, dtype=np.float64)
    n = t.shape[0]
    w = np.ones(n) if w is None else np.asarray(w, dtype=np.float64)
    # Previous time the same (entity, item) pair occurred.
    o2 = np.lexsort((t, item, ent))
    same = np.zeros(n, dtype=bool)
    same[1:] = (ent[o2][1:] == ent[o2][:-1]) & (item[o2][1:] == item[o2][:-1])
    prev_sorted = np.full(n, np.nan)
    ts2 = t[o2].astype(np.float64)
    prev_sorted[1:][same[1:]] = ts2[:-1][same[1:]]
    prev = np.empty(n)
    prev[o2] = prev_sorted

    o = _order(t, ent)
    out = np.empty((n, taus.shape[0]))
    _kernel(t[o].astype(np.float64), ent[o], w[o], prev[o], taus, out)
    res = np.empty_like(out)
    res[o] = out
    return res


def decayed_sum_at(t, ent, w, t_query, ent_query, taus) -> np.ndarray:
    """State of ``decayed_sum`` at arbitrary (time, entity) queries.

    Includes every event with time <= query time (queries sort after ties).
    """
    n = len(t)
    T = np.concatenate([t, t_query]).astype(np.float64)
    E = np.concatenate([ent, ent_query])
    W = np.concatenate([w, np.zeros(len(t_query))])
    return decayed_sum(T, E, W, taus)[n:]


def decayed_distinct_at(t, ent, item, t_query, ent_query, taus) -> np.ndarray:
    """State of ``decayed_distinct`` at arbitrary (time, entity) queries."""
    n = len(t)
    item = np.asarray(item, dtype=np.int64)
    probe_items = -1 - np.arange(len(t_query), dtype=np.int64)  # unused by real events
    T = np.concatenate([t, t_query]).astype(np.float64)
    E = np.concatenate([ent, ent_query])
    I_ = np.concatenate([item, probe_items])
    W = np.concatenate([np.ones(n), np.zeros(len(t_query))])
    return decayed_distinct(T, E, I_, taus, w=W)[n:]
