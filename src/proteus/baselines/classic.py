"""Classic rate-based detectors on flow records, as baselines.

* ``trw_scores``: Threshold Random Walk (Jung et al., IEEE S&P 2004). Per source, a
  sequential likelihood ratio over the outcomes of its first contacts with distinct
  destinations: a failed first contact (no answer) is evidence of scanning, a
  successful one of benign use.
* ``syn_cusum_scores``: the non-parametric CUSUM of Wang et al. (INFOCOM 2002) for SYN
  floods, adapted from packet counts to flow records: per destination and interval, the
  unanswered flows normalised by the destination's recent flow rate play the role of
  the SYN-FIN difference.

Both return one score per flow (the state of its source or destination when the flow
ends), so they are thresholded and evaluated like every other detector.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from numba import njit

# TRW: probability that a first contact succeeds for a benign host and for a scanner.
THETA0, THETA1 = 0.8, 0.2
TRW_FLOOR = float(np.log(0.01))  # the "benign" decision bound, kept as a floor


@njit(cache=True)
def _trw_kernel(src, first, failed, up, down, floor, out):
    lam = 0.0
    for i in range(src.shape[0]):
        if i == 0 or src[i] != src[i - 1]:
            lam = 0.0
        if first[i]:
            lam = max(lam + (up if failed[i] else down), floor)
        out[i] = lam


def trw_scores(t_end: np.ndarray, src: np.ndarray, dst: np.ndarray,
               failed: np.ndarray) -> np.ndarray:
    """Log-likelihood ratio of each flow's source after the flow, in input order.
    ``failed``: the flow got no answer. Only the first contact of a (source,
    destination) pair moves the walk."""
    n = len(t_end)
    s = pd.factorize(src)[0].astype(np.int64)
    d = pd.factorize(dst)[0].astype(np.int64)
    o = np.lexsort((t_end, s))
    pair = s[o] * (int(d.max()) + 1 if n else 1) + d[o]
    first = ~pd.Series(pair).duplicated().to_numpy()
    out = np.empty(n)
    _trw_kernel(s[o], first, failed[o].astype(np.bool_),
                float(np.log((1 - THETA1) / (1 - THETA0))), float(np.log(THETA1 / THETA0)),
                TRW_FLOOR, out)
    res = np.empty(n)
    res[o] = out
    return res


@njit(cache=True)
def _cusum_kernel(dst, slot, x, flows, a, alpha, out):
    y, mean, last = 0.0, 0.0, -1
    for i in range(dst.shape[0]):
        if i == 0 or dst[i] != dst[i - 1]:
            y, mean, last = 0.0, 0.0, -1
        if last >= 0 and slot[i] > last + 1:  # empty intervals: the excess drains
            y = max(0.0, y - a * (slot[i] - last - 1))
        norm = x[i] / max(mean, 1.0)
        y = max(0.0, y + norm - a)
        mean = alpha * mean + (1 - alpha) * flows[i]
        last = slot[i]
        out[i] = y


def syn_cusum_scores(t_end: np.ndarray, dst: np.ndarray, failed: np.ndarray,
                     interval_s: float = 20.0, a: float = 0.35,
                     alpha: float = 0.9) -> np.ndarray:
    """CUSUM statistic of each flow's destination in the flow's interval, in input
    order. Per interval, x = unanswered flows, normalised by an exponential average of
    the destination's flows per interval; ``a`` is the allowed mean (Wang et al.)."""
    n = len(t_end)
    d = pd.factorize(dst)[0].astype(np.int64)
    t = np.asarray(t_end).astype("datetime64[us]").astype(np.int64) / 1e6
    slot = np.floor((t - (t.min() if n else 0.0)) / interval_s).astype(np.int64)
    g = pd.DataFrame({"d": d, "s": slot, "f": failed.astype(np.float64)})
    agg = g.groupby(["d", "s"], sort=True)["f"].agg(["sum", "size"]).reset_index()
    y = np.empty(len(agg))
    _cusum_kernel(agg["d"].to_numpy(), agg["s"].to_numpy(), agg["sum"].to_numpy(),
                  agg["size"].to_numpy().astype(np.float64), a, alpha, y)
    agg["y"] = y
    return g.merge(agg[["d", "s", "y"]], on=["d", "s"], how="left")["y"].to_numpy()
