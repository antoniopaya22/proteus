"""Maximum of per-entity-type monotone cores.

Each sub-core sees only the evidence of one side (destination or source), so it
cannot learn shortcuts that mix them (e.g. relying on per-source volume for a DDoS,
which spreading the attack over bots defeats). The maximum of monotone functions is
monotone, so the guarantee of every sub-core carries over to the combination.
"""

from __future__ import annotations

import numpy as np
from sklearn.base import clone


class MaxCore:
    def __init__(self, columns: list[str], parts: list[tuple[list[str], object]]):
        self.columns = list(columns)
        pos = {c: i for i, c in enumerate(self.columns)}
        self.parts = [([pos[c] for c in cols], m) for cols, m in parts]
        cst = np.zeros(len(self.columns), dtype=int)
        for idx, m in self.parts:
            mc = np.asarray(m.monotonic_cst if m.monotonic_cst is not None else [0] * len(idx))
            cst[idx] = np.where(mc != 0, mc, cst[idx])
        self.monotonic_cst = cst.tolist()

    def fit(self, X, y, sample_weight=None):
        self.parts = [(idx, clone(m).fit(X[:, idx], y, sample_weight=sample_weight))
                      for idx, m in self.parts]
        return self

    def predict_proba(self, X):
        p = np.max([m.predict_proba(X[:, idx])[:, 1] for idx, m in self.parts], axis=0)
        return np.stack([1 - p, p], axis=1)

    def predict(self, X):
        return (self.predict_proba(X)[:, 1] >= 0.5).astype(int)


class CalibratedMax(MaxCore):
    """Maximum of fitted monotone cores after mapping each one through the CDF of its
    scores on local benign traffic: ``max_i F_i(s_i)``.

    A plain maximum with one threshold is dominated by the part with the highest benign
    scores, and recalibrating the threshold silences the others. Each ``F_i`` is
    non-decreasing, so the combination stays monotone (and certifiable). ``fit`` takes
    benign flows only (local calibration); the parts are not refitted.
    """

    local = True  # fitted per test day on benign traffic of the other days
    # Optional (set by the caller): exclude sub-cores that cannot reach this FPR on the
    # local benign traffic, because more than that share of benign flows ties at their
    # maximum score (a saturated model, as on CTU-13). Such a sub-core cannot separate
    # anything at the target rate and only adds false alarms; METIS likewise drops a
    # metric whose two references do not separate. The maximum over the remaining
    # sub-cores is still monotone.
    exclude_fpr: float | None = None

    def fit(self, X, y=None):
        self.ref_ = [np.sort(m.predict_proba(X[:, idx])[:, 1]) for idx, m in self.parts]
        self.active_ = [True] * len(self.ref_)
        if self.exclude_fpr is not None:
            for i, ref in enumerate(self.ref_):
                at_max = float((ref >= ref[-1]).mean())
                self.active_[i] = at_max <= self.exclude_fpr
            if not any(self.active_):
                self.active_ = [True] * len(self.ref_)
        return self

    def score(self, X):
        u = []
        active = getattr(self, "active_", [True] * len(self.ref_))
        for (idx, m), ref, on in zip(self.parts, self.ref_, active):
            if not on:
                continue
            s = m.predict_proba(X[:, idx])[:, 1]
            f = np.searchsorted(ref, s, side="right") / len(ref)
            # Beyond the benign maximum keep ranking by the score instead of saturating.
            u.append(np.where(s > ref[-1], 1.0 + (s - ref[-1]), f))
        return np.max(u, axis=0)

    def predict_proba(self, X):
        s = self.score(X)
        p = s / (1.0 + s)  # monotone map to [0, 1) for code that expects probabilities
        return np.stack([1 - p, p], axis=1)
