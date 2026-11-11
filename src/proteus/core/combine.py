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

    def fit(self, X, y):
        self.parts = [(idx, clone(m).fit(X[:, idx], y)) for idx, m in self.parts]
        return self

    def predict_proba(self, X):
        p = np.max([m.predict_proba(X[:, idx])[:, 1] for idx, m in self.parts], axis=0)
        return np.stack([1 - p, p], axis=1)

    def predict(self, X):
        return (self.predict_proba(X)[:, 1] >= 0.5).astype(int)
