"""Fixed per-feature thresholds (classic rate detection) as a baseline."""

from __future__ import annotations

import numpy as np


class RateRules:
    """Fixed per-feature thresholds: score = max over features of the benign CDF."""

    def fit(self, X: np.ndarray) -> RateRules:
        self.cols_ = [np.sort(c[~np.isnan(c)]) for c in X.T]
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        u = np.zeros(X.shape, dtype=np.float64)  # NaN (no baseline yet) -> 0
        for j, col in enumerate(self.cols_):
            if len(col) == 0:
                continue
            x = X[:, j]
            ok = ~np.isnan(x)
            u[ok, j] = np.searchsorted(col, x[ok], side="right") / len(col)
            # Beyond the calibration maximum, keep ranking by the excess (features are
            # log counts) instead of saturating at 1.
            above = ok & (np.nan_to_num(x, nan=-np.inf) > col[-1])
            u[above, j] = 1.0 + (x[above] - col[-1])
        return u.max(axis=1)
