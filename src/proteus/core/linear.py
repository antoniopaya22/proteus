"""A monotone linear classifier: logistic regression whose coefficients are constrained
to the sign of each feature's monotonicity constraint (non-negative for evidence,
non-positive for baselines, free where the constraint is 0).

It is the simplest monotone model that can take the place of a gradient-boosted
sub-core in the calibrated maximum, so comparing the two isolates what the trees add.
"""

from __future__ import annotations

import numpy as np
from scipy.optimize import minimize
from sklearn.base import BaseEstimator, ClassifierMixin


class MonotoneLogistic(BaseEstimator, ClassifierMixin):
    def __init__(self, monotonic_cst=None, l2: float = 1e-4, class_weight: str | None = "balanced",
                 max_iter: int = 500):
        self.monotonic_cst = monotonic_cst
        self.l2 = l2
        self.class_weight = class_weight
        self.max_iter = max_iter

    def fit(self, X, y, sample_weight=None):
        X = np.asarray(X, dtype=np.float64)
        y = np.asarray(y).astype(np.float64)
        n, d = X.shape
        w = np.ones(n) if sample_weight is None else np.asarray(sample_weight, dtype=np.float64)
        if self.class_weight == "balanced":
            for c in (0.0, 1.0):
                m = y == c
                if m.any():
                    w[m] *= n / (2.0 * w[m].sum())
        w = w / w.sum()
        # Standardise with a positive scale, which keeps the sign of every effect.
        self.mean_ = X.mean(axis=0)
        self.scale_ = X.std(axis=0)
        self.scale_[self.scale_ == 0] = 1.0
        Z = (X - self.mean_) / self.scale_
        cst = np.zeros(d) if self.monotonic_cst is None else np.asarray(self.monotonic_cst)
        bounds = [(0.0, None) if c > 0 else (None, 0.0) if c < 0 else (None, None) for c in cst]
        bounds.append((None, None))  # intercept

        def loss(theta):
            z = Z @ theta[:-1] + theta[-1]
            # log(1 + e^z) - y z, stably; gradient (sigmoid(z) - y)
            lz = np.logaddexp(0.0, z)
            f = np.sum(w * (lz - y * z)) + 0.5 * self.l2 * np.sum(theta[:-1] ** 2)
            g = w * (1.0 / (1.0 + np.exp(-z)) - y)
            grad = np.append(Z.T @ g + self.l2 * theta[:-1], g.sum())
            return f, grad

        res = minimize(loss, np.zeros(d + 1), jac=True, method="L-BFGS-B", bounds=bounds,
                       options={"maxiter": self.max_iter})
        self.coef_, self.intercept_ = res.x[:-1], res.x[-1]
        self.classes_ = np.array([0, 1])
        return self

    def decision_function(self, X):
        Z = (np.asarray(X, dtype=np.float64) - self.mean_) / self.scale_
        return Z @ self.coef_ + self.intercept_

    def predict_proba(self, X):
        p = 1.0 / (1.0 + np.exp(-self.decision_function(X)))
        return np.stack([1 - p, p], axis=1)

    def predict(self, X):
        return (self.predict_proba(X)[:, 1] >= 0.5).astype(int)
