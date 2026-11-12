"""Randomised smoothing with feature-wise noise, the mechanism behind BARS
(Wang et al., NDSS 2023), as a budget-certified baseline.

The smoothed detector alerts on x when the base detector alerts on most Gaussian
perturbations x + eps, eps_j ~ N(0, sigma_j^2). With p a lower confidence bound of
that probability, the alert is certified for every perturbation delta with
||delta / sigma||_2 <= Phi^{-1}(p) (Cohen et al., ICML 2019, in the metric scaled by
the per-feature noise). BARS learns the noise shape per feature with a distribution
transformer; here sigma_j is ``scale`` times the feature's standard deviation on
benign traffic, which keeps the idea (heterogeneous noise) without its training.
This is a reimplementation of the mechanism, not the BARS code.
"""

from __future__ import annotations

import numpy as np
from scipy.stats import beta, norm


def lower_bound(k: np.ndarray, n: int, alpha: float = 0.001) -> np.ndarray:
    """Clopper-Pearson lower confidence bound of a binomial proportion."""
    k = np.asarray(k, dtype=float)
    lo = beta.ppf(alpha, k, n - k + 1)
    return np.where(k == 0, 0.0, lo)


class Smoothed:
    def __init__(self, decide, sigma: np.ndarray, n: int = 200, alpha: float = 0.001,
                 seed: int = 0) -> None:
        """``decide(X) -> bool array``: the base detector's alert decision."""
        self.decide, self.sigma, self.n, self.alpha = decide, np.asarray(sigma), n, alpha
        self.rng = np.random.default_rng(seed)

    def certify(self, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """(alert, radius): smoothed alert and its certified radius in the
        sigma-scaled L2 metric (0 where there is no alert)."""
        X = np.nan_to_num(np.asarray(X, dtype=np.float64))
        hits = np.zeros(len(X))
        for _ in range(self.n):
            hits += self.decide(X + self.rng.normal(size=X.shape) * self.sigma)
        p = lower_bound(hits, self.n, self.alpha)
        alert = p > 0.5
        radius = np.where(alert, norm.ppf(np.clip(p, 0.5, 1 - 1e-12)), 0.0)
        return alert, radius

    def distance(self, X0: np.ndarray, X1: np.ndarray) -> np.ndarray:
        d = (np.nan_to_num(X1) - np.nan_to_num(X0)) / np.maximum(self.sigma, 1e-9)
        return np.linalg.norm(d, axis=1)
