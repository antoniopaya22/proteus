"""KitNET (Mirsky et al., NDSS 2018) as an unsupervised aggregate baseline.

Kitsune extracts damped statistics per host, channel and socket from packets
(AfterImage) and scores them with KitNET: features are clustered by correlation
into groups of at most ``m``, each group is reconstructed by a small autoencoder,
and an output autoencoder reconstructs the vector of their errors; the anomaly
score is the output RMSE.

We work on flow records, not packets, so the input is our own damped per-entity
evidence (decayed counts per destination service, destination host and source host
at several time scales), which plays the role of AfterImage. The network follows
the original: correlation-based feature map, tied-weight sigmoid autoencoders with
a hidden ratio of 0.75, min-max scaling learned on benign traffic, SGD. Training is
mini-batch over the benign sample instead of one online pass.
"""

from __future__ import annotations

import numpy as np
from scipy.cluster.hierarchy import linkage, to_tree
from scipy.spatial.distance import squareform


def _sigmoid(z: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-z))


class _AE:
    """Tied-weight sigmoid autoencoder on min-max scaled inputs (Kitsune's dA)."""

    def __init__(self, n: int, ratio: float, rng: np.random.Generator) -> None:
        h = max(1, int(np.ceil(n * ratio)))
        a = 1.0 / n
        self.W = rng.uniform(-a, a, (n, h))
        self.b_h = np.zeros(h)
        self.b_v = np.zeros(n)

    def fit_scale(self, X: np.ndarray) -> None:
        self.lo = X.min(axis=0)
        self.span = np.maximum(X.max(axis=0) - self.lo, 1e-12)

    def _scale(self, X: np.ndarray) -> np.ndarray:
        return (X - self.lo) / self.span  # beyond the benign range stays > 1 (anomalous)

    def step(self, X: np.ndarray, lr: float) -> None:
        x = self._scale(X)
        y = _sigmoid(x @ self.W + self.b_h)
        z = _sigmoid(y @ self.W.T + self.b_v)
        d_z = (z - x) * z * (1 - z)
        d_y = (d_z @ self.W) * y * (1 - y)
        n = len(X)
        self.W -= lr * (x.T @ d_y + d_z.T @ y) / n
        self.b_h -= lr * d_y.mean(axis=0)
        self.b_v -= lr * d_z.mean(axis=0)

    def rmse(self, X: np.ndarray) -> np.ndarray:
        x = self._scale(X)
        z = _sigmoid(_sigmoid(x @ self.W + self.b_h) @ self.W.T + self.b_v)
        return np.sqrt(((x - z) ** 2).mean(axis=1))


def feature_map(X: np.ndarray, m: int) -> list[np.ndarray]:
    """Groups of at most ``m`` features, by hierarchical clustering on correlation
    distance (1 - correlation), as Kitsune's feature mapper."""
    n = X.shape[1]
    if n <= m:
        return [np.arange(n)]
    with np.errstate(invalid="ignore", divide="ignore"):
        c = np.corrcoef(X, rowvar=False)
    c = np.nan_to_num(c, nan=0.0)
    d = np.clip(1.0 - c, 0.0, 2.0)
    np.fill_diagonal(d, 0.0)
    root = to_tree(linkage(squareform(d, checks=False), method="single"))
    groups, stack = [], [root]
    while stack:
        node = stack.pop()
        if node.get_count() <= m:
            groups.append(np.array(sorted(node.pre_order())))
        else:
            stack += [node.get_left(), node.get_right()]
    return groups


class KitNET:
    """Unsupervised ensemble of autoencoders; ``score`` is the anomaly score."""

    def __init__(self, m: int = 10, ratio: float = 0.75, lr: float = 0.1, epochs: int = 2,
                 batch: int = 256, max_rows: int = 500_000, seed: int = 0) -> None:
        self.m, self.ratio, self.lr, self.epochs = m, ratio, lr, epochs
        self.batch, self.max_rows, self.seed = batch, max_rows, seed

    def _clean(self, X: np.ndarray) -> np.ndarray:
        return np.nan_to_num(np.asarray(X, dtype=np.float64), nan=0.0, posinf=0.0, neginf=0.0)

    def fit(self, X: np.ndarray) -> KitNET:
        rng = np.random.default_rng(self.seed)
        X = self._clean(X)
        if len(X) > self.max_rows:
            X = X[rng.choice(len(X), self.max_rows, replace=False)]
        self.groups_ = feature_map(X, self.m)
        self.ens_ = [_AE(len(g), self.ratio, rng) for g in self.groups_]
        for g, ae in zip(self.groups_, self.ens_):
            ae.fit_scale(X[:, g])
        self._train(self.ens_, lambda idx: [X[idx][:, g] for g in self.groups_], len(X), rng)
        R = self._ensemble(X)
        self.out_ = _AE(R.shape[1], self.ratio, rng)
        self.out_.fit_scale(R)
        self._train([self.out_], lambda idx: [R[idx]], len(R), rng)
        return self

    def _train(self, aes, batches, n, rng) -> None:
        for _ in range(self.epochs):
            order = rng.permutation(n)
            for s in range(0, n, self.batch):
                for ae, xb in zip(aes, batches(order[s:s + self.batch])):
                    ae.step(xb, self.lr)

    def _ensemble(self, X: np.ndarray) -> np.ndarray:
        return np.stack([ae.rmse(X[:, g]) for g, ae in zip(self.groups_, self.ens_)], axis=1)

    def score(self, X: np.ndarray, chunk: int = 1_000_000) -> np.ndarray:
        X = np.asarray(X)
        out = np.empty(len(X), dtype=np.float64)
        for s in range(0, len(X), chunk):
            x = self._clean(X[s:s + chunk])
            out[s:s + chunk] = self.out_.rmse(self._ensemble(x))
        return out
