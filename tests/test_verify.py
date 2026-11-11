import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier

from proteus.core.verify import monotonicity_violations


def data(rng, n=4000):
    X = rng.normal(size=(n, 4))
    X[rng.random((n, 4)) < 0.05] = np.nan  # baselines are NaN on the first day
    # Label depends non-monotonically on feature 0 so an unconstrained model breaks it.
    y = ((np.sin(3 * np.nan_to_num(X[:, 0])) + np.nan_to_num(X[:, 1])
          - np.nan_to_num(X[:, 2])) > 0).astype(int)
    return X, y


def test_constrained_model_has_no_violations():
    rng = np.random.default_rng(0)
    X, y = data(rng)
    cst = np.array([1, 1, -1, 0])
    m = HistGradientBoostingClassifier(max_iter=50, monotonic_cst=list(cst), random_state=0)
    m.fit(X, y)
    r = monotonicity_violations(lambda Z: m.predict_proba(Z)[:, 1], X, cst, rng, n_rows=300)
    assert r["violations"] == 0, r


def test_unconstrained_model_is_caught():
    rng = np.random.default_rng(0)
    X, y = data(rng)
    cst = np.array([1, 1, -1, 0])
    m = HistGradientBoostingClassifier(max_iter=50, random_state=0).fit(X, y)
    r = monotonicity_violations(lambda Z: m.predict_proba(Z)[:, 1], X, cst, rng, n_rows=300)
    assert r["violations"] > 0
