import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier

from proteus.core.combine import MaxCore
from proteus.core.verify import monotonicity_violations


def test_max_of_monotone_cores_is_monotone():
    rng = np.random.default_rng(0)
    X = rng.normal(size=(3000, 4))
    y = ((X[:, 0] + X[:, 1] > 1) | (X[:, 2] - X[:, 3] > 1)).astype(int)
    cols = ["a", "b", "c", "d"]

    def hgb(cst):
        return HistGradientBoostingClassifier(max_iter=50, monotonic_cst=cst, random_state=0)

    m = MaxCore(cols, [(["a", "b"], hgb([1, 1])), (["c", "d"], hgb([1, -1]))]).fit(X, y)
    assert m.monotonic_cst == [1, 1, 1, -1]
    r = monotonicity_violations(lambda Z: m.predict_proba(Z)[:, 1], X,
                                np.asarray(m.monotonic_cst), rng, n_rows=300)
    assert r["violations"] == 0
    assert (m.predict(X) == y).mean() > 0.9


def test_unconstrained_parts_are_not_certifiable():
    from proteus.core.combine import CalibratedMax

    def hgb():
        return HistGradientBoostingClassifier(max_iter=5, random_state=0)

    m = CalibratedMax(["a", "b"], [(["a"], hgb()), (["b"], hgb())])
    assert m.monotonic_cst is None


def test_rate_rules_are_monotone():
    from proteus.baselines.rate_rules import RateRules

    rng = np.random.default_rng(1)
    X = rng.exponential(size=(2000, 3))
    m = RateRules().fit(X)
    r = monotonicity_violations(m.score, X * 2, np.ones(3, dtype=int), rng, n_rows=300)
    assert r["violations"] == 0
