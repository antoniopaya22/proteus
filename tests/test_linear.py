import numpy as np


def test_monotone_logistic_respects_the_sign_of_every_constraint():
    from proteus.core.linear import MonotoneLogistic

    rng = np.random.default_rng(0)
    X = rng.normal(size=(4000, 3))
    # The label falls with feature 0, which is constrained to be non-decreasing; rises
    # with feature 1 (non-decreasing) and with feature 2 (non-increasing constraint).
    z = -2 * X[:, 0] + 2 * X[:, 1] + 2 * X[:, 2]
    y = (z + rng.normal(size=len(z)) > 0).astype(int)
    m = MonotoneLogistic(monotonic_cst=[1, 1, -1]).fit(X, y)
    assert m.coef_[0] >= 0 and m.coef_[1] > 0 and m.coef_[2] <= 0
    assert abs(m.coef_[0]) < 1e-6 and abs(m.coef_[2]) < 1e-6
    # Monotone in the constrained directions: raising evidence never lowers the score.
    Z = X[:200].copy()
    up = Z.copy()
    up[:, 1] += 1.0
    assert (m.predict_proba(up)[:, 1] >= m.predict_proba(Z)[:, 1]).all()


def test_monotone_logistic_fits_a_separable_direction_and_clones():
    from sklearn.base import clone

    from proteus.core.linear import MonotoneLogistic

    rng = np.random.default_rng(1)
    X = rng.normal(size=(2000, 2))
    y = (X[:, 0] > 0).astype(int)
    m = clone(MonotoneLogistic(monotonic_cst=[1, 0])).fit(X, y, sample_weight=np.ones(len(y)))
    assert (m.predict(X) == y).mean() > 0.95
