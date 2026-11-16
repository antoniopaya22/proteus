import numpy as np
import pytest
from sklearn.datasets import make_classification

from proteus.baselines.apollon import ApollonMAB


def data(n=3000):
    return make_classification(n_samples=n, n_features=10, n_informative=6,
                               weights=[0.7, 0.3], random_state=0)


def test_apollon_uses_whole_pool():
    X, y = data()
    m = ApollonMAB(random_state=0).fit(X, y)
    assert m.n_arms == 5
    assert (m.predict(X) == y).mean() > 0.8


def test_scaled_ignores_non_finite_values_and_empty_columns():
    from proteus.baselines.apollon import Scaled

    X = np.array([[0.0, np.inf, np.nan], [9.0, 3.0, np.nan], [99.0, np.nan, np.nan]])
    sc = Scaled().fit(X)
    Z = sc.transform(X)
    assert np.isfinite(Z).all() and Z.min() >= 0 and Z.max() <= 1
    assert Z[0, 0] == 0 and Z[2, 0] == 1 and Z[0, 1] == 1  # inf saturates, not the scale
    assert (Z[:, 2] == 0).all()


def test_apollon_flow_scores_raw_flow_statistics_in_batches():
    from proteus.baselines.apollon import ApollonFlow

    rng = np.random.default_rng(0)
    n = 600
    y = (rng.random(n) < 0.5).astype(int)
    X = np.column_stack([rng.lognormal(3 + 4 * y, 1.0), rng.lognormal(2, 1.0, n),
                         np.where(rng.random(n) < 0.05, np.nan, 1e6 * rng.random(n))])
    m = ApollonFlow(random_state=0, batch=100).fit(X.astype(np.float32), y)
    p = m.predict_proba(X.astype(np.float32))
    assert p.shape == (n, 2) and np.isfinite(p).all()
    assert ((p[:, 1] > 0.5) == y).mean() > 0.9
    assert m.monotonic_cst is None
    with pytest.raises(ValueError):
        m.fit(X, y, sample_weight=np.ones(n))
