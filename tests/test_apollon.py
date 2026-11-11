import numpy as np
from sklearn.datasets import make_classification

from proteus.baselines.apollon import ApollonMAB, ApollonV1Code


def data(n=3000):
    return make_classification(n_samples=n, n_features=10, n_informative=6,
                               weights=[0.7, 0.3], random_state=0)


def test_code_variant_reproduces_label_indexed_rewards():
    X, y = data()
    m = ApollonV1Code(random_state=0).fit(X, y)
    # RF scored on benign only, DT on attacks only (both ~1 in-sample), NB never scored.
    assert np.all(m.reward_[:, 0] > 0.95) and np.all(m.reward_[:, 1] > 0.95)
    assert np.all(m.reward_[:, 2] == 0)
    f = m.selection_frequencies(X, n_draws=5)
    # Beta(2,1), Beta(2,1), Beta(1,2): NB answers a small share, RF and DT the rest equally.
    assert 0.03 < f[2] < 0.15
    assert abs(f[0] - f[1]) < 0.05


def test_fixed_variant_uses_whole_pool():
    X, y = data()
    m = ApollonMAB(random_state=0).fit(X, y)
    assert m.n_arms == 5
    assert (m.predict(X) == y).mean() > 0.8
