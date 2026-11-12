import numpy as np

from proteus.baselines.kitnet import KitNET, feature_map


def benign(rng, n):
    z = rng.normal(size=(n, 3))
    # Three correlated blocks of features.
    return np.hstack([z[:, [0]] + 0.1 * rng.normal(size=(n, 8)),
                      z[:, [1]] + 0.1 * rng.normal(size=(n, 7)),
                      z[:, [2]] + 0.1 * rng.normal(size=(n, 5))])


def test_feature_map_partitions_features_in_small_groups():
    X = benign(np.random.default_rng(0), 2000)
    groups = feature_map(X, 10)
    assert sorted(np.concatenate(groups).tolist()) == list(range(X.shape[1]))
    assert max(len(g) for g in groups) <= 10
    # Correlated blocks are not split across groups.
    for g in groups:
        blocks = {0 if i < 8 else 1 if i < 15 else 2 for i in g}
        assert len(blocks) == 1


def test_anomalies_score_higher_than_benign():
    rng = np.random.default_rng(1)
    m = KitNET(epochs=3, seed=0).fit(benign(rng, 20_000))
    normal = m.score(benign(rng, 2000))
    odd = benign(rng, 2000)
    odd[:, :8] += 3.0 * rng.choice([-1, 1], size=(2000, 1))  # breaks the scale of block 0
    odd[:, 8:15] = -odd[:, 8:15]  # breaks a correlation
    assert np.median(m.score(odd)) > np.quantile(normal, 0.99)


def test_score_handles_nan_and_chunks():
    rng = np.random.default_rng(2)
    X = benign(rng, 3000)
    m = KitNET(epochs=1).fit(X)
    Y = X.copy()
    Y[0, 0] = np.nan
    a, b = m.score(Y), m.score(Y, chunk=700)
    assert np.isfinite(a).all() and np.allclose(a, b)
