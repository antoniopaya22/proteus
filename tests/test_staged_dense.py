import numpy as np

from proteus.datasets.staged import features_kept
from proteus.evidence.features import build

from test_chunked import flows


def test_dense_path_matches_exact_when_one_sub_window_covers_all():
    df = flows(n=3000, horizon_s=1800)
    keep = np.random.default_rng(1).random(len(df)) < 0.3
    exact, _ = build(df)
    dense, _ = features_kept(df, keep, warmup_s=1800, dense_rows=10, sub_s=3600)
    assert np.allclose(dense.to_numpy(), exact.loc[keep].to_numpy())


def test_dense_path_never_exceeds_exact():
    df = flows(n=4000, horizon_s=2 * 3600)
    keep = np.random.default_rng(2).random(len(df)) < 0.5
    exact, _ = build(df)
    dense, _ = features_kept(df, keep, warmup_s=1800, dense_rows=10, sub_s=600)
    e, a = exact.loc[keep].to_numpy(), dense.to_numpy()
    assert a.shape == e.shape
    assert np.all(a <= e + 1e-6 * (1 + np.abs(e)))
