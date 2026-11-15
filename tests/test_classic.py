import numpy as np
import pandas as pd

from proteus.baselines.classic import TRW_FLOOR, syn_cusum_scores, trw_scores


def _t(n):
    return (pd.Timestamp("2020-01-01") + pd.to_timedelta(np.arange(n), unit="s")).to_numpy()


def test_trw_rises_for_a_scanner_and_stays_low_for_a_client():
    n = 40
    src = np.array(["scan"] * n + ["client"] * n)
    dst = np.array([f"h{i}" for i in range(n)] + [f"s{i % 3}" for i in range(n)])
    failed = np.r_[np.ones(n, bool), np.zeros(n, bool)]
    s = trw_scores(np.r_[_t(n), _t(n)], src, dst, failed)
    assert np.all(np.diff(s[:n]) > 0)          # every failed first contact raises it
    assert s[n - 1] > 10 and s[n:].max() <= 0  # the client never goes positive
    assert s[n:].min() >= TRW_FLOOR


def test_trw_counts_each_destination_once():
    n = 30
    s = trw_scores(_t(n), np.array(["a"] * n), np.array(["same"] * n), np.ones(n, bool))
    assert np.allclose(s, s[0])  # repeated failures to one destination do not add up


def test_cusum_detects_a_flood_of_unanswered_flows_only():
    n = 600
    t = _t(n)
    dst = np.array(["victim"] * n)
    quiet = np.zeros(n, bool)
    flood = quiet.copy()
    flood[300:] = True
    assert syn_cusum_scores(t, dst, quiet).max() == 0
    y = syn_cusum_scores(t, dst, flood)
    assert y[:300].max() == 0 and y[-1] > 3
    assert np.all(np.diff(y[300:]) >= 0)
