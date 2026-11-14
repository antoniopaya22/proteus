import numpy as np
import pandas as pd
import pytest
from test_chunked import flows

from proteus.evidence.features import build
from proteus.evidence.stream import StreamingEvidence


def _windows(df, window_s):
    w = (df["t_end"] - df["t_end"].min()).dt.total_seconds() // window_s
    return [g for _, g in df.groupby(w, sort=True)]


@pytest.mark.parametrize("version", ["v1", "v3"])
def test_stream_matches_whole_capture(version):
    df = flows(n=5000, horizon_s=6 * 3600)
    df["bwd_pkts"] = np.where(np.arange(len(df)) % 3 == 0, 0, df["bwd_pkts"])  # unanswered
    exact, specs = build(df, version=version)
    se = StreamingEvidence(version=version, horizon_s=np.inf)
    parts = []
    for g in _windows(df, 1800):
        f, _ = se.build(g)
        parts.append(f)
    got = pd.concat(parts).loc[exact.index]
    assert list(got.columns) == list(exact.columns)
    assert np.allclose(got.to_numpy(), exact.to_numpy(), atol=1e-4)


def test_pruning_stays_within_its_bound():
    df = flows(n=4000, horizon_s=8 * 3600)
    exact, _ = build(df, version="v3")
    se = StreamingEvidence(version="v3", horizon_s=3600)  # short horizon: forces pruning
    got = pd.concat([se.build(g)[0] for g in _windows(df, 900)]).loc[exact.index]
    for c in exact.columns:
        tau = float(c.rsplit("__t", 1)[1])
        e = np.expm1(exact[c].to_numpy().astype(np.float64))
        a = np.expm1(got[c].to_numpy().astype(np.float64))
        b = np.exp(-3600 / tau)
        tol = 1e-5 * (1 + e)
        # dropped entities can only lower a counter, by at most b of its value
        assert np.all(e - a <= b * e.max() + tol), c
        if 3 * tau <= 3600:  # horizon >= 3 tau: a forgotten item returns at most once
            assert np.all(a - e <= b * (e.max() + 1) + tol), c  # per tau, by <= b each


def test_windows_must_come_in_order():
    df = flows(n=500, horizon_s=3600)
    se = StreamingEvidence(version="v3")
    w = _windows(df, 1200)
    se.build(w[1])
    with pytest.raises(ValueError):
        se.build(w[0])
