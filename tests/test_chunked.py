import numpy as np
import pandas as pd

from proteus.evidence.chunked import build_chunked
from proteus.evidence.features import build


def flows(n=4000, horizon_s=4 * 3600, seed=0):
    rng = np.random.default_rng(seed)
    t = pd.Timestamp("2020-01-01") + pd.to_timedelta(np.sort(rng.uniform(0, horizon_s, n)), "s")
    df = pd.DataFrame({
        "t_end": t.astype("datetime64[us]"),
        "src_ip": rng.choice([f"10.0.0.{i}" for i in range(20)], n),
        "dst_ip": rng.choice([f"10.0.1.{i}" for i in range(8)], n),
        "dst_port": rng.choice([22, 80, 443], n).astype(np.int32),
        "proto": np.full(n, 6, dtype=np.int16),
        "fwd_pkts": rng.integers(1, 30, n).astype(np.int64),
        "bwd_pkts": rng.integers(0, 30, n).astype(np.int64),
        "fwd_bytes": rng.integers(40, 5000, n).astype(np.int64),
        "bwd_bytes": rng.integers(0, 5000, n).astype(np.int64),
        "f_bwd_rst_flags": (rng.random(n) < 0.1).astype(np.float32),
        "duration_us": rng.integers(0, 10_000_000, n).astype(np.int64),
    })
    return df.reset_index(drop=True)


def test_chunked_matches_exact_within_warmup_bound():
    df = flows()
    exact, _ = build(df)
    approx, _ = build_chunked(df, window_s=1800)
    approx = approx.loc[exact.index]
    for c in exact.columns:
        e, a = np.expm1(exact[c].to_numpy()), np.expm1(approx[c].to_numpy())
        # Never above the exact value (old events can only be dropped).
        assert np.all(a <= e + 1e-6 * (1 + e)), c
        # Missing mass <= exp(-warmup/tau) times the counter value at the start of the
        # warm-up, bounded here by the column maximum (warm-up = 3 tau_max).
        assert np.all(e - a <= np.exp(-3) * e.max() + 1e-3), (c, float((e - a).max()))


def test_sampling_keeps_counters_from_all_flows():
    df = flows()
    exact, _ = build(df)
    keep = df.index % 7 == 0
    approx, _ = build_chunked(df, window_s=1800, sample=lambda w: (w.index % 7 == 0))
    assert set(approx.index) == set(df.index[keep])
    e = np.expm1(exact.loc[approx.index, "dhost__flows__t60"].to_numpy())
    a = np.expm1(approx["dhost__flows__t60"].to_numpy())
    np.testing.assert_allclose(a, e, rtol=1e-6, atol=1e-6)
