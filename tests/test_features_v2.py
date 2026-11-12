import numpy as np
import pandas as pd
import pytest

from proteus.evidence.features import build


def flows(rows):
    df = pd.DataFrame(rows, columns=["t", "src_ip", "dst_ip", "bwd_pkts"])
    n = len(df)
    df["t_end"] = (pd.Timestamp("2020-01-01") + pd.to_timedelta(df.pop("t"), "s")).astype(
        "datetime64[us]")
    df["dst_port"] = np.int32(22)
    df["proto"] = np.int16(6)
    for c in ("fwd_pkts", "fwd_bytes", "bwd_bytes"):
        df[c] = np.ones(n, dtype=np.int64)
    df["f_bwd_rst_flags"] = np.zeros(n, dtype=np.float32)
    df["duration_us"] = np.zeros(n, dtype=np.int64)
    df["bwd_pkts"] = df["bwd_pkts"].astype(np.int64)
    return df


def test_v1_has_no_noreply_columns():
    f, _ = build(flows([(0, "a", "x", 0)]), version="v1")
    assert not any("noreply" in c or "dhost_nr" in c for c in f.columns)


def test_v2_counts_distinct_unanswered_destinations():
    # a probes x (no reply), y (reply), z (no reply), x again (no reply)
    df = flows([(0, "a", "x", 0), (1, "a", "y", 3), (2, "a", "z", 0), (3, "a", "x", 0)])
    f, specs = build(df, taus=(1e9,), version="v2")
    nr = np.expm1(f["shost__n_dhost_nr__t1000000000"].to_numpy())
    np.testing.assert_allclose(nr, [1, 1, 2, 2], atol=1e-6)
    cnt = np.expm1(f["shost__noreply__t1000000000"].to_numpy())
    np.testing.assert_allclose(cnt, [1, 1, 2, 3], atol=1e-6)
    spec = {s.name: s.conservation for s in specs}
    assert spec["shost__n_dhost_nr__t1000000000"] == "conserved"


def test_v2_adding_flows_never_lowers_unanswered_evidence():
    rng = np.random.default_rng(0)
    base = [(float(t), "a", f"h{rng.integers(30)}", int(rng.integers(0, 2)) * 3)
            for t in np.sort(rng.uniform(0, 600, 200))]
    extra = [(float(t), "a", f"h{rng.integers(60)}", int(rng.integers(0, 2)) * 3)
             for t in rng.uniform(0, 600, 100)]
    f0, _ = build(flows(base), version="v2")
    both = flows(base + extra)
    both["orig"] = np.r_[np.ones(len(base), bool), np.zeros(len(extra), bool)]
    both = both.sort_values("t_end", kind="stable")
    f1, _ = build(both.drop(columns="orig"), version="v2")
    f1 = f1[both["orig"].to_numpy()]
    for c in [c for c in f0.columns if "noreply" in c or "dhost_nr" in c]:
        assert np.all(f1[c].to_numpy() >= f0[c].to_numpy() - 1e-5), c


def test_unknown_version():
    with pytest.raises(ValueError):
        build(flows([(0, "a", "x", 0)]), version="v9")
