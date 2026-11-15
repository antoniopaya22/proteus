import numpy as np
import pandas as pd

from proteus.evaluation.adaptive import Scored, mimic


def test_mimic_only_adds_and_reaches_benign_medians():
    bg = pd.DataFrame({"fwd_pkts": [10, 10, 12], "fwd_bytes": [1000, 1200, 1200]})
    df = pd.DataFrame({"fwd_pkts": [2, 20, 5], "fwd_bytes": [100, 5000, 50],
                       "_atk": [True, True, False]})
    out = mimic(df, bg)
    assert (out["fwd_pkts"] >= df["fwd_pkts"]).all()
    assert (out["fwd_bytes"] >= df["fwd_bytes"]).all()
    assert out.loc[0, "fwd_pkts"] == 10 and out.loc[0, "fwd_bytes"] >= 10 * 100
    assert out.loc[1, "fwd_pkts"] == 20 and out.loc[1, "fwd_bytes"] == 5000  # already above
    assert out.loc[2].equals(df.loc[2])  # benign flows untouched


def test_scored_exposes_score_as_column_one():
    class M:
        def score(self, X):
            return X.sum(axis=1)

    p = Scored(M()).predict_proba(np.array([[1.0, 2.0], [0.5, 0.0]]))
    assert np.allclose(p[:, 1], [3.0, 0.5])


def test_structured_plans_touch_only_the_attack_flows():
    import numpy as np
    import pandas as pd

    from proteus.evaluation.adaptive import STRUCTURED, structured

    t0 = pd.Timestamp("2020-01-01 10:00")
    n = 300
    df = pd.DataFrame({
        "t_start": (t0 + pd.to_timedelta(np.arange(n) * 2.0, unit="s")).astype("datetime64[us]"),
        "duration_us": np.full(n, 100_000, dtype=np.int64),
        "src_ip": pd.array(["10.0.0.5"] * 100 + ["203.0.113.1"] * 200, dtype="string"),
        "dst_ip": pd.array(["10.0.1.1"] * n, dtype="string"),
        "src_port": np.arange(n, dtype=np.int32) + 2000, "dst_port": np.int32(80),
        "proto": np.int16(6), "fwd_pkts": np.full(n, 8, dtype=np.int64),
        "bwd_pkts": np.full(n, 5, dtype=np.int64), "fwd_bytes": np.full(n, 700, dtype=np.int64),
        "bwd_bytes": np.full(n, 900, dtype=np.int64), "f_bwd_rst_flags": np.zeros(n, np.float32),
        "_atk": [False] * 100 + [True] * 200,
    })
    df["t_end"] = df["t_start"] + pd.to_timedelta(df["duration_us"], unit="us")
    df["orig_id"] = np.arange(n)
    bytes_atk = df.loc[df["_atk"], "fwd_bytes"].sum()
    for plan, (k, srcs, _) in STRUCTURED.items():
        v = structured(df, plan, np.random.default_rng(0))
        bg, atk = v[~v["_atk"]], v[v["_atk"]]
        assert len(bg) == 100 and (bg["src_ip"] == "10.0.0.5").all(), plan
        assert atk["fwd_bytes"].sum() == bytes_atk, plan       # payload is never reduced
        assert (len(atk) < 200) == (k > 1), plan
        assert (atk["src_ip"].nunique() > 1) == (srcs > 1), plan
        assert v["t_end"].is_monotonic_increasing, plan
