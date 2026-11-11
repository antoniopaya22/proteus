import numpy as np
import pandas as pd

from proteus.evaluation.free_ops import variant
from proteus.evidence.features import build


def trace(n=400, seed=0):
    rng = np.random.default_rng(seed)
    t = pd.Timestamp("2020-01-01") + pd.to_timedelta(np.sort(rng.uniform(0, 1800, n)), "s")
    df = pd.DataFrame({
        "t_start": t.astype("datetime64[us]"),
        "duration_us": rng.integers(0, 5_000_000, n).astype(np.int64),
        "src_ip": pd.array(rng.choice(["10.0.0.1", "10.0.0.2", "6.6.6.6"], n), dtype="string"),
        "src_port": rng.integers(1024, 65536, n).astype(np.int32),
        "dst_ip": pd.array(["10.0.1.1"] * n, dtype="string"),
        "dst_port": np.full(n, 80, dtype=np.int32),
        "proto": np.full(n, 6, dtype=np.int16),
        "fwd_pkts": rng.integers(1, 20, n).astype(np.int64),
        "bwd_pkts": rng.integers(0, 20, n).astype(np.int64),
        "fwd_bytes": rng.integers(100, 2000, n).astype(np.int64),
        "bwd_bytes": rng.integers(0, 2000, n).astype(np.int64),
        "f_bwd_rst_flags": np.zeros(n, dtype=np.float32),
    })
    df["t_end"] = df["t_start"] + pd.to_timedelta(df["duration_us"], unit="us")
    df["_atk"] = (df["src_ip"] == "6.6.6.6").to_numpy()
    df["orig_id"] = np.arange(n)
    return df


def test_variants_keep_schema_and_never_lose_attack_flows():
    df = trace()
    rng = np.random.default_rng(1)
    for k in range(12):
        v, p = variant(df, rng, "10.0.1.1", 80, retime=k % 2 == 1)
        assert v["_atk"].dtype == bool
        assert set(v.loc[v["orig_id"] >= 0, "orig_id"]) == set(range(len(df)))
        assert v.loc[v["_atk"], "fwd_pkts"].sum() >= df.loc[df["_atk"], "fwd_pkts"].sum()
        if not p["ext"]:
            same = v.set_index("orig_id").loc[df["orig_id"], "t_end"].to_numpy()
            if p["split"] == 1:
                assert (same == df["t_end"].to_numpy()).all()
        build(v.sort_values("t_end", kind="stable"))
