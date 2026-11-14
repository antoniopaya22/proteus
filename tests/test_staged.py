import numpy as np
import pandas as pd

from proteus.datasets import staged
from proteus.evidence.features import build


def flows(n=3000, horizon_s=3 * 3600, seed=0):
    rng = np.random.default_rng(seed)
    t = pd.Timestamp("2020-01-01 22:00") + pd.to_timedelta(
        np.sort(rng.uniform(0, horizon_s, n)), "s")
    atk = rng.random(n) < 0.5
    df = pd.DataFrame({
        "t_start": t.astype("datetime64[us]"),
        "src_ip": pd.array(rng.choice([f"10.0.0.{i}" for i in range(20)], n), dtype="string"),
        "dst_ip": pd.array(rng.choice([f"10.0.1.{i}" for i in range(5)], n), dtype="string"),
        "src_port": rng.integers(1024, 65536, n).astype(np.int32),
        "dst_port": rng.choice([22, 80], n).astype(np.int32),
        "proto": np.full(n, 6, dtype=np.int16),
        "duration_us": rng.integers(0, 2_000_000, n).astype(np.int64),
        "fwd_pkts": rng.integers(1, 30, n).astype(np.int64),
        "bwd_pkts": rng.integers(0, 30, n).astype(np.int64),
        "fwd_bytes": rng.integers(40, 5000, n).astype(np.int64),
        "bwd_bytes": rng.integers(0, 5000, n).astype(np.int64),
        "f_bwd_rst_flags": np.zeros(n, dtype=np.float32),
        "label_raw": np.where(atk, "x", "benign"),
        "attack": np.where(atk, "x", "benign"),
        "family": np.where(atk, "ddos", "benign"),
        "attempted": False,
        "is_attack": atk,
    })
    df["t_end"] = df["t_start"] + pd.to_timedelta(df["duration_us"], unit="us")
    return df.sort_values("t_end", kind="stable").reset_index(drop=True)


def test_process_keeps_benign_samples_attacks_and_bounds_evidence(tmp_path):
    df = flows()
    st = tmp_path / "stage"
    staged.partition(st, df, "a", minutes=10)
    staged.partition(st, df.iloc[:50], "dup", minutes=10)  # exact duplicates
    stats = staged.process(st, tmp_path / "out", "toy", attack_rate=0.3, warmup_s=1800)
    assert sum(s["flows"] for s in stats) == len(df)
    days = sorted((tmp_path / "out" / "evidence").glob("*.parquet"))
    assert [d.stem for d in days] == ["2020-01-01", "2020-01-02"]
    ev = pd.concat([pd.read_parquet(d) for d in days], ignore_index=True)
    assert (~ev["is_attack"]).sum() == (~df["is_attack"]).sum()
    share = ev["is_attack"].sum() / df["is_attack"].sum()
    assert 0.2 < share < 0.4
    exact, _ = build(df)
    exact = pd.concat([df[["t_end", "src_port", "src_ip"]], exact], axis=1)
    m = ev.merge(exact, on=["t_end", "src_ip"], suffixes=("", "_e"))
    for c, tau in (("dhost__flows__t600", 600), ("dsvc__fpkts__t60", 60)):
        a, e = np.expm1(m[c].to_numpy()), np.expm1(m[c + "_e"].to_numpy())
        assert np.all(a <= e + 1e-3 * (1 + e)), c  # warm-up only drops old events
        # missing mass <= exp(-warmup/tau) x counter value at the start of the warm-up
        assert np.all(e - a <= np.exp(-1800 / tau) * e.max() + 1e-2), c


def test_dense_windows_are_sliced_and_never_exceed_exact(tmp_path):
    df = flows(n=4000, horizon_s=2 * 3600)
    st = tmp_path / "stage"
    staged.partition(st, df, "a", minutes=60)
    stats = staged.process(st, tmp_path / "out", "toy", attack_rate=1.0, warmup_s=1800,
                           dense_rows=300)
    assert sum(s["flows"] for s in stats) == len(df)
    ev = pd.concat([pd.read_parquet(d) for d in
                    sorted((tmp_path / "out" / "evidence").glob("*.parquet"))],
                   ignore_index=True)
    assert len(ev) == len(df)
    exact, _ = build(df)
    exact = pd.concat([df[["t_end", "src_port", "src_ip"]], exact], axis=1)
    m = ev.merge(exact, on=["t_end", "src_ip"], suffixes=("", "_e"))
    for c in ("dhost__flows__t600", "dsvc__fpkts__t60", "dhost__flows__t10"):
        a, e = np.expm1(m[c].to_numpy()), np.expm1(m[c + "_e"].to_numpy())
        assert np.all(a <= e + 1e-3 * (1 + e)), c
