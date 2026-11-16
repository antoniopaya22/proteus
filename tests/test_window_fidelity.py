import numpy as np
import pandas as pd

from proteus.evaluation.window_fidelity import (
    BINS,
    bin_flows,
    reference,
    statistics,
    window_statistic,
    windows,
)


def _flows(n, rng, t0, attack=False):
    t = pd.Timestamp("2021-03-01 10:00") + pd.to_timedelta(t0 + np.sort(rng.uniform(0, 30, n)), unit="s")
    if attack:  # a brute force: many near-identical connections
        fp, bp, fb, bb, dur = [np.full(n, v) for v in (12, 10, 900, 1500, 400_000)]
    else:
        fp = rng.integers(2, 40, n); bp = rng.integers(1, 40, n)
        fb = fp * rng.integers(40, 1200, n); bb = bp * rng.integers(40, 1400, n)
        dur = rng.integers(1_000, 5_000_000, n)
    return pd.DataFrame({"t_start": t.astype("datetime64[us]"), "t_end": t.astype("datetime64[us]"),
                         "duration_us": dur, "src_ip": "172.16.0.9" if attack else "10.0.0.5",
                         "dst_ip": "10.0.1.1", "dst_port": 22, "proto": 6, "fwd_pkts": fp,
                         "bwd_pkts": bp, "fwd_bytes": fb, "bwd_bytes": bb,
                         "attack": "bf_ssh" if attack else "benign", "is_attack": attack,
                         "_dirty": attack})


def test_a_window_like_the_reference_scores_low_and_a_uniform_one_scores_high():
    rng = np.random.default_rng(0)
    ref_df = _flows(5000, rng, 0)
    ref = reference(statistics(ref_df), ref_df["dst_port"].to_numpy(), min_flows=100)
    assert ref[22].shape == (7, BINS - 1)
    df = pd.concat([_flows(400, rng, 0), _flows(400, rng, 60, attack=True)], ignore_index=True)
    bins = bin_flows(statistics(df), df["dst_port"].to_numpy(), ref)
    s = window_statistic(bins, df["is_attack"].to_numpy().astype(int), 2)
    assert s[0] < 0.12 and s[1] > 0.4  # benign window near 0; identical flows far from it


def test_windows_group_by_entity_and_time_and_count_attack_flows():
    rng = np.random.default_rng(1)
    ref_df = _flows(3000, rng, 0)
    ref = reference(statistics(ref_df), ref_df["dst_port"].to_numpy(), min_flows=100)
    df = pd.concat([_flows(200, rng, 0), _flows(300, rng, 60, attack=True), _flows(5, rng, 120)],
                   ignore_index=True).sort_values("t_end", kind="stable").reset_index(drop=True)
    bins = bin_flows(statistics(df), df["dst_port"].to_numpy(), ref)
    w, codes = windows(df, bins, "service", 30.0, min_flows=10)
    assert len(codes) == len(df) and len(w) == 3
    assert int(w["ok"].sum()) == 2 and set(w["entity"]) == {"10.0.1.1:22"}  # 5 flows: not scored
    assert (w.loc[codes, "flows"].to_numpy() >= 5).all()
    w = w[w["ok"]]
    a = w[w["attack_flows"] > 0].iloc[0]
    assert a["attack_flows"] == 300 and a["attack"] == "bf_ssh" and bool(a["dirty"])
    b = w[w["attack_flows"] == 0].iloc[0]
    assert a["stat"] > 3 * b["stat"] and not bool(b["dirty"])
    src, _ = windows(df, bins, "source", 30.0, min_flows=10)
    assert set(src.loc[src["ok"], "entity"]) == {"10.0.0.5", "172.16.0.9"}


def test_thresholds_are_set_per_size_class_and_fall_back_to_the_smaller_one():
    from proteus.evaluation.window_fidelity import alerts, thresholds

    calib = pd.DataFrame({"kind": "service", "dirty": False,
                          "flows": [12] * 50 + [500] * 50,
                          "stat": list(np.linspace(0.2, 0.6, 50)) + list(np.linspace(0.02, 0.1, 50))})
    thr = thresholds(calib, 0.02)
    assert thr[("service", 0)] > 0.55 and thr[("service", 3)] < 0.11
    assert thr[("service", 4)] == thr[("service", 3)]  # no benign window that large
    w = pd.DataFrame({"kind": "service", "flows": [12, 500, 5000], "stat": [0.5, 0.3, 0.3]})
    assert alerts(w, thr).tolist() == [False, True, True]
