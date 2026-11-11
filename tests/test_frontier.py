import numpy as np
import pandas as pd

from proteus.core.frontier import Scenario, attack_scores, frontier, nested_attack

COLS = ["dsvc__flows__t60", "dsvc__fpkts__t600__x"]
SPECS = {c: "conserved" for c in COLS}


class MonotoneSum:
    """Toy monotone model: score increases with every feature."""

    monotonic_cst = (1, 1)

    def predict_proba(self, X):
        s = 1 / (1 + np.exp(-(np.nan_to_num(X).sum(axis=1) - 10)))
        return np.stack([1 - s, s], axis=1)


def scenario(rng):
    n = 300
    t = pd.Timestamp("2020-01-01 12:00") + pd.to_timedelta(np.sort(rng.uniform(0, 7200, n)), "s")
    bg = pd.DataFrame({
        "t_start": t.astype("datetime64[us]"),
        "duration_us": rng.integers(0, 5_000_000, n).astype(np.int64),
        "src_ip": pd.array(rng.choice(["10.0.0.1", "10.0.0.2"], n), dtype="string"),
        "src_port": rng.integers(1024, 65536, n).astype(np.int32),
        "dst_ip": pd.array(["10.0.1.1"] * n, dtype="string"),
        "dst_port": np.full(n, 22, dtype=np.int32),
        "proto": np.full(n, 6, dtype=np.int16),
        "fwd_pkts": rng.integers(1, 20, n).astype(np.int64),
        "bwd_pkts": rng.integers(1, 20, n).astype(np.int64),
        "fwd_bytes": rng.integers(100, 2000, n).astype(np.int64),
        "bwd_bytes": rng.integers(100, 2000, n).astype(np.int64),
        "f_bwd_rst_flags": np.zeros(n, dtype=np.float32),
    })
    bg["t_end"] = bg["t_start"] + pd.to_timedelta(bg["duration_us"], unit="us")
    template = bg.sample(50, random_state=0).copy()
    return Scenario(bg, template, "10.0.1.1", 22, 6, pd.Timestamp("2020-01-01 12:30"), 1800.0)


BASE = {"dsvc": pd.DataFrame({"dsvc__fpkts__t600": [3.0]}, index=["10.0.1.1:22/6"]),
        "dhost": pd.DataFrame()}


def test_alerts_are_monotone_in_rate():
    rng = np.random.default_rng(0)
    sc = scenario(rng)
    m = MonotoneSum()
    r_max = 5.0
    atk = nested_attack(sc, r_max, np.random.default_rng(1))
    prev = -np.inf
    for r in np.geomspace(0.01, r_max, 12):
        a = atk[atk["u"] < r / r_max]
        top = attack_scores(sc, a, m, COLS, SPECS, BASE, None).max() if len(a) else -np.inf
        assert top >= prev - 1e-12
        prev = top


def test_frontier_brackets_the_alert():
    rng = np.random.default_rng(0)
    sc = scenario(rng)
    m = MonotoneSum()
    thr = 0.9
    res = frontier(sc, m, COLS, SPECS, BASE, thr, np.random.default_rng(1), r_min=1e-3,
                   r_max=5.0, iters=14)
    assert res["bounded"] == "ok"
    assert res["rate"] < res["rate_alert"]
    cert = frontier(sc, m, COLS, SPECS, BASE, thr, np.random.default_rng(1), r_min=1e-3,
                    r_max=5.0, iters=14, delta_s=120.0)
    # The certified frontier lets the attacker go at least as fast.
    assert cert["bounded"] != "ok" or cert["rate"] >= res["rate"]


def test_source_side_scenario_keeps_destinations_and_one_source():
    rng = np.random.default_rng(1)
    sc = scenario(rng)
    n = 400
    sc.template = sc.template.sample(n, replace=True, random_state=0).reset_index(drop=True)
    sc.template["dst_ip"] = pd.array([f"10.0.2.{i % 200}" for i in range(n)], dtype="string")
    sc.template["dst_port"] = np.int32(445)
    sc.src_ip, sc.keep_dst, sc.keep_ports = "198.51.100.7", True, True
    a = nested_attack(sc, 0.1, np.random.default_rng(0))
    assert set(a["src_ip"]) == {"198.51.100.7"}
    assert set(a["dst_ip"]) <= set(sc.template["dst_ip"]) and a["dst_ip"].nunique() > 50
    assert set(a["dst_port"]) == {445}
