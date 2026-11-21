import numpy as np
import pandas as pd

from proteus.evaluation.injection import pick_victims, scan_rates


def _flows():
    rng = np.random.default_rng(0)
    rows = []
    for i, n in enumerate((25, 60, 200, 900, 3000, 10)):  # benign load per server
        rows += [{"dst_ip": f"10.0.1.{i}", "src_ip": "10.0.0.9", "dst_port": 80, "proto": 6,
                  "family": "benign", "is_attack": False}] * n
    rows += [{"dst_ip": "10.0.2.1", "src_ip": "10.0.0.9", "dst_port": 22, "proto": 6,
              "family": "benign", "is_attack": False}] * 500
    rows += [{"dst_ip": "10.0.1.4", "src_ip": "172.16.0.1", "dst_port": 80, "proto": 6,
              "family": "dos", "is_attack": True}] * 50  # the busiest server is attacked
    df = pd.DataFrame(rows)
    return df.sample(frac=1.0, random_state=int(rng.integers(100))).reset_index(drop=True)


def test_pick_victims_spans_the_load_and_skips_attacked_and_idle_hosts():
    f = _flows()
    v = pick_victims(f, 80, 6, 3)
    names = [h for h, _ in v]
    assert "10.0.1.4" not in names and "10.0.1.5" not in names  # attacked; under 20 flows
    assert names[0] == "10.0.1.0" and names[-1] == "10.0.1.3" and len(v) == 3
    assert [n for _, n in v] == sorted(n for _, n in v)
    assert pick_victims(f, 80, 6, 10) == [("10.0.1.0", 25), ("10.0.1.1", 60), ("10.0.1.2", 200),
                                          ("10.0.1.3", 900)]
    hosts = [h for h, _ in pick_victims(f, None, 6, 10)]
    assert "10.0.2.1" in hosts  # scans: hosts, whatever the port


class FakeOracle:
    """Monotone detector A quiet below 1 flow/s, but reuse lets it pass up to 3 and
    minimal requests up to 10; non-monotone B quiet everywhere; A certified below 0.5."""

    def __init__(self):
        class Mono:
            monotonic_cst = (1,)
        self.models = {"A": ([], Mono()), "B": ([], object())}
        self.calls = []

    def query(self, v, names, certified=False):
        r = v["_atk"].sum() / 100.0
        shrink = bool(v.attrs.get("shrink"))
        reuse = bool(v.attrs.get("reuse"))
        limit = 10.0 if shrink else 3.0 if reuse else 1.0
        self.calls.append((round(r, 2), tuple(names)))
        quiet = {n: (n == "B") or r <= limit for n in names}
        return quiet, ({"A": r <= 0.5} if certified and "A" in names else {})


def test_scan_rates_keeps_free_and_minimal_requests_apart_and_stops_monotone_detectors(monkeypatch):
    import proteus.evaluation.injection as inj

    def fake_structured(df, plan, rng):
        out = df.copy()
        out.attrs["shrink"] = plan.startswith("shrink")
        out.attrs["reuse"] = "reuse" in plan
        return out

    monkeypatch.setattr(inj, "structured", fake_structured)
    rates = np.array([0.25, 0.5, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0])
    full = pd.DataFrame({"u": np.linspace(0, 1, 6400, endpoint=False), "x": 0})
    sc = type("S", (), {"background": pd.DataFrame({"x": [0]})})()
    oracle = FakeOracle()
    ladder, best = scan_rates(full, sc, oracle, rates, 64.0, ["plain", "reuse", "shrink+reuse"],
                              ["A"], None)
    a, b = best["A"], best["B"]
    assert (a["plain"], a["free"], a["shrink"], a["cert"]) == (1.0, 2.0, 8.0, 0.5)
    assert b["free"] == 64.0 and np.isnan(b["cert"])
    # A is scored at 16 and 32, where no plan is quiet, and not after them.
    assert any("A" in names for r, names in oracle.calls if r == 32.0)
    assert all("A" not in names for r, names in oracle.calls if r > 33)
    assert {r["plan"] for r in ladder} == {"plain", "reuse", "shrink+reuse"}


def test_additive_plans_only_add_to_the_attack():
    import proteus.evaluation.injection as inj
    from proteus.core.frontier import Scenario
    rng = np.random.default_rng(0)
    n = 60
    t = pd.Timestamp("2020-01-01") + pd.to_timedelta(np.sort(rng.uniform(0, 600, n)), unit="s")
    df = pd.DataFrame({
        "t_start": t.astype("datetime64[us]"), "duration_us": np.full(n, 1_000_000, np.int64),
        "src_ip": ["10.0.0.1"] * n, "src_port": rng.integers(1024, 65536, n).astype(np.int32),
        "dst_ip": ["10.0.1.1"] * n, "dst_port": np.full(n, 80, np.int32),
        "proto": np.full(n, 6, np.int16), "fwd_pkts": np.full(n, 3, np.int64),
        "bwd_pkts": np.full(n, 2, np.int64), "fwd_bytes": np.full(n, 300, np.int64),
        "bwd_bytes": np.full(n, 200, np.int64), "f_bwd_rst_flags": np.zeros(n, np.float32),
    })
    df["t_end"] = df["t_start"] + pd.to_timedelta(df["duration_us"], unit="us")
    df["_atk"] = np.arange(n) % 2 == 0
    df["orig_id"] = np.arange(n)
    sc = Scenario(df[~df["_atk"]].drop(columns=["_atk", "orig_id"]), df[df["_atk"]],
                  "10.0.1.1", 80, 6, df["t_start"].min(), 600.0)
    for plan in inj.ADDITIVE:
        v = inj.plan_traffic(df, plan, sc)
        kept = v[v["orig_id"] >= 0]
        assert set(df["orig_id"]) <= set(kept["orig_id"]), plan
        assert v["fwd_bytes"].sum() >= df["fwd_bytes"].sum(), plan
