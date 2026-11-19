import numpy as np
import pandas as pd

from proteus.envelope import attacker, calibrate, witness

T0 = pd.Timestamp("2026-01-05 10:00:00")


def _flows(rows):
    """rows: (start s, duration s, dst_ip, dst_port, fwd_pkts, fwd_bytes, attack or '')."""
    return pd.DataFrame({
        "t_start": [T0 + pd.Timedelta(seconds=r[0]) for r in rows],
        "t_end": [T0 + pd.Timedelta(seconds=r[0] + r[1]) for r in rows],
        "dst_ip": [r[2] for r in rows], "dst_port": [r[3] for r in rows], "proto": 6,
        "fwd_pkts": [r[4] for r in rows], "fwd_bytes": [r[5] for r in rows],
        "is_attack": [bool(r[6]) for r in rows], "attack": [r[6] or "benign" for r in rows],
    })


LOW = {"conc": 1.0, "conn": 1.0, "pkts": 1.0, "bytes": 1.0, "ports": 1.0}


def test_peak_concurrency_counts_overlaps_in_every_window_a_record_covers():
    us = 10**6
    key = np.array([1, 1, 1, 2])
    ts = np.array([0, 10, 590, 0]) * us
    te = np.array([100, 20, 700, 0]) * us  # the third record runs into the next window
    p = witness.peak_concurrency(key, ts, te, 600 * us).set_index(["key", "win"])["conc"]
    assert p[(1, 0)] == 2 and p[(1, 1)] == 1 and p[(2, 0)] == 1  # zero-length record counts once
    kept = witness.peak_concurrency(key, ts, te, 600 * us, keep=(1, 2))
    assert kept[["key", "win", "conc"]].to_numpy().tolist() == [[1, 1, 1.0]]


def test_service_windows_totals_and_attack_marks():
    f = _flows([(0, 5, "10.0.0.1", 80, 3, 300, ""), (1, 5, "10.0.0.1", 80, 2, 100, ""),
                (2, 700, "10.0.0.1", 80, 1, 50, "dos_slowloris"), (0, 1, "10.0.0.2", 22, 4, 40, "")])
    t = witness.service_windows(f, floors=LOW)
    w0 = int(T0.value // 1000 // (600 * 10**6))
    a = t[(t["dst_ip"] == "10.0.0.1") & (t["win"] == w0)].iloc[0]
    assert (a["conn"], a["pkts"], a["bytes"], a["conc"]) == (3, 6, 450, 3)
    assert a["dirty"] and a["attack"] == "dos_slowloris"
    b = t[(t["dst_ip"] == "10.0.0.1") & (t["win"] == w0 + 1)].iloc[0]  # only the slot held
    assert (b["conn"], b["conc"], bool(b["dirty"])) == (0, 1, True)
    c = t[t["dst_ip"] == "10.0.0.2"].iloc[0]
    assert not c["dirty"] and c["attack"] == "" and c["dst_port"] == 22
    assert len(witness.service_windows(f)) == 0  # everything under the default floors


def test_keys_are_stable_across_tables_and_host_windows_count_ports():
    f = _flows([(i, 1, "10.0.0.9", 1000 + i, 1, 1, "portscan") for i in range(30)]
               + [(0, 1, "10.0.0.9", 80, 1, 1, "")])
    h = witness.host_windows(f)
    assert len(h) == 1 and h["ports"].iloc[0] == 31 and h["attack"].iloc[0] == "portscan"
    g = f.iloc[::-1].reset_index(drop=True).astype({"dst_ip": "category"})
    assert set(witness.entity_key(f, witness.SERVICE)) == set(witness.entity_key(g, witness.SERVICE))


def _table(day_vals, dirty=()):
    """day_vals: {key: [values per window]} -> a witness table with one witness ``conn``."""
    rows = [{"key": k, "win": i, "conn": float(v), "dirty": (k, i) in dirty}
            for k, vs in day_vals.items() for i, v in enumerate(vs)]
    return pd.DataFrame(rows)


def test_reference_needs_history_and_fit_lambda_meets_the_budget():
    mx = [pd.Series({1: 50.0, 2: 30.0}), pd.Series({1: 80.0}), pd.Series({1: 60.0, 3: 5.0})]
    r = calibrate.reference(mx, min_days=2)
    assert r.to_dict() == {1: 80.0}
    pooled = np.array([0.2, 0.9, 1.5, 3.0, 0.4, 2.0])
    lam = calibrate.fit_lambda(pooled, hours=4.0, budget=0.5)  # two alarms allowed
    assert lam == 1.5 and (pooled > lam).sum() == 2
    assert calibrate.fit_lambda(pooled, hours=100.0, budget=0.5) == 0.0


def test_loo_envelope_scales_with_the_entity_and_skips_labelled_attacks():
    days = {"a": _table({1: [100, 120, 110], 2: [30, 25, 28]}),
            "b": _table({1: [105, 900, 100], 2: [31, 22, 500]}, dirty={(1, 1)}),
            "c": _table({1: [90, 130, 95], 2: [27, 33, 26], 3: [400, 10, 10]})}
    hours = {d: 0.5 for d in days}
    env = calibrate.loo(days, hours, ("conn",), budget=1.0, min_days=2, floors={"conn": 20.0})
    e = env["c"]  # reference from a and b, without b's labelled attack window
    assert e.ref["conn"].to_dict() == {1: 120.0, 2: 500.0}
    th = e.thresholds("conn", np.array([1, 2, 3]))
    assert th[0] == max(e.lam["conn"] * 120.0, 20.0)
    assert e.monitored("conn", np.array([1, 2, 3])).tolist() == [True, True, False]
    assert th[2] == e.fallback["conn"] >= 20.0  # entity 3, no history: the network's level
    al = e.alerts(days["c"], ("conn",))["conn"].to_numpy()
    assert al[(days["c"]["key"] == 3).to_numpy()].tolist() == [True, False, False]
    flat = calibrate.loo(days, hours, ("conn",), budget=1.0, per_entity=False,
                         floors={"conn": 20.0})["c"]
    assert len(set(flat.thresholds("conn", np.array([1, 2, 3])))) == 1  # one rule for all
    assert not flat.monitored("conn", np.array([1, 2, 3])).any()


def test_causal_envelope_uses_only_the_past_and_the_analysts_verdicts():
    days = {"a": _table({1: [100, 120, 110]}), "b": _table({1: [105, 900, 100]}, dirty={(1, 1)}),
            "c": _table({1: [90, 130, 95]}), "d": _table({1: [95, 5000, 99]}, dirty={(1, 1)})}
    hours = {d: 0.5 for d in days}
    env = calibrate.causal(days, hours, ("conn",), budget=0.0, min_days=1, floors={"conn": 20.0})
    assert "a" not in env and env["b"].ref["conn"].to_dict() == {1: 120.0}
    # the attack of day b alerted (900 > 120), so the analyst's verdict keeps it out
    assert env["c"].ref["conn"].to_dict() == {1: 120.0}
    assert env["d"].ref["conn"].to_dict() == {1: 130.0}
    assert env["d"].alerts(days["d"], ("conn",))["conn"].tolist() == [False, True, False]


def test_quiet_harm_is_the_tightest_witness_and_ignores_noisy_windows():
    h = attacker.harms(600.0, reuse=100, min_request=18.0)["requests"]
    bg = pd.DataFrame({"pkts": [0.0, 400.0, 2000.0], "bytes": [0.0, 0.0, 0.0],
                       "conn": [0.0, 10.0, 0.0]})
    th = {"pkts": 1000.0, "bytes": 1e9, "conn": 20.0}
    q = attacker.quiet_harm(bg, th, h)
    assert np.isclose(q[0], min(1000 / 600, 20 / 6))  # packets bind: 1.67 requests/s
    assert np.isclose(q[1], min(600 / 600, 10 / 6)) and np.isnan(q[2])  # third: benign alert
    assert np.isclose(attacker.sustained(q, 2), 1.0) and np.isclose(attacker.sustained(q, 1), 1000 / 600)
    assert np.isnan(attacker.sustained(q, 2, start=1)) and np.isnan(attacker.sustained(q, 5))
    slots = attacker.harms(600.0)["slots"]
    assert attacker.quiet_harm(pd.DataFrame({"conc": [5.0], "pkts": [0.0]}),
                               {"conc": 30.0, "pkts": 1e9}, slots)[0] == 25.0


def test_campaign_harm_in_the_units_of_the_bound():
    hs = attacker.harms(600.0)
    w = pd.DataFrame({"conn": [0.0, 6000.0, 12000.0, 9000.0], "conc": [0.0, 250.0, 300.0, 280.0]})
    assert attacker.campaign_harm(w, hs["requests"]) == 15.0  # median 9000 connections / 600 s
    assert attacker.campaign_harm(w, hs["slots"]) == 280.0
    assert set(attacker.KIND.values()) <= set(hs)


def test_experiment_end_to_end_on_a_small_network(tmp_path, monkeypatch):
    """Three days of two web servers (one busy, one small) and a flood on the last day:
    the envelope bounds the attacker by each server's own level, the single rule by
    the busy one's."""
    from proteus.evaluation import envelope_exp as ex

    monkeypatch.setattr(ex.h1, "DATA", tmp_path)
    monkeypatch.setattr(ex, "OUT", tmp_path / "out")
    (tmp_path / "net").mkdir()
    rng = np.random.default_rng(0)
    for i, day in enumerate(("d1", "d2", "d3")):
        rows = []
        for w in range(6):
            for ip, n in (("10.0.0.1", 3000), ("10.0.0.2", 60)):
                n = int(n * rng.uniform(0.8, 1.2))
                rows += [(86400 * i + 600 * w + int(s), 1, ip, 80, 5, 500, "")
                         for s in rng.uniform(0, 600, n)]
        if day == "d3":
            rows += [(86400 * i + 600 * 2 + int(s), 1, "10.0.0.3", 80, 3, 60, "dos_hulk")
                     for s in rng.uniform(0, 600, 6000)]
        _flows(rows).to_parquet(tmp_path / "net" / f"{day}.parquet", index=False)
    monkeypatch.setattr("sys.argv", ["x", "--test", "net", "--alarm-budget", "1",
                                     "--victims", "5", "--attack-windows", "2"])
    ex.main()
    out = tmp_path / "out" / "net__net__loo_b1"
    res = pd.read_csv(out / "residual.csv")
    assert set(res["victim"]) == {"10.0.0.1", "10.0.0.2"} and (res["campaign"] == 10.0).all()
    k = res.set_index(["day", "victim", "detector"])["kept_best"]
    assert k[("d3", "10.0.0.2", "envelope")] < 0.2 * k[("d3", "10.0.0.2", "rules")]
    dt = pd.read_csv(out / "detection.csv").set_index(["detector", "attack"])["share"]
    assert dt[("envelope", "dos_hulk")] == 1.0  # a flood on a server never seen before
    s = pd.read_csv(out / "summary.csv").set_index("detector")
    assert s.loc["envelope", "mean_best"] < s.loc["rules", "mean_best"]


def test_ugr16_weekly_files_are_read_by_the_hour_into_one_table_per_day(tmp_path, monkeypatch):
    from proteus.evaluation import envelope_exp as ex

    monkeypatch.setattr(ex.h1, "DATA", tmp_path)
    t0 = pd.Timestamp("2016-07-28 22:00:00").timestamp()
    rng = np.random.default_rng(1)
    n = 4000  # one server, four hours across midnight, 1000 records an hour
    ts = t0 + np.sort(rng.uniform(0, 4 * 3600, n))
    raw = pd.DataFrame({
        "ts_start": ts, "ts_end": ts + 2.0, "src_ip": "42.219.1.1", "dst_ip": "42.219.153.7",
        "src_port": rng.integers(1024, 60000, n), "dst_port": 80, "l4_proto": 6,
        "duration": 2.0, "packets": 4, "bytes": 400,
        "label_binary": "background", "label_attack": ""})
    raw.loc[::2].to_parquet(tmp_path / "w1.parquet", index=False)
    raw.loc[1::2].to_parquet(tmp_path / "w2.parquet", index=False)
    ex.build_from_raw([tmp_path / "w1.parquet", tmp_path / "w2.parquet"], 600.0)
    svc, host, hours = ex.load("ugr16", 600.0)
    assert list(svc) == list(host) == ["2016-07-28", "2016-07-29"]
    assert hours == {"2016-07-28": 2.0, "2016-07-29": 2.0}
    both = pd.concat(svc.values())
    assert both["conn"].sum() == n and both["pkts"].sum() == 4 * n and len(both) == 24
    assert not both["dirty"].any() and both["win"].is_unique
    direct = witness.service_windows(pd.DataFrame({
        "t_start": pd.to_datetime(raw["ts_start"], unit="s"),
        "t_end": pd.to_datetime(raw["ts_end"], unit="s"),
        "dst_ip": raw["dst_ip"], "dst_port": 80, "proto": 6, "fwd_pkts": 4, "fwd_bytes": 400}))
    m = both.merge(direct, on=["key", "win"], suffixes=("", "_d"))
    assert len(m) == 24 and (m["conc"] == m["conc_d"]).all()  # peaks agree across chunk edges
    written = tmp_path / "ugr16" / "witness_w600" / "2016-07-28.svc.parquet"
    before = written.stat().st_mtime_ns
    ex.build_from_raw([tmp_path / "w1.parquet", tmp_path / "w2.parquet"], 600.0)  # nothing redone
    assert written.stat().st_mtime_ns == before
