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
    assert h["conn"].iloc[0] == len(f) and h["pkts"].iloc[0] == f["fwd_pkts"].sum()  # all ports
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


def test_references_without_each_day_match_the_reference_of_the_other_days():
    rng = np.random.default_rng(5)
    mx = []
    for _ in range(6):
        keys = rng.choice(40, int(rng.integers(5, 30)), replace=False)
        mx.append(pd.Series(rng.integers(1, 8, len(keys)).astype(float), index=keys))
    for min_days in (1, 2, 3):
        fast = calibrate.references_without(mx, min_days)
        for i in range(len(mx)):
            slow = calibrate.reference(mx[:i] + mx[i + 1:], min_days)
            assert fast[i].sort_index().to_dict() == slow.sort_index().to_dict()


def test_causal_second_day_takes_its_levels_from_the_two_halves_of_the_first():
    first = _table({1: [100, 80, 150, 120], 2: [40, 50, 30, 45], 3: [0, 0, 60, 70]})
    first = first[first["conn"] > 0]  # entity 3 appears in the second half only
    days = {"a": first, "b": _table({1: [140, 400, 90, 90], 2: [70, 20, 20, 20]})}
    env = calibrate.causal(days, {"a": 4.0, "b": 4.0}, ("conn",), budget=0.0, min_days=1,
                           floors={"conn": 20.0})["b"]
    # scores of the second half against the first: 150/100, 120/100, 30/50, 45/50
    assert np.isclose(env.lam["conn"], 1.5)
    assert env.fallback["conn"] == 70.0  # entity 3 has no first half: 70 / floor 20, times 20
    assert env.ref["conn"].to_dict() == {1: 150.0, 2: 50.0, 3: 70.0}  # the whole first day
    assert env.alerts(days["b"], ("conn",))["conn"].tolist() == [False, True, False, False,
                                                                 False, False, False, False]


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
    # requests can share a segment, so packets hardly bind; connections do: 3.33 requests/s
    assert np.isclose(q[0], 20 / 6) and np.isclose(h.cost["pkts"], 600 * 18 / 1460)
    assert np.isclose(q[1], 10 / 6) and np.isnan(q[2])  # third: the benign traffic alerts
    wr, sp = np.ones(3, bool), np.zeros(3, np.int64)

    def held(a: int, n: int) -> float:
        return attacker.kept(q[a:a + n], wr[a:a + n], sp[a:a + n], {}, 0.0, False)

    assert np.isclose(held(0, 2), 10 / 6) and np.isnan(held(1, 2))
    assert np.isclose(attacker.best_start(3, 1, lambda a: held(a, 1)), 20 / 6)
    # a probe of a port the host already uses adds nothing: the whole threshold is room
    probes = attacker.harms(600.0)["probes"]
    assert attacker.quiet_harm(pd.DataFrame({"ports": [12.0]}), {"ports": 30.0}, probes)[0] == 30.0
    ssh = attacker.harms(600.0, tries_ssh=6)["guesses_ssh"]
    assert ssh.cost == {"conn": 100.0, "pkts": 300.0}  # six attempts and three packets a connection
    assert np.isnan(attacker.best_start(3, 5, lambda a: held(a, 5)))
    slots = attacker.harms(600.0)["slots"]
    assert attacker.quiet_harm(pd.DataFrame({"conc": [5.0], "pkts": [0.0]}),
                               {"conc": 30.0, "pkts": 1e9}, slots)[0] == 25.0


def test_coarsen_adds_up_the_windows_of_a_span():
    t = pd.DataFrame({"key": [1, 1, 1, 1, 2], "dst_ip": ["a"] * 4 + ["b"], "proto": 6,
                      "win": [0, 1, 2, 3, 5], "ports": [10.0, 20.0, 30.0, 40.0, 9.0],
                      "dirty": [False, True, False, False, False],
                      "attack": ["", "portscan", "", "", ""]})
    c = witness.coarsen(t, 3).set_index(["key", "win"])
    assert c["ports"].to_dict() == {(1, 0): 60.0, (1, 1): 40.0, (2, 1): 9.0}
    assert c["dirty"].to_dict() == {(1, 0): True, (1, 1): False, (2, 1): False}
    assert c.loc[(1, 0), "attack"] == "portscan" and "conn" not in c


def test_kept_against_two_scales_is_the_better_of_hiding_and_spending_the_room():
    T, F = True, False
    one = np.zeros(4, np.int64)
    q = np.full(4, 5.0)
    # a held rate: every window counts against the room of the span
    assert attacker.kept(q, np.array([T, T, T, T]), one, {0: 2.0}, 0.1, False) == 0.5
    # with little room, staying under the floor in the idle windows pays more
    assert attacker.kept(q, np.array([T, F, F, F]), one, {0: 0.4}, 0.3, False) == 0.3
    assert np.isclose(attacker.kept(q, np.array([T, F, F, F]), one, {0: 0.1}, 0.3, False), 0.1)
    # a total: the rate is free; hide in two idle windows and spend the room in the rest
    q = np.full(4, 4.0)
    assert attacker.kept(q, np.array([T, T, F, F]), one, {0: 5.0}, 1.0, True) == (2 + 5) / 4
    assert attacker.kept(q, np.array([T, T, F, F]), one, {0: 50.0}, 1.0, True) == 4.0
    # spans without a test on totals are bound by the single windows only
    two = np.array([0, 0, 1, 1])
    assert attacker.kept(np.array([2.0, 2.0, 3.0, 3.0]), np.ones(4, bool), two, {0: 1.0},
                         0.0, True) == (1 + 6) / 4
    assert attacker.kept(np.array([2.0, 1.0, 3.0]), np.ones(3, bool), one[:3], {}, 0.0, True) == 2.0
    # the victim's own traffic alerts: nothing to say
    assert np.isnan(attacker.kept(q, np.ones(4, bool), one, {0: np.nan}, 1.0, True))
    assert np.isnan(attacker.kept(np.array([1.0, np.nan]), np.ones(2, bool), one[:2], {}, 0.0, False))
    assert attacker.hidden_rate(attacker.harms(600.0)["guesses_ssh"], witness.FLOORS) == 0.2


def test_kept_agrees_with_trying_every_plan():
    """On random small cases: every choice of which idle windows to hide in (totals)
    and a fine grid of rates (held rate) find nothing better than the closed form."""
    from itertools import product

    rng = np.random.default_rng(3)
    for _ in range(200):
        n = int(rng.integers(2, 7))
        hidden = float(rng.uniform(0.1, 1.0))
        q = hidden + rng.uniform(0, 4, n)
        wr = rng.random(n) < 0.5
        sp = np.sort(rng.integers(0, 2, n))
        room = {int(s): float(rng.uniform(0, 8)) for s in np.unique(sp) if rng.random() < 0.8}
        best = 0.0
        for hide in product([False, True], repeat=n):
            if any(h and wr[i] for i, h in enumerate(hide)):
                continue
            tot = sum(hidden for h in hide if h)
            for s in np.unique(sp):
                cap = sum(q[i] for i in range(n) if sp[i] == s and not hide[i])
                tot += min(cap, room.get(int(s), np.inf))
            best = max(best, tot)
        assert np.isclose(attacker.kept(q, wr, sp, room, hidden, True), best / n)
        ok = [h for h in np.linspace(0, q.min(), 4001)
              if all(h * sum(1 for i in range(n) if sp[i] == s and (wr[i] or h > hidden)) <= r
                     for s, r in room.items())]
        held = attacker.kept(q, wr, sp, room, hidden, False)
        assert held >= max(ok) - 1e-9 and held <= max(ok) + q.min() / 4000 + 1e-9


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


def test_second_scale_bounds_long_slow_guessing(tmp_path, monkeypatch):
    """An SSH server with steady logins and one busy window a day. Guessing held just
    under the busy window's level passes the test on single windows all day; the test
    on the day's total leaves the attacker a fraction of it."""
    from proteus.evaluation import envelope_exp as ex

    monkeypatch.setattr(ex.h1, "DATA", tmp_path)
    monkeypatch.setattr(ex, "OUT", tmp_path / "out")
    (tmp_path / "net").mkdir()
    rng = np.random.default_rng(1)
    for i, day in enumerate(("d1", "d2", "d3", "d4")):
        rows = []
        for w in range(12):
            for ip, n in (("10.0.0.1", 30), ("10.0.0.2", 40)):
                n = int(n * rng.uniform(0.9, 1.1)) * (10 if w == 5 else 1)
                rows += [(86400 * i + 600 * w + int(s), 1, ip, 22, 12, 2000, "")
                         for s in rng.uniform(0, 600, n)]
        if day == "d4":
            rows += [(86400 * i + 600 * w + int(s), 1, "10.0.0.9", 22, 12, 2000, "bf_ssh")
                     for w in range(12) for s in rng.uniform(0, 600, 600)]
            # a packet flood on another host, spread over fifty ports
            rows += [(86400 * i + 600 * w + int(s), 1, "10.0.0.8", 5000 + j % 50, 100, 6000,
                      "ddos_loic_udp")
                     for w in range(3) for j, s in enumerate(rng.uniform(0, 600, 300))]
        _flows(rows).to_parquet(tmp_path / "net" / f"{day}.parquet", index=False)
    monkeypatch.setattr("sys.argv", ["x", "--test", "net", "--alarm-budget", "1", "--victims", "5",
                                     "--attack-windows", "2", "12", "--span", "12"])
    ex.main()
    out = tmp_path / "out" / "net__net__loo_b1"
    res = pd.read_csv(out / "residual.csv")
    assert set(res["detector"]) == {"envelope", "rules", "envelope2", "rules2"}
    assert set(res["windows"]) == {2, 12} and res["share_best"].dropna().between(0, 1).all()
    k = res[res["day"] == "d1"].groupby(["detector", "windows"])["kept_best"].mean()
    assert k[("envelope2", 12)] < 0.5 * k[("envelope", 12)]  # the day's total binds
    assert k[("envelope2", 2)] >= k[("envelope2", 12)]  # a shorter attack keeps a higher rate
    al = pd.read_csv(out / "alarms.csv")
    assert {"conn", "conn_c", "h_pkts", "h_ports_c"} <= set(al.columns) and "conc_c" not in al
    s = pd.read_csv(out / "summary.csv")
    assert len(s) == 8
    # the flood is bound on the victim hosts, whatever ports it uses: 50 packets/s recorded
    fl = res[res["attack"] == "ddos_loic_udp"]
    assert set(fl["victim"]) == {"10.0.0.1", "10.0.0.2"} and (fl["campaign"] == 50.0).all()
    assert "th_pkts" in fl and fl["share_best"].dropna().between(0, 1).all()
    dt = pd.read_csv(out / "detection.csv").set_index(["detector", "attack"])["share"]
    assert dt[("envelope", "ddos_loic_udp")] == 1.0  # each port stays small; the host does not


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
    monkeypatch.setattr(ex, "OUT", tmp_path / "out")
    monkeypatch.setattr("sys.argv", ["x", "--test", "ugr16", "--build-only"])
    ex.main()  # reports the size of the tables and stops before calibrating
    assert not (tmp_path / "out").exists()
