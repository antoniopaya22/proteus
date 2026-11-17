import numpy as np

from proteus.evaluation.tables import bootstrap_mean, wilson


def test_wilson_interval_contains_proportion_and_is_bounded():
    lo, hi = wilson(6, 6)
    assert 0.5 < lo < 1.0 and np.isclose(hi, 1.0)
    lo, hi = wilson(0, 3)
    assert lo == 0.0 and 0.4 < hi < 0.8
    lo, hi = wilson(50, 100)
    assert lo < 0.5 < hi


def test_bootstrap_mean_interval():
    lo, hi = bootstrap_mean(np.array([1.0, 2.0, 3.0, 4.0, 5.0]))
    assert lo < 3.0 < hi
    assert np.isnan(bootstrap_mean(np.array([1.0]))[0])


def test_curves_keep_the_best_detection_at_or_below_each_alarm_rate(tmp_path):
    import pandas as pd

    from proteus.evaluation.tables import curve_points, curves_figure

    run = tmp_path / "csecicids2018__cicids2017__loo_labels__r2"
    run.mkdir()
    rows, fa = [], []
    for thr, kind, det, eah in ((1e-3, "local", 2, 3.0), (1e-4, "local", 1, 0.5),
                                (1.0, "entity", 2, 1.0), (1.0, "local+ent", 0, 0.1)):
        rows.append({"model": "proteus", "target_fpr": thr, "threshold": kind,
                     "attack": "dos_hulk", "campaigns": 2, "detected": det,
                     "detected_strict": det, "flow_recall": 0.5, "median_ttd_s": 1.0})
        fa.append({"model": "proteus", "target_fpr": thr, "threshold": kind,
                   "alarms_per_hour": eah * 4, "entity_alarms_per_hour": eah})
    pd.DataFrame(rows).to_csv(run / "summary.csv", index=False)
    pd.DataFrame(fa).to_csv(run / "false_alarms.csv", index=False)
    pts = curve_points([run])
    assert len(pts) == 3  # the alert-rule variant is left out
    tex = curves_figure(pts)
    assert "(0.5,1) (1,2) (3,2)" in tex and r"\sysname" in tex


def test_curve_points_tell_the_two_directions_and_the_classic_runs_apart(tmp_path):
    import pandas as pd

    from proteus.evaluation.tables import curve_points

    names = {"csecicids2018__cicids2017__loo_labels__r2": "csecicids2018__cicids2017",
             "cicids2017__csecicids2018__loo_labels__r2b": "cicids2017__csecicids2018",
             "classic__cicids2017__r2": "csecicids2018__cicids2017",
             "classic__csecicids2018__r2": "cicids2017__csecicids2018"}
    runs = []
    for i, name in enumerate(names):
        run = tmp_path / name
        run.mkdir()
        pd.DataFrame([{"model": f"m{i}", "target_fpr": 1e-3, "threshold": "local",
                       "attack": "dos_hulk", "campaigns": 1, "detected": 1,
                       "flow_recall": 0.5}]).to_csv(run / "summary.csv", index=False)
        pd.DataFrame([{"model": f"m{i}", "target_fpr": 1e-3, "threshold": "local",
                       "alarms_per_hour": 2.0, "entity_alarms_per_hour": 1.0}]
                     ).to_csv(run / "false_alarms.csv", index=False)
        runs.append(run)
    pts = curve_points(runs).set_index("model")["direction"]
    assert pts.to_dict() == {f"m{i}": d for i, d in enumerate(names.values())}


def test_curves_figure_restricts_detectors_and_rejects_unknown_ones():
    import pandas as pd
    import pytest

    from proteus.evaluation.tables import curves_figure

    pts = pd.DataFrame([{"direction": "csecicids2018__cicids2017", "model": m,
                         "detected": 1, "campaigns": 2, "entity_alarms_per_hour": 1.0}
                        for m in ("proteus", "rate_rules_local")])
    tex = curves_figure(pts, detectors=["rate_rules_local", "kitnet_local"])
    assert "rate thresholds" in tex and r"\sysname" not in tex
    assert r"\addlegendimage" in tex and "KitNET" in tex  # absent here, still in the legend
    with pytest.raises(ValueError):
        curves_figure(pts, detectors=["nope"])


def test_query_table_takes_the_best_of_the_free_and_costly_searches(tmp_path):
    import pandas as pd

    from proteus.evaluation.tables import query_table

    run = tmp_path / "csecicids2018__cicids2017__loo_labels__r2"
    run.mkdir()
    rows = []
    for target, free, costly, capped in (("proteus", 2000.0, 9000.0, False),
                                         ("proteus_sys_r", 300.0, 200.0, False),
                                         ("rate_rules_sel", 50000.0, 50000.0, True)):
        for c, v in ((False, free), (True, costly)):
            rows.append({"day": "wednesday", "attack": "dos_hulk", "target": target, "costly": c,
                         "real_flows_per_h": 5000.0, "query_flows_per_h": v, "queries": 150,
                         "capped": capped and not c, "rmax_flows_per_h": 720000.0})
    path = run / "query_attack_0.001_b150.csv"
    pd.DataFrame(rows).to_csv(path, index=False)
    tex = query_table([path])
    line = next(ln for ln in tex.splitlines() if ln.startswith("DoS Hulk"))
    cells = [c.strip() for c in line.rstrip("\\").split("&")]
    assert cells[1] == "5.0k"
    assert cells[2] == r"\textbf{9.0k}$^s$"      # passes at its real rate, only with sources
    assert cells[3] == "300"                       # the costly search found less: the free one counts
    assert cells[4] == "--" and cells[5] == "--"   # Cert.-R and Rules were not attacked
    assert cells[6] == r"\textbf{50k}$^c$"
    assert r"2018$\to$2017" in tex


def test_ladder_damage_of_a_union_needs_every_member_quiet_on_the_same_plan():
    import pandas as pd

    from proteus.evaluation.tables import ladder_damage

    rows = []
    quiet = {("a", "plain"): {10, 100}, ("a", "reuse"): {10, 100, 1000}, ("a", "spread"): {10, 100, 1000, 10000},
             ("b", "plain"): {10, 100, 1000}, ("b", "reuse"): {10}, ("b", "spread"): {10, 100, 1000, 10000}}
    for (det, plan), ok in quiet.items():
        for r in (10, 100, 1000, 10000):
            rows.append({"day": "wed", "attack": "dos_hulk", "detector": det, "plan": plan,
                         "flows_per_h": float(r), "detected": r not in ok})
    L = pd.DataFrame(rows)
    assert ladder_damage(L, ["a"]).iloc[0] == 1000        # reuse passes detector a
    assert ladder_damage(L, ["b"]).iloc[0] == 1000        # the plain attack passes detector b
    assert ladder_damage(L, ["a", "b"]).iloc[0] == 100    # no single plan passes both above 100
    assert ladder_damage(L, ["a", "b"], costly=True).iloc[0] == 10000
    assert ladder_damage(L[L["flows_per_h"] > 5000], ["a", "b"]).iloc[0] == 0  # nothing quiet: 0


def test_ablation_table_reports_alarms_per_alerted_entity(tmp_path):
    import pandas as pd

    from proteus.evaluation.tables import ablation_table

    run = tmp_path / "csecicids2018__cicids2017__loo_labels__r2_ablation"
    run.mkdir()
    rows, fa = [], []
    for model, hulk, ent in (("proteus", 1, 1.75), ("proteus-3", 0, 1.82)):
        for attack, det in (("dos_hulk", hulk), ("web_xss", 0)):
            rows.append({"model": model, "threshold": "local", "target_fpr": 1e-3, "day": "wed",
                         "attack": attack, "flows": 100, "detected": det, "alarms_per_hour": 60.0})
        fa.append({"model": model, "threshold": "local", "target_fpr": 1e-3,
                   "alarms_per_hour": 60.0, "entity_alarms_per_hour": ent})
    pd.DataFrame(rows).to_csv(run / "campaigns.csv", index=False)
    pd.DataFrame(fa).to_csv(run / "false_alarms.csv", index=False)
    table = ablation_table([run], 1e-3)
    assert r"All sub-cores & 1.00 & 0.00 & 1.75 \\" in table
    assert r"without raw destination & 0.00 & 0.00 & 1.82 \\" in table and "60.0" not in table


def test_curves_name_the_fast_member_next_to_the_system():
    import pandas as pd

    from proteus.evaluation.tables import curves_figure

    pts = pd.DataFrame([
        {"direction": "csecicids2018__cicids2017", "model": m, "entity_alarms_per_hour": 1.0,
         "detected": 3, "campaigns": 11} for m in ("proteus", "proteus_pcr")])
    fig = curves_figure(pts, detectors=["proteus_pcr", "proteus"])
    assert r"\addlegendentry{\sysname}" in fig and r"\addlegendentry{\sysname-fast}" in fig
    assert r"\addlegendentry{\sysname}" in curves_figure(pts, detectors=["proteus"])


def test_adaptive_table_reads_the_system_from_the_ladder(tmp_path):
    import pandas as pd

    from proteus.evaluation.tables import ADAPTIVE_PAPER, adaptive_table

    run = tmp_path / "csecicids2018__cicids2017__loo_labels__r2"
    run.mkdir()
    rows = [{"day": "wed", "attack": "dos_hulk", "detector": m, "real_flows_per_h": 5000.0,
             "adaptive_flows_per_h": v, "certified_flows_per_h": v, "best_plan": "plain",
             "rmax_flows_per_h": 720000.0} for m, v in (("proteus", 4000.0), ("proteus_cert_r", 900.0))]
    pd.DataFrame(rows).to_csv(run / "adaptive_0.001_g30.csv", index=False)
    ladder = [{"day": "wed", "attack": "dos_hulk", "detector": m, "plan": plan,
               "flows_per_h": rate, "detected": rate > quiet}
              for plan, limits in (("plain", {"proteus": 300.0, "proteus_cert_r": 300.0}),
                                   ("reuse", {"proteus": 4000.0, "proteus_cert_r": 900.0}))
              for m, quiet in limits.items() for rate in (300.0, 900.0, 4000.0)]
    pd.DataFrame(ladder).to_csv(run / "adaptive_ladder_0.001_g30.csv", index=False)
    table = adaptive_table([run / "adaptive_0.001_g30.csv"], ADAPTIVE_PAPER)
    row = next(line for line in table.splitlines() if line.startswith("DoS Hulk"))
    # The system passes where both members are quiet with the same plan: 900, by reuse;
    # no plan with minimal requests was tried, so that column is the same.
    cells = row.split(" & ")
    assert cells[2] == "900$^a$" and cells[3] == "900$^a$" and cells[4] == "4.0k"
    assert cells[7] == "--"  # a detector that is not in the run


def test_budget_table_counts_campaigns_and_takes_a_detector_from_the_first_run_that_has_it(tmp_path):
    import pandas as pd

    from proteus.evaluation.tables import budget_table

    def run(name, models):
        d = tmp_path / f"csecicids2018__cicids2017__loo_labels__{name}"
        d.mkdir()
        s = [{"model": m, "threshold": "entity", "target_fpr": 0.5, "attack": a, "detected_strict": k}
             for m, (vol, other, _) in models.items() for a, k in (("dos_hulk", vol), ("web_xss", other))]
        fa = [{"model": m, "threshold": "entity", "target_fpr": 0.5, "entity_alarms_per_hour": e}
              for m, (_, _, e) in models.items()]
        pd.DataFrame(s).to_csv(d / "summary.csv", index=False)
        pd.DataFrame(fa).to_csv(d / "false_alarms.csv", index=False)
        return d

    first = run("r2_pcr", {"proteus_pcr": (3, 1, 1.35), "proteus": (3, 0, 1.01)})
    more = run("r2c", {"proteus": (9, 9, 9.0), "rate_rules_local": (2, 1, 5.28)})
    table = budget_table([first], [more])
    row = next(line for line in table.splitlines() if line.startswith("Budget 0.5"))
    cells = [c.strip() for c in row.rstrip("\\").split("&")]
    assert cells[1:3] == ["3+1 (1.35)", "3+0 (1.01)"]  # the first run wins for proteus
    assert cells[3] == "--" and cells[5] == "2+1 (5.28)"
    assert "Budget 1 & -- & --" in table


def test_ladder_damage_leaves_minimal_requests_out_unless_asked():
    import pandas as pd

    from proteus.evaluation.tables import ladder_damage

    ladder = pd.DataFrame([
        {"day": "wed", "attack": "dos_hulk", "detector": "proteus", "plan": plan,
         "flows_per_h": rate, "detected": rate > quiet}
        for plan, quiet in (("reuse", 300.0), ("shrink+reuse", 4000.0), ("spread", 900.0))
        for rate in (300.0, 900.0, 4000.0)])
    key = ("wed", "dos_hulk")
    assert ladder_damage(ladder, ["proteus"])[key] == 300.0
    assert ladder_damage(ladder, ["proteus"], shrink=True)[key] == 4000.0
    assert ladder_damage(ladder, ["proteus"], costly=True)[key] == 900.0


def test_intervals_at_an_alarm_budget_use_strict_detection_and_alarms_per_entity(tmp_path):
    import pandas as pd

    from proteus.evaluation.tables import intervals_table, summary_table

    run = tmp_path / "csecicids2018__cicids2017__loo_labels__r2_pcr"
    run.mkdir()
    rows = [{"model": "proteus_pcr", "threshold": kind, "target_fpr": t, "day": day, "attack": a,
             "flows": 10, "detected": 1, "detected_strict": k, "alarms_per_hour": 50.0,
             "entity_alarms_per_hour": e}
            for kind, t, shift in (("entity", 0.5, 0.0), ("local", 1e-3, 9.0))
            for day, a, k, e in (("mon", "(none)", 0, 1.0 + shift), ("tue", "dos_hulk", 1, 2.0 + shift),
                                 ("wed", "portscan", 0, 3.0 + shift))]
    pd.DataFrame(rows).to_csv(run / "campaigns.csv", index=False)
    s = summary_table([run], [], 0.5, kind="entity")
    r = s.iloc[0]
    assert (r["volumetric_detected"], r["volumetric_campaigns"], r["days"]) == (1, 2, 3)
    assert abs(r["entity_alarms_per_hour"] - 2.0) < 1e-9 and r["entity_alarms_lo"] <= 2.0 <= r["entity_alarms_hi"]
    table = intervals_table(s, [("proteus_pcr", "Proteus")])
    assert "Proteus & 1/2 & [" in table and "& 2.00 & [" in table


def test_minimal_requests_are_ignored_for_udp_floods():
    import pandas as pd

    from proteus.evaluation.tables import ladder_damage

    ladder = pd.DataFrame([
        {"day": "tue", "attack": "ddos_loic_udp", "detector": "proteus", "plan": plan,
         "flows_per_h": rate, "detected": rate > quiet}
        for plan, quiet in (("plain", 40.0), ("shrink", 4000.0)) for rate in (40.0, 4000.0)])
    assert ladder_damage(ladder, ["proteus"], shrink=True)[("tue", "ddos_loic_udp")] == 40.0


def test_frontier_at_the_budget_takes_the_plain_plan_of_the_system_and_the_certified_damage(tmp_path):
    import pandas as pd

    from proteus.evaluation.tables import frontier_budget_table

    run = tmp_path / "csecicids2018__cicids2017__loo_labels__r2"
    run.mkdir()
    rows = [{"day": "wed", "attack": a, "detector": m, "real_flows_per_h": 5000.0,
             "certified_flows_per_h": c, "rmax_flows_per_h": 720000.0}
            for a, c in (("dos_hulk", 1000.0), ("ddos_loic_udp", 0.0))
            for m in ("proteus", "proteus_cert_r")]
    pd.DataFrame(rows).to_csv(run / "adaptive_b0.5_g30.csv", index=False)
    ladder = [{"day": "wed", "attack": a, "detector": m, "plan": plan, "flows_per_h": rate,
               "detected": rate > quiet[m] if a == "dos_hulk" else True}
              for a in ("dos_hulk", "ddos_loic_udp")
              for plan, quiet in (("plain", {"proteus": 900.0, "proteus_cert_r": 300.0}),
                                  ("reuse", {"proteus": 4000.0, "proteus_cert_r": 4000.0}))
              for m in quiet for rate in (4.0, 300.0, 900.0, 4000.0)]
    pd.DataFrame(ladder).to_csv(run / "adaptive_ladder_b0.5_g30.csv", index=False)
    lines = frontier_budget_table([run / "adaptive_b0.5_g30.csv"]).splitlines()
    hulk = next(x for x in lines if x.startswith("DoS Hulk")).rstrip(" \\").split(" & ")
    # Plain: both members quiet with the plain plan, so 300 (reuse does not count); 5000/300.
    assert hulk[2:] == ["300", "17", "1.0k", "5.0"]
    udp = next(x for x in lines if x.startswith("DDoS LOIC-UDP")).rstrip(" \\").split(" & ")
    assert udp[2] == "$<$4" and udp[4] == "$<$4"  # alerted at every rate of the grid
