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
