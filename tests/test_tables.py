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
