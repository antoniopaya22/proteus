import numpy as np
import pandas as pd

from proteus.evaluation.bench import alarm_score, damage_score, pareto, ssd


def test_ssd_between_mean_and_min():
    x = np.array([1.0, 1.0, 0.0])
    s = ssd(x, 3.0)
    assert x.min() < s < x.mean()
    assert np.isclose(ssd(x, 1e-6), x.mean(), atol=1e-4)
    assert ssd(x, 200.0) < 0.05
    # METIS's check: a table perfect except for one dimension at 0 must not beat one
    # at 0.5 everywhere.
    assert ssd([1.0, 1.0, 0.0], 3.0) < ssd([0.5, 0.5, 0.5], 3.0)


def test_alarm_and_damage_scores_are_anchored():
    assert alarm_score(0) == 1.0 and alarm_score(60) == 0.0 and alarm_score(1000) == 0.0
    assert 0 < alarm_score(2) < 1
    assert damage_score(1000, 5000) == 0.0  # passes above its real rate
    assert damage_score(1000, 1.0) == 1.0  # must drop to the lowest rate tried
    assert 0 < damage_score(1000, 100) < damage_score(1000, 10) < 1


def test_pareto_front():
    s = pd.DataFrame({"a": [1, 0.5, 0.4], "b": [0.2, 0.9, 0.1]}, index=["x", "y", "z"])
    assert pareto(s).to_dict() == {"x": True, "y": True, "z": False}


def test_robustness_of_a_system_comes_from_the_ladder_and_certified_alerts_get_both_tags(tmp_path):
    import pandas as pd

    from proteus.evaluation.bench import damage_score, robustness

    rows = [{"day": "wed", "attack": "dos_hulk", "detector": m, "real_flows_per_h": 36000.0,
             "adaptive_flows_per_h": v, "certified_flows_per_h": c}
            for m, v, c in (("proteus", 3600.0, float("nan")), ("proteus_cert_r", 360.0, 720.0))]
    csv = tmp_path / "adaptive_0.001_g30.csv"
    pd.DataFrame(rows).to_csv(csv, index=False)
    ladder = [{"day": "wed", "attack": "dos_hulk", "detector": m, "plan": "reuse",
               "flows_per_h": rate, "detected": rate > quiet}
              for m, quiet in (("proteus", 3600.0), ("proteus_cert_r", 360.0))
              for rate in (36.0, 360.0, 3600.0)]
    pd.DataFrame(ladder).to_csv(tmp_path / "adaptive_ladder_0.001_g30.csv", index=False)
    r = robustness([csv])
    # The system is quiet only where both members are: 360 flows/h.
    assert abs(r.loc["proteus_pcr", "robustness"] - damage_score(36000.0, 360.0)) < 1e-9
    assert r.loc["proteus_pcr", "attacks"] == 1 and "proteus_sys_r" not in r.index
    cert = damage_score(36000.0, 720.0)
    assert abs(r.loc["proteus_cert_r@cert", "robustness"] - cert) < 1e-9
    assert abs(r.loc["proteus_cert_r@certr", "robustness"] - cert) < 1e-9
