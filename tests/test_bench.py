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
