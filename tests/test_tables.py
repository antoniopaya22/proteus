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
