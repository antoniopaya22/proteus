import numpy as np

from proteus.baselines.smoothing import Smoothed, lower_bound


def test_radius_matches_linear_decision_boundary():
    # Base: alert when x0 >= 0. Exact smoothed radius of a point at x0 = d is d / sigma.
    sm = Smoothed(lambda Z: Z[:, 0] >= 0, sigma=np.array([0.5, 2.0]), n=4000, alpha=0.001)
    X = np.array([[0.5, 0.0], [1.0, 3.0], [-1.0, 0.0]])
    alert, r = sm.certify(X)
    assert alert.tolist() == [True, True, False] and r[2] == 0
    assert 0.7 < r[0] <= 1.0 and 1.5 < r[1] <= 2.0  # lower bounds of 1.0 and 2.0
    # Distances are measured in units of sigma: feature 1 is cheap to move.
    assert np.allclose(sm.distance(X[:1], X[:1] + [0.5, 2.0]), np.sqrt(2))


def test_lower_bound_is_conservative():
    lb = lower_bound(np.array([0, 100, 200]), 200)
    assert lb[0] == 0 and lb[1] < 0.5 and 0.95 < lb[2] < 1
