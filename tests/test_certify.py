import numpy as np
import pytest

from proteus.core.certify import slack, worst_case_features


def test_slack_per_time_constant():
    names = ["dsvc__flows__t10", "dsvc__flows__t600__x", "dsvc__flows__t600__b"]
    cons = {names[0]: "conserved", names[1]: "conserved", names[2]: "baseline"}
    s = slack(names, cons, delta_s=120)
    np.testing.assert_allclose(s, [24.0, 0.4, 0.0])


def test_slack_requires_time_constant():
    with pytest.raises(ValueError):
        slack(["flow__duration"], {"flow__duration": "conserved"}, 120)


def test_worst_case_moves_against_evidence():
    X = np.array([[1.0, 1.0, 1.0]])
    cst = np.array([1, -1, 0])
    s = np.array([0.5, 0.5, 0.5])
    np.testing.assert_allclose(worst_case_features(X, cst, s), [[0.5, 1.5, 1.0]])
