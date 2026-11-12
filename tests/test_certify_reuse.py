import numpy as np

from proteus.core.certify import reuse_worst_case, worst_case_features


def test_reuse_worst_case_zeroes_per_connection_counters():
    names = ["dsvc__flows__t600", "dsvc__flows__t600__x", "dsvc__fpkts__t600",
             "dsvc__fbytes__t600", "dsvc__n_src__t600", "dsvc__flows__t600__b"]
    cst = np.array([1, 1, 1, 1, 1, -1])
    s = np.array([0.4, 0.4, 0.4, 0.4, 0.4, 0.0])
    X = np.array([[5.0, 3.0, 6.0, 9.0, 2.0, 2.0]])  # raw 5, baseline 2, excess 3
    W = reuse_worst_case(X, names, cst, s)
    T = worst_case_features(X, cst, s)
    assert W[0, 0] == 0.0  # flows: one connection can carry everything
    assert W[0, 1] == -2.0  # excess at raw 0: minus the baseline
    assert np.isclose(W[0, 2], T[0, 2] - np.log(5.0))
    assert W[0, 3] == T[0, 3] and W[0, 4] == T[0, 4]  # bytes and distinct: timing only
    assert W[0, 5] == X[0, 5]  # baseline untouched
    assert (W <= T + 1e-12).all()  # never above the timing worst case
