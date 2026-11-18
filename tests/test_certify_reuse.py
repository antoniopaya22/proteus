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


def test_reuse_within_the_service_limit_divides_connections_by_at_most_k():
    from proteus.core.certify import DEFAULT_REQUESTS, log_requests

    names = ["dsvc__flows__t600", "dsvc__flows__t600__x", "dhost__flows__t600",
             "spair__flows__t600", "dsvc__fbytes__t600"]
    cst = np.array([1, 1, 1, 1, 1])
    s = np.full(5, 0.4)
    X = np.array([[5.0, 3.0, 6.0, 4.0, 9.0], [5.0, 3.0, 6.0, 4.0, 9.0]])
    lk = log_requests(np.array([22, 80]))  # SSH: 6 attempts per connection; HTTP: 100
    assert np.allclose(lk, np.log([6.0, 100.0]))
    W = reuse_worst_case(X, names, cst, s, log_k=lk)
    T = worst_case_features(X, cst, s)
    assert np.allclose(W[:, 0], T[:, 0] - lk) and np.allclose(W[:, 1], T[:, 1] - lk)
    assert np.allclose(W[:, 3], T[:, 3] - lk)                       # pair: its service
    assert np.allclose(W[:, 2], T[:, 2] - np.log(DEFAULT_REQUESTS))  # host: any service
    assert np.allclose(W[:, 4], T[:, 4])
    # log1p(E / k) >= log1p(E) - log k: the shifted value is a lower bound of the evidence
    E = np.expm1(5.0)
    for k in (3.0, 6.0, 100.0):
        assert np.log1p(E / k) >= 5.0 - np.log(k)
