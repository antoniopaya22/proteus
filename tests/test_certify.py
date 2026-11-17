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


def test_slack_with_rescoring_timer():
    s = slack(["dsvc__flows__t600"], {"dsvc__flows__t600": "conserved"}, delta_s=120,
              timer_s=10)
    assert abs(s[0] - 250 / 600) < 1e-12



def test_the_packet_certified_detector_uses_no_payload_bytes_and_no_per_connection_counts():
    import numpy as np

    from proteus.evaluation import h1
    from proteus.evidence.features import build
    from test_operators import flows

    _, specs = build(flows(np.random.default_rng(0)), version="v3")
    cols, _ = h1.detectors({s.name: s.conservation for s in specs}, [])["proteus_cert_p"]
    counters = {c.split("__")[1] for c in cols}
    assert counters <= set(h1.PACKET_SAFE) and "fpkts" in counters
    assert all(float(c.split("__t")[1].split("__")[0]) >= 600 for c in cols)
