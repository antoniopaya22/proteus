import numpy as np
import pytest


def test_decayed_counts_decay_and_refuse_events_out_of_order():
    from proteus.evaluation.feedback import decayed_counts

    src = np.array(["a", "a", "b", "a"])
    t = np.array([0.0, 60.0, 61.0, 6000.0])
    c = decayed_counts(src, t, tau=60.0)
    assert c[0] == 1.0 and np.isclose(c[1], 1 + np.exp(-1.0)) and c[2] == 1.0
    assert c[3] < 1.01                                   # after 99 minutes the counter is back to ~1
    with pytest.raises(ValueError):
        decayed_counts(src, t[::-1], tau=60.0)
