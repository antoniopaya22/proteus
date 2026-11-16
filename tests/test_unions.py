import numpy as np

from proteus.evaluation.unions import member, targets_of, union


def test_targets_members_and_union_of_alerts():
    al = {"proteus__local0.001": np.array([1, 0, 0, 0], bool), "proteus__local0.0001": np.array([1, 0, 0, 0], bool),
          "proteus__entity0.5": np.array([0, 0, 0, 0], bool), "proteus__side": np.array([0, 0, 0, 0], bool),
          "window_fidelity__local0.001": np.array([0, 1, 0, 0], bool),
          "window_fidelity__side": np.array([0, 1, 0, 0], bool)}
    assert targets_of(al) == [("entity", 0.5), ("local", 0.0001), ("local", 0.001)]
    assert member(al, "nope", "local", 0.001) is None
    a, side = member(al, "window_fidelity", "entity", 0.5)  # no budget: its laxer local alerts
    assert a.tolist() == [False, True, False, False] and side.tolist() == [False, True, False, False]
    alert, side = union([member(al, "proteus", "local", 0.001), member(al, "window_fidelity", "local", 0.001)])
    assert alert.tolist() == [True, True, False, False] and side.tolist() == [False, True, False, False]
