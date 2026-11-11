import numpy as np

from proteus.evaluation.h1 import entity_threshold


def test_budget_counts_entity_minutes_not_flows():
    # day 1: host 1 has 100 high-scoring flows in one minute (one alarm); host 2 one flow
    sc = np.r_[np.full(100, 0.99), 0.95, 0.5]
    key = np.r_[np.full(100, 1), 2, 3].astype(np.uint64)
    minute = np.zeros(102, dtype=np.uint64)
    tops = [(sc, key, minute)]
    # 1 alarm allowed in 1 hour: only host 1 may alert
    t = entity_threshold(tops, hours=1.0, budget=1.0)
    alarms = len({(k, m) for s, k, m in zip(sc, key, minute) if s >= t})
    assert alarms == 1 and 0.95 < t <= 0.99
    # 2 alarms allowed: host 2 too, host 3 not
    t2 = entity_threshold(tops, hours=1.0, budget=2.0)
    assert 0.5 < t2 <= 0.95
    # 0 alarms allowed: above every score
    assert entity_threshold(tops, hours=1.0, budget=0.0) > 0.99
