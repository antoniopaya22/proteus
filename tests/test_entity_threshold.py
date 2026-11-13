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


def test_alert_side_follows_the_sub_core_that_fires():
    from sklearn.ensemble import HistGradientBoostingClassifier

    from proteus.core.combine import MaxCore
    from proteus.evaluation.h1 import alert_side

    rng = np.random.default_rng(0)
    X = rng.random((600, 2))
    y = ((X[:, 0] > 0.8) | (X[:, 1] > 0.8)).astype(int)
    cols = ["dhost__flows__t60", "shost__flows__t60"]
    m = MaxCore(cols, [([cols[0]], HistGradientBoostingClassifier(max_iter=30)),
                       ([cols[1]], HistGradientBoostingClassifier(max_iter=30))]).fit(X, y)
    side = alert_side(m, cols, np.array([[0.95, 0.1], [0.1, 0.95]]))
    assert side.tolist() == [False, True]
    assert alert_side(object(), ["shost__n_dhost__t60"], np.zeros((3, 1))).all()
    assert not alert_side(object(), ["dsvc__flows__t60"], np.zeros((3, 1))).any()


def test_ties_at_the_top_push_the_threshold_above_them():
    # Ten hosts tie at the benign maximum (a saturated score): a budget of five alarms
    # cannot be met inside the tie, so the threshold goes above it (zero alarms).
    sc = np.r_[np.ones(10), 0.9]
    key = np.arange(11, dtype=np.uint64)
    minute = np.zeros(11, dtype=np.uint64)
    t = entity_threshold([(sc, key, minute)], hours=1.0, budget=5.0)
    assert t > 1.0
    # a budget that covers the whole tie lets it through
    assert entity_threshold([(sc, key, minute)], hours=1.0, budget=10.0) <= 1.0


def test_budget_pools_the_hours_of_every_day():
    # two days with one alarm each; one alarm per hour over two hours allows both
    day = (np.array([0.9]), np.array([1], dtype=np.uint64), np.array([0], dtype=np.uint64))
    assert entity_threshold([day, day], hours=2.0, budget=1.0) <= 0.9
    assert entity_threshold([day, day], hours=2.0, budget=0.5) > 0.9
