import numpy as np

from proteus.evidence.baseline import quantile_with_zeros


def brute(codes, values, n_groups, total, q):
    out = []
    for g in range(n_groups):
        v = np.concatenate([values[codes == g], np.zeros(total - np.sum(codes == g))])
        v.sort()
        out.append(v[int(np.ceil(q * total)) - 1])
    return np.array(out)


def test_quantile_with_zeros_matches_brute_force():
    rng = np.random.default_rng(0)
    for total in (20, 100, 1000):
        n_groups = 7
        codes = np.concatenate([rng.choice(n_groups, size=rng.integers(0, total), replace=True)])
        # At most `total` active minutes per group.
        keep = np.concatenate([np.flatnonzero(codes == g)[:total] for g in range(n_groups)])
        codes = codes[keep]
        values = rng.uniform(0, 10, len(codes))
        for q in (0.5, 0.9, 0.95):
            np.testing.assert_allclose(
                quantile_with_zeros(codes, values, n_groups, total, q),
                brute(codes, values, n_groups, total, q),
            )


def test_rare_entity_has_zero_baseline():
    codes = np.array([0, 0, 1])
    values = np.array([5.0, 6.0, 9.0])
    b = quantile_with_zeros(codes, values, 2, total_minutes=100, q=0.95)
    assert np.all(b == 0)


def _day(minutes, attack_minutes, level_benign=1.0, level_attack=9.0):
    import pandas as pd

    from proteus.evidence.baseline import day_table

    t0 = pd.Timestamp("2020-01-01 00:00:00")
    t_end, val, mal = [], [], []
    for m in range(minutes):
        t_end.append(t0 + pd.Timedelta(minutes=m, seconds=30))
        attacked = m in attack_minutes
        val.append(level_attack if attacked else level_benign)
        mal.append(attacked)
    ev = pd.DataFrame({"t_start": t_end, "t_end": t_end, "x": val})
    key = pd.Series(np.zeros(len(ev), dtype=np.int64))
    return day_table(ev, ["x"], key, np.array(mal), minutes)


def test_masking_removes_attack_minutes_from_baseline():
    from proteus.evidence.baseline import baseline

    # Entity active every minute at level 1, attacked (level 9) for 30 of 100 minutes.
    d = _day(100, set(range(10, 40)))
    b = baseline([d], ["x"])
    assert b.loc[0, "x"] == 1.0

    # Without masking the attack would set the 95th percentile.
    import pandas as pd

    from proteus.evidence.baseline import DayTable
    unmasked = DayTable(pd.concat([d.table, pd.DataFrame(
        {"key": [0] * 30, "minute": [10_000 + i for i in range(30)], "x": [9.0] * 30})]),
        pd.Series(dtype=np.int64), 100)
    assert baseline([unmasked], ["x"]).loc[0, "x"] == 9.0
