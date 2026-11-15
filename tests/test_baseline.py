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


def test_masked_minutes_are_discounted_from_the_quantile_rank():
    """An entity attacked during most of a day: the masked minutes must leave the
    reference, so its baseline is the quantile of the remaining benign minutes (not of
    the whole day with the masked minutes counted as zeros)."""
    import numpy as np
    import pandas as pd

    from proteus.evidence import baseline as bl

    t0 = pd.Timestamp("2020-01-01 08:00")
    n = 480  # one flow per minute, 8 hours; benign level rises with time
    ev = pd.DataFrame({"t_end": (t0 + pd.to_timedelta(np.arange(n), unit="min")
                                 ).astype("datetime64[us]"),
                       "c": np.linspace(1.0, 5.0, n).astype(np.float32)})
    ev["t_start"] = ev["t_end"]
    key = pd.Series(np.zeros(n, dtype=np.int64))
    mal = np.zeros(n, dtype=bool)
    mal[60:420] = True  # attacked for six of the eight hours
    d = bl.day_table(ev, ["c"], key, mal, n)
    assert int(d.masked.get(0, 0)) >= 360  # the bug: this was always empty
    b_masked = float(bl.baseline([d], ["c"])["c"].iloc[0])
    rest = ev["c"].to_numpy()[np.r_[0:60, 431:480]]  # masked: 60..430 (ten minutes after)
    assert abs(b_masked - np.quantile(rest, 0.95)) < 0.1
