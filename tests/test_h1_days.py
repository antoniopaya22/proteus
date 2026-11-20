from pathlib import Path

from proteus.evaluation.h1 import reference_days


def test_reference_days_leave_one_out_or_only_earlier():
    days = [Path(f"{d}.parquet") for d in ("mon", "tue", "wed")]
    assert reference_days(days, days[1]) == [days[0], days[2]]
    assert reference_days(days, days[1], "prior") == [days[0]]
    assert reference_days(days, days[0], "prior") == []  # warm-up: not evaluated
    assert reference_days(days, days[2], "prior") == days[:2]
    # With causal baselines the first day has none and calibrates no other day.
    assert reference_days(days, days[1], "prior", warm=1) == []
    assert reference_days(days, days[2], "prior", warm=1) == [days[1]]
    assert reference_days(days, days[1], warm=1) == [days[0], days[2]]
