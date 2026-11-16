import numpy as np
import pandas as pd

from proteus.evaluation.query_attack import (
    CHOICES,
    Shape,
    apply,
    mutate,
    search,
    shape_pool,
    transfer,
)


def test_mutate_changes_the_shape_and_keeps_sources_unless_costly():
    rng = np.random.default_rng(0)
    s = Shape()
    for _ in range(200):
        t = mutate(s, rng)
        assert t != s and t.sources == 1
        assert all(getattr(t, k) in CHOICES[k] for k in CHOICES)
    assert any(mutate(s, rng, costly=True).sources > 1 for _ in range(200))


def test_search_reports_only_rates_that_were_answered_quiet():
    asked = []

    def quiet(shape, i):  # reuse raises the quiet rate; padding makes it worse
        cap = 5 + (10 if shape.reuse >= 5 else 0) + (6 if shape.duty < 1 else 0) - (
            3 if shape.pad else 0)
        asked.append((shape, i, i <= cap))
        return i <= cap

    res = search(quiet, 40, 120, np.random.default_rng(1))
    assert res["queries"] == len(asked) <= 120
    assert (res["shape"], res["index"], True) in asked
    assert res["index"] > 5  # better than the plain attack
    assert res["shape"].reuse >= 5 or res["shape"].duty < 1
    assert [t["index"] for t in res["trace"]] == sorted(t["index"] for t in res["trace"])


def test_search_respects_a_small_budget_and_a_detector_that_always_alerts():
    res = search(lambda s, i: False, 40, 7, np.random.default_rng(0))
    assert res["index"] == -1 and res["queries"] == 7
    res = search(lambda s, i: True, 40, 50, np.random.default_rng(0))
    assert res["index"] == 39  # nothing to gain: stops at the top rate
    assert res["queries"] < 50


def _traffic(n_bg=100, n_atk=200):
    t0 = pd.Timestamp("2020-01-01 10:00")
    n = n_bg + n_atk
    df = pd.DataFrame({
        "t_start": (t0 + pd.to_timedelta(np.arange(n) * 2.0, unit="s")).astype("datetime64[us]"),
        "duration_us": np.full(n, 100_000, dtype=np.int64),
        "src_ip": pd.array(["10.0.0.5"] * n_bg + ["203.0.113.1"] * n_atk, dtype="string"),
        "dst_ip": pd.array(["10.0.1.1"] * n, dtype="string"),
        "src_port": np.arange(n, dtype=np.int32) + 2000, "dst_port": np.int32(80),
        "proto": np.int16(6), "fwd_pkts": np.full(n, 8, dtype=np.int64),
        "bwd_pkts": np.full(n, 5, dtype=np.int64), "fwd_bytes": np.full(n, 700, dtype=np.int64),
        "bwd_bytes": np.full(n, 900, dtype=np.int64), "f_bwd_rst_flags": np.zeros(n, np.float32),
        "_atk": [False] * n_bg + [True] * n_atk,
    })
    df["t_end"] = df["t_start"] + pd.to_timedelta(df["duration_us"], unit="us")
    df["orig_id"] = np.arange(n)
    return df


def test_apply_never_removes_payload_and_leaves_the_background_alone():
    df = _traffic()
    bytes_atk = df.loc[df["_atk"], "fwd_bytes"].sum()
    rng = np.random.default_rng(0)
    shapes = [Shape(), Shape(pad=40, ins=5, ports=True), Shape(reuse=20),
              Shape(split=5, split_frac=1.0), Shape(duty=0.1, period=60.0),
              Shape(sources=10), Shape(decoys=100), Shape(pad=400, reuse=5, duty=0.5)]
    shapes += [mutate(mutate(Shape(), rng, True), rng, True) for _ in range(20)]
    for s in shapes:
        v = apply(df, s, "10.0.1.1", 80, np.random.default_rng(1))
        bg = v[~v["_atk"]]
        assert len(bg) == 100 and (bg["src_ip"] == "10.0.0.5").all(), s
        assert (bg["fwd_bytes"] == 700).all() and (bg["fwd_pkts"] == 8).all(), s
        assert v.loc[v["_atk"], "fwd_bytes"].sum() >= bytes_atk, s
        assert v["t_end"].is_monotonic_increasing, s
    v = apply(df, Shape(reuse=20), "10.0.1.1", 80, np.random.default_rng(1))
    assert v["_atk"].sum() < 200  # fewer records, same payload
    v = apply(df, Shape(sources=10), "10.0.1.1", 80, np.random.default_rng(1))
    assert v.loc[v["_atk"], "src_ip"].nunique() > 1


def test_submit_does_not_try_rates_above_the_flow_cap():
    from proteus.evaluation.query_attack import submit

    full = pd.DataFrame({"u": np.linspace(0, 0.999, 1000)})
    sent: dict[int, int] = {}
    quiet = submit(full, None, None, np.array([1.0, 50.0, 100.0]), 100.0, [], sent, max_flows=400)
    assert quiet(Shape(), 2) is False and sent == {-1: 1}  # 1000 flows: over the cap, not sent


def test_transfer_keeps_the_best_shape_found_elsewhere():
    limit = {0: 3, 100: 9, 400: 6}  # quiet up to this index, by padding

    def quiet(shape, i):
        return i <= limit[shape.pad]

    shapes = [(Shape(pad=400), 5), (Shape(pad=100), 2)]
    res = transfer(quiet, 12, 3, shapes)
    assert (res["index"], res["shape"]) == (9, Shape(pad=100))
    # A shape that passes neither where it was found nor one step above the best costs
    # at most two queries and changes nothing.
    res = transfer(quiet, 12, 9, [(Shape(pad=400), 11), (Shape(pad=100), 9)])
    assert (res["index"], res["shape"], res["queries"]) == (9, None, 3)


def test_transfer_reaches_what_a_shape_reached_elsewhere_even_if_rates_are_not_monotone():
    def quiet(shape, i):  # quiet at 8 and below 3, alerted in between
        return i == 8 or i < 3

    res = transfer(quiet, 12, 2, [(Shape(pad=100), 8)])
    assert (res["index"], res["shape"]) == (8, Shape(pad=100))


def test_transfer_stops_at_the_top_of_the_grid():
    res = transfer(lambda shape, i: True, 5, 1, [(Shape(pad=100), 0), (Shape(pad=400), 0)])
    assert (res["index"], res["shape"]) == (4, Shape(pad=100))


def test_shape_pool_offers_free_shapes_and_the_own_shape_when_it_went_further_elsewhere():
    def entry(target, costly, shape, index):
        return {"row": {"target": target, "costly": costly}, "shape": shape, "index": index}

    free = entry("a", False, Shape(reuse=20), 9)
    spread = entry("a", True, Shape(reuse=20), 6)  # same shape, lower rate: the restart lost it
    other = entry("b", True, Shape(sources=100), 11)
    none = entry("b", False, Shape(pad=100), -1)
    found = [free, spread, other, none]
    assert shape_pool(spread, found) == [("b", Shape(sources=100), 11), ("a", Shape(reuse=20), 9)]
    # The free search takes no shape that spreads, nor its own shape from a worse search.
    assert shape_pool(free, found) == []
