import numpy as np
import pandas as pd

from proteus.core import poisoning as po
from proteus.core.frontier import frontier
from test_frontier import BASE, COLS, SPECS, scenario


class ClippedSum:
    """Monotone and bounded below per feature, like a tree ensemble below its first
    split: an infinite baseline cannot push the score below the raw counter's."""

    monotonic_cst = (1, 1)

    def predict_proba(self, X):
        z = np.clip(np.nan_to_num(X), 0.0, 50.0).sum(axis=1)
        s = 1 / (1 + np.exp(-(2 * z - 12)))
        return np.stack([1 - s, s], axis=1)


BCOLS = {"dsvc": ["dsvc__fpkts__t600"], "dhost": [], "shost": []}


def test_raise_baseline_never_lowers_and_respects_cap():
    base = {"dsvc": pd.DataFrame({"a": [1.0, 5.0]}, index=["k1", "k2"])}
    lv = {"dsvc": pd.DataFrame({"a": [3.0, 2.0, 4.0]}, index=["k1", "k2", "k3"])}
    up = po.raise_baseline(base, lv)["dsvc"]["a"]
    assert up.to_dict() == {"k1": 3.0, "k2": 5.0, "k3": 4.0}
    capped = po.raise_baseline(base, lv, cap=0.5)["dsvc"]["a"]
    assert capped.to_dict() == {"k1": 1.5, "k2": 5.0, "k3": 0.5}
    assert base["dsvc"]["a"].to_dict() == {"k1": 1.0, "k2": 5.0}  # input untouched


def test_entity_levels_counts_idle_minutes_as_zero():
    rng = np.random.default_rng(0)
    sc = scenario(rng)
    t0, t1 = sc.start, sc.start + pd.Timedelta(seconds=sc.duration_s)
    keys = {"dsvc": ["10.0.1.1:22/6"]}
    busy = po.entity_levels(po.poisoning_traffic(sc, 2.0, np.random.default_rng(1)),
                            BCOLS, keys, t0, t1)["dsvc"].iloc[0, 0]
    quiet = po.entity_levels(sc.background, BCOLS, keys, t0, t1)["dsvc"].iloc[0, 0]
    assert busy > quiet > 0


def test_poisoning_raises_frontier_up_to_the_ceiling():
    rng = np.random.default_rng(0)
    sc = scenario(rng)
    m = ClippedSum()
    thr = 0.9
    keys = {"dsvc": ["10.0.1.1:22/6"]}
    t0, t1 = sc.start, sc.start + pd.Timedelta(seconds=sc.duration_s)

    def front(base):
        return frontier(sc, m, COLS, SPECS, base, thr, np.random.default_rng(1), r_min=1e-3,
                        r_max=50.0, iters=14)

    r0 = front(BASE)
    assert r0["bounded"] == "ok"
    lv = po.entity_levels(po.poisoning_traffic(sc, 0.95 * r0["rate"], np.random.default_rng(2)),
                          BCOLS, keys, t0, t1)
    r1 = front(po.raise_baseline(BASE, lv))
    ceil = front(po.saturate(BASE, keys, BCOLS))
    assert r1["rate"] >= r0["rate"]
    # The raw counter (dsvc__flows__t60) still bounds the attack: finite ceiling.
    assert ceil["bounded"] == "ok" and ceil["rate"] >= r1["rate"]


def test_combined_is_the_maximum_of_fitted_models():
    from sklearn.ensemble import HistGradientBoostingClassifier

    from proteus.evaluation.poisoning import combined

    rng = np.random.default_rng(0)
    X = rng.normal(size=(500, 2))
    y = (X.sum(axis=1) > 0).astype(int)
    a = HistGradientBoostingClassifier(max_iter=20, monotonic_cst=[1]).fit(X[:, [0]], y)
    b = HistGradientBoostingClassifier(max_iter=20, monotonic_cst=[1, 1]).fit(X[:, [1, 0]], y)
    cols, m = combined({"a": (["x"], a), "b": (["y", "x"], b)}, "a+b")
    assert cols == ["x", "y"]
    Z = rng.normal(size=(50, 2))
    want = np.maximum(a.predict_proba(Z[:, [0]])[:, 1], b.predict_proba(Z[:, [1, 0]])[:, 1])
    assert np.allclose(m.predict_proba(Z)[:, 1], want)
    assert m.monotonic_cst == [1, 1]


def test_calibrated_max_is_monotone_max_of_benign_cdfs():
    from sklearn.ensemble import HistGradientBoostingClassifier

    from proteus.evaluation.poisoning import combined

    rng = np.random.default_rng(0)
    X = rng.normal(size=(2000, 2))
    y = (X[:, 0] + X[:, 1] > 1).astype(int)
    a = HistGradientBoostingClassifier(max_iter=20, monotonic_cst=[1]).fit(X[:, [0]], y)
    b = HistGradientBoostingClassifier(max_iter=20, monotonic_cst=[1]).fit(X[:, [1]], y)
    _, m = combined({"a": (["x"], a), "b": (["y"], b)}, "a|b")
    assert getattr(m, "local", False)
    m.fit(X[y == 0])
    s = m.score(X)
    Z = X.copy()
    Z[:, 0] += rng.uniform(0, 2, len(Z))
    assert (m.score(Z) >= s - 1e-12).all()  # monotone
    cdf = [np.searchsorted(r, p.predict_proba(X[:, idx])[:, 1], side="right") / len(r)
           for (idx, p), r in zip(m.parts, m.ref_)]
    inside = s <= 1.0
    assert np.allclose(s[inside], np.max(cdf, axis=0)[inside])
    p = m.predict_proba(X)[:, 1]
    assert ((p >= 0) & (p < 1)).all()


def test_ablation_drops_one_subcore():
    from sklearn.ensemble import HistGradientBoostingClassifier

    from proteus.evaluation.poisoning import combined

    rng = np.random.default_rng(0)
    X = rng.normal(size=(500, 3))
    y = (X.sum(axis=1) > 0).astype(int)
    parts = [(["a"], HistGradientBoostingClassifier(max_iter=10).fit(X[:, [0]], y)),
             (["b", "c"], HistGradientBoostingClassifier(max_iter=10).fit(X[:, [1, 2]], y))]
    _, full = combined({"x": (["a"], parts[0][1]), "y": (["b", "c"], parts[1][1])}, "x|y")
    cols, abl = combined({"m": (["a", "b", "c"], full)}, "m-0")
    assert cols == ["b", "c"] and len(abl.parts) == 1 and type(abl) is type(full)
