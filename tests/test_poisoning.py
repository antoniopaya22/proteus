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
