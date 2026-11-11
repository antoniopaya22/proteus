import numpy as np
import pytest

from proteus.evidence.counters import decayed_distinct, decayed_sum

TAUS = [1.0, 10.0, 100.0]


def brute_sum(t, ent, w, tau):
    out = np.empty(len(t))
    for i in range(len(t)):
        m = (ent == ent[i]) & (t <= t[i])
        out[i] = np.sum(w[m] * np.exp(-(t[i] - t[m]) / tau))
    return out


def brute_distinct(t, ent, item, tau):
    out = np.empty(len(t))
    for i in range(len(t)):
        m = (ent == ent[i]) & (t <= t[i])
        last = {}
        for tt, it in zip(t[m], item[m]):
            last[it] = max(last.get(it, -np.inf), tt)
        out[i] = sum(np.exp(-(t[i] - v) / tau) for v in last.values())
    return out


def random_events(rng, n=300, n_ent=5, n_item=8):
    t = np.sort(rng.uniform(0, 200, n))
    # Distinct times: ties make "after including the event" ambiguous for brute force.
    t = t + np.arange(n) * 1e-6
    rng.shuffle(t)
    ent = rng.integers(0, n_ent, n)
    item = rng.integers(0, n_item, n)
    w = rng.integers(0, 5, n).astype(float)
    return t, ent, item, w


@pytest.mark.parametrize("seed", range(5))
def test_sum_matches_brute_force(seed):
    t, ent, _, w = random_events(np.random.default_rng(seed))
    got = decayed_sum(t, ent, w, TAUS)
    for j, tau in enumerate(TAUS):
        np.testing.assert_allclose(got[:, j], brute_sum(t, ent, w, tau), rtol=1e-9, atol=1e-9)


@pytest.mark.parametrize("seed", range(5))
def test_distinct_matches_brute_force(seed):
    t, ent, item, _ = random_events(np.random.default_rng(seed))
    got = decayed_distinct(t, ent, item, TAUS)
    for j, tau in enumerate(TAUS):
        np.testing.assert_allclose(
            got[:, j], brute_distinct(t, ent, item, tau), rtol=1e-9, atol=1e-9
        )


@pytest.mark.parametrize("seed", range(5))
def test_insertion_never_decreases_evidence(seed):
    """Free operations add events: evidence of the original events must not drop."""
    rng = np.random.default_rng(seed)
    t, ent, item, w = random_events(rng)
    t2, ent2, item2, w2 = random_events(rng, n=150)
    T = np.concatenate([t, t2 + 1e-7])
    E = np.concatenate([ent, ent2])
    I = np.concatenate([item, item2])
    W = np.concatenate([w, w2])
    n = len(t)
    for f, a, b in (
        (decayed_sum, (t, ent, w), (T, E, W)),
        (decayed_distinct, (t, ent, item), (T, E, I)),
    ):
        base = f(*a, TAUS)
        more = f(*b, TAUS)[:n]
        assert np.all(more >= base - 1e-9)
