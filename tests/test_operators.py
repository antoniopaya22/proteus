"""End-to-end checks of the guarantee on flow records.

Exact: operations that only add evidence never lower any feature of any original flow.
Bounded: operations that re-time flows lower evidence by at most exp(-2Δ/τ), read Δ later.
"""

import numpy as np
import pandas as pd
import pytest

from proteus.attacks import operators as op
from proteus.evidence.counters import (
    decayed_distinct,
    decayed_distinct_at,
    decayed_sum,
    decayed_sum_at,
)
from proteus.evidence.features import DEFAULT_TAUS, build

DELTA_S = 120.0


def flows(rng, n=400, horizon_s=1800):
    start = pd.Timestamp("2020-01-01") + pd.to_timedelta(
        np.sort(rng.uniform(0, horizon_s, n)), unit="s")
    dur = rng.integers(0, int(DELTA_S * 1e6), n)
    fp = rng.integers(1, 40, n)
    bp = rng.integers(0, 40, n)
    df = pd.DataFrame({
        "t_start": start.astype("datetime64[us]"),
        "duration_us": dur.astype(np.int64),
        "src_ip": rng.choice([f"10.0.0.{i}" for i in range(8)], n),
        "src_port": rng.integers(1024, 65536, n).astype(np.int32),
        "dst_ip": rng.choice([f"10.0.1.{i}" for i in range(5)], n),
        "dst_port": rng.choice([22, 80, 443, 8080], n).astype(np.int32),
        "proto": np.full(n, 6, dtype=np.int16),
        "fwd_pkts": fp.astype(np.int64),
        "bwd_pkts": bp.astype(np.int64),
        "fwd_bytes": (fp * rng.integers(40, 1500, n)).astype(np.int64),
        "bwd_bytes": (bp * rng.integers(40, 1500, n)).astype(np.int64),
        "f_bwd_rst_flags": (rng.random(n) < 0.2).astype(np.float32),
        "attack": "x",
    })
    df["t_end"] = df["t_start"] + pd.to_timedelta(df["duration_us"], unit="us")
    return df


def attacker(df):
    return df["src_ip"].isin(["10.0.0.0", "10.0.0.1", "10.0.0.2"]).to_numpy()


EXACT_OPS = {
    "pad": lambda df, rng: op.pad(df, attacker(df), 100),
    "insert": lambda df, rng: op.insert_packets(df, attacker(df), 5, 60),
    "src_ports": lambda df, rng: op.change_src_ports(df, attacker(df), rng),
    "decoys": lambda df, rng: op.add_decoys(
        df, 200, rng, ["10.0.0.0", "10.0.0.1"], ["10.0.1.0", "10.0.1.9"], [22, 80, 9999]),
    "all": lambda df, rng: op.add_decoys(
        op.change_src_ports(op.insert_packets(op.pad(df, attacker(df), 50), attacker(df), 3, 40),
                            attacker(df), rng),
        100, rng, ["10.0.0.1"], ["10.0.1.2"], [80]),
}


@pytest.mark.parametrize("name", list(EXACT_OPS))
@pytest.mark.parametrize("seed", range(3))
def test_additive_operations_never_lower_evidence(name, seed):
    rng = np.random.default_rng(seed)
    x = flows(rng)
    x2 = EXACT_OPS[name](x, rng)
    f1, specs = build(x)
    f2, _ = build(x2)
    orig = x2["orig_id"].to_numpy()
    rows = np.flatnonzero(orig >= 0)
    f2o = f2.iloc[rows].set_axis(orig[rows]).sort_index()
    for s in specs:
        a, b = f1[s.name].to_numpy(), f2o[s.name].to_numpy()
        assert np.all(b >= a - 1e-5), (name, s.name, float((a - b).max()))


def _codes(*cols):
    return pd.Series(list(zip(*cols))).factorize()[0] if len(cols) > 1 else pd.factorize(cols[0])[0]


@pytest.mark.parametrize("which", ["split", "extend", "both"])
@pytest.mark.parametrize("seed", range(3))
def test_retiming_operations_are_bounded(which, seed):
    rng = np.random.default_rng(seed)
    x = flows(rng)
    if which in ("split", "both"):
        x2 = op.split_flows(x, attacker(x), 4, rng)
    else:
        x2 = x
    if which in ("extend", "both"):
        x2 = op.insert_packets(x2, attacker(x2), 2, 60, extend_s=60, timeout_s=DELTA_S)

    both = pd.concat([x.assign(_v=0), x2.assign(_v=1)], ignore_index=True)
    t0 = both["t_end"].min()
    t = (both["t_end"] - t0).dt.total_seconds().to_numpy()
    dhost = pd.factorize(both["dst_ip"])[0]
    dsvc = _codes(both["dst_ip"], both["dst_port"])
    src = pd.factorize(both["src_ip"])[0]
    v = both["_v"].to_numpy()
    a, b = v == 0, v == 1
    taus = np.asarray(DEFAULT_TAUS)
    factor = np.exp(-2 * DELTA_S / taus)[None, :]

    checks = {
        "dhost_fpkts": (dhost, both["fwd_pkts"].to_numpy(float)),
        "dsvc_flows": (dsvc, np.ones(len(both))),
        "dsvc_conn_s": (dsvc, both["duration_us"].to_numpy(float) / 1e6),
    }
    for name, (ent, w) in checks.items():
        orig = decayed_sum(t[a], ent[a], w[a], taus)
        later = decayed_sum_at(t[b], ent[b], w[b], t[a] + DELTA_S, ent[a], taus)
        assert np.all(later >= factor * orig - 1e-9), name

    orig = decayed_distinct(t[a], dhost[a], src[a], taus)
    later = decayed_distinct_at(t[b], dhost[b], src[b], t[a] + DELTA_S, dhost[a], taus)
    assert np.all(later >= factor * orig - 1e-9), "dhost_n_src"


def test_split_conserves_work():
    rng = np.random.default_rng(0)
    x = flows(rng)
    x2 = op.split_flows(x, attacker(x), 4, rng)
    for c in ("fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes", "duration_us"):
        assert x2[c].sum() == x[c].sum(), c
    assert len(x2) > len(x)


def test_splitting_can_lower_evidence_without_slack():
    """Why the slack exists: pieces exported earlier have decayed by the original end."""
    rng = np.random.default_rng(0)
    x = flows(rng)
    x2 = op.split_flows(x, attacker(x), 8, rng)
    f1, _ = build(x)
    f2, _ = build(x2)
    orig = x2["orig_id"].to_numpy()
    rows = np.flatnonzero(orig >= 0)
    f2o = f2.iloc[rows].set_axis(orig[rows]).sort_index()
    col = "dhost__fpkts__t10"
    assert np.any(f2o[col].to_numpy() < f1[col].to_numpy() - 1e-6)
