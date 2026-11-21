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
        # No conn_s: the record-level split keeps durations by construction, but on
        # packets a split loses the gaps between pieces (tests/test_packets.py).
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


def _attack_flows(n=40, gap_s=1.0):
    import pandas as pd

    t0 = pd.Timestamp("2020-01-01 10:00")
    return pd.DataFrame({
        "t_start": (t0 + pd.to_timedelta(np.arange(n) * gap_s, unit="s")).astype("datetime64[us]"),
        "duration_us": np.full(n, 200_000, dtype=np.int64),
        "src_ip": pd.array(["10.0.0.9"] * n, dtype="string"),
        "dst_ip": pd.array(["10.0.1.1"] * n, dtype="string"),
        "src_port": np.arange(40000, 40000 + n, dtype=np.int32), "dst_port": np.int32(80),
        "proto": np.int16(6), "fwd_pkts": np.full(n, 8, dtype=np.int64),
        "bwd_pkts": np.full(n, 6, dtype=np.int64), "fwd_bytes": np.full(n, 900, dtype=np.int64),
        "bwd_bytes": np.full(n, 3000, dtype=np.int64), "f_bwd_rst_flags": np.zeros(n, np.float32),
    }).assign(t_end=lambda d: d["t_start"] + pd.to_timedelta(d["duration_us"], unit="us"))


def test_reuse_keeps_bytes_and_lowers_flows_and_packets():
    from proteus.attacks import operators as op

    df = _attack_flows()
    out = op.reuse_connections(df, np.ones(len(df), bool), k=10, timeout_s=120)
    assert len(out) == 4                                   # 40 flows in connections of 10
    assert out["fwd_bytes"].sum() == df["fwd_bytes"].sum()  # payload conserved
    assert out["fwd_pkts"].sum() == df["fwd_pkts"].sum() - 4 * 36
    assert (out["t_end"] - out["t_start"]).dt.total_seconds().max() <= 120
    assert op.reuse_connections(df, np.ones(len(df), bool), k=1, timeout_s=120) is df


def test_reuse_never_spans_the_active_timeout():
    from proteus.attacks import operators as op

    df = _attack_flows(n=30, gap_s=20.0)  # ten minutes of flows
    out = op.reuse_connections(df, np.ones(len(df), bool), k=1000, timeout_s=120)
    assert len(out) >= 5
    assert (out["t_end"] - out["t_start"]).dt.total_seconds().max() <= 120.3


def test_spread_and_pulse_keep_the_flows():
    from proteus.attacks import operators as op

    df = _attack_flows(n=200, gap_s=3.0)
    sel = np.ones(len(df), bool)
    s = op.spread_sources(df, sel, 50, np.random.default_rng(0))
    assert s["src_ip"].nunique() > 30 and len(s) == len(df)
    p = op.pulse(df, sel, period_s=60, duty=0.1)
    assert len(p) == len(df) and p["fwd_bytes"].sum() == df["fwd_bytes"].sum()
    phase = (p["t_start"] - p["t_start"].min()).dt.total_seconds() % 60
    assert phase.max() <= 6.0                              # bursts in the first tenth
    assert (p["t_end"] - p["t_start"]).equals(df["t_end"] - df["t_start"])


def _split_reference(df: pd.DataFrame, sel: np.ndarray, parts: int,
                rng: np.random.Generator) -> pd.DataFrame:
    """``split_flows`` one flow at a time: slow, kept as the reference of the fast one."""
    out = op._with_ids(df)
    keep = out[~sel]
    pieces = [keep]
    src = out[sel]
    for _, r in src.iterrows():
        k = int(max(1, min(parts, r["fwd_pkts"])))
        if k == 1:
            pieces.append(r.to_frame().T)
            continue
        edges = np.linspace(0, r["duration_us"], k + 1).astype(np.int64)
        fp = np.full(k, r["fwd_pkts"] // k)
        fp[: r["fwd_pkts"] % k] += 1
        bp = np.full(k, r["bwd_pkts"] // k)
        bp[: r["bwd_pkts"] % k] += 1
        fb = np.floor(r["fwd_bytes"] * fp / max(r["fwd_pkts"], 1)).astype(np.int64)
        fb[-1] += r["fwd_bytes"] - fb.sum()
        bb = np.floor(r["bwd_bytes"] * bp / max(r["bwd_pkts"], 1)).astype(np.int64)
        bb[-1] += r["bwd_bytes"] - bb.sum()
        t0 = r["t_start"]
        rows = pd.DataFrame([r] * k).reset_index(drop=True)
        rows["t_start"] = [t0 + pd.Timedelta(microseconds=int(e)) for e in edges[:-1]]
        rows["t_end"] = [t0 + pd.Timedelta(microseconds=int(e)) for e in edges[1:]]
        rows["duration_us"] = np.diff(edges)
        rows["fwd_pkts"], rows["bwd_pkts"] = fp, bp
        rows["fwd_bytes"], rows["bwd_bytes"] = fb, bb
        rows["src_port"] = rng.integers(1024, 65536, k)
        # A responder RST closes the original connection: keep it on the last piece.
        rst = r.get("f_bwd_rst_flags", 0)
        rows["f_bwd_rst_flags"] = [0.0] * (k - 1) + [rst]
        rows["orig_id"] = [-1] * (k - 1) + [r["orig_id"]]
        pieces.append(rows)
    res = pd.concat(pieces, ignore_index=True)
    return res.astype({c: df[c].dtype for c in df.columns if c in res.columns})


@pytest.mark.parametrize("parts", [1, 2, 4, 9])
@pytest.mark.parametrize("seed", range(3))
def test_split_matches_the_flow_by_flow_reference(parts, seed):
    x = flows(np.random.default_rng(seed))
    x.loc[x.index[:5], "duration_us"] = 0
    sel = attacker(x) & (np.random.default_rng(seed + 10).random(len(x)) < 0.7)
    got = op.split_flows(x, sel, parts, np.random.default_rng(7))
    want = _split_reference(x, sel, parts, np.random.default_rng(7))
    pd.testing.assert_frame_equal(got, want.astype({"orig_id": np.int64}))


def test_split_without_the_reset_column_matches_the_reference():
    x = flows(np.random.default_rng(0)).drop(columns=["f_bwd_rst_flags"], errors="ignore")
    got = op.split_flows(x, attacker(x), 3, np.random.default_rng(7))
    want = _split_reference(x, attacker(x), 3, np.random.default_rng(7))
    pd.testing.assert_frame_equal(got, want, check_dtype=False)


def test_shrink_requests_only_lowers_payload_bytes_of_known_services():
    x = flows(np.random.default_rng(0))
    x.loc[x.index[:3], "fwd_bytes"] = 5  # already below the smallest request
    sel = attacker(x)
    y = op.shrink_requests(x, sel)
    assert (y["fwd_bytes"] <= x["fwd_bytes"]).all() and (y.loc[~sel, "fwd_bytes"] == x.loc[~sel, "fwd_bytes"]).all()
    for port, floor in op.MIN_REQUEST_BYTES.items():
        m = sel & (x["dst_port"] == port).to_numpy()
        if m.any():
            assert (y.loc[m, "fwd_bytes"] == np.minimum(x.loc[m, "fwd_bytes"], floor)).all()
    other = sel & ~x["dst_port"].isin(list(op.MIN_REQUEST_BYTES)).to_numpy()
    assert (y.loc[other, "fwd_bytes"] == x.loc[other, "fwd_bytes"]).all()
    for c in ("fwd_pkts", "bwd_pkts", "bwd_bytes", "duration_us"):
        assert (y[c] == x[c]).all(), c  # the same requests, connections and packets


def test_shrink_requests_leaves_udp_floods_alone():
    x = flows(np.random.default_rng(0))
    x["proto"] = np.int16(17)
    y = op.shrink_requests(x, attacker(x))
    assert (y["fwd_bytes"] == x["fwd_bytes"]).all()


def test_reuse_never_merges_flows_that_overlap_in_time():
    from proteus.attacks import operators as op

    # A slow denial of service: 40 connections of 90 s opened one per second, all open
    # at once. A client cannot carry them in fewer connections.
    df = _attack_flows(n=40, gap_s=1.0).assign(duration_us=np.int64(90_000_000))
    df["t_end"] = df["t_start"] + pd.to_timedelta(df["duration_us"], unit="us")
    out = op.reuse_connections(df, np.ones(len(df), bool), k=20, timeout_s=120)
    assert len(out) == 40


def test_reuse_respects_the_service_limit_on_requests_per_connection():
    from proteus.attacks import operators as op

    df = _attack_flows(n=36, gap_s=0.5)                     # 0.2 s requests, sequential
    ssh = df.assign(dst_port=np.int32(22))
    assert len(op.reuse_connections(ssh, np.ones(len(ssh), bool), k=20, timeout_s=120)) == 6
    ftp = df.assign(dst_port=np.int32(21))
    assert len(op.reuse_connections(ftp, np.ones(len(ftp), bool), k=20, timeout_s=120)) == 12
    http = op.reuse_connections(df, np.ones(len(df), bool), k=20, timeout_s=120)
    assert len(http) == 2


@pytest.mark.parametrize("period,duty", [(60.0, 0.1), (300.0, 0.1), (300.0, 0.5)])
@pytest.mark.parametrize("seed", range(3))
def test_bursts_are_bounded_by_the_retiming_slack(period, duty, seed):
    """Bursts move flows earlier by up to d = period (1 - duty): evidence read Δ later
    keeps at least exp(-(2Δ + d)/τ) of the original, the slack of ``--retime-s d``."""
    from proteus.core.certify import slack
    rng = np.random.default_rng(seed)
    x = flows(rng)
    x2 = op.pulse(x, attacker(x), period, duty)
    d = period * (1 - duty)
    both = pd.concat([x.assign(_v=0), x2.assign(_v=1)], ignore_index=True)
    t0 = both["t_end"].min()
    t = (both["t_end"] - t0).dt.total_seconds().to_numpy()
    dsvc = _codes(both["dst_ip"], both["dst_port"])
    v = both["_v"].to_numpy()
    a, b = v == 0, v == 1
    taus = np.asarray(DEFAULT_TAUS)
    names = [f"f__t{int(tau)}" for tau in taus]
    s = slack(names, {n: "count" for n in names}, DELTA_S, d)
    assert np.allclose(s, (2 * DELTA_S + d) / taus)
    orig = decayed_sum(t[a], dsvc[a], np.ones(a.sum()), taus)
    later = decayed_sum_at(t[b], dsvc[b], np.ones(b.sum()), t[a] + DELTA_S, dsvc[a], taus)
    assert np.all(later >= np.exp(-s)[None, :] * orig - 1e-9)
