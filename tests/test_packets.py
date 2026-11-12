import numpy as np
import pandas as pd

from proteus.evaluation.packet_check import check
from proteus.packets import exporter, ops
from proteus.packets.exporter import FIN, RST, SYN


def packets(rows):
    return pd.DataFrame(rows, columns=exporter.COLUMNS).astype(
        {"sport": np.int32, "dport": np.int32, "proto": np.int16, "size": np.int64,
         "flags": np.int16})


def conn(t0, a="10.0.0.9", sp=5000, v="10.0.0.1", n=4, gap=1.0, close=True):
    rows = [(t0, a, v, sp, 80, 6, 20, SYN), (t0 + 0.01, v, a, 80, sp, 6, 20, SYN | 0x10)]
    for i in range(n):
        rows.append((t0 + gap * (i + 1), a, v, sp, 80, 6, 100, 0x10))
        rows.append((t0 + gap * (i + 1) + 0.01, v, a, 80, sp, 6, 500, 0x10))
    if close:
        rows += [(t0 + gap * (n + 2), a, v, sp, 80, 6, 20, FIN),
                 (t0 + gap * (n + 2) + 0.01, v, a, 80, sp, 6, 20, FIN)]
    return rows


def test_exporter_directions_fin_and_active_timeout():
    f = exporter.export(packets(conn(0.0)))
    assert len(f) == 1
    r = f.iloc[0]
    assert (r.src_ip, r.dst_ip, r.fwd_pkts, r.bwd_pkts) == ("10.0.0.9", "10.0.0.1", 6, 6)
    assert r.fwd_bytes == 20 + 400 + 20 and r.bwd_bytes == 20 + 2000 + 20
    long = exporter.export(packets(conn(0.0, n=30, gap=10.0, close=False)), active_s=120)
    assert len(long) == 3  # 300 s of activity, Δ = 120 s
    assert (long["duration_us"] <= 120e6).all()


def test_exporter_counts_responder_resets():
    rows = conn(0.0, n=1, close=False) + [(5.0, "10.0.0.1", "10.0.0.9", 80, 5000, 6, 0, RST)]
    f = exporter.export(packets(rows))
    assert len(f) == 1 and f.iloc[0].f_bwd_rst_flags == 1


def test_free_operations_respect_the_bound():
    rows = []
    for k in range(40):
        rows += conn(k * 7.0, sp=6000 + k)
    rows += conn(3.0, a="10.0.0.5", sp=7000)  # benign client of the same service
    pk = packets(rows)
    base = exporter.export(pk)
    atk = (pk["src"] == "10.0.0.9").to_numpy()
    rng = np.random.default_rng(0)
    variants = [ops.pad(pk, atk, 400), ops.insert(pk, atk, rng, 1.0),
                ops.hop_ports(pk, atk, rng, 2),
                ops.decoys(pk, ["10.0.0.9"], [("10.0.0.1", 80)], 50, rng)]
    for v in variants:
        r = check(base, exporter.export(v), "10.0.0.1", 80, 120.0, (10.0, 60.0, 600.0))
        assert r["violations"].sum() == 0, r[r["violations"] > 0]
    # Identity: the counter only decays during Δ, ratio exp(-Δ/τ) above the bound.
    same = check(base, base, "10.0.0.1", 80, 120.0, (600.0,)).dropna()
    assert np.allclose(same["min_ratio"], np.exp(-120.0 / 600.0), rtol=1e-3)
