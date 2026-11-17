import numpy as np
import pandas as pd
import pytest

from proteus.baselines.kitsune import LAMBDAS, N_FEATURES, AfterImage
from proteus.evaluation.kitsune_pcap import best_shift, campaigns, ip_int, label, mimic, variants


def test_damped_statistics_of_the_source_host():
    fe = AfterImage(lambdas=(1.0,))
    fe.update(0.0, "10.0.0.1", "10.0.0.2", 1000, 80, 100.0)
    x = fe.update(1.0, "10.0.0.1", "10.0.0.2", 1000, 80, 300.0)
    w = 0.5 + 1.0  # the first packet has decayed by 2^-1
    mean = (0.5 * 100 + 300) / w
    var = (0.5 * 100**2 + 300**2) / w - mean**2
    assert x[0] == pytest.approx(w) and x[1] == pytest.approx(mean) and x[2] == pytest.approx(var)
    assert x[3:6] == pytest.approx(x[0:3])  # MI is keyed by the source IP, like H
    assert len(x) == 23 and N_FEATURES == 23 * len(LAMBDAS)


def test_channel_statistics_are_two_sided_and_bounded():
    fe = AfterImage()
    rng = np.random.default_rng(0)
    for i in range(200):
        fwd = i % 2 == 0
        a, b = ("10.0.0.1", "10.0.0.2") if fwd else ("10.0.0.2", "10.0.0.1")
        x = fe.update(i * 0.1, a, b, 1000 if fwd else 80, 80 if fwd else 1000, float(rng.integers(40, 1500)))
    x = np.asarray(x)
    pcc = x[[12, 22]]  # correlation of HH and HpHp at the first lambda
    assert np.all(np.abs(pcc) <= 1.0 + 1e-6) and np.all(np.isfinite(x))


def _flows():
    t = pd.Timestamp("2017-07-07 13:00")
    rows = [{"t_start": t + pd.Timedelta(minutes=m), "t_end": t + pd.Timedelta(minutes=m, seconds=5),
             "src_ip": "172.16.0.1", "dst_ip": "192.168.10.50", "dst_port": 80, "attack": "dos", "is_attack": True}
            for m in (0, 1, 2, 30, 31)]  # two episodes, 28 minutes apart
    rows.append({"t_start": t, "t_end": t, "src_ip": "192.168.10.3", "dst_ip": "8.8.8.8", "dst_port": 53,
                 "attack": "BENIGN", "is_attack": False})
    df = pd.DataFrame(rows)
    df["t_start"] = df["t_start"].astype("datetime64[us]")
    df["t_end"] = df["t_end"].astype("datetime64[us]")
    return df


def test_campaigns_labels_and_the_capture_shift():
    camps = campaigns(_flows())
    assert list(camps["episode"]) == [0, 1] and list(camps["flows"]) == [3, 2]
    t0 = camps["t0"].iloc[0]
    shift = 3 * 3600.0  # capture times are three hours behind the day file
    ts = np.array([t0 + 10, t0 + 30 * 60 + 2, t0 + 10, t0 + 5000]) - shift
    a, v, o = ip_int("172.16.0.1"), ip_int("192.168.10.50"), ip_int("192.168.10.3")
    src = np.array([a, v, o, a], dtype=np.uint32)
    dst = np.array([v, a, v, v], dtype=np.uint32)
    assert best_shift(ts, src, dst, camps) == shift
    assert list(label(ts, src, dst, camps, shift)) == [0, 1, -1, -1]


def test_variants_change_only_the_attackers_packets():
    rng = np.random.default_rng(0)
    n = 400
    pk = pd.DataFrame({"ts": np.sort(rng.uniform(0, 600, n)),
                       "src": rng.choice(["172.16.0.1", "10.0.0.7", "192.168.10.50"], n),
                       "dst": "192.168.10.50", "sport": rng.integers(1024, 65536, n).astype(np.int32),
                       "dport": np.int32(80), "proto": np.int16(6),
                       "size": rng.integers(0, 1400, n).astype(np.int64), "flags": np.int16(16)})
    benign = pk[pk["src"] != "172.16.0.1"].sort_values(["ts", "src"]).reset_index(drop=True)
    out = variants(pk, "172.16.0.1", "192.168.10.50", 80, 6, rng)
    assert [name for name, _ in out[:2]] == ["identity", "mimic"] and len(out) == 8
    for name, v in out:
        b = v[v["src"] != "172.16.0.1"].sort_values(["ts", "src"]).reset_index(drop=True)
        pd.testing.assert_frame_equal(b[benign.columns], benign, check_dtype=False, obj=name)
    m = mimic(pk, (pk["src"] == "172.16.0.1").to_numpy(), "192.168.10.50")
    sel = (pk["src"] == "172.16.0.1").to_numpy()
    assert (m.loc[sel, "size"] >= pk.loc[sel, "size"]).all()
