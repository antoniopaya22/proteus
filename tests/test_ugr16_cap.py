import numpy as np
import pandas as pd

from proteus.datasets.ugr16 import _cap_attacks


def _df(n_att, n_bg):
    n = n_att + n_bg
    return pd.DataFrame({
        "t_end": pd.to_datetime(np.arange(n), unit="s"),
        "src_ip": [f"10.0.{i // 250}.{i % 250}" for i in range(n)],
        "dst_ip": "10.1.0.1", "src_port": np.arange(n) % 60000, "dst_port": 80,
        "is_attack": np.r_[np.ones(n_att, bool), np.zeros(n_bg, bool)],
    })


def test_cap_samples_attacks_and_keeps_background():
    df = _df(20_000, 500)
    keep = np.ones(len(df), bool)
    out = _cap_attacks(df, keep, cap=2_000, salt=0)
    att = out & df["is_attack"].to_numpy()
    assert 1_600 < att.sum() < 2_400
    assert out[~df["is_attack"].to_numpy()].all()          # background untouched
    assert (out == _cap_attacks(df, keep, cap=2_000, salt=0)).all()  # deterministic


def test_cap_is_a_no_op_below_the_cap():
    df = _df(100, 50)
    keep = np.ones(len(df), bool)
    assert (_cap_attacks(df, keep, cap=1_000, salt=0) == keep).all()
    assert (_cap_attacks(df, keep, cap=None, salt=0) == keep).all()
