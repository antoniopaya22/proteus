import numpy as np
import pandas as pd

from proteus.evaluation import h1


def frame():
    return pd.DataFrame({
        "is_attack": [True] * 6 + [False] * 6,
        "attack": ["hulk"] * 5 + ["ssh"] + ["benign"] * 6,
        "dst_ip": ["v"] * 6 + ["busy"] * 4 + ["a", "b"],
    })


def test_type_weights_equalise_attack_types_and_classes():
    old = dict(h1.BALANCE)
    try:
        h1.BALANCE["mode"] = "type"
        tr = frame()
        w = h1.sample_weights(tr)
        hulk, ssh = w[:5].sum(), w[5]
        assert np.isclose(hulk, ssh)
        assert np.isclose(w[:6].sum(), w[6:].sum())
        assert np.isclose(w.mean(), 1.0)
        h1.BALANCE["mode"] = "type_entity"
        w = h1.sample_weights(tr)
        busy, single = w[6:10].sum(), w[10]
        assert busy < 4 * single  # sqrt tempering: 4 flows weigh 2x one flow
        assert np.isclose(busy, 2 * single)
        h1.BALANCE["mode"] = "cap"
        assert h1.sample_weights(tr) is None
        assert h1.hgb(None).class_weight == "balanced"
        h1.BALANCE["mode"] = "none"
        assert h1.hgb(None).class_weight is None
    finally:
        h1.BALANCE.update(old)


def test_campaign_balance_weighs_campaigns_and_windows_not_flows():
    import numpy as np
    import pandas as pd

    from proteus.evaluation import h1

    t0 = pd.Timestamp("2021-03-01 10:00")
    rows = []
    # A flood: 1000 flows to one victim in one window. A slow attack: 10 flows in each of
    # two windows. Benign: 500 flows spread over two hosts.
    rows += [("d1", "dos_hulk", True, "v1", t0)] * 1000
    rows += [("d1", "dos_slowloris", True, "v2", t0)] * 10
    rows += [("d1", "dos_slowloris", True, "v2", t0 + pd.Timedelta(minutes=20))] * 10
    rows += [("d1", "benign", False, h, t0) for h in ["b1"] * 400 + ["b2"] * 100]
    tr = pd.DataFrame(rows, columns=["_day", "attack", "is_attack", "dst_ip", "t_start"])
    saved = dict(h1.BALANCE)
    h1.BALANCE["mode"] = "campaign"
    try:
        w = h1.sample_weights(tr)
    finally:
        h1.BALANCE.clear()
        h1.BALANCE.update(saved)
    hulk, slow = tr["attack"] == "dos_hulk", tr["attack"] == "dos_slowloris"
    ben = ~tr["is_attack"]
    assert np.isclose(w[hulk].sum(), w[slow].sum())            # one campaign, one share
    early = slow & (tr["t_start"] == t0)
    assert np.isclose(w[early].sum(), w[slow & ~early].sum())  # each window half of it
    assert np.isclose(w[ben].sum(), w[hulk | slow].sum())      # benign as much as attacks
    b1 = ben & (tr["dst_ip"] == "b1")
    assert np.isclose(w[b1].sum(), w[ben & ~b1].sum())         # each benign cell the same
    assert np.isclose(w.mean(), 1.0)
