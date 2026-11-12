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
