import numpy as np
import pandas as pd

from proteus.evidence import baseline as bl


def test_pair_baseline_compares_with_the_services_busiest_normal_pair(monkeypatch):
    monkeypatch.setitem(bl.COUNTERS, "pairsvc", ("flows",))
    cols = bl.baseline_columns(["spair__flows__t600", "dsvc__flows__t600", "spair__fpkts__t600"])
    assert cols["pairsvc"] == ["spair__flows__t600"]
    assert bl.entity_of("spair__flows__t600") == "pairsvc"
    assert bl.entity_of("dsvc__flows__t600") == "dsvc"

    # Reference day: a DNS service whose normal client pairs are busy (log count ~6),
    # and an SSH service whose clients log in a few times (log count ~1).
    t0 = pd.Timestamp("2020-01-01")
    rows = []
    for m in range(60):
        rows.append((t0 + pd.Timedelta(minutes=m), "dns", 53, 6.0))
        rows.append((t0 + pd.Timedelta(minutes=m), "ssh", 22, 1.0))
    ref = pd.DataFrame(rows, columns=["t_end", "dst_ip", "dst_port", "spair__flows__t600"])
    ref["proto"] = 6
    ref["src_ip"] = "c"
    key = bl.entity_keys(ref)["pairsvc"]
    codes = bl.KeyCodes()
    k = pd.Series(codes.encode(key), index=ref.index)
    table = bl.day_table(ref, ["spair__flows__t600"], k, None, 60)
    base = bl.baseline([table], ["spair__flows__t600"])
    base.index = codes.index[base.index.to_numpy()]
    # Test day: the same busy DNS pair, and a brute force against SSH (log count 6).
    test = pd.DataFrame({"dst_ip": ["dns", "ssh"], "dst_port": [53, 22], "proto": [6, 6],
                         "src_ip": ["c", "attacker"], "spair__flows__t600": [6.0, 6.0]})
    kt = pd.Series(codes.encode(bl.entity_keys(test)["pairsvc"], grow=False), index=test.index)
    base_coded = base.copy()
    base_coded.index = codes.index.get_indexer(base.index)
    x = bl.attach(test, "pairsvc", ["spair__flows__t600"], kt, base_coded)
    excess = x["spair__flows__t600__x"]
    assert np.isclose(excess[0], 0.0)  # as busy as the service's normal pairs
    assert np.isclose(excess[1], 5.0)  # far above what SSH clients normally do
