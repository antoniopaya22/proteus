import numpy as np

from proteus.evaluation import h1
from proteus.evidence.features import LONG_TAUS, build, taus_for
from test_features_v2 import flows


def test_v3_adds_long_scales_and_pair_counters():
    df = flows([(0, "a", "x", 0), (10, "a", "x", 1), (20, "b", "x", 0)])
    f, specs = build(df, version="v3")
    assert taus_for("v3")[-len(LONG_TAUS):] == LONG_TAUS
    assert "dsvc__flows__t3600" in f.columns and "dsvc__flows__t21600" in f.columns
    assert "dsvc__fpkts__t600" in f.columns and "dsvc__fpkts__t3600" not in f.columns
    assert "spair__flows__t600" in f.columns and "spair__fpkts__t600" not in f.columns
    # The pair counter separates the two sources hitting the same service.
    pair = np.expm1(f["spair__flows__t21600"].to_numpy())
    svc = np.expm1(f["dsvc__flows__t21600"].to_numpy())
    assert pair[2] < 1.01 and svc[2] > 2.9
    assert {s.name: s.conservation for s in specs}["spair__noreply__t3600"] == "conserved"


def test_v3_pair_counters_never_drop_when_flows_are_added():
    base = flows([(0, "a", "x", 0), (30, "a", "x", 0), (60, "a", "x", 1)])
    more = flows([(0, "a", "x", 0), (15, "a", "x", 0), (30, "a", "x", 0), (60, "a", "x", 1)])
    f0, _ = build(base, version="v3")
    f1, _ = build(more, version="v3")
    cols = [c for c in f0.columns if c.startswith("spair__")]
    # Same original flows: rows 0, 2, 3 of the extended trace.
    assert (f1.iloc[[0, 2, 3]][cols].to_numpy() >= f0[cols].to_numpy() - 1e-6).all()


def test_v3_detectors_build_proteus_with_four_subcores():
    df = flows([(0, "a", "x", 0)])
    _, specs = build(df, version="v3")
    names = list({s.name: s.conservation for s in specs})
    spec = {s.name: s.conservation for s in specs}
    # Add baseline columns as h1 would.
    for c in names:
        if c.startswith(("dsvc__flows", "shost__flows")):
            spec[f"{c}__b"] = "baseline"
            spec[f"{c}__x"] = "conserved"
    det = h1.detectors(spec, [])
    cols, m = det["proteus"]
    assert len(m.parts) == 4
    cert_cols, _ = det["proteus_cert"]
    assert all(h1._tau(c) >= 600 for c in cert_cols)
    assert all(not c.startswith("spair__") or spec[c] == "conserved" for c in cols)
