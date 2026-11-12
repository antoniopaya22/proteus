import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier

from proteus.core.explain import describe, explain
from proteus.evaluation.poisoning import combined


def test_explain_names_the_subcore_and_the_unusual_evidence():
    rng = np.random.default_rng(0)
    X = rng.normal(size=(3000, 3))
    y = ((X[:, 0] > 1.5) | (X[:, 2] > 1.5)).astype(int)
    a = HistGradientBoostingClassifier(max_iter=30, monotonic_cst=[1, 1]).fit(X[:, [0, 1]], y)
    b = HistGradientBoostingClassifier(max_iter=30, monotonic_cst=[1]).fit(X[:, [2]], y)
    cols, m = combined({"dst": (["dsvc__flows__t600__x", "dsvc__fbytes__t600"], a),
                        "pair": (["spair__flows__t600"], b)}, "dst|pair")
    benign = X[y == 0]
    m.fit(benign)
    alert = np.array([[0.0, 0.0, 4.0], [4.0, 0.0, 0.0]])  # pair-driven, destination-driven
    e = explain(m, cols, alert, benign, names=("destination", "pair"))
    assert e[0]["subcore"] == "pair"
    assert e[1]["subcore"] == "destination"
    assert e[0]["evidence"][0]["feature"] == "spair__flows__t600"
    assert e[1]["evidence"][0]["feature"] == "dsvc__flows__t600__x"
    assert np.isclose(e[1]["evidence"][0]["times_normal"], np.exp(4.0))
    assert "x normal" in describe(e[1])
