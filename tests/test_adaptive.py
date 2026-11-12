import numpy as np
import pandas as pd

from proteus.evaluation.adaptive import Scored, mimic


def test_mimic_only_adds_and_reaches_benign_medians():
    bg = pd.DataFrame({"fwd_pkts": [10, 10, 12], "fwd_bytes": [1000, 1200, 1200]})
    df = pd.DataFrame({"fwd_pkts": [2, 20, 5], "fwd_bytes": [100, 5000, 50],
                       "_atk": [True, True, False]})
    out = mimic(df, bg)
    assert (out["fwd_pkts"] >= df["fwd_pkts"]).all()
    assert (out["fwd_bytes"] >= df["fwd_bytes"]).all()
    assert out.loc[0, "fwd_pkts"] == 10 and out.loc[0, "fwd_bytes"] >= 10 * 100
    assert out.loc[1, "fwd_pkts"] == 20 and out.loc[1, "fwd_bytes"] == 5000  # already above
    assert out.loc[2].equals(df.loc[2])  # benign flows untouched


def test_scored_exposes_score_as_column_one():
    class M:
        def score(self, X):
            return X.sum(axis=1)

    p = Scored(M()).predict_proba(np.array([[1.0, 2.0], [0.5, 0.0]]))
    assert np.allclose(p[:, 1], [3.0, 0.5])
