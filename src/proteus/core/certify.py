"""Certification of alerts for a monotone core.

Free attacker operations either only add evidence (exact) or move the moment a
flow's packets are accounted (splitting a flow exports its pieces earlier;
appending packets exports it later). With a flow exporter whose active timeout is
Δ, every packet is accounted between its send time and Δ after it, in any variant
of the trace. Then, for a decayed counter with time constant τ, the evidence of
any variant X' at time t + Δ satisfies

    E_X'(t + Δ) >= exp(-2Δ/τ) · E_X(t),

and on the log1p scale used by the features, log1p(E') >= log1p(E) - 2Δ/τ.
Distinct counts obey the same bound (each item's last-seen time moves by <= Δ).
Baselines are fixed during scoring and need no slack.

Because the model is monotone, the worst case over all such variants is one model
evaluation: score(x - slack). An alert is *certified* if that score still exceeds
the threshold; every free-operation variant then alerts by Δ later.
"""

from __future__ import annotations

import re

import numpy as np

_TAU = re.compile(r"__t(\d+)")


def slack(names: list[str], conservation: dict[str, str], delta_s: float) -> np.ndarray:
    """Per-feature slack 2Δ/τ in the direction of less evidence (0 for baselines)."""
    out = np.zeros(len(names))
    for j, n in enumerate(names):
        if conservation[n] == "baseline":
            continue
        m = _TAU.search(n)
        if m is None:
            raise ValueError(f"feature {n!r} has no time constant")
        out[j] = 2.0 * delta_s / float(m.group(1))
    return out


def worst_case_features(X: np.ndarray, cst: np.ndarray, s: np.ndarray) -> np.ndarray:
    """Move every constrained feature by its slack against the evidence direction."""
    return X - np.where(cst > 0, s, 0.0)[None, :] + np.where(cst < 0, s, 0.0)[None, :]
