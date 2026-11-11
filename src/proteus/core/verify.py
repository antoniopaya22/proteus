"""Empirical check that a trained model respects its monotonic constraints.

The constraint is enforced by the learner; this test guards against wiring errors
(wrong column order, wrong sign, a feature silently left unconstrained), which would
void the guarantee without changing accuracy.
"""

from __future__ import annotations

import numpy as np


def monotonicity_violations(predict, X: np.ndarray, cst: np.ndarray, rng: np.random.Generator,
                            n_rows: int = 2000, deltas=(0.1, 1.0, 5.0), tol: float = 1e-9) -> dict:
    """Count score changes against the constraint direction.

    For every row, constrained feature and delta, move the feature in its
    "more evidence" direction (+delta if cst=+1, -delta if cst=-1) and check the
    score does not drop. Also checks joint moves of all constrained features.
    """
    rows = X[rng.choice(len(X), min(n_rows, len(X)), replace=False)].astype(np.float64)
    base = predict(rows)
    cols = np.flatnonzero(cst != 0)
    checks = violations = 0
    worst = 0.0
    for d in deltas:
        for j in cols:
            Z = rows.copy()
            Z[:, j] += d * cst[j]
            drop = base - predict(Z)
            valid = ~np.isnan(rows[:, j])
            checks += int(valid.sum())
            violations += int((drop[valid] > tol).sum())
            worst = max(worst, float(np.nanmax(np.where(valid, drop, -np.inf))))
        Z = rows + d * np.where(cst != 0, cst, 0)[None, :]
        drop = base - predict(Z)
        checks += len(rows)
        violations += int((drop > tol).sum())
        worst = max(worst, float(drop.max()))
    return {"checks": checks, "violations": violations, "worst_drop": worst}
