"""Why did an entity alert? Walk down the core, as METIS walks down its hierarchy.

For an alerted flow: which sub-core gave the maximum (destination, source, pair, raw),
and within it the evidence that is most unusual on local benign traffic, with its
percentile and, for excess features, how many times the entity's normal it is. The
core is monotone, so these features can only push the score up: they are the evidence
the analyst should look at first.
"""

from __future__ import annotations

import numpy as np

SUBCORE_NAMES = ("destination", "source", "pair", "raw destination")


def _parts(model, cols: list[str]):
    parts = getattr(model, "parts", None)
    if not parts:
        return [(np.arange(len(cols)), model)]
    return parts


def explain(model, cols: list[str], X: np.ndarray, ref: np.ndarray, top: int = 3,
            names=SUBCORE_NAMES) -> list[dict]:
    """One explanation per row of ``X``. ``ref`` is a benign sample with the same
    columns, used to place every feature value as a percentile."""
    parts = _parts(model, cols)
    refs = getattr(model, "ref_", None)
    sub = []
    for j, (idx, m) in enumerate(parts):
        s = m.predict_proba(X[:, idx])[:, 1]
        if refs is not None:  # calibrated maximum: compare on the benign CDF
            s = np.searchsorted(refs[j], s, side="right") / len(refs[j])
        sub.append(s)
    sub = np.vstack(sub)
    win = sub.argmax(axis=0)
    ref_sorted = np.sort(ref, axis=0)
    out = []
    for i in range(len(X)):
        idx = np.asarray(parts[win[i]][0])
        pct = np.array([np.searchsorted(ref_sorted[:, j], X[i, j], side="right")
                        / len(ref_sorted) for j in idx])
        order = np.argsort(-pct, kind="stable")[:top]
        feats = []
        for o in order:
            j = idx[o]
            f = {"feature": cols[j], "value": float(X[i, j]), "benign_percentile": float(pct[o])}
            if cols[j].endswith("__x"):
                f["times_normal"] = float(np.exp(X[i, j]))  # log1p excess -> ratio
            feats.append(f)
        out.append({"subcore": names[win[i]] if len(parts) > 1 and win[i] < len(names)
                    else "core", "subcore_scores": sub[:, i].round(4).tolist(),
                    "evidence": feats})
    return out


def describe(e: dict) -> str:
    """One-line text of an explanation, for alert reports."""
    parts = []
    for f in e["evidence"]:
        name = f["feature"].replace("__", " ")
        if "times_normal" in f:
            parts.append(f"{name}: {f['times_normal']:.0f}x normal")
        else:
            parts.append(f"{name}: p{100 * f['benign_percentile']:.2f}")
    return f"[{e['subcore']}] " + "; ".join(parts)
