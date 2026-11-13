"""Multidimensional comparison of defences, following METIS (Arroni et al., in review).

    python -m proteus.evaluation.bench \
        --h1 experiments/outputs/h1/csecicids2018__cicids2017__loo_labels__v3 \
             experiments/outputs/h1/csecicids2018__cicids2017__loo_labels__v3_kitnet \
        --adaptive experiments/outputs/h1/csecicids2018__cicids2017__loo_labels__v3/adaptive_0.001.csv \
        --out experiments/outputs/bench/18_17.csv

Every defence gets a score in [0, 1] per dimension (1 = best), each anchored to
declared or empirical references, and the dimensions are combined as METIS does:

* **detection**: share of campaigns detected, volumetric attacks and scans on one side
  and the rest on the other, averaged (already on an absolute scale, like utility in
  METIS: 0 = nothing detected, 1 = everything);
* **false alarms**: alarms per hour on benign traffic, on a log scale between 0 alarms
  (score 1) and ``ALARM_LIMIT`` per hour (score 0: one per minute is more than a
  team can triage);
* **robustness**: per attack, how much of its real rate the attacker keeps when it
  adapts (rate and free operations, ``evaluation.adaptive``), on a log scale between
  the real rate (score 0: the attack passes unchanged) and the lowest rate tried
  (score 1); attacks are combined with ``ssd``, so the weakest attacks dominate, since
  security is a worst-case property.

The composite is ``ssd`` (lambda = 3) over the dimensions: a dimension at zero is
barely offset by the others, so a detector that detects everything but can be evaded
for free cannot rank first. The Pareto front over the dimensions is reported too, and
is the first reading; the composite only orders within it.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

ALARM_LIMIT = 60.0  # alarms/h at which the false-alarm score reaches 0
LAMBDA = 3.0  # risk aversion of ssd, as fixed in METIS
VOLUMETRIC = ("dos_", "ddos_", "portscan")
RMIN_PER_H = 1e-3 * 3600  # lowest rate tried by evaluation.adaptive (flows/h)
NAMES = {
    "proteus": "Proteus", "proteus_cert@cert": "Proteus (cert.\\ alerts)",
    "proteus_cert": "Proteus certified core", "core_free_dst_b": "Unconstrained core",
    "rate_rules_local": "Rate thresholds", "kitnet_local": "KitNET",
    "flow_clf": "Per-flow classifier", "core_mono_dst_x": "Monotone core (single)",
}


def ssd(x, lam: float = LAMBDA, w=None) -> float:
    """Second-order stochastic dominance aggregator (exponential certainty
    equivalent): the mean for lam -> 0, the minimum for lam -> inf."""
    x = np.asarray(x, dtype=float)
    x = x[~np.isnan(x)]
    if len(x) == 0:
        return np.nan
    w = np.full(len(x), 1 / len(x)) if w is None else np.asarray(w, float) / np.sum(w)
    return float(-np.log(np.sum(w * np.exp(-lam * x))) / lam)


def alarm_score(alarms_per_hour: float, limit: float = ALARM_LIMIT) -> float:
    return float(np.clip(1 - np.log1p(alarms_per_hour) / np.log1p(limit), 0, 1))


def damage_score(real_per_h: float, damage_per_h: float, rmin_per_h: float = RMIN_PER_H) -> float:
    """1 if the attacker must drop to the lowest rate tried, 0 if it keeps its real rate."""
    if damage_per_h <= rmin_per_h:
        return 1.0
    if damage_per_h >= real_per_h:
        return 0.0
    return float(np.log(real_per_h / damage_per_h) / np.log(real_per_h / rmin_per_h))


def pareto(scores: pd.DataFrame) -> pd.Series:
    """True for the rows no other row beats on every column (higher is better)."""
    v = scores.to_numpy(float)
    front = []
    for i in range(len(v)):
        others = np.delete(v, i, axis=0)
        dominated = np.any(np.all(others >= v[i], axis=1) & np.any(others > v[i], axis=1))
        front.append(not dominated)
    return pd.Series(front, index=scores.index)


def detection_alarms(runs: list[Path], fpr: float) -> pd.DataFrame:
    rows = {}
    for run in runs:
        c = pd.read_csv(run / "campaigns.csv")
        c = c[(c["threshold"] == "local") & (c["target_fpr"] == fpr)]
        for m, g in c.groupby("model"):
            if m in rows:
                continue
            g = g.drop_duplicates(["day", "attack", "flows"])
            vol = g["attack"].str.startswith(VOLUMETRIC)
            per_day = g.drop_duplicates("day")["alarms_per_hour"]
            rows[m] = {"det_volumetric": g.loc[vol, "detected"].mean(),
                       "det_other": g.loc[~vol, "detected"].mean(),
                       "alarms_per_hour": per_day.mean()}
    return pd.DataFrame(rows).T


def robustness(adaptive: list[Path]) -> pd.DataFrame:
    a = pd.concat([pd.read_csv(p) for p in adaptive], ignore_index=True)
    a["score"] = [damage_score(r, d) for r, d in zip(a["real_flows_per_h"],
                                                      a["adaptive_flows_per_h"])]
    out = a.groupby("detector").agg(robustness=("score", ssd),
                                    robustness_mean=("score", "mean"),
                                    attacks=("score", "size"))
    if "certified_flows_per_h" in a:
        cert = a.dropna(subset=["certified_flows_per_h"]).copy()
        cert["score"] = [damage_score(r, d) for r, d in zip(cert["real_flows_per_h"],
                                                             cert["certified_flows_per_h"])]
        out = out.join(cert.groupby("detector")["score"].agg(ssd).rename("robustness_certified"))
        # Certified alerts (``model@cert`` in the h1 runs) are robust to the certified
        # damage: the worst case over every combination of free operations.
        c = out["robustness_certified"].dropna().rename("robustness").to_frame()
        c.index = c.index + "@cert"
        out = pd.concat([out, c])
    return out


def bench(runs: list[Path], adaptive: list[Path], fpr: float,
          detectors: list[str] | None = None) -> pd.DataFrame:
    d = detection_alarms(runs, fpr)
    if detectors:
        d = d.loc[[m for m in detectors if m in d.index]]
    # Left join: a defence without an adaptive run keeps its row, with no composite.
    t = d.join(robustness(adaptive), how="left") if adaptive else d
    t["detection"] = t[["det_volumetric", "det_other"]].mean(axis=1)
    t["false_alarms"] = t["alarms_per_hour"].map(alarm_score)
    dims = ["detection", "false_alarms"] + (["robustness"] if adaptive else [])
    full = t[dims].notna().all(axis=1)
    t["composite"] = t[dims].apply(lambda r: ssd(r.to_numpy()), axis=1).where(full)
    t["mean_composite"] = t[dims].mean(axis=1).where(full)
    t["pareto"] = False
    if full.any():
        t.loc[full, "pareto"] = pareto(t.loc[full, dims])
    return t.sort_values("composite", ascending=False)


def latex(t: pd.DataFrame, dims: list[str]) -> str:
    cols = ["detection", "false_alarms", "robustness", "composite"]
    cols = [c for c in cols if c in t.columns]
    head = {"detection": "Det.", "false_alarms": "Alarms",
            "robustness": "Robust.", "composite": "$A_3$"}
    lines = [r"\begin{tabular}{l" + "r" * len(cols) + "c}", r"\toprule",
             "Defence & " + " & ".join(head[c] for c in cols) + r" & Pareto \\", r"\midrule"]
    for m, r in t.iterrows():
        cells = [f"{r[c]:.2f}" if pd.notna(r[c]) else "--" for c in cols]
        lines.append(f"{NAMES.get(m, m)} & " + " & ".join(cells)
                     + (r" & $\bullet$ \\" if r["pareto"] else r" & \\"))
    lines += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--h1", type=Path, nargs="+", required=True,
                    help="h1 run directories (first one wins for a repeated model)")
    ap.add_argument("--adaptive", type=Path, nargs="*", default=[])
    ap.add_argument("--fpr", type=float, default=1e-3)
    ap.add_argument("--detectors", nargs="*", default=None,
                    help="defences to compare (default: every model found)")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    t = bench(args.h1, args.adaptive, args.fpr, args.detectors)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    t.to_csv(args.out)
    dims = ["detection", "false_alarms"] + (["robustness"] if args.adaptive else [])
    args.out.with_suffix(".tex").write_text(latex(t, dims))
    print(t.round(3).to_string())


if __name__ == "__main__":
    main()
