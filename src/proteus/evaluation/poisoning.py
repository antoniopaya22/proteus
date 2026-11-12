"""Baseline poisoning experiment (see ``proteus.core.poisoning``).

    python -m proteus.evaluation.poisoning \
        --run experiments/outputs/h1/csecicids2018__cicids2017__loo_labels \
        --test cicids2017 --model core_mono_dst_x --rounds 8 --caps none 0.25

For every attack scenario of ``frontier_exp`` (real victim, background and campaign
shapes, local threshold): the frontier after k = 0..rounds baseline refreshes in
which the attacker poisons the whole reference period just below the current
frontier, with and without a cap on baseline growth per refresh, and the ceiling
(baseline -> infinity on every entity the attack touches). The poisoned periods
reuse the scenario's background, i.e. the reference days look like the attack day.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from proteus.core import poisoning as po
from proteus.core.combine import MaxCore
from proteus.core.frontier import frontier, nested_attack
from proteus.evaluation import h1
from proteus.evaluation.frontier_exp import (
    ATTACKS,
    FLOW_COLS,
    Baselines,
    local_threshold,
    scenarios,
)

BELOW = 0.95  # poisoning rate as a fraction of the current frontier (stays alert-free)


def combined(models: dict, name: str):
    """``a+b``: maximum of already fitted monotone models (``MaxCore``, still monotone),
    e.g. the fast core plus the raw-count core, which bounds poisoning."""
    if "+" not in name:
        return models[name]
    parts = [models[n] for n in name.split("+")]
    cols = list(dict.fromkeys(c for cs, _ in parts for c in cs))
    return cols, MaxCore(cols, parts)


def growth_stats(ds: str, caps: list[float]) -> pd.DataFrame:
    """How fast benign baselines grow: for consecutive days with causal ("prior")
    baselines, the increase b_d - b_(d-1) per (entity, counter) seen on both days, and
    the share above each cap (those baselines would be clipped by the cap, which costs
    false positives on that entity)."""
    old = dict(h1.BASELINE)
    h1.BASELINE["mode"] = "prior"
    try:
        bls = Baselines(ds)
        prev, rows = None, []
        for day in bls.days[1:]:
            cur = bls.for_day(day)
            if prev is not None:
                for ent, b in cur.items():
                    common = b.index.intersection(prev[ent].index)
                    if not len(common):
                        continue
                    d = (b.loc[common] - prev[ent].loc[common]).to_numpy().ravel()
                    nz = d[(b.loc[common].to_numpy().ravel() > 0)]
                    row = {"day": day.stem, "entity": ent, "pairs": len(nz),
                           "p50": float(np.median(nz)) if len(nz) else np.nan,
                           "p99": float(np.quantile(nz, 0.99)) if len(nz) else np.nan,
                           "max": float(nz.max()) if len(nz) else np.nan}
                    for c in caps:
                        row[f"above_{c:g}"] = float((nz > c).mean()) if len(nz) else np.nan
                    rows.append(row)
            prev = cur
    finally:
        h1.BASELINE.update(old)
    return pd.DataFrame(rows)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", type=Path, required=True)
    ap.add_argument("--test", required=True)
    ap.add_argument("--model", default="core_mono_dst_x",
                    help="a model of the run, or a+b for the maximum of several")
    ap.add_argument("--fpr", type=float, default=1e-3)
    ap.add_argument("--rounds", type=int, default=8)
    ap.add_argument("--caps", nargs="+", default=["none", "0.25"],
                    help="baseline growth caps per refresh (log1p units), 'none' = uncapped")
    ap.add_argument("--rmax", type=float, default=200.0)
    ap.add_argument("--attacks", nargs="*", default=None)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--growth-only", action="store_true",
                    help="only measure day-to-day growth of benign baselines")
    args = ap.parse_args()
    caps = [None if c == "none" else float(c) for c in args.caps]
    if args.growth_only:
        g = growth_stats(args.test, [c for c in caps if c is not None])
        g.to_csv(args.run / f"baseline_growth_{args.test}.csv", index=False)
        print(g.round(4).to_string())
        return
    rng = np.random.default_rng(args.seed)
    cols, model = combined(h1.load_models(args.run), args.model)
    _, specs = h1.evidence_b(args.test, h1.days(args.test)[0], columns=["clean"])
    wanted = args.attacks or ATTACKS

    baselines = Baselines(args.test)
    bcols = baselines.cols
    rows = []
    for day in h1.days(args.test):
        flows = pd.read_parquet(day, columns=FLOW_COLS)
        present = [a for a in wanted if (flows["is_attack"] & (flows["attack"] == a)).any()]
        if not present:
            continue
        base0 = baselines.for_day(day)
        thr = local_threshold(args.test, day, model, cols, args.fpr, rng)
        for attack, sc, A in scenarios(flows, present):
            span = max((A["t_end"].max() - A["t_start"].min()).total_seconds(), 1.0)
            t0 = sc.start
            t1 = sc.start + pd.Timedelta(seconds=sc.duration_s)
            keys = po.touched_keys(nested_attack(sc, 1.0, np.random.default_rng(0)))

            def front(base, sc=sc, thr=thr):
                return frontier(sc, model, cols, specs, base, thr,
                                np.random.default_rng(args.seed), r_max=args.rmax)

            ceil = front(po.saturate(base0, keys, bcols))
            info = {"day": day.stem, "attack": attack,
                    "target": f"{sc.target_ip}:{sc.target_port}", "threshold": thr,
                    "real_flows_per_h": len(A) / span * 3600,
                    "ceiling_flows_per_h": ceil["rate"] * 3600,
                    "ceiling_status": ceil["bounded"]}
            for cap in caps:
                base = base0
                for k in range(args.rounds + 1):
                    r = front(base)
                    rows.append({**info, "cap": "none" if cap is None else cap, "round": k,
                                 "flows_per_h": r["rate"] * 3600, "status": r["bounded"]})
                    print(rows[-1], flush=True)
                    if r["bounded"] != "ok" or k == args.rounds:
                        break
                    traffic = po.poisoning_traffic(sc, BELOW * r["rate"],
                                                   np.random.default_rng(args.seed + k))
                    levels = po.entity_levels(traffic, bcols, keys, t0, t1)
                    base = po.raise_baseline(base, levels, cap)
    out = pd.DataFrame(rows)
    out.to_csv(args.run / f"poisoning_{args.model.replace('+', '_max_')}_{args.fpr:g}.csv",
               index=False)
    piv = out.pivot_table(index=["day", "attack", "cap"], columns="round",
                          values="flows_per_h").round(0)
    print(piv.to_string())
    print(out.groupby(["day", "attack"])[["real_flows_per_h", "ceiling_flows_per_h"]]
          .first().round(0).to_string())


if __name__ == "__main__":
    main()
