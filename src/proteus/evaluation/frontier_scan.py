"""Harm frontier of horizontal scans (source side), e.g. the CTU-13 botnet scans.

    python -m proteus.evaluation.frontier_scan \
        --run experiments/outputs/h1/ctu13__ctu13__loo_labels__foldB \
        --test ctu13 --model core_both_x --fpr 1e-3

For every day with a scan campaign: template = the probes of the busiest scanning
source (destinations and ports kept), replayed from one fresh source at rate r over
the real traffic towards the same destinations. Reports the frontier in probes and
distinct destinations per minute, plus the rate the real bot used.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from proteus.core.frontier import Scenario, frontier
from proteus.evaluation import h1
from proteus.evaluation.frontier_exp import FLOW_COLS, Baselines, local_threshold

WINDOW_S = 3600.0
ATTACKER = "198.51.100.7"  # TEST-NET-2: a source with no history


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", type=Path, required=True)
    ap.add_argument("--test", required=True)
    ap.add_argument("--model", default="core_both_x")
    ap.add_argument("--family", default="portscan")
    ap.add_argument("--fpr", type=float, default=1e-3)
    ap.add_argument("--delta", type=float, default=h1.EXPORT_TIMEOUT_S)
    ap.add_argument("--rmax", type=float, default=200.0, help="highest rate tried (probes/s)")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--hours", type=float, default=WINDOW_S / 3600,
                    help="duration of the replayed scan (long time scales need hours)")
    args = ap.parse_args()
    window_s = args.hours * 3600
    rng = np.random.default_rng(args.seed)
    cols, model = h1.load_models(args.run)[args.model]
    _, specs = h1.evidence_b(args.test, h1.days(args.test)[0], columns=["clean"])
    baselines = Baselines(args.test)
    rows = []
    for day in h1.days(args.test):
        flows = pd.read_parquet(day, columns=FLOW_COLS)
        A = flows[flows["is_attack"] & (flows["family"] == args.family)]
        if A.empty:
            continue
        bot = A["src_ip"].value_counts().index[0]
        A = A[A["src_ip"] == bot]
        span = max((A["t_end"].max() - A["t_start"].min()).total_seconds(), 1.0)
        start = A["t_start"].min()
        dsts = set(A["dst_ip"].unique())
        lo, hi = start - pd.Timedelta(hours=1), start + pd.Timedelta(seconds=window_s + 3600)
        bg = flows[~flows["is_attack"] & flows["dst_ip"].isin(dsts)
                   & (flows["t_end"] >= lo) & (flows["t_start"] <= hi)]
        bg = bg.drop(columns=["attack", "family", "is_attack"])
        template = A.drop(columns=["attack", "family", "is_attack"])
        sc = Scenario(bg, template, "", 0, 0, start, window_s, src_ip=ATTACKER,
                      keep_ports=True, keep_dst=True)
        base = baselines.for_day(day)
        if getattr(model, "local", False):  # calibrated maximum: fit on local benign
            from proteus.evaluation.poisoning import local_benign

            model.fit(local_benign(args.test, day, cols, rng))
        thr = local_threshold(args.test, day, model, cols, args.fpr, rng)
        row = {"day": day.stem, "bot": bot, "threshold": thr, "probes": len(A),
               "distinct_dsts": len(dsts), "background_flows": len(bg),
               "real_probes_per_min": len(A) / span * 60,
               "real_dsts_per_min": A["dst_ip"].nunique() / span * 60,
               "top_ports": A["dst_port"].value_counts().head(3).to_dict()}
        for kind, delta in (("plain", None), ("certified", args.delta)):
            r = frontier(sc, model, cols, specs, base, thr, np.random.default_rng(args.seed),
                         r_max=args.rmax, delta_s=delta)
            row[f"{kind}_probes_per_min"] = r["rate"] * 60
            row[f"{kind}_status"] = r["bounded"]
        rows.append(row)
        print(row, flush=True)
    out = pd.DataFrame(rows)
    out.to_csv(args.run / f"frontier_scan_{args.model}_{args.fpr:g}_{args.hours:g}h.csv",
               index=False)
    print(out.to_string())


if __name__ == "__main__":
    main()
