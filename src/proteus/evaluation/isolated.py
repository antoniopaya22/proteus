"""Detection of each campaign with the other attacks of the day removed.

    python -m proteus.evaluation.isolated \
        --run experiments/outputs/h1/csecicids2018__cicids2017__loo_labels__r2 \
        --test cicids2017 --models proteus proteus_cert

Several campaigns of the benchmarks hit the same victim one after another, and the
evidence counters reach back up to six hours: an alert during a campaign could rest on
evidence left by the previous one. Here every campaign is scored on the traffic of its
day *without* the flows of any other attack, so its detection is its own. Only the
flows that share a source or a destination host with the campaign are kept, which is
all its evidence depends on. Thresholds are local, as in ``h1``.

Reports, per campaign and detector, detection in place (every attack present, as in
``h1``) and isolated, with the strict criterion, the flow recall and the time to
detection.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from proteus.core.frontier import _features
from proteus.evaluation import h1
from proteus.evaluation.frontier_exp import FLOW_COLS, Baselines, local_threshold
from proteus.evaluation.poisoning import combined, local_benign


def _measure(alert: np.ndarray, t_end: pd.Series, start: pd.Timestamp) -> dict:
    ttd = (t_end[alert].min() - start).total_seconds() if alert.any() else np.nan
    return {"detected": bool(alert.any()),
            "detected_strict": bool(alert.sum() >= h1.STRICT_MIN_FLOWS
                                    and alert.mean() >= h1.STRICT_MIN_RECALL),
            "flow_recall": float(alert.mean()), "ttd_s": ttd}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--run", type=Path, required=True)
    ap.add_argument("--test", required=True)
    ap.add_argument("--models", nargs="+", default=["proteus", "proteus_cert"])
    ap.add_argument("--fpr", type=float, default=1e-3)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    rng = np.random.default_rng(args.seed)
    fitted = h1.load_models(args.run)
    dets = {n: combined(fitted, n) for n in args.models}
    baselines = Baselines(args.test)
    rows = []
    for day in h1.days(args.test):
        flows = pd.read_parquet(day, columns=[*FLOW_COLS, "day"])
        camps = h1.campaigns(flows)
        if not camps:
            continue
        base = baselines.for_day(day)
        thr = {}
        for n, (cols, m) in dets.items():
            if getattr(m, "local", False):
                m.fit(local_benign(args.test, day, cols, rng))
            thr[n] = local_threshold(args.test, day, m, cols, args.fpr, rng)
        attack_rows = flows["is_attack"].to_numpy()
        for _, attack, idx in camps:
            A = flows.loc[idx]
            near = (flows["dst_ip"].isin(set(A["dst_ip"])) | flows["src_ip"].isin(set(A["src_ip"]))
                    ).to_numpy()
            mine = np.zeros(len(flows), dtype=bool)
            mine[flows.index.get_indexer(idx)] = True
            start = A["t_start"].min()
            for label, keep in (("in_place", near), ("isolated", near & (mine | ~attack_rows))):
                sub = flows[keep].sort_values("t_end", kind="stable")
                is_mine = mine[keep][np.argsort(flows.loc[keep, "t_end"].to_numpy(), kind="stable")]
                sub = sub.drop(columns=["attack", "family", "is_attack", "day"]).reset_index(drop=True)
                for n, (cols, m) in dets.items():
                    X = _features(sub, cols, base)[cols].to_numpy(np.float64)
                    alert = (m.predict_proba(X)[:, 1] >= thr[n])[is_mine]
                    rows.append({"day": day.stem, "attack": attack, "flows": len(idx),
                                 "model": n, "setting": label,
                                 **_measure(alert, sub.loc[is_mine, "t_end"].reset_index(drop=True),
                                            start)})
            print(f"  {day.stem} {attack} ({len(idx):,} flows)", flush=True)
    out = pd.DataFrame(rows)
    out.to_csv(args.run / f"isolated_{args.fpr:g}.csv", index=False)
    wide = out.pivot_table(index=["day", "attack", "flows", "model"], columns="setting",
                           values=["detected_strict", "flow_recall", "ttd_s"], aggfunc="first")
    print(wide.round(3).to_string())
    g = out.groupby(["model", "setting"])["detected_strict"].agg(["sum", "size"])
    print(g.to_string())


if __name__ == "__main__":
    main()
