"""Classic rate-based baselines on the test network: TRW (scans) and SYN-flood CUSUM.

    python -m proteus.evaluation.classic --test cicids2017 --entity-budgets 0.5 1 3 10

They need no training network. Thresholds are set as for the other local detectors:
the quantile of the scores of clean benign flows on the *other* days of the test
network, or the alarm budget on those days. Output has the format of an H1 run
(``campaigns.csv``, ``summary.csv``, ``false_alarms.csv``) in
``<out>/classic__<test>[__tag]``.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from proteus.baselines.classic import syn_cusum_scores, trw_scores
from proteus.evaluation import h1

SOURCE_SIDE = ("trw", "trw_svc")  # detectors whose alerts are about the source host


def day_scores(ds: str, day: Path) -> tuple[pd.DataFrame, dict[str, np.ndarray]]:
    """Metadata (with ``clean``) and the score of every flow of one day."""
    import pyarrow.parquet as pq

    names = pq.read_schema(h1._bdir(ds) / day.name).names
    cols = [*h1.META, "clean"] + (["suspect"] if "suspect" in names else [])
    ev, _ = h1.evidence_b(ds, day, columns=cols)
    raw = pd.read_parquet(day, columns=["bwd_pkts", "f_bwd_rst_flags"])
    if len(raw) != len(ev):
        raise SystemExit(f"{ds}/{day.stem}: flows and evidence have different rows")
    # A failed connection: no answer, or refused (reset by the responder).
    failed = ((raw["bwd_pkts"].to_numpy() == 0)
              | (raw["f_bwd_rst_flags"].fillna(0).to_numpy() > 0))
    t = ev["t_end"].to_numpy()
    src, dst = ev["src_ip"].astype(str).to_numpy(), ev["dst_ip"].astype(str).to_numpy()
    svc = pd.util.hash_pandas_object(ev[["dst_ip", "dst_port", "proto"]].astype(str),
                                     index=False).to_numpy()
    scores = {
        "trw": trw_scores(t, src, dst, failed),
        # The same walk over first contacts with services (host, port): vertical scans
        # of one host, which the original host-level test cannot see.
        "trw_svc": trw_scores(t, src, svc, failed),
        "syn_cusum": syn_cusum_scores(t, ev["dst_ip"].astype(str).to_numpy(), failed),
    }
    return ev, scores


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--test", required=True)
    ap.add_argument("--out", type=Path, default=Path("experiments/outputs/h1"))
    ap.add_argument("--tag", default="")
    ap.add_argument("--test-days", nargs="*", default=None)
    ap.add_argument("--entity-budgets", nargs="*", type=float, default=[])
    args = ap.parse_args()
    out = args.out / ("classic__" + args.test + (f"__{args.tag}" if args.tag else ""))
    out.mkdir(parents=True, exist_ok=True)
    h1.write_manifest(out, args)
    days = [d for d in h1.days(args.test) if not args.test_days or d.stem in args.test_days]
    kept: dict = {}
    for day in days:  # pass 1: clean scores of every day (references of the others)
        ev, scores = day_scores(args.test, day)
        clean = ev["clean"].to_numpy()
        key = pd.util.hash_array(ev["dst_ip"].astype(str).to_numpy()).astype(np.uint64)
        skey = pd.util.hash_array(ev["src_ip"].astype(str).to_numpy()).astype(np.uint64)
        minute = (ev["t_start"].astype("int64") // 60_000_000).to_numpy().astype(np.uint64)
        hours = (ev["t_end"].max() - ev["t_start"].min()).total_seconds() / 3600
        kept[day] = ({n: s[clean] for n, s in scores.items()}, key[clean], minute[clean], hours,
                     skey[clean])
        print(f"  scored {args.test}/{day.stem}", flush=True)
    results = []
    for day in days:  # pass 2
        others = [d for d in days if d != day]
        ev, scores = day_scores(args.test, day)
        th = {}
        for n in scores:
            ref = np.concatenate([kept[d][0][n] for d in others])
            for fpr in h1.FPRS:
                # strictly above the quantile: these scores have many ties (0, floor)
                th[(n, fpr, "local")] = np.nextafter(np.quantile(ref, 1 - fpr), np.inf)
            # an alarm is about the alerted entity: the source for the scan detectors
            ent = 4 if n in SOURCE_SIDE else 1
            tops = [(kept[d][0][n], kept[d][ent], kept[d][2]) for d in others]
            for b in args.entity_budgets:
                th[(n, b, "entity")] = h1.entity_threshold(
                    tops, sum(kept[d][3] for d in others), b)
        sides = {n: np.full(len(ev), n in SOURCE_SIDE) for n in scores}
        results.append(h1.evaluate(ev, scores, th, sides))
        print(f"  evaluated {args.test}/{day.stem}", flush=True)
    res = pd.concat(results, ignore_index=True)
    res.to_csv(out / "campaigns.csv", index=False)
    summary = (res[res["attack"] != h1.NO_CAMPAIGN]
               .groupby(["model", "target_fpr", "threshold", "attack"], observed=True)
               .agg(campaigns=("detected", "size"), detected=("detected", "sum"),
                    detected_strict=("detected_strict", "sum"),
                    flow_recall=("flow_recall", "mean"), median_ttd_s=("ttd_s", "median"))
               .reset_index())
    summary.to_csv(out / "summary.csv", index=False)
    fa = (res.groupby(["model", "target_fpr", "threshold", "day"], observed=True)
          [["benign_fpr", "alarms_per_hour", "entity_alarms_per_hour"]]
          .first().groupby(level=[0, 1, 2]).mean())
    fa.to_csv(out / "false_alarms.csv")
    print(summary.to_string())
    print(fa.to_string())


if __name__ == "__main__":
    main()
