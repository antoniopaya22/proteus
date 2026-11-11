"""Alarms per entity on real traffic: who is alerted, how often, and why.

    python -m proteus.evaluation.alarms \
        --run experiments/outputs/h1/ctu13__ctu13__loo_labels__foldB --test ctu13 \
        --models core_both_x core_both_cert --days s05 s07 s08 s09 s11 s12 s13

``h1`` counts alarms as (day, destination host, minute) groups, which suits the
destination core but over-counts a source-side alert (one scanner alerted on many
destinations). Here every alert is attributed to the side whose sub-core gives the
maximum score (``MaxCore``) and to that side's entity (destination or source host);
an alarm is a (day, entity, ``--bucket-min`` window) group. Thresholds are local,
leave-one-day-out over the ``--days`` of the test network, as in ``h1``.

Writes ``alarms_<model>_<fpr>.csv`` (entities alerted on non-attack traffic, with a
description) and prints a summary.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from proteus.evaluation import h1

META = ["t_start", "src_ip", "dst_ip", "dst_port", "proto", "family", "clean", "suspect"]


def side_scores(model, cols: list[str], X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Score and attributed side ("src"/"dst") of every row."""
    parts = getattr(model, "parts", None)
    if not parts:
        side = "src" if all(c.startswith("shost") for c in cols) else "dst"
        return h1.score(model, X), np.full(len(X), side)
    subs, sides = [], []
    for idx, m in parts:
        subs.append(m.predict_proba(X[:, idx])[:, 1])
        sides.append("src" if all(cols[i].startswith("shost") for i in idx) else "dst")
    subs = np.vstack(subs)
    return subs.max(axis=0), np.asarray(sides)[subs.argmax(axis=0)]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", type=Path, required=True)
    ap.add_argument("--test", required=True)
    ap.add_argument("--models", nargs="+", default=["core_both_x"])
    ap.add_argument("--days", nargs="*", default=None, help="test days (stems); default all")
    ap.add_argument("--fpr", type=float, default=1e-3)
    ap.add_argument("--bucket-min", type=int, default=10)
    ap.add_argument("--top", type=int, default=25)
    args = ap.parse_args()
    models = h1.load_models(args.run)
    days = [d for d in h1.days(args.test) if args.days is None or d.stem in args.days]
    for name in args.models:
        cols, model = models[name]
        per_day = []
        for day in days:
            ev, _ = h1.evidence_b(args.test, day, columns=[*cols, *META])
            s, side = side_scores(model, cols, ev[cols].to_numpy(np.float32))
            meta = ev[META].copy()
            meta["day"], meta["score"], meta["side"] = day.stem, s, side
            per_day.append(meta)
            del ev
        rows, alerts = [], []
        for i, d in enumerate(per_day):
            ref = np.concatenate([o.loc[o["clean"] & ~o["suspect"], "score"].to_numpy()
                                  for j, o in enumerate(per_day) if j != i])
            thr = float(np.quantile(ref, 1 - args.fpr, method="higher"))
            a = d[d["score"] >= thr].copy()
            a["entity"] = np.where(a["side"] == "src", a["src_ip"].astype(str),
                                   a["dst_ip"].astype(str))
            a["bucket"] = a["t_start"].dt.floor(f"{args.bucket_min}min")
            hours = (d["t_start"].max() - d["t_start"].min()).total_seconds() / 3600
            fa = a[a["clean"] & ~a["suspect"]]
            rows.append({"day": d["day"].iloc[0], "hours": hours, "threshold": thr,
                         "flow_fpr": float((d["score"][d["clean"] & ~d["suspect"]] >= thr).mean()),
                         "alarms": fa.groupby(["side", "entity", "bucket"]).ngroups,
                         "alarms_src": fa[fa["side"] == "src"].groupby(["entity", "bucket"]).ngroups,
                         "alarms_dst": fa[fa["side"] == "dst"].groupby(["entity", "bucket"]).ngroups,
                         "entities": fa.groupby(["side", "entity"]).ngroups,
                         "suspect_entities": a[a["suspect"]].groupby(["side", "entity"]).ngroups})
            alerts.append(fa)
        summ = pd.DataFrame(rows)
        tot_h = summ["hours"].sum()
        print(f"== {name} @ FPR {args.fpr:g} (bucket {args.bucket_min} min)")
        print(summ.round(4).to_string(index=False))
        print(f"alarms/hour: {summ['alarms'].sum() / tot_h:.2f} "
              f"(src {summ['alarms_src'].sum() / tot_h:.2f}, dst {summ['alarms_dst'].sum() / tot_h:.2f}); "
              f"h1-style (dst, minute) groups would be "
              f"{sum(x.groupby(['day', 'dst_ip', x['t_start'].dt.floor('min')], observed=True).ngroups for x in alerts) / tot_h:.2f}")
        fa = pd.concat(alerts, ignore_index=True)
        if fa.empty:
            continue
        desc = fa.groupby(["side", "entity"]).agg(
            alarms=("bucket", "nunique"), flows=("score", "size"), days=("day", "nunique"),
            peers=("dst_ip", "nunique"), srcs=("src_ip", "nunique"),
            ports=("dst_port", lambda p: ",".join(map(str, p.value_counts().head(3).index))),
            family=("family", lambda f: f.value_counts().index[0])).reset_index()
        desc = desc.sort_values("alarms", ascending=False)
        desc.to_csv(args.run / f"alarms_{name}_{args.fpr:g}.csv", index=False)
        print(desc.head(args.top).to_string(index=False))


if __name__ == "__main__":
    main()
