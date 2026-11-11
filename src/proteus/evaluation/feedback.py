"""Feedback of shell alerts into the core: calibration of the per-source counter (H5).

    python -m proteus.evaluation.feedback \
        --run experiments/outputs/h1/cicids2017__csecicids2018__loo_labels --test csecicids2018

In inline mode every flow the shell blocks is evidence the sender cannot take back.
The core keeps, per source host, the decayed count of shell alerts
``F_s(t) = sum_i exp(-(t - t_i)/tau)`` and alerts the source when ``F_s >= K``. This is
monotone in the attacker's blocked probes, so a query attack against the shell gets
a source blocked after about ``K`` blocked probes within ``tau``.

K is set on the benign traffic of the test network: for each K, the number of
(source, 10-minute) alarms per hour caused by the shell's false positives. The
script prints that curve; dividing an attack's blocked queries per successful
evasion (``aml_feature``) by K gives the number of sources it burns.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from proteus.evaluation import h1

KS = (1, 2, 3, 5, 10, 20, 50, 100, 200, 500)
TAUS = (60.0, 600.0, 3600.0)


def decayed_counts(src: np.ndarray, t: np.ndarray, tau: float) -> np.ndarray:
    """Counter value right after each event (events sorted by time)."""
    out = np.empty(len(t))
    last: dict = {}
    for i, (s, ti) in enumerate(zip(src, t)):
        v, tp = last.get(s, (0.0, ti))
        v = v * np.exp(-(ti - tp) / tau) + 1.0
        last[s] = (v, ti)
        out[i] = v
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", type=Path, required=True)
    ap.add_argument("--test", required=True)
    ap.add_argument("--model", default="flow_clf")
    ap.add_argument("--block", type=float, default=0.5, help="shell score that blocks a flow")
    args = ap.parse_args()
    cols, model = h1.load_models(args.run)[args.model]
    hours, fp_rows, stats = 0.0, [], []
    for day in h1.days(args.test):
        ev, _ = h1.evidence_b(args.test, day, columns=["t_start", "t_end", "src_ip", "clean",
                                                       "is_attack"])
        flow = h1.flow_features(day).add_prefix("flow__")
        s = model.predict_proba(flow[cols].to_numpy(np.float32))[:, 1]
        blocked = s >= args.block
        clean = ev["clean"].to_numpy()
        hours += (ev["t_end"].max() - ev["t_start"].min()).total_seconds() / 3600
        stats.append({"day": day.stem, "flows": len(ev), "clean": int(clean.sum()),
                      "fp": int((blocked & clean).sum()),
                      "fpr": float(blocked[clean].mean()) if clean.any() else np.nan,
                      "attack_blocked": float(blocked[ev["is_attack"].to_numpy()].mean())
                      if ev["is_attack"].any() else np.nan})
        fp = ev.loc[blocked & clean, ["t_end", "src_ip"]].sort_values("t_end", kind="stable")
        fp["day"] = day.stem
        fp_rows.append(fp)
        print(stats[-1], flush=True)
        del ev, flow
    fp = pd.concat(fp_rows, ignore_index=True)
    t = fp["t_end"].astype("int64").to_numpy() / 1e6
    src = fp["src_ip"].astype(str).to_numpy()
    bucket = fp["t_end"].dt.floor("10min")
    rows = []
    for tau in TAUS:
        c = decayed_counts(src, t, tau)
        for k in KS:
            hit = c >= k
            alarms = fp[hit].groupby([fp["day"][hit], src[hit], bucket[hit]]).ngroups
            rows.append({"tau_s": tau, "K": k, "alarms_per_hour": alarms / hours,
                         "sources": int(pd.unique(src[hit]).size)})
    curve = pd.DataFrame(rows)
    print(pd.DataFrame(stats).to_string(index=False))
    print(f"hours {hours:.1f}, shell false positives {len(fp):,} from "
          f"{pd.unique(src).size:,} sources")
    print(curve.pivot(index="K", columns="tau_s", values="alarms_per_hour").round(3).to_string())
    curve.to_csv(args.run / f"feedback_{args.model}_{args.test}.csv", index=False)


if __name__ == "__main__":
    main()
