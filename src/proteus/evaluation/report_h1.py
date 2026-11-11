"""Print H1 tables: campaign detection per attack and model, and false alarms.

    python -m proteus.evaluation.report_h1 experiments/outputs/h1
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import pandas as pd

MODELS = ["core_mono_strict", "core_mono_dst", "core_mono_dst@cert", "core_mono_dst_x",
          "core_mono_dst_x@cert", "core_cert", "core_cert@cert", "core_src_x", "core_both_x", "core_both_x@cert",
          "core_both_cert", "core_both_cert@cert", "core_mono_dst_b",
          "core_mono_dst_b@cert", "core_mono_full", "core_free", "core_free_dst_b",
          "rate_rules", "rate_rules_local", "flow_clf"]


def _family(attack: str) -> str:
    """CTU-13 campaigns are named ctu<scenario>_<behaviour>: group by behaviour."""
    m = re.match(r"ctu\d+_(\w+)$", attack)
    return m.group(1) if m else attack


def report(run: Path, threshold: str = "local", by_family: bool = False,
           models: list[str] | None = None) -> str:
    s = pd.read_csv(run / "summary.csv")
    if by_family:
        s = (s.assign(attack=s["attack"].map(_family))
             .groupby(["model", "target_fpr", "threshold", "attack"], as_index=False)
             .agg(campaigns=("campaigns", "sum"), detected=("detected", "sum"),
                  flow_recall=("flow_recall", "mean")))
    if models:
        s = s[s["model"].isin(models)]
    fa = pd.read_csv(run / "false_alarms.csv")
    lines = [f"== {run.name}  (threshold: {threshold})"]
    for fpr in sorted(s["target_fpr"].unique(), reverse=True):
        sub = s[(s["target_fpr"] == fpr) & (s["threshold"] == threshold)]
        cell = sub.assign(v=sub["detected"].astype(str) + "/" + sub["campaigns"].astype(str)
                          + " " + sub["flow_recall"].map("{:.2f}".format))
        tab = cell.pivot(index="attack", columns="model", values="v")
        order = models or MODELS
        tab = tab[[m for m in order if m in tab.columns]]
        f = fa[(fa["target_fpr"] == fpr) & (fa["threshold"] == threshold)].set_index("model")
        tab.loc["benign FPR"] = [f"{f.loc[m, 'benign_fpr']:.1e}" for m in tab.columns]
        tab.loc["alarms/hour"] = [f"{f.loc[m, 'alarms_per_hour']:.1f}" for m in tab.columns]
        if "suspect_sources" in f.columns and f["suspect_sources"].max() > 0:
            tab.loc["suspect src det."] = [
                f"{int(f.loc[m, 'suspect_detected'])}/{int(f.loc[m, 'suspect_sources'])}"
                for m in tab.columns]
        lines += [f"-- target FPR {fpr:g}  (campaigns detected | mean flow recall)",
                  tab.to_string(), ""]
    return "\n".join(lines)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("runs", type=Path, nargs="+",
                    help="run directories, or a parent directory holding them")
    ap.add_argument("--threshold", default="local")
    ap.add_argument("--by-family", action="store_true")
    ap.add_argument("--models", nargs="*", default=None)
    a = ap.parse_args()
    runs = []
    for r in a.runs:
        runs += [r] if (r / "summary.csv").exists() else sorted(
            p for p in r.iterdir() if (p / "summary.csv").exists())
    for run in runs:
        print(report(run, a.threshold, a.by_family, a.models))
