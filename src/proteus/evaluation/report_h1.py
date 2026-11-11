"""Print H1 tables: campaign detection per attack and model, and false alarms.

    python -m proteus.evaluation.report_h1 experiments/outputs/h1
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

MODELS = ["core_mono_strict", "core_mono_dst", "core_mono_dst@cert", "core_mono_dst_x",
          "core_mono_dst_x@cert", "core_cert", "core_cert@cert", "core_mono_dst_b",
          "core_mono_dst_b@cert", "core_mono_full", "core_free", "core_free_dst_b",
          "rate_rules", "rate_rules_local", "flow_clf"]


def report(run: Path, threshold: str = "local") -> str:
    s = pd.read_csv(run / "summary.csv")
    fa = pd.read_csv(run / "false_alarms.csv")
    lines = [f"== {run.name}  (threshold: {threshold})"]
    for fpr in sorted(s["target_fpr"].unique(), reverse=True):
        sub = s[(s["target_fpr"] == fpr) & (s["threshold"] == threshold)]
        cell = sub.assign(v=sub["detected"].astype(str) + "/" + sub["campaigns"].astype(str)
                          + " " + sub["flow_recall"].map("{:.2f}".format))
        tab = cell.pivot(index="attack", columns="model", values="v")
        tab = tab[[m for m in MODELS if m in tab.columns]]
        f = fa[(fa["target_fpr"] == fpr) & (fa["threshold"] == threshold)].set_index("model")
        tab.loc["benign FPR"] = [f"{f.loc[m, 'benign_fpr']:.1e}" for m in tab.columns]
        tab.loc["alarms/hour"] = [f"{f.loc[m, 'alarms_per_hour']:.1f}" for m in tab.columns]
        lines += [f"-- target FPR {fpr:g}  (campaigns detected | mean flow recall)",
                  tab.to_string(), ""]
    return "\n".join(lines)


if __name__ == "__main__":
    root = Path(sys.argv[1])
    for run in sorted(p for p in root.iterdir() if p.is_dir()):
        for th in ("local", "train"):
            print(report(run, th))
