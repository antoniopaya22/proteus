"""LaTeX tables of the paper from the outputs of ``h1``.

    python -m proteus.evaluation.tables h1 \
        --runs experiments/outputs/h1/csecicids2018__cicids2017__loo_labels \
               experiments/outputs/h1/cicids2017__csecicids2018__loo_labels \
        --extra experiments/outputs/h1/csecicids2018__cicids2017__loo_labels__cert \
                experiments/outputs/h1/cicids2017__csecicids2018__loo_labels__cert \
        --out paper/tables/h1.tex

One block of rows per run (direction); per attack type, campaigns detected over
campaigns and, in parentheses, the mean flow recall; the last rows of each block give
false alarms per hour and the median time to detection over the detected attack
types. Local thresholds only.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

DETECTORS = [  # (model in summary.csv, column header)
    ("core_mono_dst_x", "Fast"),
    ("core_cert@cert", "Cert."),
    ("core_free_dst_b", "Unc."),
    ("flow_clf", "Flow"),
    ("rate_rules_local", "Rules"),
]
ATTACK_NAMES = {
    "dos_hulk": "DoS Hulk", "dos_goldeneye": "DoS GoldenEye", "dos_slowloris": "DoS Slowloris",
    "dos_slowhttptest": "DoS Slowhttptest", "ddos_loic_http": "DDoS LOIC-HTTP",
    "ddos_loic_udp": "DDoS LOIC-UDP", "ddos_hoic": "DDoS HOIC", "portscan": "Port scan",
    "bf_ssh": "SSH brute force", "bf_ftp": "FTP brute force", "botnet": "Botnet",
    "infiltration": "Infiltration", "web_bruteforce": "Web brute force",
    "web_sqli": "Web SQLi", "web_xss": "Web XSS", "heartbleed": "Heartbleed",
}
DIRECTION = {"csecicids2018__cicids2017": r"2018$\to$2017",
             "cicids2017__csecicids2018": r"2017$\to$2018"}


def _load(runs: list[Path], extra: list[Path]) -> dict[str, tuple[pd.DataFrame, pd.DataFrame]]:
    out = {}
    for run in runs:
        key = "__".join(run.name.split("__")[:2])
        s = [pd.read_csv(run / "summary.csv")]
        f = [pd.read_csv(run / "false_alarms.csv")]
        for e in extra:
            if e.name.startswith(key):
                s.append(pd.read_csv(e / "summary.csv"))
                f.append(pd.read_csv(e / "false_alarms.csv"))
        s, f = pd.concat(s), pd.concat(f)
        s = s[s["threshold"] == "local"].drop_duplicates(["model", "target_fpr", "attack"])
        f = f[f["threshold"] == "local"].drop_duplicates(["model", "target_fpr"])
        out[key] = (s, f)
    return out


def _cell(row: pd.Series | None) -> str:
    if row is None:
        return "--"
    return f"{int(row['detected'])}/{int(row['campaigns'])} ({row['flow_recall']:.2f})"


def h1_table(runs: list[Path], extra: list[Path], fpr: float) -> str:
    """One block of rows per direction, one column per detector."""
    data = _load(runs, extra)
    lines = [r"\begin{tabular}{l" + "r" * len(DETECTORS) + "}", r"\toprule",
             "Attack & " + " & ".join(h for _, h in DETECTORS) + r" \\"]
    for key, (s, f) in data.items():
        lines += [r"\midrule",
                  rf"\multicolumn{{{1 + len(DETECTORS)}}}{{l}}{{\emph{{{DIRECTION.get(key, key)}}}}} \\"]
        for a in [a for a in ATTACK_NAMES if a in s["attack"].values]:
            cells = []
            for m, _ in DETECTORS:
                r = s[(s["model"] == m) & (s["target_fpr"] == fpr) & (s["attack"] == a)]
                cells.append(_cell(r.iloc[0] if len(r) else None))
            lines.append(f"{ATTACK_NAMES[a]} & " + " & ".join(cells) + r" \\")
        alarms, ttd = [], []
        for m, _ in DETECTORS:
            r = f[(f["model"] == m) & (f["target_fpr"] == fpr)]
            alarms.append(f"{r['alarms_per_hour'].iloc[0]:.1f}" if len(r) else "--")
            t = s[(s["model"] == m) & (s["target_fpr"] == fpr)]["median_ttd_s"].dropna()
            ttd.append(f"{np.median(t):.0f}" if len(t) else "--")
        lines.append(r"\addlinespace Alarms/h & " + " & ".join(alarms) + r" \\")
        lines.append(r"Median TTD (s) & " + " & ".join(ttd) + r" \\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("table", choices=["h1"])
    ap.add_argument("--runs", type=Path, nargs="+", required=True)
    ap.add_argument("--extra", type=Path, nargs="*", default=[],
                    help="runs with more detectors for the same direction (e.g. __cert)")
    ap.add_argument("--fpr", type=float, default=1e-3)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(h1_table(args.runs, args.extra, args.fpr))
    print(args.out.read_text())


if __name__ == "__main__":
    main()
