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

DETECTOR_SETS = {
    "v1": [("core_mono_dst_x", "Fast"), ("core_cert@cert", "Cert."),
           ("core_free_dst_b", "Unc."), ("flow_clf", "Flow"), ("rate_rules_local", "Rules")],
    "v3": [("proteus", "Proteus"), ("proteus_cert@cert", "Cert."),
           ("core_free_dst_b", "Unc."), ("rate_rules_local", "Rules"),
           ("kitnet_local", "KitNET"), ("flow_clf", "Flow")],
}
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


VOLUMETRIC = ("dos_", "ddos_", "portscan")


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval of a proportion k/n."""
    if n == 0:
        return (np.nan, np.nan)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def bootstrap_mean(x: np.ndarray, n: int = 2000, seed: int = 0) -> tuple[float, float]:
    """95% percentile bootstrap interval of a mean (resampling days)."""
    x = np.asarray(x, dtype=float)
    if len(x) < 2:
        return (np.nan, np.nan)
    rng = np.random.default_rng(seed)
    m = rng.choice(x, (n, len(x)), replace=True).mean(axis=1)
    return (float(np.quantile(m, 0.025)), float(np.quantile(m, 0.975)))


def summary_table(runs: list[Path], extra: list[Path], fpr: float,
                  detectors=None) -> pd.DataFrame:
    """Per detector and direction: campaigns detected (volumetric and scans / other)
    with Wilson intervals, and alarms per hour with a bootstrap interval over days."""
    rows = []
    for run in runs:
        key = "__".join(run.name.split("__")[:2])
        c = [pd.read_csv(run / "campaigns.csv")]
        c += [pd.read_csv(e / "campaigns.csv") for e in extra if e.name.startswith(key)]
        c = pd.concat(c)
        c = c[(c["threshold"] == "local") & (c["target_fpr"] == fpr)]
        for m, g in c.groupby("model"):
            if detectors and m not in detectors:
                continue
            g = g.drop_duplicates(["day", "attack", "flows"])
            vol = g["attack"].str.startswith(VOLUMETRIC)
            row = {"direction": DIRECTION.get(key, key), "model": m}
            for part, sel in (("volumetric", vol), ("other", ~vol)):
                k, n = int(g.loc[sel, "detected"].sum()), int(sel.sum())
                lo, hi = wilson(k, n)
                row.update({f"{part}_detected": k, f"{part}_campaigns": n,
                            f"{part}_lo": lo, f"{part}_hi": hi})
            per_day = g.drop_duplicates("day")["alarms_per_hour"].to_numpy()
            lo, hi = bootstrap_mean(per_day)
            row.update({"alarms_per_hour": float(per_day.mean()), "alarms_lo": lo,
                        "alarms_hi": hi, "days": len(per_day)})
            rows.append(row)
    return pd.DataFrame(rows)


SUBCORES = ["destination", "source", "pair", "raw destination"]


def ablation_table(runs: list[Path], fpr: float, base: str = "proteus") -> str:
    """Full calibrated maximum against the same without each sub-core: campaigns
    detected (volumetric and scans / other) and alarms per hour, per direction."""
    from proteus.evaluation.bench import detection_alarms

    lines = [r"\begin{tabular}{lrrr}", r"\toprule",
             r"Variant & Volumetric & Other & Alarms/h \\"]
    for run in runs:
        key = "__".join(run.name.split("__")[:2])
        d = detection_alarms([run], fpr)
        lines += [r"\midrule", rf"\multicolumn{{4}}{{l}}{{\emph{{{DIRECTION.get(key, key)}}}}} \\"]
        names = [(base, "All sub-cores")] + [(f"{base}-{k}", f"without {s}")
                                             for k, s in enumerate(SUBCORES)]
        for m, label in names:
            if m not in d.index:
                continue
            r = d.loc[m]
            lines.append(f"{label} & {r['det_volumetric']:.2f} & {r['det_other']:.2f} & "
                         f"{r['alarms_per_hour']:.1f} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(lines) + "\n"


def frontier_table(csvs: list[Path], data_out: Path | None = None) -> str:
    """Certified harm frontier against the real campaign rate, one block per test
    network (one ``frontier_*_attr.csv`` per direction). Optionally writes the data of
    the dumbbell figure (attack, real, plain, certified) for pgfplots."""
    lines = [r"\begin{tabular}{lrrrr}", r"\toprule",
             r"Attack & Real rate & Frontier & Certified & Factor \\"]
    fig = []
    for path in csvs:
        d = pd.read_csv(path)
        key = "__".join(path.parent.name.split("__")[:2])
        lines += [r"\midrule", rf"\multicolumn{{5}}{{l}}{{\emph{{{DIRECTION.get(key, key)}}}}} \\"]
        for _, r in d.iterrows():
            name = ATTACK_NAMES.get(r["attack"], r["attack"])
            if (d["attack"] == r["attack"]).sum() > 1:
                name += f" ({r['day'][:3].title()}.)"
            cert = r["certified_flows_per_h"]
            fac = r["real_flows_per_h"] / cert if np.isfinite(cert) and cert > 0 else np.nan
            fmt = lambda v: "--" if not np.isfinite(v) else f"{v:,.0f}".replace(",", "\\,")
            lines.append(f"{name} & {fmt(r['real_flows_per_h'])} & {fmt(r['plain_flows_per_h'])} & "
                         f"{fmt(cert)} & " + (f"{fac:,.1f}" if np.isfinite(fac) and fac >= 1
                                              else "--") + r" \\")
            fig.append({"direction": key, "attack": name, "real": r["real_flows_per_h"],
                        "plain": r["plain_flows_per_h"], "certified": cert})
    lines += [r"\bottomrule", r"\end{tabular}"]
    if data_out is not None:
        pd.DataFrame(fig).replace([np.inf, -np.inf], np.nan).to_csv(data_out, index=False)
    return "\n".join(lines) + "\n"


def frontier_system_table(runs: list[Path], fpr: float = 1e-3,
                          data_out: Path | None = None) -> str:
    """Frontier of the deployed system, which alerts when proteus (every scale) or
    proteus_cert alerts: the plain frontier is the lower of their plain frontiers
    (the attack as it ran, no free operations), the certified frontier the lower of
    their certified ones (every combination of free operations is alerted above it).
    Factor: how many times slower than the real campaign the attack must run; ``--``
    when the real campaign already ran below the frontier."""
    lines = [r"\begin{tabular}{lrrrrr}", r"\toprule",
             r"& & \multicolumn{2}{c}{Plain} & \multicolumn{2}{c}{Certified} \\",
             r"\cmidrule(lr){3-4}\cmidrule(lr){5-6}",
             r"Attack & Real rate & Frontier & Factor & Frontier & Factor \\"]
    fig = []
    fmt = lambda v: "--" if not np.isfinite(v) else f"{v:,.0f}".replace(",", "\\,")
    fac = lambda real, v: (f"{real / v:,.1f}" if np.isfinite(v) and v > 0 and real / v >= 1
                           else "--")
    for run in runs:
        parts = {m: pd.read_csv(run / f"frontier_{m}_{fpr}_attr.csv")
                 for m in ("proteus", "proteus_cert")
                 if (run / f"frontier_{m}_{fpr}_attr.csv").exists()}
        if not parts:
            continue
        key = "__".join(run.name.split("__")[:2])
        lines += [r"\midrule", rf"\multicolumn{{6}}{{l}}{{\emph{{{DIRECTION.get(key, key)}}}}} \\"]
        idx = ["day", "attack", "target"]
        d = None
        for m, f in parts.items():
            f = f.set_index(idx)[["real_flows_per_h", "plain_flows_per_h",
                                   "certified_flows_per_h"]].add_suffix(f"_{m}")
            d = f if d is None else d.join(f, how="outer")
        first = pd.MultiIndex.from_frame(next(iter(parts.values()))[idx])
        d = d.reindex(first.append(d.index.difference(first))).reset_index()
        for _, r in d.iterrows():
            name = ATTACK_NAMES.get(r["attack"], r["attack"])
            if (d["attack"] == r["attack"]).sum() > 1:
                name += f" ({r['day'][:3].title()}.)"
            real = np.nanmax([r.get(f"real_flows_per_h_{m}", np.nan) for m in parts])
            plain = np.nanmin([r.get(f"plain_flows_per_h_{m}", np.nan) for m in parts])
            cert = np.nanmin([r.get(f"certified_flows_per_h_{m}", np.nan) for m in parts])
            lines.append(f"{name} & {fmt(real)} & {fmt(plain)} & {fac(real, plain)} & "
                         f"{fmt(cert)} & {fac(real, cert)} \\\\")
            fig.append({"direction": key, "attack": name, "real": real, "plain": plain,
                        "certified": cert})
    lines += [r"\bottomrule", r"\end{tabular}"]
    if data_out is not None:
        pd.DataFrame(fig).replace([np.inf, -np.inf], np.nan).to_csv(data_out, index=False)
    return "\n".join(lines) + "\n"


ADAPTIVE = [("proteus", "Proteus", "adaptive_flows_per_h"),
            ("proteus_cert", "Cert.", "adaptive_flows_per_h"),
            ("proteus_cert", "Certified", "certified_flows_per_h"),
            ("core_free_dst_b", "Unc.", "adaptive_flows_per_h"),
            ("rate_rules_local", "Rules", "adaptive_flows_per_h"),
            ("kitnet_local", "KitNET", "adaptive_flows_per_h")]


def _rate(v: float, rmax: float) -> str:
    """Compact flows/h: 614, 1.2k, 15k; the highest rate tried as >=720k."""
    if not np.isfinite(v):
        return "--"
    ge = r"$\geq$" if v >= rmax else ""
    if v < 1000:
        return f"{ge}{v:.0f}"
    return f"{ge}{v / 1000:.1f}k" if v < 10_000 else f"{ge}{v / 1000:.0f}k"


def adaptive_table(csvs: list[Path]) -> str:
    """Damage under the adaptive attacker: the highest rate (flows/h) at which each
    attack raises no attributable alert of its own, when the attacker also picks its
    free operations, per detector; one block per direction. Bold: the attack passes at
    its real rate. a: free operations or mimicry raised the damage over the plain attack."""
    n = len(ADAPTIVE)
    lines = [r"\begin{tabular}{l" + "r" * (n + 1) + "}", r"\toprule",
             "Attack & Real & " + " & ".join(h for _, h, _ in ADAPTIVE) + r" \\"]
    for path in csvs:
        d = pd.read_csv(path)
        key = "__".join(path.parent.name.split("__")[:2])
        lines += [r"\midrule", rf"\multicolumn{{{n + 2}}}{{l}}{{\emph{{{DIRECTION.get(key, key)}}}}} \\"]
        attacks = d.drop_duplicates(["day", "attack"])[["day", "attack", "real_flows_per_h"]]
        for _, a in attacks.iterrows():
            name = ATTACK_NAMES.get(a["attack"], a["attack"])
            if (attacks["attack"] == a["attack"]).sum() > 1:
                name += f" ({a['day'][:3].title()}.)"
            g = d[(d["day"] == a["day"]) & (d["attack"] == a["attack"])].set_index("detector")
            cells = []
            for m, _, col in ADAPTIVE:
                if m not in g.index:
                    cells.append("--")
                    continue
                r = g.loc[m]
                v = float(r[col])
                c = _rate(v, float(r["rmax_flows_per_h"]))
                if np.isfinite(v) and v >= a["real_flows_per_h"]:
                    c = rf"\textbf{{{c}}}"
                if (col == "adaptive_flows_per_h" and isinstance(r["best_plan"], str)
                        and r["best_plan"] != "plain"):
                    c += r"$^a$"
                cells.append(c)
            lines.append(f"{name} & {_rate(a['real_flows_per_h'], np.inf)} & "
                         + " & ".join(cells) + r" \\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("table", choices=["h1", "summary", "ablation", "frontier", "frontier_system",
                                       "adaptive"])
    ap.add_argument("--csv", type=Path, nargs="*", default=[], help="frontier or adaptive CSVs")
    ap.add_argument("--data-out", type=Path, default=None)
    ap.add_argument("--detectors", nargs="*", default=None)
    ap.add_argument("--base", default="proteus", help="ablation: the full model")
    ap.add_argument("--set", choices=sorted(DETECTOR_SETS), default="v1",
                    help="detector columns of the h1 table")
    ap.add_argument("--runs", type=Path, nargs="*", default=[])
    ap.add_argument("--extra", type=Path, nargs="*", default=[],
                    help="runs with more detectors for the same direction (e.g. __cert)")
    ap.add_argument("--fpr", type=float, default=1e-3)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    if args.table == "summary":
        t = summary_table(args.runs, args.extra, args.fpr, args.detectors)
        t.to_csv(args.out, index=False)
        print(t.round(3).to_string())
        return
    if args.table == "frontier":
        args.out.write_text(frontier_table(args.csv, args.data_out))
        print(args.out.read_text())
        return
    if args.table == "adaptive":
        args.out.write_text(adaptive_table(args.csv))
        print(args.out.read_text())
        return
    if args.table == "frontier_system":
        args.out.write_text(frontier_system_table(args.runs, args.fpr, args.data_out))
        print(args.out.read_text())
        return
    if args.table == "ablation":
        args.out.write_text(ablation_table(args.runs, args.fpr, args.base))
        print(args.out.read_text())
        return
    DETECTORS[:] = DETECTOR_SETS[args.set]
    args.out.write_text(h1_table(args.runs, args.extra, args.fpr))
    print(args.out.read_text())


if __name__ == "__main__":
    main()
