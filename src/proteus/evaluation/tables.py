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
    # Revision 2: the deployed system, alerts certified also against connection reuse,
    # and the unconstrained counterpart of the same sub-cores.
    "r2": [("proteus", "Proteus"), ("proteus_sys_r", "System"), ("proteus_cert@cert", "Cert."),
           ("proteus_cert_r@certr", "Cert.-R"), ("proteus_free", "Unc."),
           ("rate_rules_local", "Rules"), ("kitnet_local", "KitNET"), ("flow_clf", "Flow"),
           ("apollon", "Apollon")],
    # The paper: the system (the fast detector or the certified one), its two members
    # (of the certified one, the alerts certified also against connection reuse) and
    # the detectors it is compared with.
    "paper": [("proteus_pcr", r"\sysname"), ("proteus", "Fast"),
              ("proteus_cert_r@certr", "Cert."), ("proteus_free", "Unc."),
              ("rate_rules_local", "Rules"), ("rate_rules_sel", "Sel."),
              ("kitnet_local", "KitNET"), ("flow_clf", "Flow"), ("apollon", "Apollon")],
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
    """Campaigns detected (strict criterion when the run has it) and mean flow recall."""
    if row is None:
        return "--"
    det = row["detected_strict"] if pd.notna(row.get("detected_strict", np.nan)) else row["detected"]
    return f"{int(det)}/{int(row['campaigns'])} ({row['flow_recall']:.2f})"


def h1_table(runs: list[Path], extra: list[Path], fpr: float,
             entity_alarms: bool = False) -> str:
    """One block of rows per direction, one column per detector. ``entity_alarms``:
    alarms per alerted entity and ten-minute window first, then per (destination,
    minute)."""
    data = _load(runs, extra)
    present = set().union(*(set(s["model"]) for s, _ in data.values()))
    dets = [d for d in DETECTORS if d[0] in present]  # detectors without a run: no column
    lines = [r"\begin{tabular}{l" + "r" * len(dets) + "}", r"\toprule",
             "Attack & " + " & ".join(h for _, h in dets) + r" \\"]
    for key, (s, f) in data.items():
        lines += [r"\midrule",
                  rf"\multicolumn{{{1 + len(dets)}}}{{l}}{{\emph{{{DIRECTION.get(key, key)}}}}} \\"]
        for a in [a for a in ATTACK_NAMES if a in s["attack"].values]:
            cells = []
            for m, _ in dets:
                r = s[(s["model"] == m) & (s["target_fpr"] == fpr) & (s["attack"] == a)]
                cells.append(_cell(r.iloc[0] if len(r) else None))
            lines.append(f"{ATTACK_NAMES[a]} & " + " & ".join(cells) + r" \\")
        alarms, entity, ttd = [], [], []
        for m, _ in dets:
            r = f[(f["model"] == m) & (f["target_fpr"] == fpr)]
            alarms.append(f"{r['alarms_per_hour'].iloc[0]:.1f}" if len(r) else "--")
            entity.append(f"{r['entity_alarms_per_hour'].iloc[0]:.2f}"
                          if len(r) and "entity_alarms_per_hour" in r else "--")
            t = s[(s["model"] == m) & (s["target_fpr"] == fpr)]["median_ttd_s"].dropna()
            ttd.append(f"{np.median(t):.0f}" if len(t) else "--")
        if entity_alarms:
            lines.append(r"\addlinespace Alarms/h (entity) & " + " & ".join(entity) + r" \\")
            lines.append(r"Alarms/h (dst., min.) & " + " & ".join(alarms) + r" \\")
        else:
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
            per_day_all = g.drop_duplicates("day")["alarms_per_hour"]  # benign-only days too
            g = g[g["attack"] != "(none)"]
            vol = g["attack"].str.startswith(VOLUMETRIC)
            row = {"direction": DIRECTION.get(key, key), "model": m}
            for part, sel in (("volumetric", vol), ("other", ~vol)):
                k, n = int(g.loc[sel, "detected"].sum()), int(sel.sum())
                lo, hi = wilson(k, n)
                row.update({f"{part}_detected": k, f"{part}_campaigns": n,
                            f"{part}_lo": lo, f"{part}_hi": hi})
            per_day = per_day_all.to_numpy()
            lo, hi = bootstrap_mean(per_day)
            row.update({"alarms_per_hour": float(per_day.mean()), "alarms_lo": lo,
                        "alarms_hi": hi, "days": len(per_day)})
            rows.append(row)
    return pd.DataFrame(rows)


SUBCORES = ["destination", "source", "pair", "raw destination"]


def ablation_table(runs: list[Path], fpr: float, base: str = "proteus") -> str:
    """Full calibrated maximum against the same without each sub-core: campaigns
    detected (volumetric and scans / other) and false alarms per alerted entity and
    hour (per destination and minute in runs that lack them), per direction."""
    from proteus.evaluation.bench import detection_alarms

    lines = [r"\begin{tabular}{lrrr}", r"\toprule",
             r"Variant & Volumetric & Other & Alarms/h \\"]
    for run in runs:
        key = "__".join(run.name.split("__")[:2])
        d = detection_alarms([run], fpr)
        fa = pd.read_csv(run / "false_alarms.csv")
        fa = fa[(fa["threshold"] == "local") & (fa["target_fpr"] == fpr)]
        if "entity_alarms_per_hour" in fa:
            ent = fa.drop_duplicates("model").set_index("model")["entity_alarms_per_hour"]
            d["alarms_per_hour"] = ent.reindex(d.index).fillna(d["alarms_per_hour"])
        lines += [r"\midrule", rf"\multicolumn{{4}}{{l}}{{\emph{{{DIRECTION.get(key, key)}}}}} \\"]
        names = [(base, "All sub-cores")] + [(f"{base}-{k}", f"without {s}")
                                             for k, s in enumerate(SUBCORES)]
        for m, label in names:
            if m not in d.index:
                continue
            r = d.loc[m]
            lines.append(f"{label} & {r['det_volumetric']:.2f} & {r['det_other']:.2f} & "
                         f"{r['alarms_per_hour']:.2f} \\\\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(lines) + "\n"


BUDGET_ROWS = [("entity", 0.5, "Budget 0.5"), ("entity", 1.0, "Budget 1"), ("entity", 3.0, "Budget 3"),
               ("entity", 10.0, "Budget 10"), ("local", 1e-3, r"FPR $10^{-3}$"),
               ("local", 1e-4, r"FPR $10^{-4}$")]
BUDGET_PAPER = [("proteus_pcr", r"\sysname"), ("proteus", "Fast"), ("proteus_cert_r", "Cert."),
                ("proteus_free", "Unc."), ("rate_rules_local", "Rules"), ("rate_rules_sel", "Sel.")]


def budget_table(runs: list[Path], extra: list[Path],
                 detectors: list[tuple[str, str]] | None = None) -> str:
    """Every threshold evaluated, per direction: campaigns detected under the strict
    criterion, volumetric and scans + others, and in parentheses the false alarms per
    alerted entity and hour. ``runs`` gives one run per direction; ``extra`` adds
    detectors that it lacks (a detector is read from the first run that has it)."""
    from proteus.evaluation.bench import VOLUMETRIC

    detectors = detectors or BUDGET_PAPER
    n = len(detectors)
    lines = [r"\begin{tabular}{l" + "r" * n + "}", r"\toprule",
             "Threshold & " + " & ".join(h for _, h in detectors) + r" \\"]
    for run in runs:
        key = "__".join(run.name.split("__")[:2])
        dirs = [run] + [e for e in extra if e.name.startswith(key)]
        s = pd.concat([pd.read_csv(d / "summary.csv").assign(_run=i) for i, d in enumerate(dirs)])
        fa = pd.concat([pd.read_csv(d / "false_alarms.csv").assign(_run=i) for i, d in enumerate(dirs)])
        first = s.groupby("model")["_run"].min()
        s = s[s["_run"] == s["model"].map(first)]
        fa = fa[fa["_run"] == fa["model"].map(first)]
        s = s.assign(vol=s["attack"].str.startswith(VOLUMETRIC))
        lines += [r"\midrule", rf"\multicolumn{{{n + 1}}}{{l}}{{\emph{{{DIRECTION.get(key, key)}}}}} \\"]
        for kind, target, label in BUDGET_ROWS:
            cells = []
            for m, _ in detectors:
                g = s[(s["model"] == m) & (s["threshold"] == kind) & np.isclose(s["target_fpr"], target)]
                a = fa[(fa["model"] == m) & (fa["threshold"] == kind) & np.isclose(fa["target_fpr"], target)]
                if g.empty or a.empty:
                    cells.append("--")
                    continue
                vol, other = (int(g.loc[g["vol"] == v, "detected_strict"].sum()) for v in (True, False))
                cells.append(f"{vol}+{other} ({a['entity_alarms_per_hour'].iloc[0]:.2f})")
            lines.append(f"{label} & " + " & ".join(cells) + r" \\")
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
# The paper: the system (a union, from the per-rate ladder), its two detectors, the
# certified damage of the certified one, and the detectors it is compared with.
ADAPTIVE_PAPER = [("proteus+proteus_cert_r", r"\sysname", "union"),
                  ("proteus", "Fast", "adaptive_flows_per_h"),
                  ("proteus_cert_r", "Cert.", "adaptive_flows_per_h"),
                  ("proteus_cert_r", "Certified", "certified_flows_per_h"),
                  ("proteus_free", "Unc.", "adaptive_flows_per_h"),
                  ("rate_rules_local", "Rules", "adaptive_flows_per_h"),
                  ("rate_rules_sel", "Sel.", "adaptive_flows_per_h"),
                  ("kitnet_local", "KitNET", "adaptive_flows_per_h")]


def _rate(v: float, rmax: float) -> str:
    """Compact flows/h: 614, 1.2k, 15k; the highest rate tried as >=720k."""
    if not np.isfinite(v):
        return "--"
    ge = r"$\geq$" if v >= rmax else ""
    if v < 1000:
        return f"{ge}{v:.0f}"
    return f"{ge}{v / 1000:.1f}k" if v < 10_000 else f"{ge}{v / 1000:.0f}k"


def adaptive_table(csvs: list[Path], columns: list[tuple[str, str, str]] | None = None) -> str:
    """Damage under the adaptive attacker: the highest rate (flows/h) at which each
    attack raises no attributable alert of its own, when the attacker also picks its
    free operations, per detector; one block per direction. Bold: the attack passes at
    its real rate. a: free operations or mimicry raised the damage over the plain attack.
    A column of kind ``union`` (members joined by ``+``) is read from the ladder file
    next to each CSV: a plan must leave every member quiet at the same rate."""
    columns = columns or ADAPTIVE
    n = len(columns)
    lines = [r"\begin{tabular}{l" + "r" * (n + 1) + "}", r"\toprule",
             "Attack & Real & " + " & ".join(h for _, h, _ in columns) + r" \\"]
    for path in csvs:
        d = pd.read_csv(path)
        unions = {}
        if any(col == "union" for _, _, col in columns):
            ladder = pd.read_csv(path.with_name(path.name.replace("adaptive_", "adaptive_ladder_", 1)))
            for m, _, col in columns:
                if col == "union":
                    unions[m] = (ladder_damage(ladder, m.split("+")),
                                 ladder_damage(ladder[ladder["plan"] == "plain"], m.split("+")))
        key = "__".join(path.parent.name.split("__")[:2])
        lines += [r"\midrule", rf"\multicolumn{{{n + 2}}}{{l}}{{\emph{{{DIRECTION.get(key, key)}}}}} \\"]
        attacks = d.drop_duplicates(["day", "attack"])[["day", "attack", "real_flows_per_h"]]
        for _, a in attacks.iterrows():
            name = ATTACK_NAMES.get(a["attack"], a["attack"])
            if (attacks["attack"] == a["attack"]).sum() > 1:
                name += f" ({a['day'][:3].title()}.)"
            g = d[(d["day"] == a["day"]) & (d["attack"] == a["attack"])].set_index("detector")
            cells = []
            rmax = float(g["rmax_flows_per_h"].iloc[0])
            for m, _, col in columns:
                if col == "union":
                    best, plain = (s.get((a["day"], a["attack"]), np.nan) for s in unions[m])
                    c = _rate(float(best), rmax)
                    if np.isfinite(best) and best >= a["real_flows_per_h"]:
                        c = rf"\textbf{{{c}}}"
                    cells.append(c + (r"$^a$" if best > plain else ""))
                    continue
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


def ladder_damage(ladder: pd.DataFrame, members: list[str], costly: bool = False) -> pd.Series:
    """Damage of a union of detectors from the ladder of ``evaluation.adaptive``: the
    highest rate (flows/h) of each (day, attack) at which some plan leaves every member
    quiet. ``costly``: plans that spread the attack over sources count too."""
    d = ladder[ladder["detector"].isin(members)]
    q = (d.groupby(["day", "attack", "plan", "flows_per_h"])
         .agg(det=("detected", "max"), n=("detector", "nunique")).reset_index())
    q = q[(q["n"] == len(set(members))) & ~q["det"].astype(bool)]
    if not costly:
        q = q[~q["plan"].str.startswith("spread")]
    every = ladder.drop_duplicates(["day", "attack"]).set_index(["day", "attack"]).index
    return q.groupby(["day", "attack"])["flows_per_h"].max().reindex(every).fillna(0.0)


QUERY = [("proteus", "Proteus"), ("proteus_sys_r", "System"), ("proteus_cert_r", "Cert.-R"),
         ("rate_rules_local", "Rules"), ("rate_rules_sel", "Sel. rules")]
# The paper: the system is the union that the query attacker was run against (``pcr``).
QUERY_PAPER = [("pcr", r"\sysname"), ("proteus", "Fast"), ("proteus_cert_r", "Cert."),
               ("rate_rules_local", "Rules"), ("rate_rules_sel", "Sel.")]


def query_table(csvs: list[Path], targets: list[tuple[str, str]] | None = None) -> str:
    """Damage under the query attacker: the highest rate (flows/h) at which an attempt
    passed without an alert, per target; one block per direction. Bold: the attack
    passes at its real rate. s: only by spreading over sources (the costly search). c:
    the largest attack tried was reached, so the figure is a lower bound."""
    targets = targets or QUERY
    n = len(targets)
    lines = [r"\begin{tabular}{l" + "r" * (n + 1) + "}", r"\toprule",
             "Attack & Real & " + " & ".join(h for _, h in targets) + r" \\"]
    for path in csvs:
        d = pd.read_csv(path)
        key = "__".join(path.parent.name.split("__")[:2])
        lines += [r"\midrule", rf"\multicolumn{{{n + 2}}}{{l}}{{\emph{{{DIRECTION.get(key, key)}}}}} \\"]
        attacks = d.drop_duplicates(["day", "attack"])[["day", "attack", "real_flows_per_h"]]
        for _, a in attacks.iterrows():
            name = ATTACK_NAMES.get(a["attack"], a["attack"])
            if (attacks["attack"] == a["attack"]).sum() > 1:
                name += f" ({a['day'][:3].title()}.)"
            g = d[(d["day"] == a["day"]) & (d["attack"] == a["attack"])]
            cells = []
            for m, _ in targets:
                t = g[g["target"] == m]
                if t.empty:
                    cells.append("--")
                    continue
                free = t.loc[~t["costly"].astype(bool), "query_flows_per_h"].max()
                best = t["query_flows_per_h"].max()  # the costly search includes the free one
                free = 0.0 if not np.isfinite(free) else float(free)
                c = _rate(float(best), float(t["rmax_flows_per_h"].iloc[0]))
                if best >= a["real_flows_per_h"]:
                    c = rf"\textbf{{{c}}}"
                if best > free:
                    c += r"$^s$"
                if "capped" in t and t["capped"].astype(bool).any():
                    c += r"$^c$"
                cells.append(c)
            lines.append(f"{name} & {_rate(a['real_flows_per_h'], np.inf)} & "
                         + " & ".join(cells) + r" \\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    return "\n".join(lines) + "\n"


CURVE_STYLE = {  # detector -> (legend, pgfplots style)
    "proteus": (r"\sysname", "color=pblue, mark=*, line width=1.1pt"),
    "proteus_sys": (r"\sysname{} $\cup$ \sysname-cert", "color=pnavy, mark=square*"),
    "proteus_sys_r": ("system", "color=pnavy, mark=square, densely dashed"),
    "proteus_pcr": (r"\sysname", "color=pnavy, mark=square*, line width=1.1pt"),
    "proteus_cert_r": ("reuse-safe sub-cores", "color=pgreen, mark=triangle*"),
    "proteus2_sys": (r"\sysname-2 system", "color=pgreen, mark=triangle, densely dashed"),
    "rate_rules_local": ("rate thresholds", "color=porange, mark=o"),
    "rate_rules_sel": ("selected rate thresholds", "color=porange, mark=square, densely dashed"),
    "proteus_free": ("unconstrained core", "color=pgrey, mark=x, densely dashed"),
    "kitnet_local": ("KitNET", "color=porange, mark=diamond, densely dotted"),
    "syn_cusum": ("failed-flow CUSUM", "color=pgrey, mark=+, densely dotted"),
    "trw_svc": ("TRW (services)", "color=pgrey, mark=asterisk, densely dotted"),
}


def curve_points(runs: list[Path], detected: str = "detected_strict") -> pd.DataFrame:
    """Operating points of every detector of the runs: realised alarms per alerted
    entity and hour against volumetric and scan campaigns detected, at every local
    FPR and alarm budget evaluated."""
    rows = []
    for run in runs:
        name = run.name.removeprefix("classic__")
        key = next((k for k in DIRECTION if name.startswith(k)), None)
        if key is None:  # classic baselines are named after the test network only
            key = next(k for k in DIRECTION if k.endswith("__" + name.split("__")[0]))
        s = pd.read_csv(run / "summary.csv")
        fa = pd.read_csv(run / "false_alarms.csv")
        col = detected if detected in s else "detected"
        s = s[s["attack"].str.startswith(VOLUMETRIC)
              & ~s["threshold"].str.contains("+", regex=False)]
        g = (s.groupby(["model", "target_fpr", "threshold"])
             .agg(detected=(col, "sum"), campaigns=("campaigns", "sum"),
                  recall=("flow_recall", "mean")).reset_index())
        g = g.merge(fa[["model", "target_fpr", "threshold", "alarms_per_hour",
                        "entity_alarms_per_hour"]], on=["model", "target_fpr", "threshold"])
        g.insert(0, "direction", key)
        rows.append(g)
    out = pd.concat(rows, ignore_index=True)
    return out.drop_duplicates(["direction", "model", "target_fpr", "threshold"])


def curves_figure(points: pd.DataFrame, x: str = "entity_alarms_per_hour",
                  detectors: list[str] | None = None) -> str:
    """pgfplots figure: campaigns detected against alarms per hour, one panel per
    direction. Each curve is the best detection reached at or below each alarm rate.
    ``detectors`` restricts and orders the curves (default: every known detector)."""
    unknown = sorted(set(detectors or ()) - set(CURVE_STYLE))
    if unknown:
        raise ValueError(f"no curve style for {unknown}")
    styles = {m: CURVE_STYLE[m] for m in (detectors or CURVE_STYLE)}
    if detectors and "proteus_pcr" in styles and "proteus" in styles:
        # Next to the system, the detector on every time scale is its fast member.
        styles["proteus"] = (r"\sysname-fast", "color=pblue, mark=*")
    lines = ["% Detection against alarms per alerted entity and hour (tables.py curves).",
             r"\begin{tikzpicture}",
             r"\begin{groupplot}[group style={group size=2 by 1, horizontal sep=1.4cm},",
             r"  width=0.5\textwidth, height=5.6cm, xmode=log,",
             r"  every axis/.append style={font=\sffamily\scriptsize},",
             r"  xlabel={alarms per alerted entity and hour}, grid=major,",
             r"  grid style={draw=pgreyL}, axis line style={draw=pgrey}, tick style={draw=pgrey},",
             r"  every axis plot/.append style={line width=0.8pt, mark size=1.5pt},",
             r"  legend style={draw=none, fill=none, font=\sffamily\tiny, cells={anchor=west}}]"]
    present = [k for k in DIRECTION if (points["direction"] == k).any()]
    for key in present:
        title, last = DIRECTION[key], key == present[-1]
        d = points[points["direction"] == key]
        if d.empty:
            continue
        n = int(d["campaigns"].max())
        opts = f"title={{{title}}}, ymin=0, ymax={n + 0.5}, ylabel={{campaigns detected (of {n})}}"
        if last:  # one legend for both panels
            opts += ", legend to name=curveslegend, legend columns=4"
        lines.append(rf"\nextgroupplot[{opts}]")
        for m, (label, style) in styles.items():
            c = d[(d["model"] == m) & (d[x] > 0)].sort_values([x, "detected"])
            if c.empty:  # keep the legend complete when a detector lacks one direction
                if last:
                    lines += [rf"\addlegendimage{{{style}}}", rf"\addlegendentry{{{label}}}"]
                continue
            c = c.assign(best=c["detected"].cummax()).drop_duplicates(x, keep="last")
            coords = " ".join(f"({r[x]:.3g},{int(r['best'])})" for _, r in c.iterrows())
            lines.append(rf"\addplot[{style}] coordinates {{{coords}}};")
            if last:
                lines.append(rf"\addlegendentry{{{label}}}")
    lines += [r"\end{groupplot}", r"\end{tikzpicture}", "", r"\ref{curveslegend}"]
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("table", choices=["h1", "summary", "ablation", "frontier", "frontier_system",
                                       "adaptive", "curves", "query", "budgets"])
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
    if args.table == "budgets":
        args.out.write_text(budget_table(args.runs, args.extra))
        print(args.out.read_text())
        return
    if args.table == "curves":
        pts = curve_points(args.runs + args.extra)
        if args.data_out:
            pts.to_csv(args.data_out, index=False)
        args.out.write_text(curves_figure(pts, detectors=args.detectors))
        print(pts.round(3).to_string())
        return
    if args.table == "frontier":
        args.out.write_text(frontier_table(args.csv, args.data_out))
        print(args.out.read_text())
        return
    if args.table == "adaptive":
        args.out.write_text(adaptive_table(args.csv, ADAPTIVE_PAPER if args.set == "paper" else None))
        print(args.out.read_text())
        return
    if args.table == "query":
        args.out.write_text(query_table(args.csv, QUERY_PAPER if args.set == "paper" else None))
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
    args.out.write_text(h1_table(args.runs, args.extra, args.fpr,
                                 entity_alarms=args.set in ("r2", "paper")))
    print(args.out.read_text())


if __name__ == "__main__":
    main()
