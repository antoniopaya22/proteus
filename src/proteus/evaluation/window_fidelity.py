"""Pilot: a window-fidelity detector as the uncertified complement of the core.

    python -m proteus.evaluation.window_fidelity --test cicids2017

The idea comes from METIS, which measures how far a synthetic table is from a real
one. Here the "table under test" is what an entity (a destination service or a source
host) did in the last ``--window`` seconds, and the "real table" is the benign traffic
of the same network on the other days. A window that is distributed unlike benign
traffic raises an alert on its entity.

* Reference: for every destination port with enough benign flows on the other days,
  the deciles of each per-flow statistic; rarer ports share one reference.
* Statistic of a window: for each statistic, the largest gap between the window's
  empirical distribution and the reference one on that decile grid (a Kolmogorov-
  Smirnov distance on ten bins), averaged over the statistics.
* Calibration: no attack labels of the test network are used to fit anything. The
  threshold is the quantile, at the target rate, of the statistic over the clean
  benign windows of the other days (as the local thresholds of ``h1``).

No guarantee is claimed: the shape of its flows is under the attacker's control.
The module reports, per attack, the campaigns it detects and its false alarms per
alerted entity and hour, so that it can be compared with the per-flow shell.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from proteus.evaluation import h1

COLS = ["t_start", "t_end", "duration_us", "src_ip", "dst_ip", "dst_port", "proto",
        "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes", "attack", "is_attack"]
STATS = ["fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes", "duration", "fwd_bpp", "ratio"]
BINS = 10
OTHER = -1  # reference shared by the ports without enough benign flows


def statistics(df: pd.DataFrame) -> pd.DataFrame:
    """Per-flow statistics compared between a window and the reference."""
    fp, bp = df["fwd_pkts"].to_numpy(np.float64), df["bwd_pkts"].to_numpy(np.float64)
    fb, bb = df["fwd_bytes"].to_numpy(np.float64), df["bwd_bytes"].to_numpy(np.float64)
    return pd.DataFrame({
        "fwd_pkts": np.log1p(fp), "bwd_pkts": np.log1p(bp), "fwd_bytes": np.log1p(fb),
        "bwd_bytes": np.log1p(bb), "duration": np.log1p(df["duration_us"].to_numpy(np.float64)),
        "fwd_bpp": np.log1p(fb / np.maximum(fp, 1.0)), "ratio": np.log1p(bb) - np.log1p(fb),
    }, index=df.index)


def reference(stats: pd.DataFrame, port: np.ndarray, min_flows: int = 500) -> dict[int, np.ndarray]:
    """Decile edges (BINS - 1 per statistic) of the benign flows of every port with at
    least ``min_flows`` of them, and of all the others together (key ``OTHER``)."""
    q = np.arange(1, BINS) / BINS
    X = stats[STATS].to_numpy()
    ref = {OTHER: np.quantile(X, q, axis=0).T}
    ports, counts = np.unique(port, return_counts=True)
    for p in ports[counts >= min_flows]:
        ref[int(p)] = np.quantile(X[port == p], q, axis=0).T
    rare = ~np.isin(port, ports[counts >= min_flows])
    if rare.sum() >= min_flows:
        ref[OTHER] = np.quantile(X[rare], q, axis=0).T
    return ref


def bin_flows(stats: pd.DataFrame, port: np.ndarray, ref: dict[int, np.ndarray]) -> np.ndarray:
    """Bin (0 .. BINS-1) of every flow, per statistic, against its port's reference."""
    X = stats[STATS].to_numpy()
    out = np.zeros(X.shape, dtype=np.int8)
    key = np.where(np.isin(port, [p for p in ref if p != OTHER]), port, OTHER)
    for p in np.unique(key):
        m = key == p
        edges = ref[int(p)]
        for j in range(X.shape[1]):
            out[m, j] = np.searchsorted(edges[j], X[m, j], side="right")
    return out


def window_statistic(bins: np.ndarray, group: np.ndarray, n_groups: int) -> np.ndarray:
    """Mean over the statistics of the Kolmogorov-Smirnov distance, on the decile grid,
    between each group's flows and the reference (which has 1/BINS of its mass per bin)."""
    out = np.zeros(n_groups)
    expected = np.arange(1, BINS) / BINS
    for j in range(bins.shape[1]):
        hist = np.zeros((n_groups, BINS))
        np.add.at(hist, (group, bins[:, j]), 1.0)
        cdf = np.cumsum(hist, axis=1)[:, :-1] / np.maximum(hist.sum(axis=1, keepdims=True), 1.0)
        out += np.abs(cdf - expected).max(axis=1)
    return out / bins.shape[1]


def windows(df: pd.DataFrame, bins: np.ndarray, entity: str, window_s: float,
            min_flows: int) -> pd.DataFrame:
    """One row per (entity, window) with at least ``min_flows`` flows: its statistic,
    how many of its flows are attack flows and of which attack, and whether its host is
    clean (not involved in any attack of the day)."""
    ent = (df["dst_ip"].astype(str) + ":" + df["dst_port"].astype(str) if entity == "service"
           else df["src_ip"].astype(str))
    w = df["t_end"].astype("int64").to_numpy() // int(window_s * 1e6)
    codes, _ = pd.factorize(pd.Series(ent.to_numpy()) + "|" + pd.Series(w).astype(str))
    n = int(codes.max()) + 1 if len(codes) else 0
    size = np.bincount(codes, minlength=n)
    stat = window_statistic(bins, codes, n)
    atk = df["is_attack"].to_numpy(bool)
    first = pd.Series(np.arange(len(df))).groupby(codes).first().to_numpy()
    out = pd.DataFrame({
        "entity": ent.to_numpy()[first], "window": w[first], "flows": size, "stat": stat,
        "attack_flows": np.bincount(codes, weights=atk, minlength=n).astype(int),
        "dirty": np.bincount(codes, weights=df["_dirty"].to_numpy(float), minlength=n) > 0,
    })
    name = pd.Series(np.where(atk, df["attack"].astype(str).to_numpy(), ""))
    out["attack"] = name[atk].groupby(codes[atk]).agg(lambda s: s.mode().iloc[0]).reindex(
        range(n), fill_value="").to_numpy()
    out["kind"] = entity
    return out[out["flows"] >= min_flows].reset_index(drop=True)


def load_day(day: Path) -> pd.DataFrame:
    df = pd.read_parquet(day, columns=COLS).sort_values("t_end", kind="stable").reset_index(drop=True)
    hosts = set(df.loc[df["is_attack"], "src_ip"].astype(str)) | set(
        df.loc[df["is_attack"], "dst_ip"].astype(str))
    df["_dirty"] = df["src_ip"].astype(str).isin(hosts) | df["dst_ip"].astype(str).isin(hosts)
    return df


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--test", required=True)
    ap.add_argument("--window", type=float, nargs="+", default=[30.0, 300.0])
    ap.add_argument("--min-flows", type=int, default=10)
    ap.add_argument("--fpr", type=float, nargs="+", default=[1e-3, 1e-4],
                    help="target rate of alerting windows among clean benign windows")
    ap.add_argument("--out", type=Path, default=Path("experiments/outputs/window_fidelity"))
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    days = h1.days(args.test)
    data = {d: load_day(d) for d in days}
    stats = {d: statistics(df) for d, df in data.items()}
    rows, alarms = [], []
    for window_s in args.window:
        # Windows of every day, scored against the benign traffic of the other days.
        scored = {}
        for day in days:
            others = [d for d in days if d != day]
            benign = [~data[d]["is_attack"].to_numpy() & ~data[d]["_dirty"].to_numpy() for d in others]
            ref = reference(pd.concat([stats[d][m] for d, m in zip(others, benign, strict=True)]),
                            np.concatenate([data[d]["dst_port"].to_numpy()[m]
                                            for d, m in zip(others, benign, strict=True)]))
            bins = bin_flows(stats[day], data[day]["dst_port"].to_numpy(), ref)
            scored[day] = pd.concat([windows(data[day], bins, e, window_s, args.min_flows)
                                     for e in ("service", "source")], ignore_index=True)
            print(f"  scored {day.stem} at {window_s:g}s: {len(scored[day]):,} windows", flush=True)
        for day in days:
            w = scored[day]
            calib = pd.concat([scored[d] for d in days if d != day])
            hours = (data[day]["t_end"].max() - data[day]["t_start"].min()).total_seconds() / 3600
            for fpr in args.fpr:
                for kind in ("service", "source", "any"):
                    sel = w if kind == "any" else w[w["kind"] == kind]
                    thr = {k: np.quantile(c.loc[~c["dirty"], "stat"], 1 - fpr, method="higher")
                           for k, c in calib.groupby("kind")}
                    alert = sel["stat"].to_numpy() > sel["kind"].map(thr).to_numpy()
                    clean = ~sel["dirty"].to_numpy()
                    bucket = sel["window"].to_numpy() * int(window_s) // 600
                    fa = len(set(zip(sel["entity"][alert & clean], bucket[alert & clean], strict=True)))
                    alarms.append({"day": day.stem, "window_s": window_s, "fpr": fpr, "kind": kind,
                                   "entity_alarms_per_hour": fa / max(hours, 1e-9),
                                   "clean_windows": int(clean.sum()),
                                   "alerting_clean_windows": int((alert & clean).sum())})
                    hit = sel[sel["attack_flows"] > 0].assign(alert=alert[sel["attack_flows"].to_numpy() > 0])
                    for attack, g in hit.groupby("attack"):
                        rows.append({"day": day.stem, "attack": attack, "window_s": window_s, "fpr": fpr,
                                     "kind": kind, "windows": len(g), "alerted_windows": int(g["alert"].sum()),
                                     "detected": bool(g["alert"].any()),
                                     "flow_recall": float(g.loc[g["alert"], "attack_flows"].sum()
                                                          / max(g["attack_flows"].sum(), 1))})
    c = pd.DataFrame(rows)
    a = pd.DataFrame(alarms)
    c.to_csv(args.out / f"campaigns_{args.test}.csv", index=False)
    a.to_csv(args.out / f"false_alarms_{args.test}.csv", index=False)
    summary = (c.groupby(["window_s", "fpr", "kind", "attack"])
               .agg(campaigns=("detected", "size"), detected=("detected", "sum"),
                    flow_recall=("flow_recall", "mean")).reset_index())
    summary.to_csv(args.out / f"summary_{args.test}.csv", index=False)
    print(summary.round(3).to_string())
    print(a.groupby(["window_s", "fpr", "kind"])["entity_alarms_per_hour"].mean().round(2).to_string())


if __name__ == "__main__":
    main()
