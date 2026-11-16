"""Pilot: a window-fidelity detector as the uncertified complement of the core.

    python -m proteus.evaluation.window_fidelity --test cicids2017 \
        --with-alerts experiments/outputs/h1/<run of h1 --export-alerts> \
        --out experiments/outputs/h1/<run>_wf

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
A flow is alerted when the window of its destination service or of its source host
is, and the metrics are those of ``h1`` (campaigns, strict criterion, alarms per
alerted entity), alone and in union with the detectors of a run of ``h1``
(``proteus_w``, ``proteus_sys_rw``).
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from proteus.evaluation import h1

STATS = ["fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes", "duration", "fwd_bpp", "ratio"]
BINS = 10
OTHER = -1  # reference shared by the ports without enough benign flows
SIZES = np.array([30, 100, 300, 1000])  # window sizes are calibrated apart (see thresholds)


def thresholds(calib: pd.DataFrame, fpr: float) -> dict[tuple[str, int], float]:
    """Threshold of the statistic per kind of entity and size class of the window. A
    window of ten flows is far from any reference by chance and one of a thousand is
    not, so each size class is calibrated on clean benign windows of its own size. A
    class with no such window takes the threshold of the next smaller one."""
    out: dict[tuple[str, int], float] = {}
    c = calib[~calib["dirty"]]
    size = np.searchsorted(SIZES, c["flows"].to_numpy(), side="right")
    for kind in c["kind"].unique():
        last = np.inf
        for b in range(len(SIZES) + 1):
            v = c.loc[(c["kind"] == kind).to_numpy() & (size == b), "stat"]
            last = float(np.quantile(v, 1 - fpr, method="higher")) if len(v) else last
            out[(kind, b)] = last
    return out


def alerts(w: pd.DataFrame, thr: dict[tuple[str, int], float]) -> np.ndarray:
    size = np.searchsorted(SIZES, w["flows"].to_numpy(), side="right")
    t = np.array([thr.get((k, int(b)), np.inf) for k, b in zip(w["kind"], size, strict=True)])
    return w["stat"].to_numpy() > t


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
            min_flows: int) -> tuple[pd.DataFrame, np.ndarray]:
    """One row per (entity, window): its statistic, its size, how many of its flows are
    attack flows and of which attack, and whether any of its flows is not clean benign
    traffic. Also returns, for every flow, the row of its window."""
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
    out["ok"] = out["flows"] >= min_flows  # smaller windows are never scored
    return out, codes


def frame(test: str, day: Path) -> pd.DataFrame:
    """Flows of a test day in the row order of ``h1`` (so that alerts align by
    position), with the metadata and the clean-benign mark of ``h1``."""
    ev, _ = h1.evidence_b(test, day, columns=sorted(set(h1.META) | {"clean"}))
    fl = pd.read_parquet(day, columns=["duration_us", "fwd_pkts", "bwd_pkts", "fwd_bytes",
                                       "bwd_bytes"])
    if len(fl) != len(ev):
        raise SystemExit(f"{day.stem}: the evidence cache and the day file differ in rows")
    df = pd.concat([ev.reset_index(drop=True), fl.reset_index(drop=True)], axis=1)
    df["_dirty"] = ~df["clean"].to_numpy(bool)
    return df


class WindowFidelity:
    """The detector as deployed on one test day: the reference of the other days and
    the thresholds, per kind of entity and size class, at each target rate. It scores
    raw flow records (not evidence features), so the attackers of ``adaptive`` and
    ``query_attack`` call ``flow_alerts`` on the traffic they send."""

    def __init__(self, ref: dict[int, np.ndarray], thr: dict[float, dict], window_s: float,
                 min_flows: int, fpr: float) -> None:
        self.ref, self.thr, self.window_s, self.min_flows, self.fpr = ref, thr, window_s, min_flows, fpr

    def flow_alerts(self, df: pd.DataFrame, fpr: float | None = None) -> np.ndarray:
        """Alert of every flow of ``df``: its service window or its source window is
        distributed unlike the benign reference."""
        work = df.assign(is_attack=False, attack="", _dirty=False)
        bins = bin_flows(statistics(work), work["dst_port"].to_numpy(), self.ref)
        thr = self.thr[self.fpr if fpr is None else fpr]
        out = np.zeros(len(df), dtype=bool)
        for e in ("service", "source"):
            t, codes = windows(work, bins, e, self.window_s, self.min_flows)
            out |= (alerts(t, thr) & t["ok"].to_numpy())[codes]
        return out


def fit_days(test: str, window_s: float, min_flows: int, sample_n: int,
             rng: np.random.Generator) -> tuple[dict, dict, dict]:
    """For every test day: the detector fitted on the other days, and that day's own
    windows and flow-to-window codes (scored against the other days' reference)."""
    days = h1.days(test)
    # Pass 1: a sample of the clean benign flows of every day (the reference tables).
    sample = {}
    for day in days:
        df = frame(test, day)
        idx = np.flatnonzero(df["clean"].to_numpy(bool))
        idx = np.sort(rng.choice(idx, min(len(idx), sample_n), replace=False))
        sample[day] = (statistics(df.iloc[idx]), df["dst_port"].to_numpy()[idx])
        print(f"  sampled {day.stem}: {len(idx):,} of {len(df):,} flows", flush=True)
        del df
    # Pass 2: the windows of every day against the benign traffic of the other days.
    refs, tables, codes = {}, {}, {}
    for day in days:
        others = [d for d in days if d != day]
        refs[day] = reference(pd.concat([sample[d][0] for d in others]),
                              np.concatenate([sample[d][1] for d in others]))
        df = frame(test, day)
        bins = bin_flows(statistics(df), df["dst_port"].to_numpy(), refs[day])
        got = [windows(df, bins, e, window_s, min_flows) for e in ("service", "source")]
        tables[day] = {e: t for e, (t, _) in zip(("service", "source"), got, strict=True)}
        codes[day] = {e: c.astype(np.int32) for e, (_, c) in zip(("service", "source"), got, strict=True)}
        n = sum(int(t["ok"].sum()) for t in tables[day].values())
        print(f"  scored {day.stem}: {n:,} windows of {window_s:g}s", flush=True)
        del df, bins
    fitted = {}
    for day in days:
        calib = pd.concat([t[t["ok"]] for d in days if d != day for t in tables[d].values()])
        fitted[day] = WindowFidelity(refs[day], {fpr: thresholds(calib, fpr) for fpr in h1.FPRS},
                                     window_s, min_flows, h1.FPRS[0])
    return fitted, tables, codes


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--test", required=True)
    ap.add_argument("--window", type=float, default=300.0)
    ap.add_argument("--min-flows", type=int, default=10)
    ap.add_argument("--sample", type=int, default=300_000, help="benign flows per day in the reference")
    ap.add_argument("--with-alerts", type=Path, default=None,
                    help="run of h1 --export-alerts on the same test network: its detectors "
                         "are evaluated in union with this one")
    ap.add_argument("--out", type=Path, required=True, help="run directory to write")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    days = h1.days(args.test)
    fitted, tables, codes = fit_days(args.test, args.window, args.min_flows, args.sample,
                                     np.random.default_rng(args.seed))
    # Pass 3: thresholds from the clean benign windows of the other days; per-flow alerts;
    # the metrics of h1, alone and in union with its detectors.
    results = []
    for day in days:
        n_rows = len(codes[day]["service"])
        score = np.zeros(n_rows, dtype=np.int8)      # 0, 1 (alert at 1e-3), 2 (also at 1e-4)
        side = np.zeros(n_rows, dtype=bool)
        for fpr in h1.FPRS:                          # 1e-3, then 1e-4
            thr = fitted[day].thr[fpr]
            flow = {}
            for e in ("service", "source"):
                t = tables[day][e]
                flow[e] = (alerts(t, thr) & t["ok"].to_numpy())[codes[day][e]]
            score += (flow["service"] | flow["source"]).astype(np.int8)
            if fpr == h1.FPRS[0]:
                side = flow["source"] & ~flow["service"]
        ev, _ = h1.evidence_b(args.test, day, columns=sorted(set(h1.META) | {"clean"}))
        scores, sides = {"window_fidelity": score.astype(np.float64)}, {"window_fidelity": side}
        if args.with_alerts is not None:
            al = h1.load_alerts(args.with_alerts / "alerts" / f"{day.stem}.npz")
            for key in [k for k in al if k.endswith(f"__local{h1.FPRS[0]:g}")]:
                m = key.split("__local")[0]
                if m in h1.UNIONS:
                    continue  # unions are formed again here
                scores[m] = (al[key].astype(np.float64)
                             + al[f"{m}__local{h1.FPRS[1]:g}"].astype(np.float64))
                if f"{m}__side" in al:
                    sides[m] = al[f"{m}__side"]
        h1.save_alerts(args.out / "alerts" / f"{day.stem}.npz",
                       {("window_fidelity", fpr, "local"): (score > i, side)
                        for i, fpr in enumerate(h1.FPRS)})
        th = {(m, fpr, "local"): 0.5 + i for m in scores for i, fpr in enumerate(h1.FPRS)}
        results.append(h1.evaluate(ev, scores, th, sides))
        print(f"  evaluated {day.stem}", flush=True)
        del ev
    h1.write_results(pd.concat(results, ignore_index=True), args.out)


if __name__ == "__main__":
    main()
