"""Injection study: the attacks of the test network against many real victims.

    python -m proteus.evaluation.injection \
        --run experiments/outputs/h1/csecicids2018__cicids2017__loo_labels__r2 \
        --test cicids2017 --models proteus proteus_cert_r --local rate_rules_local \
        --certify proteus_cert_r --alarm-budget 0.5 --victims 12

The benchmarks have one victim per attack, almost idle. Here every attack of a test day
(its real flow shapes, as in ``frontier_exp``) is aimed in turn at ``--victims`` real
services of that day that no attack touches, chosen to span the range of benign load
on the attacked port (for scans: hosts, any port), over each victim's own real traffic.
For every (victim, attack) pair and every detector it reports the highest rate on a
geometric grid at which the attack raises no alert of its own, for the plain attack and
for the attacker's plans (connection reuse, bursts; minimal requests apart, since no
certificate covers them), and the certified rate of the ``--certify`` detectors. With
tens of victims per attack, comparisons between detectors rest on hundreds of cases
instead of one campaign per attack type.

Thresholds, the notion of an alert of the attack's own and the plans are those of
``evaluation.adaptive``; a rate that needs more than ``--max-flows`` attack flows is not
tried and counts as alerted, so the damage reported is a lower bound.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from proteus.core.frontier import Scenario, nested_attack
from proteus.evaluation import h1
from proteus.evaluation.adaptive import (
    STRUCTURED,
    Oracle,
    day_models,
    structured,
    threshold_label,
)
from proteus.evaluation.frontier_exp import ATTACKS, FLOW_COLS, Baselines
from proteus.evaluation.poisoning import combined

STOP_AFTER = 2  # a monotone detector alerted at this many consecutive rates is done
PLANS = ["plain", "reuse", "reuse+pulse", "shrink", "shrink+reuse"]


def pick_victims(flows: pd.DataFrame, port: int | None, proto: int, n: int,
                 min_flows: int = 20) -> list[tuple[str, int]]:
    """``n`` destinations of benign traffic that no attack of the day touches, spread
    over the range of their benign load (log-spaced quantiles of their flow counts):
    services on ``port`` (destination host, port), or, with ``port`` None, hosts
    (destination host, total flows). Fewer when there are fewer candidates."""
    attacked = set(flows.loc[flows["is_attack"], "dst_ip"]) | set(
        flows.loc[flows["is_attack"], "src_ip"])
    b = flows[flows["family"].isin(h1.NOT_MALICIOUS) & (flows["proto"] == proto)
              & ~flows["dst_ip"].isin(attacked)]
    if port is not None:
        b = b[b["dst_port"] == port]
    counts = b["dst_ip"].astype(str).value_counts()
    counts = counts[counts >= min_flows]
    if counts.empty:
        return []
    counts = counts.sort_values(kind="stable")
    if len(counts) <= n:
        return list(zip(counts.index, counts.to_numpy().astype(int), strict=True))
    targets = np.geomspace(counts.iloc[0], counts.iloc[-1], n)
    pos = np.unique(np.searchsorted(counts.to_numpy(), targets).clip(0, len(counts) - 1))
    return [(counts.index[i], int(counts.iloc[i])) for i in pos]


def scenario(flows: pd.DataFrame, template: pd.DataFrame, victim: str, port: int,
             proto: int, window_s: float, n_sources: int, scan: bool) -> Scenario:
    """The attack aimed at ``victim``: its real traffic (all of it, as in
    ``frontier_exp``) around the middle of its benign activity, one hour on each side."""
    bg = flows[(flows["dst_ip"].astype(str) == victim) & flows["family"].isin(h1.NOT_MALICIOUS)]
    start = bg["t_start"].min() + (bg["t_end"].max() - bg["t_start"].min()) / 2
    lo, hi = start - pd.Timedelta(hours=1), start + pd.Timedelta(seconds=window_s + 3600)
    bg = bg[(bg["t_end"] >= lo) & (bg["t_start"] <= hi)].drop(columns=["attack", "family", "is_attack"])
    return Scenario(bg, template, victim, port, proto, start, window_s,
                    n_sources=n_sources, keep_ports=scan)


def scan_rates(full: pd.DataFrame, sc: Scenario, oracle: Oracle, rates: np.ndarray,
               rmax: float, plans: list[str], certify: list[str],
               max_flows: int | None) -> tuple[list[dict], dict]:
    """Every detector against the attack at increasing rates, with every plan. Returns
    one ladder row per (rate, plan, detector) and, per detector, the highest quiet rate
    of the plain attack, of the free plans and of the plans with minimal requests, and
    the highest certified rate (flows/s)."""
    names = list(oracle.models)
    mono = {n: getattr(m, "monotonic_cst", None) is not None for n, (_, m) in oracle.models.items()}
    best = {n: {"plain": 0.0, "free": 0.0, "shrink": 0.0, "cert": 0.0} for n in names}
    streak = {n: 0 for n in names}
    ladder = []
    for r in rates:
        active = [n for n in names if not (mono[n] and streak[n] >= STOP_AFTER)]
        if not active:
            break
        a = full[full["u"] < r / rmax].drop(columns=["u"])
        if a.empty:
            continue
        if max_flows is not None and len(a) > max_flows:
            break  # higher rates count as alerted: the damage is a lower bound
        df = pd.concat([sc.background.assign(_atk=False), a.assign(_atk=True)], ignore_index=True)
        df["orig_id"] = np.arange(len(df))
        quiet_any = {n: False for n in active}
        for plan in plans:
            v = df if plan == "plain" else structured(df, plan, np.random.default_rng(2000))
            quiet, cert = oracle.query(v, active, certified=plan == "plain")
            for n in active:
                q = quiet[n]
                ladder.append({"detector": n, "plan": plan, "flows_per_h": float(r) * 3600,
                               "detected": not q})
                quiet_any[n] = quiet_any[n] or q or bool(cert.get(n))
                if q:
                    kinds = ["shrink"] + ([] if plan.startswith("shrink") else ["free"])
                    kinds += ["plain"] if plan == "plain" else []
                    for k in kinds:
                        best[n][k] = max(best[n][k], float(r))
                if cert.get(n):
                    best[n]["cert"] = max(best[n]["cert"], float(r))
        for n in active:
            streak[n] = 0 if quiet_any[n] else streak[n] + 1
    for n in names:
        if n not in certify:
            best[n]["cert"] = np.nan
    return ladder, best


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", type=Path, required=True)
    ap.add_argument("--test", required=True)
    ap.add_argument("--models", nargs="*", default=["proteus", "proteus_cert_r"])
    ap.add_argument("--extra-runs", type=Path, nargs="*", default=[])
    ap.add_argument("--local", nargs="*", default=["rate_rules_local"])
    ap.add_argument("--certify", nargs="*", default=["proteus_cert_r"])
    ap.add_argument("--fpr", type=float, default=1e-3)
    ap.add_argument("--alarm-budget", type=float, default=None)
    ap.add_argument("--victims", type=int, default=12, help="victims per attack and day")
    ap.add_argument("--plans", nargs="*", default=PLANS)
    ap.add_argument("--window", type=float, default=1800.0, help="attack duration (s)")
    ap.add_argument("--grid", type=int, default=14)
    ap.add_argument("--rmin", type=float, default=1e-3)
    ap.add_argument("--rmax", type=float, default=100.0)
    ap.add_argument("--max-flows", type=int, default=200_000)
    ap.add_argument("--attacks", nargs="*", default=None)
    ap.add_argument("--days", nargs="*", default=None)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--templates", default=None,
                    help="take the attacks from this dataset's campaigns and inject them into "
                         "the test network (e.g. CIC attacks into UGR'16)")
    ap.add_argument("--tag", default="")
    ap.add_argument("--resume", action="store_true",
                    help="keep the (victim, attack) pairs already in the output files and skip them")
    args = ap.parse_args()
    known = ["plain"] + [p for p in STRUCTURED if not p.startswith("spread")]
    unknown = sorted(set(args.plans) - set(known))
    if unknown:  # spreading over sources changes the attacker, not its shape: not here
        raise SystemExit(f"unknown plans {unknown}; known: {', '.join(known)}")
    rng = np.random.default_rng(args.seed)
    fitted = h1.load_models(args.run)
    for extra in args.extra_runs:
        fitted = {**h1.load_models(extra), **fitted}
    _, specs = h1.evidence_b(args.test, h1.days(args.test)[0], columns=["clean"])
    dets = {n: combined(fitted, n) for n in args.models}
    fresh = h1.detectors(specs, [])
    dets.update({n: fresh[n] for n in args.local})
    rates = np.geomspace(args.rmin, args.rmax, args.grid)
    baselines = Baselines(args.test)
    label = threshold_label(args.fpr, args.alarm_budget)
    tag = f"_{args.tag}" if args.tag else ""
    out_rows = args.run / f"injection_{label}{tag}.csv"
    out_ladder = args.run / f"injection_ladder_{label}{tag}.csv"
    rows, ladders, done = [], [], set()
    if args.resume and out_rows.exists() and out_ladder.exists():
        rows = pd.read_csv(out_rows).to_dict("records")
        ladders = pd.read_csv(out_ladder).to_dict("records")
        done = {(r["day"], r["attack"], r["victim"]) for r in rows}
        print(f"resuming: {len(done)} pairs already done", flush=True)

    def save() -> None:
        pd.DataFrame(rows).to_csv(out_rows, index=False)
        pd.DataFrame(ladders).to_csv(out_ladder, index=False)

    want = args.attacks or ATTACKS
    foreign = {}  # attack -> its first campaign in the template dataset
    if args.templates:
        for tday in h1.days(args.templates):
            tf = pd.read_parquet(tday, columns=FLOW_COLS)
            for a in want:
                if a not in foreign and (tf["is_attack"] & (tf["attack"] == a)).any():
                    foreign[a] = tf[tf["is_attack"] & (tf["attack"] == a)].copy()
            del tf
        print(f"templates from {args.templates}: {sorted(foreign)}", flush=True)

    for day in h1.days(args.test):
        if args.days and day.stem not in args.days:
            continue
        flows = pd.read_parquet(day, columns=FLOW_COLS)
        if args.templates:
            present = sorted(foreign)
        else:
            present = [a for a in want if (flows["is_attack"] & (flows["attack"] == a)).any()]
        if not present:
            continue
        base = baselines.for_day(day)
        models, thr = day_models(args.test, day, dets, args.local, args.fpr, rng, args.alarm_budget)
        for attack in present:
            A = foreign[attack] if args.templates else flows[flows["is_attack"] & (flows["attack"] == attack)]
            real_victim = A["dst_ip"].mode().iloc[0]
            A = A[A["dst_ip"] == real_victim]
            port, proto = int(A["dst_port"].mode().iloc[0]), int(A["proto"].mode().iloc[0])
            span = max((A["t_end"].max() - A["t_start"].min()).total_seconds(), 1.0)
            scan = attack == "portscan"
            template = A.drop(columns=["attack", "family", "is_attack"])
            victims = pick_victims(flows, None if scan else port, proto, args.victims)
            print(f"{day.stem} {attack}: {len(victims)} victims", flush=True)
            for victim, n_benign in victims:
                if (day.stem, attack, victim) in done:
                    continue
                sc = scenario(flows, template, victim, port, proto, args.window,
                              int(A["src_ip"].nunique()), scan)
                if sc.background.empty:
                    continue
                full = nested_attack(sc, args.rmax, np.random.default_rng(args.seed))
                oracle = Oracle(sc, models, thr, base, specs, tuple(args.certify))
                ladder, best = scan_rates(full, sc, oracle, rates, args.rmax, args.plans,
                                          args.certify, args.max_flows)
                hours = (args.window + 7200) / 3600
                for n, b in best.items():
                    rows.append({"day": day.stem, "attack": attack, "victim": victim,
                                 "port": port, "victim_benign_flows_day": n_benign,
                                 "background_flows_per_h": len(sc.background) / hours,
                                 "detector": n, "threshold": thr[n],
                                 "noisy_minutes": len(oracle.noisy[n]),
                                 "real_flows_per_h": len(A) / span * 3600,
                                 "plain_flows_per_h": b["plain"] * 3600,
                                 "free_flows_per_h": b["free"] * 3600,
                                 "shrink_flows_per_h": b["shrink"] * 3600,
                                 "certified_flows_per_h": b["cert"] * 3600,
                                 "rmax_flows_per_h": args.rmax * 3600})
                for r in ladder:
                    ladders.append({"day": day.stem, "attack": attack, "victim": victim, **r})
                print(f"  {victim}: " + ", ".join(
                    f"{n} {best[n]['free'] * 3600:.0f}" for n in best), flush=True)
                save()
    save()
    out = pd.DataFrame(rows)
    if len(out):
        out["passes_free"] = out["free_flows_per_h"] >= out["real_flows_per_h"]
        out["passes_shrink"] = out["shrink_flows_per_h"] >= out["real_flows_per_h"]
        print(out.groupby("detector")[["passes_free", "passes_shrink"]].agg(["mean", "size"]).to_string())


if __name__ == "__main__":
    main()
