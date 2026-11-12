"""Damage under an adaptive attacker: Proteus against detectors without guarantees.

    python -m proteus.evaluation.adaptive \
        --run experiments/outputs/h1/csecicids2018__cicids2017__loo_labels__cert \
        --test cicids2017 --models core_cert core_mono_dst_x core_free_dst_b \
        --local rate_rules_local kitnet_local

For every attack scenario of ``frontier_exp`` (real victim, its real background, the
real campaign's flow shapes) the attacker chooses a rate and a combination of free
operations. Its damage is the highest rate (flows/h) at which no attacker flow is
alerted, maximised over

* the plain attack,
* random combinations of free operations (``free_ops.variant``), and
* mimicry: padding and inserted packets until each attack flow reaches the median
  forward packets and bytes per packet of the victim's benign traffic (only adding,
  never removing).

Only alerts in minutes where the victim's background alone raises none count against
the attacker (benign false positives are not the attack's doing). Rates are scanned on
a geometric grid (the attacker needs one quiet rate, so no
monotonicity in the rate is assumed). For monotone detectors free operations only
raise evidence, so the best variant is the plain attack, and for ``--certify``
models the certified frontier (worst case over all free operations) is reported too.
Thresholds are local (FPR on clean benign traffic of the other days); ``--local``
detectors are fitted, per day, on that same traffic.
"""

from __future__ import annotations

import argparse
import copy
from pathlib import Path

import numpy as np
import pandas as pd

from proteus.core.certify import slack, worst_case_features
from proteus.core.frontier import _features, nested_attack
from proteus.evaluation import h1
from proteus.evaluation.free_ops import variant
from proteus.evaluation.frontier_exp import ATTACKS, FLOW_COLS, Baselines, scenarios
from proteus.evaluation.poisoning import combined, local_benign


class Scored:
    """``predict_proba`` view of a detector that only has ``score`` (rate rules,
    KitNET): column 1 is the raw score, which is all thresholds compare."""

    def __init__(self, model) -> None:
        self.model = model
        self.monotonic_cst = getattr(model, "monotonic_cst", None)

    def predict_proba(self, X):
        s = np.asarray(self.model.score(X), dtype=np.float64)
        return np.stack([1 - s, s], axis=1)


def mimic(df: pd.DataFrame, bg: pd.DataFrame) -> pd.DataFrame:
    """Raise every attack flow to the victim's median benign forward packets and bytes
    per packet. Only adds packets and padding (free operations)."""
    out = df.copy()
    atk = out["_atk"].to_numpy()
    med_pkts = float(np.median(bg["fwd_pkts"])) if len(bg) else 0.0
    per_pkt = (bg["fwd_bytes"] / bg["fwd_pkts"].clip(lower=1)) if len(bg) else pd.Series([0.0])
    med_bpp = float(np.median(per_pkt))
    pk = out.loc[atk, "fwd_pkts"].to_numpy(np.int64)
    new_pk = np.maximum(pk, int(np.ceil(med_pkts)))
    by = out.loc[atk, "fwd_bytes"].to_numpy(np.int64)
    new_by = np.maximum(by + (new_pk - pk) * 60, np.ceil(new_pk * med_bpp).astype(np.int64))
    out.loc[atk, "fwd_pkts"] = new_pk
    out.loc[atk, "fwd_bytes"] = new_by
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", type=Path, required=True)
    ap.add_argument("--test", required=True)
    ap.add_argument("--models", nargs="*", default=["core_cert", "core_mono_dst_x"],
                    help="fitted models of the run (or a+b / a|b combinations)")
    ap.add_argument("--extra-runs", type=Path, nargs="*", default=[],
                    help="more runs of the same train/test pair to take models from")
    ap.add_argument("--local", nargs="*", default=["rate_rules_local", "kitnet_local"],
                    help="unsupervised detectors fitted per day on local benign traffic")
    ap.add_argument("--certify", nargs="*", default=["core_cert"])
    ap.add_argument("--fpr", type=float, default=1e-3)
    ap.add_argument("--variants", type=int, default=8, help="random free-operation variants")
    ap.add_argument("--grid", type=int, default=20)
    ap.add_argument("--rmin", type=float, default=1e-3)
    ap.add_argument("--rmax", type=float, default=200.0)
    ap.add_argument("--attacks", nargs="*", default=None)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    rng = np.random.default_rng(args.seed)
    fitted = h1.load_models(args.run)
    for extra in args.extra_runs:  # same train/test pair, other detectors
        fitted = {**h1.load_models(extra), **fitted}
    _, specs = h1.evidence_b(args.test, h1.days(args.test)[0], columns=["clean"])
    dets = {n: combined(fitted, n) for n in args.models}
    fresh = h1.detectors(specs, [])
    dets.update({n: fresh[n] for n in args.local})
    rates = np.geomspace(args.rmin, args.rmax, args.grid)
    delta = h1.EXPORT_TIMEOUT_S
    baselines = Baselines(args.test)
    rows = []
    for day in h1.days(args.test):
        flows = pd.read_parquet(day, columns=FLOW_COLS)
        want = args.attacks or ATTACKS
        present = [a for a in want if (flows["is_attack"] & (flows["attack"] == a)).any()]
        if not present:
            continue
        base = baselines.for_day(day)
        models, thr = {}, {}
        for n, (cols, m) in dets.items():
            ref = local_benign(args.test, day, cols, rng)
            if n in args.local or getattr(m, "local", False):
                m = copy.deepcopy(m).fit(ref)
            if not hasattr(m, "predict_proba"):
                m = Scored(m)
            models[n] = (cols, m)
            thr[n] = float(np.quantile(m.predict_proba(ref)[:, 1], 1 - args.fpr,
                                       method="higher"))
        all_cols = list(dict.fromkeys(c for cols, _ in models.values() for c in cols))
        for attack, sc, A in scenarios(flows, present):
            span = max((A["t_end"].max() - A["t_start"].min()).total_seconds(), 1.0)
            full = nested_attack(sc, args.rmax, np.random.default_rng(args.seed))
            plans = [("plain", None), ("mimic", None)] + [
                (f"random{k}", k) for k in range(args.variants)]
            # Minutes where the victim's background alone alerts: not the attack's doing.
            bg_feats = _features(sc.background, all_cols, base)
            bg_min = sc.background["t_end"].astype("int64").to_numpy() // 60_000_000
            noisy, noisy_cert = {}, {}
            for n, (cols, m) in models.items():
                X = bg_feats[cols].to_numpy(np.float64)
                noisy[n] = np.unique(bg_min[m.predict_proba(X)[:, 1] >= thr[n]])
                if n in args.certify:
                    W = worst_case_features(X, np.asarray(m.monotonic_cst),
                                            slack(cols, specs, delta))
                    noisy_cert[n] = np.unique(bg_min[m.predict_proba(W)[:, 1] >= thr[n]])
            best = {n: {"rate": 0.0, "plan": None} for n in models}
            plain = {n: 0.0 for n in models}
            cert = {n: 0.0 for n in args.certify if n in models}
            for r in rates:
                a = full[full["u"] < r / args.rmax].drop(columns=["u"])
                if a.empty:
                    continue
                df = pd.concat([sc.background.assign(_atk=False), a.assign(_atk=True)],
                               ignore_index=True)
                df["orig_id"] = np.arange(len(df))
                for plan, k in plans:
                    if plan == "plain":
                        v = df
                    elif plan == "mimic":
                        v = mimic(df, sc.background)
                    else:
                        v, _ = variant(df, np.random.default_rng(1000 + k), sc.target_ip,
                                       sc.target_port, retime=bool(k % 2))
                    feats = _features(v, all_cols, base)
                    minute = v["t_end"].astype("int64").to_numpy() // 60_000_000
                    for n, (cols, m) in models.items():
                        X = feats[cols].to_numpy(np.float64)
                        clean_min = ~np.isin(minute, noisy[n])
                        quiet = not ((m.predict_proba(X)[:, 1] >= thr[n]) & clean_min).any()
                        if quiet and r > best[n]["rate"]:
                            best[n] = {"rate": float(r), "plan": plan}
                        if quiet and plan == "plain":
                            plain[n] = max(plain[n], float(r))
                        if plan == "plain" and n in cert:
                            W = worst_case_features(X, np.asarray(m.monotonic_cst),
                                                    slack(cols, specs, delta))
                            hit = m.predict_proba(W)[:, 1] >= thr[n]
                            if not (hit & ~np.isin(minute, noisy_cert[n])).any():
                                cert[n] = max(cert[n], float(r))
            for n in models:
                rows.append({"day": day.stem, "attack": attack, "detector": n,
                             "threshold": thr[n], "noisy_minutes": len(noisy[n]), "real_flows_per_h": len(A) / span * 3600,
                             "plain_flows_per_h": plain[n] * 3600,
                             "adaptive_flows_per_h": best[n]["rate"] * 3600,
                             "best_plan": best[n]["plan"],
                             "certified_flows_per_h": cert[n] * 3600 if n in cert else np.nan,
                             "rmax_flows_per_h": args.rmax * 3600})
                print(rows[-1], flush=True)
    out = pd.DataFrame(rows)
    out.to_csv(args.run / f"adaptive_{args.fpr:g}.csv", index=False)
    print(out.pivot_table(index=["day", "attack"], columns="detector",
                          values="adaptive_flows_per_h").round(0).to_string())


if __name__ == "__main__":
    main()
