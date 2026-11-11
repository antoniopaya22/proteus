"""Empirical check of the guarantee (H3): free operations against real campaigns.

    python -m proteus.evaluation.free_ops \
        --run experiments/outputs/h1/csecicids2018__cicids2017__loo_labels__cert \
        --test cicids2017 --models core_cert core_mono_dst_x --variants 20

For every attack type of the test network: a window of the real campaign against its
victim plus the real traffic towards the victim (destination-side evidence of these
flows is then exact). Random combinations of the free operations of
``proteus.attacks.operators`` are applied to the attack flows. Checks:

* exact guarantee: with operations that do not re-time flows (padding, inserted
  packets without extension, decoys, new source ports), no original flow's score
  decreases;
* guarantee with slack: if the original campaign has a certified alert (worst-case
  score above the threshold), every variant alerts on the victim no later than Δ after
  the first certified alert;
* what the attacker gains against uncertified detection: share of variants in which
  the fast core no longer alerts, and change of alerted attack flows.
"""

from __future__ import annotations

import argparse
import pickle
from pathlib import Path

import numpy as np
import pandas as pd

from proteus.attacks import operators as op
from proteus.core.certify import slack, worst_case_features
from proteus.core.frontier import _features
from proteus.evaluation import h1
from proteus.evaluation.frontier_exp import ATTACKS, FLOW_COLS, Baselines, local_threshold

ATTACK_WINDOW_S = 600.0
WARMUP_S = 3600.0


def variant(df: pd.DataFrame, rng: np.random.Generator, victim: str, port: int,
            retime: bool) -> tuple[pd.DataFrame, dict]:
    atk = df["_atk"].to_numpy()
    p = {"pad": int(rng.choice([0, 40, 400])), "ins": int(rng.choice([0, 1, 5])),
         "ext": float(rng.choice([0.0, 30.0, 120.0])) if retime else 0.0,
         "ports": bool(rng.integers(2)), "decoys": int(rng.choice([0, 100, 1000])),
         "split": int(rng.choice([1, 2, 5])) if retime else 1,
         "split_frac": float(rng.choice([0.05, 0.2]))}
    out = df
    if p["pad"]:
        out = op.pad(out, atk, p["pad"])
    if p["ins"]:
        out = op.insert_packets(out, atk, p["ins"], 60, extend_s=p["ext"],
                                timeout_s=h1.EXPORT_TIMEOUT_S)
    if p["ports"]:
        out = op.change_src_ports(out, atk, rng)
    if p["split"] > 1:
        sel = atk & (rng.random(len(out)) < p["split_frac"])
        out = op.split_flows(out, sel, p["split"], rng)
    if p["decoys"]:
        srcs = df.loc[atk, "src_ip"].astype(str).unique()
        out = op.add_decoys(out, p["decoys"], rng, srcs, [victim, "192.0.2.1"], [port, 443])
        out["_atk"] = out["_atk"].where(out["orig_id"] >= 0, True).astype(bool)
    return out.reset_index(drop=True), p


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", type=Path, required=True)
    ap.add_argument("--test", required=True)
    ap.add_argument("--models", nargs="+", default=["core_cert"])
    ap.add_argument("--fpr", type=float, default=1e-3)
    ap.add_argument("--variants", type=int, default=20)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    rng = np.random.default_rng(args.seed)
    import __main__

    from proteus.baselines.rate_rules import RateRules

    __main__.RateRules = RateRules  # pickles written before RateRules had its own module
    with open(args.run / "models.pkl", "rb") as fh:
        models = {n: m for n, m in pickle.load(fh).items() if n in args.models}
    _, specs = h1.evidence_b(args.test, h1.days(args.test)[0], columns=["clean"])
    delta = h1.EXPORT_TIMEOUT_S
    baselines = Baselines(args.test)
    rows = []
    for day in h1.days(args.test):
        flows = pd.read_parquet(day, columns=FLOW_COLS)
        present = [a for a in ATTACKS if (flows["is_attack"] & (flows["attack"] == a)).any()]
        if not present:
            continue
        base = baselines.for_day(day)
        thr = {n: local_threshold(args.test, day, m, c, args.fpr, rng)
               for n, (c, m) in models.items()}
        for attack in present:
            A = flows[flows["is_attack"] & (flows["attack"] == attack)]
            victim = A["dst_ip"].mode().iloc[0]
            port = int(A[A["dst_ip"] == victim]["dst_port"].mode().iloc[0])
            t0 = A.loc[A["dst_ip"] == victim, "t_start"].min()
            lo, hi = t0 - pd.Timedelta(seconds=WARMUP_S), t0 + pd.Timedelta(seconds=ATTACK_WINDOW_S)
            to_victim = (flows["dst_ip"] == victim) & (flows["t_end"] >= lo) & (flows["t_start"] <= hi)
            df = flows[to_victim & (~flows["is_attack"] | (flows["attack"] == attack))].copy()
            df["_atk"] = df["is_attack"].to_numpy()
            df = df.drop(columns=["attack", "family", "is_attack"]).reset_index(drop=True)
            df["orig_id"] = np.arange(len(df))
            for name, (cols, model) in models.items():
                cst = np.asarray(model.monotonic_cst)
                sl = slack(cols, specs, delta)
                X0 = _features(df, cols, base)[cols].to_numpy(np.float64)
                s0 = model.predict_proba(X0)[:, 1]
                c0 = model.predict_proba(worst_case_features(X0, cst, sl))[:, 1]
                t_end0 = df["t_end"].to_numpy()
                cert_alert = c0 >= thr[name]
                first_cert = t_end0[cert_alert].min() if cert_alert.any() else None
                atk0 = df["_atk"].to_numpy()
                for k in range(args.variants):
                    retime = k % 2 == 1  # even variants: exact operations only
                    v, p = variant(df, rng, victim, port, retime)
                    X = _features(v, cols, base)[cols].to_numpy(np.float64)
                    s = model.predict_proba(X)[:, 1]
                    alert = s >= thr[name]
                    to_v = (v["dst_ip"].astype(str) == victim).to_numpy()
                    t_end = v["t_end"].to_numpy()
                    row = {"day": day.stem, "attack": attack, "model": name, "variant": k,
                           "retime": retime, **p, "threshold": thr[name],
                           "orig_attack_alerts": int((s0 >= thr[name])[atk0].sum()),
                           "orig_attack_flows": int(atk0.sum()),
                           "variant_attack_alerts": int(alert[v["_atk"].to_numpy()].sum()),
                           "variant_victim_alerted": bool((alert & to_v).any()),
                           "orig_certified": first_cert is not None}
                    ids = v["orig_id"].to_numpy()
                    keep = ids >= 0
                    if not retime:  # exact guarantee: no original score decreases
                        drop = s0[ids[keep]] - s[keep]
                        row["exact_violations"] = int((drop > 1e-9).sum())
                    if first_cert is not None:
                        ok = (alert & to_v & (t_end <= first_cert + np.timedelta64(int(delta * 1e6), "us"))).any()
                        row["cert_violation"] = not bool(ok)
                    rows.append(row)
                last = pd.DataFrame(rows[-args.variants:])
                print(f"{day.stem} {attack} {name}: orig alerts {row['orig_attack_alerts']}"
                      f"/{row['orig_attack_flows']}, variant alerts min "
                      f"{last['variant_attack_alerts'].min()}, victim alerted "
                      f"{last['variant_victim_alerted'].mean():.2f}, certified "
                      f"{row['orig_certified']}", flush=True)
    out = pd.DataFrame(rows)
    out.to_csv(args.run / "free_ops.csv", index=False)
    g = out.groupby(["model", "attack"])
    summ = pd.DataFrame({
        "orig_alerts": g["orig_attack_alerts"].first(),
        "min_variant_alerts": g["variant_attack_alerts"].min(),
        "victim_alerted_share": g["variant_victim_alerted"].mean(),
        "certified": g["orig_certified"].first(),
        "exact_violations": g["exact_violations"].sum(),
        "cert_violations": g["cert_violation"].sum() if "cert_violation" in out else np.nan,
    })
    print(summ.to_string())


if __name__ == "__main__":
    main()
