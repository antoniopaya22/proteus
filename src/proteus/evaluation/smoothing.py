"""Does a budget certificate cover the attacker's free operations?

    PROTEUS_EVIDENCE=v3 python -m proteus.evaluation.smoothing \
        --run experiments/outputs/h1/csecicids2018__cicids2017__loo_labels__v3 \
        --test cicids2017 --base core_free_dst_b --certified proteus_cert

For every real campaign (as in ``free_ops``): the unconstrained core is smoothed with
feature-wise Gaussian noise (``baselines.smoothing``, the mechanism of BARS) and each
alerted attack flow gets a certified radius. Random free-operation variants are then
applied; for the original flows we measure how far the variant moved them in the
smoothing metric and whether that is inside the certified radius (the certificate
covers the variant). The share of flows whose alert Proteus certifies against every
free operation is reported next to it.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from proteus.baselines.smoothing import Smoothed
from proteus.core.certify import slack, worst_case_features
from proteus.core.frontier import _features
from proteus.evaluation import h1
from proteus.evaluation.free_ops import ATTACK_WINDOW_S, WARMUP_S, variant
from proteus.evaluation.frontier_exp import ATTACKS, FLOW_COLS, Baselines
from proteus.evaluation.poisoning import combined, local_benign


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", type=Path, required=True)
    ap.add_argument("--test", required=True)
    ap.add_argument("--base", default="core_free_dst_b")
    ap.add_argument("--certified", default="proteus_cert")
    ap.add_argument("--fpr", type=float, default=1e-3)
    ap.add_argument("--scales", type=float, nargs="+", default=[0.1, 0.25, 0.5])
    ap.add_argument("--variants", type=int, default=6)
    ap.add_argument("--flows", type=int, default=300, help="attack flows per campaign")
    ap.add_argument("--n", type=int, default=200, help="noise samples")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    rng = np.random.default_rng(args.seed)
    fitted = h1.load_models(args.run)
    bcols, base_m = fitted[args.base]
    ccols, cert_m = combined(fitted, args.certified)
    _, specs = h1.evidence_b(args.test, h1.days(args.test)[0], columns=["clean"])
    allc = list(dict.fromkeys([*bcols, *ccols]))
    baselines = Baselines(args.test)
    rows = []
    for day in h1.days(args.test):
        flows = pd.read_parquet(day, columns=FLOW_COLS)
        present = [a for a in ATTACKS if (flows["is_attack"] & (flows["attack"] == a)).any()]
        if not present:
            continue
        base = baselines.for_day(day)
        ref_b = np.nan_to_num(local_benign(args.test, day, bcols, rng))
        ref_c = local_benign(args.test, day, ccols, rng)
        if getattr(cert_m, "local", False):
            cert_m.fit(ref_c)
        thr_b = float(np.quantile(base_m.predict_proba(ref_b)[:, 1], 1 - args.fpr, method="higher"))
        thr_c = float(np.quantile(cert_m.predict_proba(ref_c)[:, 1], 1 - args.fpr, method="higher"))
        std = ref_b.std(axis=0)
        for attack in present:
            A = flows[flows["is_attack"] & (flows["attack"] == attack)]
            victim = A["dst_ip"].mode().iloc[0]
            port = int(A[A["dst_ip"] == victim]["dst_port"].mode().iloc[0])
            t0 = A.loc[A["dst_ip"] == victim, "t_start"].min()
            lo = t0 - pd.Timedelta(seconds=WARMUP_S)
            hi = t0 + pd.Timedelta(seconds=ATTACK_WINDOW_S)
            sel = (flows["dst_ip"] == victim) & (flows["t_end"] >= lo) & (flows["t_start"] <= hi)
            df = flows[sel & (~flows["is_attack"] | (flows["attack"] == attack))].copy()
            df["_atk"] = df["is_attack"].to_numpy()
            df = df.drop(columns=["attack", "family", "is_attack"]).reset_index(drop=True)
            df["orig_id"] = np.arange(len(df))
            atk = np.flatnonzero(df["_atk"].to_numpy())
            pick = np.sort(rng.choice(atk, min(len(atk), args.flows), replace=False))
            F0 = _features(df, allc, base)
            X0 = F0[bcols].to_numpy(np.float64)[pick]
            C0 = F0[ccols].to_numpy(np.float64)[pick]
            W = worst_case_features(C0, np.asarray(cert_m.monotonic_cst),
                                    slack(ccols, specs, h1.EXPORT_TIMEOUT_S))
            proteus_cert = cert_m.predict_proba(W)[:, 1] >= thr_c
            variants = []
            for k in range(args.variants):
                v, _ = variant(df, np.random.default_rng(100 + k), victim, port, retime=bool(k % 2))
                pos = pd.Series(np.arange(len(v)), index=v["orig_id"].to_numpy())
                rows_v = pos.reindex(pick).to_numpy()
                ok = ~np.isnan(rows_v)
                Xv = np.full_like(X0, np.nan)
                Xv[ok] = _features(v, bcols, base).to_numpy(np.float64)[rows_v[ok].astype(int)]
                variants.append((Xv, ok))
            def decide(Z, m=base_m, t=thr_b):
                return m.predict_proba(Z)[:, 1] >= t
            for scale in args.scales:
                sm = Smoothed(decide, scale * np.maximum(std, 1e-6), n=args.n, seed=args.seed)
                alert, radius = sm.certify(X0)
                covered, dist, still = [], [], []
                for Xv, ok in variants:
                    d = sm.distance(X0[ok], Xv[ok])
                    a = alert[ok]
                    covered.append((d[a] <= radius[ok][a]).mean() if a.any() else np.nan)
                    dist.append(np.median(d) if len(d) else np.nan)
                    still.append(decide(np.nan_to_num(Xv[ok]))[a].mean() if a.any() else np.nan)
                rows.append({"day": day.stem, "attack": attack, "scale": scale,
                             "flows": len(pick), "base_alert": float(decide(np.nan_to_num(X0)).mean()),
                             "smoothed_alert": float(alert.mean()),
                             "median_radius": float(np.median(radius[alert])) if alert.any() else 0.0,
                             "median_variant_distance": float(np.nanmedian(dist)),
                             "covered_by_radius": float(np.nanmean(covered)) if alert.any() else 0.0,
                             "base_alert_on_variants": float(np.nanmean(still)) if alert.any() else np.nan,
                             "proteus_certified": float(proteus_cert.mean())})
                print(rows[-1], flush=True)
    out = pd.DataFrame(rows)
    out.to_csv(args.run / "smoothing_vs_free_ops.csv", index=False)
    print(out.round(3).to_string())


if __name__ == "__main__":
    main()
