"""Data for the released code of BARS (Wang et al., NDSS 2023) on our evidence.

    PROTEUS_EVIDENCE=v3 python -m proteus.evaluation.bars_export \
        --run experiments/outputs/h1/csecicids2018__cicids2017__loo_labels__r2 \
        --train csecicids2018 --test cicids2017 --out experiments/outputs/bars

``evaluation.smoothing`` reimplements the mechanism of BARS. This module writes what
``scripts/external/bars_certify.py`` needs to run BARS itself (its classifier, noise
optimisation and certification) on the same features and the same flows:

* ``train.npz``: features ``X`` and labels ``y`` (1 = attack) of a sample of the
  training network, the training data of the classifier and of the noise;
* one ``campaign_<day>_<attack>.npz`` per real campaign of the test network: the
  features ``X0`` of up to ``--flows`` attack flows, the same flows in ``--variants``
  random combinations of free operations (``V``, NaN where a flow has no counterpart),
  and whether Proteus-cert certifies each flow against every free operation
  (``proteus_certified``), as in ``evaluation.smoothing``;
* ``meta.json``: the feature columns and the campaigns.

The features are those of a model of the run (default ``core_free_dst_b``, the
destination evidence that ``evaluation.smoothing`` smooths), NaN set to 0.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

from proteus.core.certify import slack, worst_case_features
from proteus.core.frontier import _features
from proteus.evaluation import h1
from proteus.evaluation.free_ops import ATTACK_WINDOW_S, WARMUP_S, variant
from proteus.evaluation.frontier_exp import ATTACKS, FLOW_COLS, Baselines
from proteus.evaluation.poisoning import combined, local_benign


def variant_rows(orig_ids: np.ndarray, pick: np.ndarray) -> np.ndarray:
    """Row of each picked original flow in a variant (-1 where it has none). A split
    flow keeps the row of its first piece; decoys (``orig_id`` < 0) are no flow's."""
    pos = pd.Series(np.arange(len(orig_ids)), index=orig_ids)
    pos = pos[(pos.index >= 0) & ~pos.index.duplicated()]
    return pos.reindex(pick).fillna(-1).to_numpy(np.int64)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", type=Path, required=True)
    ap.add_argument("--train", required=True, help="training network of the run")
    ap.add_argument("--test", required=True)
    ap.add_argument("--model", default="core_free_dst_b", help="whose feature columns to use")
    ap.add_argument("--certified", default="proteus_cert_r")
    ap.add_argument("--fpr", type=float, default=1e-3)
    ap.add_argument("--flows", type=int, default=300, help="attack flows per campaign")
    ap.add_argument("--variants", type=int, default=6)
    ap.add_argument("--cap-attack", type=int, default=5_000, help="training rows per attack type and day")
    ap.add_argument("--cap-benign", type=int, default=30_000, help="clean training rows per day")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(args.seed)
    fitted = h1.load_models(args.run)
    cols, _ = fitted[args.model]
    ccols, cert_m = combined(fitted, args.certified)

    tr, _ = h1.training_set(args.train, rng, args.cap_attack, args.cap_benign)
    X = np.nan_to_num(tr[cols].to_numpy(np.float32))
    y = tr["is_attack"].to_numpy().astype(np.int64)
    np.savez_compressed(args.out / "train.npz", X=X, y=y)
    print(f"train: {len(y):,} rows, {int(y.sum()):,} attacks, {len(cols)} features", flush=True)
    del tr, X

    _, specs = h1.evidence_b(args.test, h1.days(args.test)[0], columns=["clean"])
    allc = list(dict.fromkeys([*cols, *ccols]))
    baselines = Baselines(args.test)
    campaigns = []
    for day in h1.days(args.test):
        flows = pd.read_parquet(day, columns=FLOW_COLS)
        present = [a for a in ATTACKS if (flows["is_attack"] & (flows["attack"] == a)).any()]
        if not present:
            continue
        base = baselines.for_day(day)
        ref_c = local_benign(args.test, day, ccols, rng)
        if getattr(cert_m, "local", False):
            cert_m.fit(ref_c)
        thr_c = float(np.quantile(cert_m.predict_proba(ref_c)[:, 1], 1 - args.fpr, method="higher"))
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
            X0 = np.nan_to_num(F0[cols].to_numpy(np.float32)[pick])
            C0 = F0[ccols].to_numpy(np.float64)[pick]
            W = worst_case_features(C0, np.asarray(cert_m.monotonic_cst),
                                    slack(ccols, specs, h1.EXPORT_TIMEOUT_S))
            certified = cert_m.predict_proba(W)[:, 1] >= thr_c
            V = np.full((args.variants, *X0.shape), np.nan, dtype=np.float32)
            params = []
            for k in range(args.variants):
                v, p = variant(df, np.random.default_rng(100 + k), victim, port, retime=bool(k % 2))
                rows = variant_rows(v["orig_id"].to_numpy(), pick)
                ok = rows >= 0
                V[k, ok] = np.nan_to_num(_features(v, cols, base).to_numpy(np.float32)[rows[ok]])
                params.append(p)
            name = f"campaign_{day.stem}_{attack}.npz"
            np.savez_compressed(args.out / name, X0=X0, V=V, proteus_certified=certified)
            campaigns.append({"file": name, "day": day.stem, "attack": attack,
                              "flows": len(pick), "variants": params,
                              "proteus_certified": float(certified.mean())})
            print(campaigns[-1]["file"], len(pick), f"{certified.mean():.2f}", flush=True)
    (args.out / "meta.json").write_text(json.dumps(
        {"run": str(args.run), "model": args.model, "columns": cols, "campaigns": campaigns},
        indent=1, default=str))


if __name__ == "__main__":
    main()
