"""Feature-space evasion attacks on per-flow detectors (front 1 of doc 07/08).

Protocol of the literature (Apollon v1, APELID+), made explicit:

* in-dataset random 80/20 split (``clean.split_mask``), "Attempted" counted benign;
* features: CICFlowMeter statistics without IPs/ports/timestamps, log1p + min-max
  scaled to [0, 1] on the training split (attacks operate in this space);
* attacks: HopSkipJump (decision-based) and ZOO (score-based), both targeted to the
  benign class through ART, black-box queries to the *whole* defended system;
* functional features (Apollon v1's list, mapped to our schema) are restored after
  the attack, so only non-functional features change;
* budgets are declared and the success rate is reported per L∞ budget;
* attacked samples: attack flows of the test split that the model detects.

    python -m proteus.evaluation.aml_feature --dataset cicids2017 --n 200
"""

from __future__ import annotations

import argparse
import json
import multiprocessing
import os
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import numpy as np
import pandas as pd

# Functional features of Apollon v1 (attacks/attack_utils.py) in our column names.
# " Destination Port" is not a model input here.
FUNCTIONAL = [
    "f_fwd_seg_size_min", "f_bwd_header_length", "f_fwd_init_win_bytes",
    "f_bwd_init_win_bytes", "f_bwd_packets_s", "fwd_bytes", "f_subflow_fwd_bytes",
    "f_packet_length_max", "f_bwd_packet_length_max", "f_bwd_segment_size_avg",
    "f_bwd_packet_length_mean", "f_fwd_packet_length_max", "f_average_packet_size",
    "f_packet_length_std", "f_packet_length_mean", "f_bwd_packet_length_std",
    "f_bwd_packet_length_min", "f_fwd_packet_length_std", "f_fwd_packet_length_min",
    "f_packet_length_min", "f_fwd_packet_length_mean", "f_fwd_segment_size_avg",
    "f_fwd_act_data_pkts", "fwd_pkts", "f_subflow_fwd_packets", "bwd_pkts",
]
EPS = (0.01, 0.05, 0.1, 0.25, 0.5, 1.0)
BUDGETS = {"hsja": {"max_iter": 20, "max_eval": 1000, "init_eval": 100},
           "zoo": {"max_iter": 100, "nb_parallel": 16, "binary_search_steps": 3}}


class Scaled:
    """log1p + min-max scaling to [0, 1] fitted on training data."""

    def fit(self, X):
        Z = np.log1p(np.clip(X, 0, None))
        self.lo, self.hi = np.nanmin(Z, axis=0), np.nanmax(Z, axis=0)
        return self

    def transform(self, X):
        Z = np.log1p(np.clip(np.nan_to_num(X), 0, None))
        return np.clip((Z - self.lo) / np.where(self.hi > self.lo, self.hi - self.lo, 1), 0, 1)


def prepare(ds: str, seed: int, cap_attack: int, cap_benign: int):
    from proteus.evaluation import clean, h1
    from proteus.shell import flow as shell

    rng = np.random.default_rng(seed)
    days = h1.days(ds)
    cols = shell.feature_columns(pd.read_parquet(days[0]).columns)
    tr_parts, te_parts = [], []
    for i, day in enumerate(days):
        d = clean.load_day(day, cols)
        test = clean.split_mask(len(d), seed * 1000 + i)
        for part, store, cap_b in ((d[~test], tr_parts, cap_benign), (d[test], te_parts, 20_000)):
            keep = []
            for _, g in part[part["is_attack"]].groupby("attack", observed=True):
                keep.append(rng.choice(g.index.to_numpy(), min(len(g), cap_attack), replace=False))
            ben = part.index[~part["is_attack"]].to_numpy()
            keep.append(rng.choice(ben, min(len(ben), cap_b), replace=False))
            store.append(part.loc[np.concatenate(keep)])
    tr, te = pd.concat(tr_parts, ignore_index=True), pd.concat(te_parts, ignore_index=True)
    sc = Scaled().fit(tr[cols].to_numpy(np.float64))
    return (sc.transform(tr[cols].to_numpy(np.float64)), tr["is_attack"].to_numpy().astype(int),
            sc.transform(te[cols].to_numpy(np.float64)), te["is_attack"].to_numpy().astype(int),
            te["attack"].astype(str).to_numpy(), cols)


def build_models(Xtr, ytr, seed, n_adv=300):
    from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier

    from proteus.baselines.apollon import ApollonMAB, ApollonV1Code
    from proteus.shell import flow as shell

    models = {
        "shell": shell.model(seed).fit(Xtr, ytr),
        "rf": RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=seed).fit(Xtr, ytr),
        "apollon_v1_code": ApollonV1Code(random_state=seed).fit(Xtr, ytr),
        "apollon_fixed": ApollonMAB(random_state=seed).fit(Xtr, ytr),
    }
    # Adversarial training in the style of APELID+: add HSJA examples crafted against
    # the undefended model on a subset of training attacks, labelled as attacks.
    base = models["shell"]
    atk = Xtr[ytr == 1]
    idx = np.random.default_rng(seed).choice(len(atk), min(n_adv, len(atk)), replace=False)
    adv = run_attack("hsja", base, atk[idx], np.arange(Xtr.shape[1]), [])
    Xa, ya = np.vstack([Xtr, adv]), np.concatenate([ytr, np.ones(len(adv), dtype=int)])
    models["advtrain"] = HistGradientBoostingClassifier(
        max_iter=400, learning_rate=0.1, max_leaf_nodes=63, l2_regularization=1.0,
        class_weight="balanced", random_state=seed).fit(Xa, ya)
    return models


def run_attack(name, model, X, modifiable, functional):
    from art.attacks.evasion import HopSkipJump, ZooAttack
    from art.estimators.classification import BlackBoxClassifier

    clf = BlackBoxClassifier(predict_fn=lambda x: model.predict_proba(x),
                             input_shape=(X.shape[1],), nb_classes=2, clip_values=(0.0, 1.0))
    y_target = np.zeros((len(X), 2))
    y_target[:, 0] = 1
    b = BUDGETS[name]
    if name == "hsja":
        att = HopSkipJump(classifier=clf, targeted=True, verbose=False, **b)
    else:
        att = ZooAttack(classifier=clf, targeted=True, verbose=False, **b)
    adv = att.generate(x=X.astype(np.float32), y=y_target).astype(np.float64)
    if len(functional):
        adv[:, functional] = X[:, functional]
    return adv


def _job(args):
    name, attack, path, _ = args
    import pickle

    with open(path, "rb") as fh:
        data = pickle.load(fh)
    model, X, functional, modifiable = (data["models"][name], data["X"], data["functional"],
                                        data["modifiable"])
    t0 = time.time()
    adv = run_attack(attack, model, X, modifiable, functional)
    return name, attack, adv, time.time() - t0


def summarize(model, X, adv, draws=10):
    """Evasion per sample (stochastic models: share of draws answering benign)."""
    ev = np.mean([model.predict(adv) == 0 for _ in range(draws)], axis=0)
    linf = np.abs(adv - X).max(axis=1)
    l2 = np.linalg.norm(adv - X, axis=1)
    out = {"asr": float((ev >= 0.5).mean()), "asr_any_draw": float((ev > 0).mean()),
           "median_linf": float(np.median(linf)), "median_l2": float(np.median(l2))}
    for e in EPS:
        out[f"asr_linf<={e}"] = float(((ev >= 0.5) & (linf <= e)).mean())
    return out, ev


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="cicids2017")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--n", type=int, default=200, help="attack flows attacked per model")
    ap.add_argument("--cap-attack", type=int, default=30_000)
    ap.add_argument("--cap-benign", type=int, default=150_000)
    ap.add_argument("--workers", type=int, default=12)
    ap.add_argument("--n-adv", type=int, default=300,
                    help="HSJA examples added by adversarial training")
    ap.add_argument("--out", type=Path, default=Path("experiments/outputs/aml_feature"))
    args = ap.parse_args()
    import pickle

    t0 = time.time()
    out = args.out / f"{args.dataset}_s{args.seed}"
    out.mkdir(parents=True, exist_ok=True)
    Xtr, ytr, Xte, yte, ate, cols = prepare(args.dataset, args.seed, args.cap_attack,
                                            args.cap_benign)
    functional = [i for i, c in enumerate(cols) if c in FUNCTIONAL]
    modifiable = [i for i, c in enumerate(cols) if c not in FUNCTIONAL]
    print(f"data ready: train {len(Xtr):,}, test {len(Xte):,}, {len(cols)} features "
          f"({len(functional)} functional) at {time.time() - t0:.0f}s", flush=True)
    models = build_models(Xtr, ytr, args.seed, args.n_adv)
    print(f"models trained at {time.time() - t0:.0f}s", flush=True)

    # Clean metrics on the test sample and the attacked set: test attack flows detected
    # by every model (same samples for all, stratified by attack type).
    from sklearn.metrics import f1_score, recall_score
    clean = {n: {"f1": f1_score(yte, m.predict(Xte)), "recall": recall_score(yte, m.predict(Xte)),
                 "fpr": float((m.predict(Xte)[yte == 0] == 1).mean())} for n, m in models.items()}
    detected = np.all([m.predict(Xte) == 1 for m in models.values()], axis=0) & (yte == 1)
    rng = np.random.default_rng(args.seed)
    idx = np.flatnonzero(detected)
    types = ate[idx]
    per_type = max(1, args.n // len(set(types)))
    pick = np.concatenate([rng.choice(idx[types == t], min(per_type, (types == t).sum()),
                                      replace=False) for t in sorted(set(types))])
    X = Xte[pick]
    path = out / "state.pkl"
    with open(path, "wb") as fh:
        pickle.dump({"models": models, "X": X, "functional": functional,
                     "modifiable": modifiable}, fh)
    print(f"attacking {len(X)} flows ({per_type} per type) at {time.time() - t0:.0f}s", flush=True)

    os.environ.setdefault("OMP_NUM_THREADS", "1")
    jobs = [(n, a, path, args.seed) for n in models for a in ("hsja", "zoo")]
    advs, results = {}, []
    # spawn, not fork: forking after OpenMP threads exist (gradient boosting) deadlocks.
    ctx = multiprocessing.get_context("spawn")
    with ProcessPoolExecutor(max_workers=args.workers, mp_context=ctx) as ex:
        for name, attack, adv, secs in ex.map(_job, jobs):
            advs[(name, attack)] = adv
            s, _ = summarize(models[name], X, adv)
            results.append({"model": name, "attack": attack, "seconds": round(secs), **s})
            print(json.dumps(results[-1]), flush=True)

    # Transfer matrix: examples crafted against one model, evaluated on every model.
    transfer = []
    for (src, attack), adv in advs.items():
        for dst, m in models.items():
            s, _ = summarize(m, X, adv)
            transfer.append({"source": src, "target": dst, "attack": attack, "asr": s["asr"]})
    report = {"dataset": args.dataset, "seed": args.seed, "n_attacked": len(X),
              "attack_types": sorted(set(ate[pick])), "budgets": BUDGETS,
              "features": len(cols), "functional": len(functional),
              "clean": clean, "direct": results, "transfer": transfer}
    (out / "report.json").write_text(json.dumps(report, indent=1))
    path.unlink()
    print(pd.DataFrame(results).to_string())
    print(pd.DataFrame(transfer).pivot_table(index=["attack", "source"], columns="target",
                                             values="asr").round(2).to_string())


if __name__ == "__main__":
    main()
