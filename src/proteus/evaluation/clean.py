"""Clean, in-dataset per-flow evaluation in the protocol of the literature.

Random 80/20 split of every capture day (seeded hash of the row, so it is
reproducible without holding the dataset in memory), binary labels with
"Attempted" flows counted as benign (Engelen et al., WTMC 2021). The model is
trained on a subsample of the training split (all attack flows up to a cap per
attack type, a benign sample) and evaluated on the *whole* test split.

    python -m proteus.evaluation.clean --dataset cicids2017 --seeds 0 1 2 3 4
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    matthews_corrcoef,
    precision_score,
    recall_score,
    roc_auc_score,
)

from proteus.evaluation import h1
from proteus.shell import flow as shell

LABEL_COLS = ["attack", "is_attack"]


def split_mask(n: int, seed: int, test_size: float = 0.2) -> np.ndarray:
    """True for test rows. Deterministic per (day length, seed)."""
    return np.random.default_rng(seed).random(n) < test_size


def load_day(day: Path, cols: list[str]) -> pd.DataFrame:
    return pd.read_parquet(day, columns=cols + LABEL_COLS)


def metrics(y: np.ndarray, pred: np.ndarray, score: np.ndarray) -> dict:
    tn = int(((y == 0) & (pred == 0)).sum())
    fp = int(((y == 0) & (pred == 1)).sum())
    return {
        "n": len(y), "attacks": int(y.sum()),
        "accuracy": accuracy_score(y, pred), "precision": precision_score(y, pred),
        "recall": recall_score(y, pred), "f1": f1_score(y, pred),
        "f1_macro": f1_score(y, pred, average="macro"), "mcc": matthews_corrcoef(y, pred),
        "fpr": fp / max(fp + tn, 1), "auroc": roc_auc_score(y, score),
    }


def run(ds: str, seed: int, with_port: bool, cap_attack: int, cap_benign: int) -> dict:
    t0 = time.time()
    rng = np.random.default_rng(seed)
    days = h1.days(ds)
    cols = shell.feature_columns(pd.read_parquet(days[0]).columns, with_port)

    # Pass 1: training subsample from the train split of every day.
    parts = []
    for i, day in enumerate(days):
        d = load_day(day, cols)
        tr = d[~split_mask(len(d), seed * 1000 + i)]
        keep = []
        for _, g in tr[tr["is_attack"]].groupby("attack", observed=True):
            keep.append(rng.choice(g.index.to_numpy(), min(len(g), cap_attack), replace=False))
        ben = tr.index[~tr["is_attack"]].to_numpy()
        keep.append(rng.choice(ben, min(len(ben), cap_benign), replace=False))
        parts.append(tr.loc[np.concatenate(keep)])
        del d, tr
    train = pd.concat(parts, ignore_index=True)
    clf = shell.model(seed).fit(shell.features(train, cols), train["is_attack"].to_numpy())
    print(f"  {ds} seed {seed}: trained on {len(train):,} flows at {time.time() - t0:.0f}s",
          flush=True)
    del train, parts

    # Pass 2: score the whole test split.
    ys, preds, scores, attacks = [], [], [], []
    for i, day in enumerate(days):
        d = load_day(day, cols)
        te = d[split_mask(len(d), seed * 1000 + i)]
        s = clf.predict_proba(shell.features(te, cols))[:, 1]
        ys.append(te["is_attack"].to_numpy())
        scores.append(s.astype(np.float32))
        preds.append((s >= 0.5).astype(np.int8))
        attacks.append(te["attack"].astype(str).to_numpy())
        del d, te
    y, pred, score = (np.concatenate(a) for a in (ys, preds, scores))
    att = np.concatenate(attacks)
    out = metrics(y.astype(int), pred, score)
    # Detection rate per attack type and false-positive rate on benign.
    out["per_attack_recall"] = {
        a: float(pred[(att == a) & (y == 1)].mean())
        for a in sorted(set(att[y == 1]))
    }
    # TPR at fixed low FPRs (threshold from the benign scores of the test split).
    ben = score[y == 0]
    for fpr in (1e-3, 1e-4):
        thr = np.quantile(ben, 1 - fpr, method="higher")
        out[f"tpr_at_fpr_{fpr:g}"] = float((score[y == 1] > thr).mean())
    out.update(dataset=ds, seed=seed, with_port=with_port, features=len(cols),
               seconds=round(time.time() - t0))
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--seeds", type=int, nargs="+", default=[0])
    ap.add_argument("--with-port", action="store_true")
    ap.add_argument("--cap-attack", type=int, default=200_000)
    ap.add_argument("--cap-benign", type=int, default=400_000)
    ap.add_argument("--out", type=Path, default=Path("experiments/outputs/clean"))
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    rows = []
    for seed in args.seeds:
        r = run(args.dataset, seed, args.with_port, args.cap_attack, args.cap_benign)
        print(json.dumps({k: v for k, v in r.items() if k != "per_attack_recall"}), flush=True)
        rows.append(r)
    tag = f"{args.dataset}{'_port' if args.with_port else ''}"
    (args.out / f"shell_{tag}.json").write_text(json.dumps(rows, indent=1))
    df = pd.DataFrame([{k: v for k, v in r.items() if k != "per_attack_recall"} for r in rows])
    print(df.describe().loc[["mean", "std"]].T.to_string())


if __name__ == "__main__":
    main()
