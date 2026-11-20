"""BARS (Wang et al., NDSS 2023) with its released code, against free operations.

Runs in the environment of BARS (PyTorch, numpy < 1.24), not in ours:

    python scripts/external/bars_certify.py --bars <clone of KaiWangGitHub/BARS> \
        --data experiments/outputs/bars --out experiments/outputs/bars/acid_gaussian

On the data of ``proteus.evaluation.bars_export``, with the code of BARS unchanged:

1. trains its ACID classifier (adaptive clustering, the supervised system of the
   BARS paper, with its hyperparameters) to separate attack flows from benign ones on
   the training network, features scaled to [0, 1] on the training data;
2. optimises the noise shape and scale for the attack class with BARS
   (``optimizing_noise``), with the Gaussian distribution transformer, so that the
   certified region is exactly the ellipsoid ||delta / sigma||_2 < R with
   sigma_j = t (|w_shared| + |w_j|) and R = Phi^-1(p_A);
3. certifies the attack flows of every real campaign of the test network
   (``Smooth2.bars_certify``: n0 = 100, n = 10 000, alpha = 0.001, as in BARS), and
   for each certified flow and each free-operation variant measures the displacement
   ||delta / sigma||_2 and whether the smoothed classifier still predicts the attack
   on the variant.

Writes ``bars_vs_free_ops.csv`` (one row per campaign) and ``flows.csv`` (one row per
certified flow and variant).
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from torch import optim
from torch.utils.data import DataLoader, TensorDataset


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bars", type=Path, required=True, help="clone of the BARS repository")
    ap.add_argument("--data", type=Path, required=True, help="output of proteus.evaluation.bars_export")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--noise", default="gaussian", help="distribution transformer of BARS")
    ap.add_argument("--epochs", type=int, default=30, help="classifier epochs (BARS: 30)")
    ap.add_argument("--shape-samples", type=int, default=20_000,
                    help="attack flows of the training network used to optimise the noise")
    ap.add_argument("--n", type=int, default=10_000, help="noise samples to certify (BARS: 10 000)")
    ap.add_argument("--n-variant", type=int, default=1_000, help="noise samples to predict on a variant")
    ap.add_argument("--seed", type=int, default=42, help="BARS: 42")
    args = ap.parse_args()
    sys.path[:0] = [str(args.bars / "bars"), str(args.bars / "smoothed_acid")]
    import optimizing_noise as on
    from classifier.classifier import AdaptiveClusteringClassifier
    from classifier.subnet import AdaptiveClustering, Loss_AdaptiveClustering
    from distribution_transformer import distribution_transformers, loss_functions
    from smoothing import Noise, Smooth2

    random.seed(args.seed)
    np.random.seed(args.seed)
    torch.manual_seed(args.seed)
    torch.cuda.manual_seed_all(args.seed)
    dev = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    args.out.mkdir(parents=True, exist_ok=True)
    meta = json.loads((args.data / "meta.json").read_text())

    tr = np.load(args.data / "train.npz")
    lo, hi = tr["X"].min(0), tr["X"].max(0)
    span = np.where(hi > lo, hi - lo, 1.0)

    def scale(X: np.ndarray) -> torch.Tensor:
        return torch.tensor((X - lo) / span, dtype=torch.float32)

    x_tr, y_tr = scale(tr["X"]), torch.tensor(tr["y"], dtype=torch.long)
    d, k = x_tr.size(1), 2

    # 1. The ACID classifier, trained as in smoothed_acid/main.py.
    ac = AdaptiveClustering(d, k, dev).to(dev)
    opt = optim.Adam(ac.parameters(), lr=1e-4)
    crit = Loss_AdaptiveClustering(k)
    loader = DataLoader(TensorDataset(x_tr, y_tr), batch_size=512, shuffle=True)
    ac.train()
    for epoch in range(args.epochs + 1):
        total = 0.0
        for X, y in loader:
            X, y = X.to(dev), y.to(dev)
            loss = crit(*ac(X), y)[0]
            if epoch > 0:
                opt.zero_grad()
                loss.backward()
                opt.step()
            total += loss.item()
        print(f"epoch {epoch}: loss {total / len(loader):.5f}", flush=True)
    clf = AdaptiveClusteringClassifier(ac.encoder_list, ac.kernel_net_list, dev)
    clf.eval()

    def predict(X: torch.Tensor) -> np.ndarray:
        with torch.no_grad():
            return torch.cat([clf(b.to(dev)).cpu() for b in X.split(4096)]).numpy()

    pred_tr = predict(x_tr)
    acc = {"train_accuracy": float((pred_tr == tr["y"]).mean()),
           "train_attack_recall": float((pred_tr[tr["y"] == 1] == 1).mean()),
           "train_benign_fpr": float((pred_tr[tr["y"] == 0] == 1).mean())}
    print(acc, flush=True)

    # 2. Noise shape and scale for the attack class, with the code of BARS.
    on.num_samples_shape = min(args.shape_samples, int((pred_tr == 1).sum()))
    on.num_samples_scale = min(1_000, on.num_samples_shape)
    noise = Noise(distribution_transformers[args.noise](d).to(dev), d, dev)
    x_c = x_tr[torch.tensor(pred_tr == 1)]
    on.optimizing_noise(x_c, 1, clf, noise, loss_functions["acid"](1e-2, 1), 1e-2, 1000, 10, d,
                        k, 100, args.n, 1e-3, 5e-2, 1e-2, 0.5, 6, 100, 128, 1_000_000, 20,
                        str(args.out))
    t = float((args.out / "t").read_text())
    noise.distribution_transformer = torch.load(args.out / "checkpoint-distribution-transformer").to(dev)
    sm = Smooth2(clf, d, k, noise, dev)
    if args.noise == "gaussian":
        w = noise.get_weight().detach().cpu().numpy()
        sigma = t * (w[0] + w[1:])
    else:  # the region is not an ellipsoid; only the predictions on variants are reported
        sigma = None

    def certify(X: torch.Tensor, n: int) -> tuple[np.ndarray, np.ndarray]:
        cA, R = [], []
        with torch.no_grad():
            for b in X.split(128):
                c, r = sm._certify2(b.to(dev), 100, n, t, 1e-3, 1_000_000)
                cA.append(c)
                R.append(r)
        return np.concatenate(cA), np.concatenate(R)

    # 3. Real campaigns of the test network and their free-operation variants.
    rows, flow_rows = [], []
    for c in meta["campaigns"]:
        z = np.load(args.data / c["file"])
        X0, V = scale(z["X0"]), z["V"]
        base = predict(X0)
        cA, R = certify(X0, args.n)
        cert = cA == 1
        cov, moved, still = [], [], []
        for j in range(V.shape[0]):
            ok = ~np.isnan(V[j]).any(1)
            m = cert & ok
            if not m.any():
                continue
            Xv = scale(np.nan_to_num(V[j]))
            cv, _ = certify(Xv[torch.tensor(m)], args.n_variant)
            keep = cv == 1
            if sigma is not None:
                dist = np.linalg.norm((Xv[torch.tensor(m)].numpy() - X0[torch.tensor(m)].numpy()) / sigma, axis=1)
                inside = dist < R[m]
                cov.append(inside.mean())
                moved.append(np.median(dist))
            else:
                dist, inside = np.full(m.sum(), np.nan), np.full(m.sum(), False)
            still.append(keep.mean())
            for i, f in enumerate(np.flatnonzero(m)):
                flow_rows.append({"campaign": c["file"], "variant": j, "flow": int(f),
                                  "radius": float(R[f]), "moved": float(dist[i]),
                                  "covered": bool(inside[i]), "still_attack": bool(keep[i])})
        rows.append({"day": c["day"], "attack": c["attack"], "flows": len(X0),
                     "acid_attack": float((base == 1).mean()), "bars_certified": float(cert.mean()),
                     "median_radius": float(np.median(R[cert])) if cert.any() else 0.0,
                     "median_moved": float(np.nanmedian(moved)) if moved else np.nan,
                     "covered": float(np.mean(cov)) if cov else np.nan,
                     "still_attack_on_variants": float(np.mean(still)) if still else np.nan,
                     "proteus_certified": c["proteus_certified"]})
        print(rows[-1], flush=True)
    out = pd.DataFrame(rows)
    out.to_csv(args.out / "bars_vs_free_ops.csv", index=False)
    pd.DataFrame(flow_rows).to_csv(args.out / "flows.csv", index=False)
    (args.out / "run.json").write_text(json.dumps({**vars(args), **acc, "t": t,
                                                   "bars": str(args.bars), "data": str(args.data),
                                                   "out": str(args.out)}, indent=1, default=str))
    print(out.round(3).to_string())


if __name__ == "__main__":
    os.environ.setdefault("CUDA_VISIBLE_DEVICES", "0")
    main()
