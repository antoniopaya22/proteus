"""CertTA (Yan et al., USENIX Security 2025) with its released code, against free
operations on packets.

Runs in the environment of CertTA, from a copy of its repository where
``evaluation/test.py --smoothed CertTA`` has classified the clean test flows of
``proteus.evaluation.certta_export`` (dataset ``<name>``) and every variant
(datasets ``<name>_vNN``, the same trained model):

    python scripts/external/certta_region.py --certta ~/tools/ext/CertTA-run \
        --data experiments/outputs/certta/datasets --out experiments/outputs/certta

For every attack flow of the clean test set that the smoothed model classifies as
attack, the robustness region is CertTA's: ``radius_joint_exp`` on the lower
confidence bound of p_A (``samples_num`` and ``alpha`` of CertTA's defaults), with the
flow's packet count n and d = ceil(pr_sel n), n_del fixed at 0 as in CertTA. A piece
of a variant is inside the region when, as in CertTA's
``collect_classification_results.py``, some point (0, n_ins, n_sub, r) with
n_sub = n_neg + s (``n_neg`` packets that only a substitution covers, s of the largest
additive changes counted as substituted too) and r = sum over the next d largest
additive changes of (beta_length + beta_time_ms)(bytes / beta_length +
ms / beta_time_ms) lies under a point of the region; a piece that lost packets of the
flow (n_del > 0) is outside it. A variant of a flow is covered when all its pieces
are. ``strict`` also counts packets pushed past CertTA's max_flow_length by the
insertions as deleted.

Writes ``certta_vs_free_ops.csv`` (one row per variant) and ``certta_flows.json`` (one
record per certified flow and variant).
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from argparse import Namespace
from pathlib import Path

import numpy as np
import pandas as pd


def results(path: Path) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for f in sorted(path.glob("*th.json")):
        for r in json.loads(f.read_text()):
            out[r["source_file"]] = r
    return out


def key(source_file: str) -> str:
    return "./dataset/" + source_file.split("./")[-1]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--certta", type=Path, required=True, help="copy of the CertTA repository")
    ap.add_argument("--data", type=Path, required=True, help="output of certta_export")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--model", default="DF")
    ap.add_argument("--samples-num", type=int, default=1000, help="CertTA: 1000")
    ap.add_argument("--alpha", type=float, default=1e-3, help="CertTA: 0.001")
    args = ap.parse_args()
    sys.path.insert(0, str(args.certta))
    from certification.radius import (
        p_A_lower_confidence_bound,
        radius_joint_exp,
        radius_packet_substitution,
    )
    from evaluation.utilities import model_name_generator

    meta = json.loads((args.data / "perturbations.json").read_text())
    name = meta["name"]
    cfg = json.loads((args.certta / "evaluation" / "config" /
                      f"{args.model}_{name}_config.json").read_text())
    bl, bt, pr_sel = cfg["beta_length"], cfg["beta_time_ms"], cfg["pr_sel"]
    model_name = model_name_generator(Namespace(model=args.model, augment="CertTA",
                                                beta_length=bl, beta_time_ms=bt, pr_sel=pr_sel))
    save = args.certta / "model" / args.model / "save"
    clean = results(save / name / model_name / "CertTA" / "clean")
    labels = np.array([r["label"] for r in clean.values()])
    pred = np.array([r["c_A"] for r in clean.values()])
    print(f"clean: {len(clean)} flows, accuracy {np.mean(labels == pred):.4f}, "
          f"attack recall {np.mean(pred[labels == 1] == 1):.4f}, "
          f"benign accuracy {np.mean(pred[labels == 0] == 0):.4f}", flush=True)

    region: dict[str, tuple] = {}
    for sf, r in clean.items():
        if r["label"] != 1 or r["c_A"] != 1:
            continue
        p_low = p_A_lower_confidence_bound(r["p_A"], args.samples_num, args.alpha)
        n = r["packet_num"]
        d = int(np.ceil(pr_sel * n))
        s_jnt = radius_joint_exp(p_low, d, bl, bt, n, False) if p_low >= 0.5 else []
        if s_jnt:
            region[sf] = (r["p_A"], p_low, n, d, np.array(s_jnt, dtype=float),
                          min(radius_packet_substitution(p_low, n, d), n))

    def inside(e: dict, reg: tuple, strict: bool) -> bool:
        if e["n_del"] > 0 or (strict and e["n_trunc"] > 0):
            return False
        _, _, _, d, s_jnt, r_sub = reg
        adds = sorted(((v, t) for v, t in e["adds"]),
                      key=lambda a: a[0] / bl + a[1] / bt, reverse=True)
        for s in range(min(r_sub, len(adds)) + 1):
            r = sum((bl + bt) * (v / bl + t / bt) for v, t in adds[s:s + d])
            point = np.array([0, e["n_ins"], e["n_neg"] + s, r])
            if (point <= s_jnt + 1e-9).all(axis=1).any():
                return True
        return False

    rows, recs = [], []
    by_variant: dict[int, list[dict]] = {}
    for f in meta["flows"]:
        by_variant.setdefault(f["variant"], []).append(f)
    attack_clean = [r for r in clean.values() if r["label"] == 1]
    for p in meta["variants"]:
        k = p["variant"]
        res = results(save / f"{name}_v{k:02d}" / model_name / "CertTA" / "clean")
        out = []
        for f in by_variant[k]:
            reg = region.get(key(f["flow"]))
            if reg is None:
                continue
            preds = [res[key(e["source_file"])]["c_A"] for e in f["pieces"]]
            main = [res[key(e["source_file"])]["c_A"] for e in f["pieces"] if e["first"]]
            spawned = [res[key(s["source_file"])]["c_A"] for s in f["spawned"]]
            rec = {"flow": f["flow"], "variant": k, "p_A": reg[0], "p_A_lower": reg[1],
                   "n": reg[2], "d": reg[3], "max_n_ins": int(reg[4][:, 1].max()),
                   "max_r": float(reg[4][:, 3].max()), "n_pieces": len(f["pieces"]),
                   "n_ins": f["n_ins"], "bytes_added": f["bytes_added"], "removed": f["removed"],
                   "n_neg": sum(e["n_neg"] for e in f["pieces"]),
                   "covered": bool(f["pieces"]) and all(inside(e, reg, False) for e in f["pieces"]),
                   "covered_strict": bool(f["pieces"])
                   and all(inside(e, reg, True) for e in f["pieces"]),
                   "pred_attack_all": bool(preds) and all(c == 1 for c in preds),
                   "pred_attack_main": bool(main) and main[0] == 1,
                   "pieces_pred_attack": int(sum(c == 1 for c in preds)),
                   "spawned": len(spawned), "spawned_pred_attack": int(sum(c == 1 for c in spawned))}
            out.append(rec)
        recs += out
        df = pd.DataFrame(out)
        decoys = [r["c_A"] for sf, r in res.items() if "/decoy/" in sf]
        n_pieces = int(df["n_pieces"].sum())
        rows.append({
            **{c: p[c] for c in ("variant", "pad", "insert", "hop", "decoys")},
            "test_attack_flows": len(attack_clean),
            "clean_pred_attack": sum(r["c_A"] == 1 for r in attack_clean),
            "certified": len(region),
            "median_p_A": float(np.median([reg[0] for reg in region.values()])),
            "median_p_A_lower": float(np.median([reg[1] for reg in region.values()])),
            "share_covered": float(df["covered"].mean()),
            "share_covered_strict": float(df["covered_strict"].mean()),
            "share_pred_attack_all_pieces": float(df["pred_attack_all"].mean()),
            "share_pred_attack_first_piece": float(df["pred_attack_main"].mean()),
            "share_pieces_pred_attack": float(df["pieces_pred_attack"].sum() / max(n_pieces, 1)),
            "pieces": n_pieces, "share_removed": float(df["removed"].mean()),
            "median_n_ins": float(df["n_ins"].median()),
            "median_bytes_added": float(df["bytes_added"].median()),
            "spawned_flows": int(df["spawned"].sum()),
            "share_spawned_pred_attack": float(df["spawned_pred_attack"].sum()
                                               / df["spawned"].sum()) if df["spawned"].sum()
            else math.nan,
            "decoy_flows_tested": len(decoys),
            "share_decoys_pred_attack": float(np.mean([c == 1 for c in decoys])) if decoys
            else math.nan})
        print({k2: (round(v, 3) if isinstance(v, float) else v) for k2, v in rows[-1].items()},
              flush=True)
    args.out.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(args.out / "certta_vs_free_ops.csv", index=False)
    (args.out / "certta_flows.json").write_text(json.dumps(
        {"model": model_name, "beta_length": bl, "beta_time_ms": bt, "pr_sel": pr_sel,
         "samples_num": args.samples_num, "alpha": args.alpha,
         "clean": {"flows": len(clean), "accuracy": float(np.mean(labels == pred)),
                   "attack_recall": float(np.mean(pred[labels == 1] == 1)),
                   "benign_accuracy": float(np.mean(pred[labels == 0] == 0))},
         "flows": recs}))


if __name__ == "__main__":
    main()
