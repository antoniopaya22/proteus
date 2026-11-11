"""Phase-1 experiment (H1): can a monotone core over conserved evidence detect
volumetric, scanning and brute-force campaigns at low false-alarm rates?

Cross-dataset protocol: train on one dataset, calibrate the threshold on held-out
benign flows of the same dataset, test on the other dataset.

    python -m proteus.evaluation.h1 --train csecicids2018 --test cicids2017
"""

from __future__ import annotations

import argparse
import json
import pickle
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier

from proteus.baselines.rate_rules import RateRules
from proteus.core.certify import slack, worst_case_features
from proteus.core.combine import MaxCore
from proteus.core.verify import monotonicity_violations
from proteus.evidence import baseline as bl
from proteus.evidence.features import DEFAULT_TAUS, build

DATA = Path("data/processed")
META = ["dataset", "day", "t_start", "t_end", "src_ip", "dst_ip", "dst_port", "proto",
        "attack", "family", "attempted", "is_attack"]
FPRS = (1e-3, 1e-4)
# Families that are not attack traffic: labelled benign and unlabelled real background
# (CTU-13). Everything else, including "Attempted" attack flows, is malicious.
NOT_MALICIOUS = ("benign", "background")


def malicious_mask(df: pd.DataFrame) -> np.ndarray:
    return (~df["family"].isin(NOT_MALICIOUS)).to_numpy()
EXPORT_TIMEOUT_S = 120.0  # CICFlowMeter flow timeout in both datasets (max duration 120 s)
CAMPAIGN_GAP_S = 600.0


# ---------------------------------------------------------------- data

def days(ds: str) -> list[Path]:
    """Capture days in chronological order (baselines only look at earlier days)."""
    paths = list((DATA / ds).glob("*.parquet"))
    start = {p: pd.read_parquet(p, columns=["t_start"])["t_start"].min() for p in paths}
    return sorted(paths, key=start.get)


def evidence(ds: str, day: Path) -> tuple[pd.DataFrame, dict[str, str]]:
    """Evidence features for one day (cached)."""
    cache = DATA / ds / "evidence" / day.name
    spec_file = DATA / ds / "evidence" / "specs.json"
    if cache.exists() and spec_file.exists():
        return pd.read_parquet(cache), json.loads(spec_file.read_text())
    df = pd.read_parquet(day, columns=META + ["fwd_pkts", "fwd_bytes", "bwd_pkts",
                                               "bwd_bytes", "f_bwd_rst_flags", "duration_us"])
    feats, specs = build(df)
    out = pd.concat([df[META], feats], axis=1)
    out["clean"] = clean_benign(out)
    cache.parent.mkdir(parents=True, exist_ok=True)
    out.to_parquet(cache, index=False)
    spec_map = {s.name: s.conservation for s in specs}
    spec_file.write_text(json.dumps(spec_map))
    return out, spec_map


# Baseline setting, chosen in main(): reference days ("loo" | "prior") and
# masking of attack minutes ("labels" | "none").
BASELINE = {"mode": "loo", "mask": "labels"}


def _bdir(ds: str) -> Path:
    return DATA / ds / f"evidence_b_{BASELINE['mode']}_{BASELINE['mask']}"


def evidence_b(ds: str, day: Path, columns: list[str] | None = None
               ) -> tuple[pd.DataFrame, dict[str, str]]:
    """Evidence plus per-entity baselines from other days (cached). ``columns``
    restricts what is read (a 2018 day is ~7 M rows x 160 columns)."""
    cache, spec_file = _bdir(ds) / day.name, _bdir(ds) / "specs.json"
    if not (cache.exists() and spec_file.exists()):
        prepare_baselines(ds)
    return pd.read_parquet(cache, columns=columns), json.loads(spec_file.read_text())


def prepare_baselines(ds: str) -> None:
    out_dir = _bdir(ds)
    out_dir.mkdir(parents=True, exist_ok=True)
    all_days = days(ds)
    codes = {e: bl.KeyCodes() for e in bl.COUNTERS}
    tables: dict[Path, dict[str, bl.DayTable]] = {}
    cols: dict[str, list[str]] = {}
    specs: dict[str, str] = {}
    # Pass A: per-minute tables of every day (masked minutes removed).
    for day in all_days:
        ev, specs = evidence(ds, day)
        cols = bl.baseline_columns(list(specs))
        keys = bl.entity_keys(ev)
        malicious = (malicious_mask(ev)
                     if BASELINE["mask"] == "labels" else None)
        minutes = int(np.ceil((ev["t_end"].max() - ev["t_start"].min()).total_seconds() / 60))
        tables[day] = {}
        for ent, c in cols.items():
            k = pd.Series(codes[ent].encode(keys[ent]), index=ev.index)
            tables[day][ent] = bl.day_table(ev, c, k, malicious, minutes)
        print(f"  minute tables {ds}/{day.stem}", flush=True)
        del ev
    # Pass B: baseline for each day from its reference days.
    spec_map: dict[str, str] = dict(specs)
    for i, day in enumerate(all_days):
        ref = all_days[:i] if BASELINE["mode"] == "prior" else all_days[:i] + all_days[i + 1:]
        ev, _ = evidence(ds, day)
        keys = bl.entity_keys(ev)
        extra: dict[str, np.ndarray] = {}
        for ent, c in cols.items():
            base = bl.baseline([tables[d][ent] for d in ref], c) if ref else None
            k = pd.Series(codes[ent].encode(keys[ent], grow=False), index=ev.index)
            extra.update(bl.attach(ev, ent, c, k, base))
        out = pd.concat([ev, pd.DataFrame(extra, index=ev.index)], axis=1)
        out.to_parquet(out_dir / day.name, index=False)
        spec_map.update({k: ("baseline" if k.endswith("__b") else "conserved") for k in extra})
        print(f"  baselines {ds}/{day.stem}: {len(ref)} reference days", flush=True)
        del ev, out
    (out_dir / "specs.json").write_text(json.dumps(spec_map))


def flow_features(day: Path) -> pd.DataFrame:
    cols = pd.read_parquet(day).columns
    keep = [c for c in cols if c.startswith("f_")] + [
        "dst_port", "proto", "duration_us", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes"]
    return pd.read_parquet(day, columns=keep).astype("float32")


def clean_benign(df: pd.DataFrame) -> np.ndarray:
    """Non-attack flows (benign or unlabelled background) whose hosts are not involved
    in any attack within +-1 minute.

    Benign traffic to a host under attack is legitimately part of an alerted
    entity; it is neither a true nor a false alarm and is left out of both.
    """
    ips, _ = pd.factorize(pd.concat([df["src_ip"], df["dst_ip"]], ignore_index=True))
    n = len(df)
    src, dst = ips[:n].astype(np.int64), ips[n:].astype(np.int64)
    minute = (df["t_start"].astype("int64") // 60_000_000).to_numpy()
    malicious = malicious_mask(df)
    keys = []
    for d in (-1, 0, 1):
        m = minute[malicious] + d
        keys += [src[malicious] * 10**8 + m, dst[malicious] * 10**8 + m]
    involved = np.unique(np.concatenate(keys)) if keys else np.array([], dtype=np.int64)
    hit = np.isin(src * 10**8 + minute, involved) | np.isin(dst * 10**8 + minute, involved)
    return (~malicious) & ~hit


# ---------------------------------------------------------------- training set

def training_set(ds: str, rng: np.random.Generator, cap_attack=50_000, cap_benign=300_000,
                 only: list[str] | None = None):
    parts = []
    for day in days(ds):
        if only and day.stem not in only:
            continue
        ev, specs = evidence_b(ds, day)
        flow = flow_features(day)
        idx = []
        for _, g in ev[ev["is_attack"]].groupby("attack", observed=True):
            idx.append(rng.choice(g.index.to_numpy(), min(len(g), cap_attack), replace=False))
        clean = ev.index[ev["clean"]].to_numpy()
        idx.append(rng.choice(clean, min(len(clean), cap_benign), replace=False))
        idx = np.sort(np.concatenate(idx))
        parts.append(pd.concat([ev.loc[idx].reset_index(drop=True),
                                flow.loc[idx].add_prefix("flow__").reset_index(drop=True)],
                               axis=1))
        print(f"  train {ds}/{day.stem}: {len(idx):,} rows", flush=True)
    return pd.concat(parts, ignore_index=True), specs


# ---------------------------------------------------------------- detectors

CST = {"conserved": 1, "response": 1, "baseline": -1}


def hgb(cst: list[int] | None) -> HistGradientBoostingClassifier:
    return HistGradientBoostingClassifier(
        max_iter=300, learning_rate=0.1, max_leaf_nodes=31, l2_regularization=1.0,
        class_weight="balanced", monotonic_cst=cst, random_state=0,
    )


def detectors(specs: dict[str, str], flow_cols: list[str]) -> dict[str, tuple[list[str], object]]:
    """Name -> (columns, model). Monotone models: +1 on evidence and excess over
    baseline, -1 on the baseline itself (a busier entity needs more evidence)."""
    dst = [k for k, v in specs.items() if not k.startswith("shost__")]
    src = [k for k in specs if k.startswith("shost__")]

    def raw_of(cols):
        return [k for k in cols if specs[k] == "conserved" and not k.endswith(("__b", "__x"))]

    raw = raw_of(dst)
    excess = [k for k in dst if k.endswith("__x")]
    with_b = raw + [k for k in dst if k.endswith(("__b", "__x"))]
    rules = raw + excess
    long_tau = f"__t{int(max(DEFAULT_TAUS))}"
    long_rules = [k for k in rules if long_tau in k]
    src_rules = raw_of(src) + [k for k in src if k.endswith("__x")]
    src_long = [k for k in src_rules if long_tau in k]

    def cst(cols):
        return [CST[specs[c]] for c in cols]

    both = rules + src_rules
    both_long = long_rules + src_long
    return {
        "core_mono_dst": (raw, hgb(cst(raw))),
        # Excess over the entity's own baseline, without the baseline itself: rarity
        # alone (baseline 0) cannot raise the score, only evidence above normal can.
        "core_mono_dst_x": (rules, hgb(cst(rules))),
        # Certifiable core: only the longest time scale, where the certification
        # slack 2Δ/τ is small (0.4 for Δ=120 s, τ=600 s).
        "core_cert": (long_rules, hgb(cst(long_rules))),
        # Destination core and source core, combined by max (monotone).
        "core_src_x": (src_rules, hgb(cst(src_rules))),
        "core_both_x": (both, MaxCore(both, [(rules, hgb(cst(rules))),
                                            (src_rules, hgb(cst(src_rules)))])),
        "core_both_cert": (both_long, MaxCore(both_long, [(long_rules, hgb(cst(long_rules))),
                                                          (src_long, hgb(cst(src_long)))])),
        "core_mono_dst_b": (with_b, hgb(cst(with_b))),
        "core_free_dst_b": (with_b, hgb(None)),
        "rate_rules": (rules, RateRules()),
        "rate_rules_local": (rules, RateRules()),
        "flow_clf": (flow_cols, hgb(None)),
    }


def score(model, X: np.ndarray) -> np.ndarray:
    if isinstance(model, RateRules):
        return model.score(X)
    return model.predict_proba(X)[:, 1]


# ---------------------------------------------------------------- metrics

def campaigns(df: pd.DataFrame) -> pd.DataFrame:
    a = df[df["is_attack"]].sort_values("t_start")
    rows = []
    for (day, attack), g in a.groupby(["day", "attack"], observed=True):
        ts = g["t_start"].astype("int64").to_numpy() / 1e6
        cid = np.concatenate([[0], np.cumsum(np.diff(ts) > CAMPAIGN_GAP_S)])
        for c in np.unique(cid):
            rows.append((day, attack, g.index[cid == c].to_numpy()))
    return rows


def evaluate(test: pd.DataFrame, scores: dict[str, np.ndarray], thresholds: dict) -> pd.DataFrame:
    camp = campaigns(test)
    hours = sum(
        (g["t_end"].max() - g["t_start"].min()).total_seconds() / 3600
        for _, g in test.groupby("day", observed=True)
    )
    clean = test["clean"].to_numpy()
    rows = []
    for (model, fpr, kind), thr in thresholds.items():
        s = scores[model]
        alert = s >= thr
        fa = test.loc[clean & alert]
        alarm_groups = fa.groupby(["day", "dst_ip", fa["t_start"].dt.floor("min")],
                                  observed=True).ngroups
        base = {"model": model, "target_fpr": fpr, "threshold": kind,
                "benign_fpr": alert[clean].mean(), "alarms_per_hour": alarm_groups / hours}
        for day, attack, idx in camp:
            hit = alert[test.index.get_indexer(idx)]
            start = test.loc[idx, "t_start"].min()
            ttd = ((test.loc[idx[hit], "t_end"].min() - start).total_seconds()
                   if hit.any() else np.nan)
            rows.append({**base, "day": day, "attack": attack, "flows": len(idx),
                         "detected": bool(hit.any()), "flow_recall": hit.mean(), "ttd_s": ttd})
    return pd.DataFrame(rows)


# ---------------------------------------------------------------- main

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", required=True)
    ap.add_argument("--test", required=True)
    ap.add_argument("--out", type=Path, default=Path("experiments/outputs/h1"))
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--baseline", choices=["loo", "prior"], default="loo")
    ap.add_argument("--mask", choices=["labels", "none"], default="labels")
    ap.add_argument("--models", nargs="*", default=None,
                    help="only these detectors (default: all)")
    ap.add_argument("--tag", default="", help="suffix for the output directory")
    ap.add_argument("--train-days", nargs="*", default=None,
                    help="restrict training to these capture days (file stems)")
    ap.add_argument("--test-days", nargs="*", default=None,
                    help="restrict testing to these capture days (file stems)")
    ap.add_argument("--train-thresholds", action="store_true",
                    help="also evaluate thresholds calibrated on the training network "
                         "(known not to transfer; slow because of the many alerts)")
    args = ap.parse_args()
    BASELINE.update(mode=args.baseline, mask=args.mask)
    rng = np.random.default_rng(args.seed)
    out = args.out / f"{args.train}__{args.test}__{args.baseline}_{args.mask}"
    if args.tag:
        out = out.with_name(f"{out.name}__{args.tag}")
    out.mkdir(parents=True, exist_ok=True)

    t0 = time.time()
    tr, specs = training_set(args.train, rng, only=args.train_days)
    flow_cols = [c for c in tr.columns if c.startswith("flow__")]
    # Held-out calibration benign flows (30%) are not used for fitting.
    calib = tr["clean"].to_numpy() & (rng.random(len(tr)) < 0.3)
    fit = ~calib
    y = tr["is_attack"].to_numpy()

    models, thresholds, checks = {}, {}, {}
    chosen = detectors(specs, flow_cols)
    if args.models:
        chosen = {k: v for k, v in chosen.items() if k in args.models}
    for name, (cols, model) in chosen.items():
        X = tr[cols].to_numpy(np.float32)
        if isinstance(model, RateRules):
            model.fit(X[fit & tr["clean"].to_numpy()])
        else:
            model.fit(X[fit], y[fit])
            if model.monotonic_cst is not None:
                checks[name] = monotonicity_violations(
                    lambda Z, m=model: m.predict_proba(Z)[:, 1], X[fit],
                    np.asarray(model.monotonic_cst), rng)
                print(f"  monotonicity {name}: {checks[name]}", flush=True)
        if args.train_thresholds:
            s_cal = score(model, X[calib])
            for fpr in FPRS:
                thresholds[(name, fpr, "train")] = np.quantile(s_cal, 1 - fpr,
                                                               method="higher")
        models[name] = (cols, model)
        print(f"  fitted {name} ({len(cols)} features) at {time.time() - t0:.0f}s", flush=True)
    (out / "monotonicity.json").write_text(json.dumps(checks, indent=2))
    with open(out / "models.pkl", "wb") as fh:
        pickle.dump(models, fh)
    del tr

    # Pass 1: score every test day; keep a sample of clean benign scores per day.
    test_days = [d for d in days(args.test) if not args.test_days or d.stem in args.test_days]
    local_cols = models["rate_rules_local"][0] if "rate_rules_local" in models else []
    ev_cols = sorted({c for cols, _ in models.values() for c in cols if not c.startswith("flow__")}
                     | set(META) | {"clean"})
    meta_cols = [*META, "clean"]
    day_scores, benign_sample, benign_feats = {}, {}, {}
    for day in test_days:
        ev, _ = evidence_b(args.test, day, columns=ev_cols)
        flow = flow_features(day).add_prefix("flow__")

        def frame(cols, ev=ev, flow=flow):
            return flow if cols[0].startswith("flow__") else ev

        scores = {n: score(m, frame(c)[c].to_numpy(np.float32)).astype(np.float32)
                  for n, (c, m) in models.items() if n != "rate_rules_local"}
        clean_idx = np.flatnonzero(ev["clean"].to_numpy())
        pick = rng.choice(clean_idx, min(len(clean_idx), 1_000_000), replace=False)
        benign_sample[day] = {n: s[pick] for n, s in scores.items()}
        # Certified scores: worst case over every free-operation variant (doc 04).
        for n, (c, m) in models.items():
            if getattr(m, "monotonic_cst", None) is not None:
                cst = np.asarray(m.monotonic_cst)
                X = worst_case_features(ev[c].to_numpy(np.float32), cst,
                                        slack(c, specs, EXPORT_TIMEOUT_S).astype(np.float32))
                scores[f"{n}@cert"] = score(m, X).astype(np.float32)
                del X
        day_scores[day] = scores
        if local_cols:
            benign_feats[day] = ev[local_cols].to_numpy(np.float32)[pick[:200_000]]
        print(f"  scored {args.test}/{day.stem} at {time.time() - t0:.0f}s", flush=True)
        del ev, flow

    # Pass 2: "local" thresholds come from clean benign flows of the *other* days of
    # the test network (no attack labels needed in deployment, only benign traffic).
    results = []
    for day in test_days:
        others = [d for d in test_days if d != day]
        ev, _ = evidence_b(args.test, day, columns=meta_cols + local_cols)
        scores = day_scores.pop(day)
        # Fixed thresholds fitted on the test network's own benign traffic (other days).
        if local_cols:
            rr = RateRules().fit(np.concatenate([benign_feats[d] for d in others]))
            scores["rate_rules_local"] = rr.score(ev[local_cols].to_numpy(np.float32))
        th = {k: v for k, v in thresholds.items() if k[0] != "rate_rules_local"}
        for n in [k for k in scores if not k.endswith("@cert")]:
            if n == "rate_rules_local":
                ref = np.concatenate([rr.score(benign_feats[d]) for d in others])
            else:
                ref = np.concatenate([benign_sample[d][n] for d in others])
            for fpr in FPRS:
                th[(n, fpr, "local")] = np.quantile(ref, 1 - fpr, method="higher")
        # A certified alert uses the same threshold as the model it certifies.
        for (n, fpr, kind), v in list(th.items()):
            if f"{n}@cert" in scores:
                th[(f"{n}@cert", fpr, kind)] = v
        results.append(evaluate(ev, scores, th))
        print(f"  evaluated {args.test}/{day.stem} at {time.time() - t0:.0f}s", flush=True)
        del ev

    res = pd.concat(results, ignore_index=True)
    res.to_csv(out / "campaigns.csv", index=False)
    summary = (
        res.groupby(["model", "target_fpr", "threshold", "attack"], observed=True)
        .agg(campaigns=("detected", "size"), detected=("detected", "sum"),
             flow_recall=("flow_recall", "mean"), median_ttd_s=("ttd_s", "median"))
        .reset_index()
    )
    summary.to_csv(out / "summary.csv", index=False)
    fa = (res.groupby(["model", "target_fpr", "threshold", "day"], observed=True)
          [["benign_fpr", "alarms_per_hour"]].first().groupby(level=[0, 1, 2]).mean())
    fa.to_csv(out / "false_alarms.csv")
    print(summary.to_string())
    print(fa.to_string())


if __name__ == "__main__":
    main()
