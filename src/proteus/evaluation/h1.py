"""Phase-1 experiment (H1): can a monotone core over conserved evidence detect
volumetric, scanning and brute-force campaigns at low false-alarm rates?

Cross-dataset protocol: train on one dataset, calibrate the threshold on held-out
benign flows of the same dataset, test on the other dataset.

    python -m proteus.evaluation.h1 --train csecicids2018 --test cicids2017
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import pickle
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier

from proteus.baselines.kitnet import KitNET
from proteus.baselines.rate_rules import RateRules
from proteus.core.certify import reuse_worst_case, slack, worst_case_features
from proteus.core.combine import CalibratedMax, MaxCore
from proteus.core.verify import monotonicity_violations
from proteus.evidence import baseline as bl
from proteus.evidence.features import DEFAULT_TAUS, EVIDENCE_VERSION, build

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
# Re-scoring period δ of active entities (slack (2Δ+δ)/τ); 0 = state at t + Δ is scored.
TIMER_S = float(os.environ.get("PROTEUS_TIMER_S", "0"))
CAMPAIGN_GAP_S = 600.0
REUSE_SAFE = ("fbytes", "n_src", "n_dport", "n_dhost", "n_dsvc", "n_dhost_nr")


# ---------------------------------------------------------------- data

def days(ds: str) -> list[Path]:
    """Capture days in chronological order (baselines only look at earlier days)."""
    paths = list((DATA / ds).glob("*.parquet"))
    start = {p: pd.read_parquet(p, columns=["t_start"])["t_start"].min() for p in paths}
    return sorted(paths, key=start.get)


def evidence(ds: str, day: Path) -> tuple[pd.DataFrame, dict[str, str]]:
    """Evidence features for one day (cached)."""
    cache = _edir(ds) / day.name
    spec_file = _edir(ds) / "specs.json"
    if cache.exists() and spec_file.exists():
        return pd.read_parquet(cache), json.loads(spec_file.read_text())
    df = pd.read_parquet(day, columns=META + ["fwd_pkts", "fwd_bytes", "bwd_pkts",
                                               "bwd_bytes", "f_bwd_rst_flags", "duration_us"])
    feats, specs = build(df)
    out = pd.concat([df[META], feats], axis=1)
    out["suspect"] = suspected_scanners(df)
    out["clean"] = clean_benign(out) & ~out["suspect"].to_numpy()
    cache.parent.mkdir(parents=True, exist_ok=True)
    out.to_parquet(cache, index=False)
    spec_map = {s.name: s.conservation for s in specs}
    spec_file.write_text(json.dumps(spec_map))
    return out, spec_map


# Baseline setting, chosen in main(): reference days ("loo" | "prior") and
# masking of attack minutes ("labels" | "none").
BASELINE = {"mode": "loo", "mask": "labels"}


# Written by their converters (evidence computed on every flow, only a sample stored):
# the evidence cannot be recomputed from the stored flows.
CHUNKED = ("ugr16", "cicddos2019", "ctusme11")


def _vsuffix(ds: str) -> str:
    if EVIDENCE_VERSION == "v1":
        return ""
    if ds in CHUNKED:
        raise ValueError(f"{ds}: evidence {EVIDENCE_VERSION} needs a new conversion")
    return f"_{EVIDENCE_VERSION}"


def _edir(ds: str) -> Path:
    return DATA / ds / f"evidence{_vsuffix(ds)}"


# Population baselines (``__xp`` features), opt-in: PROTEUS_PEER=1.
PEER = os.environ.get("PROTEUS_PEER", "0") == "1"


def _bdir(ds: str) -> Path:
    peer = "_peer" if PEER else ""
    return DATA / ds / f"evidence_b_{BASELINE['mode']}_{BASELINE['mask']}{_vsuffix(ds)}{peer}"


def _pbdir(ds: str) -> Path:
    """Side cache with only the pair-baseline columns (PROTEUS_PAIRBASE=1), so the
    large main cache is not duplicated."""
    return _bdir(ds).with_name(_bdir(ds).name + "_pairbase")


def cache_parts(ds: str, day: Path) -> list[Path]:
    """Parquet files holding a day's evidence and baselines (disjoint columns, same
    rows): the main cache and, with PROTEUS_PAIRBASE=1, the pair-baseline side cache."""
    parts = [_bdir(ds) / day.name]
    if bl.PAIRBASE:
        parts.append(_pbdir(ds) / day.name)
    return parts


def _schema(path: Path) -> list[str]:
    import pyarrow.parquet as pq

    return pq.read_schema(path).names


def evidence_b(ds: str, day: Path, columns: list[str] | None = None
               ) -> tuple[pd.DataFrame, dict[str, str]]:
    """Evidence plus per-entity baselines from other days (cached). ``columns``
    restricts what is read (a 2018 day is ~7 M rows x 160 columns)."""
    cache, spec_file = _bdir(ds) / day.name, _bdir(ds) / "specs.json"
    if not (cache.exists() and spec_file.exists()):
        prepare_baselines(ds)
    specs = json.loads(spec_file.read_text())
    if not bl.PAIRBASE:
        return pd.read_parquet(cache, columns=columns), specs
    if not (_pbdir(ds) / "specs.json").exists():
        prepare_pair_baselines(ds)
    specs.update(json.loads((_pbdir(ds) / "specs.json").read_text()))
    frames = []
    for part in cache_parts(ds, day):
        names = _schema(part)
        cols = names if columns is None else [c for c in columns if c in names]
        if cols:
            frames.append(pd.read_parquet(part, columns=cols))
    out = pd.concat(frames, axis=1)
    return (out if columns is None else out[columns]), specs


def _write_chunked(path: Path, ev: pd.DataFrame, extra: dict[str, np.ndarray],
                   chunk: int = 1_000_000) -> None:
    """Evidence plus baseline columns, written in row chunks (no full-size copy)."""
    import pyarrow as pa
    import pyarrow.parquet as pq

    writer = None
    try:
        for lo in range(0, len(ev), chunk):
            part = ev.iloc[lo:lo + chunk].reset_index(drop=True)
            for k, v in extra.items():
                part[k] = v[lo:lo + chunk]
            tbl = pa.Table.from_pandas(part, preserve_index=False)
            if writer is None:
                writer = pq.ParquetWriter(path, tbl.schema)
            writer.write_table(tbl.cast(writer.schema))
    finally:
        if writer is not None:
            writer.close()


def prepare_baselines(ds: str) -> None:
    _prepare(ds, _bdir(ds), lambda e: e != "pairsvc", side=False)


def prepare_pair_baselines(ds: str) -> None:
    """Side cache with only the pair-baseline columns (see ``bl.PAIRBASE``)."""
    _prepare(ds, _pbdir(ds), lambda e: e == "pairsvc", side=True)


def _prepare(ds: str, out_dir: Path, use, side: bool) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    all_days = days(ds)
    codes = {e: bl.KeyCodes() for e in bl.COUNTERS}
    tables: dict[Path, dict[str, bl.DayTable]] = {}
    cols: dict[str, list[str]] = {}
    specs: dict[str, str] = {}
    # Pass A: per-minute tables of every day (masked minutes removed).
    for day in all_days:
        ev, specs = evidence(ds, day)
        cols = {e: c for e, c in bl.baseline_columns(list(specs)).items() if use(e)}
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
    spec_map: dict[str, str] = {} if side else dict(specs)
    for i, day in enumerate(all_days):
        ref = all_days[:i] if BASELINE["mode"] == "prior" else all_days[:i] + all_days[i + 1:]
        ev, _ = evidence(ds, day)
        keys = bl.entity_keys(ev)
        extra: dict[str, np.ndarray] = {}
        for ent, c in cols.items():
            base = bl.baseline([tables[d][ent] for d in ref], c) if ref else None
            k = pd.Series(codes[ent].encode(keys[ent], grow=False), index=ev.index)
            extra.update(bl.attach(ev, ent, c, k, base))
            if PEER:  # excess over the peer group's baseline (``__xp``)
                if base is None:
                    extra.update({f"{x}__xp": np.full(len(ev), np.nan, np.float32) for x in c})
                else:
                    named = base.set_axis(codes[ent].index[base.index.to_numpy()])
                    pop = bl.population_for(ent, named, keys[ent])
                    extra.update({f"{x}__xp": (ev[x].to_numpy(np.float64) - pop[x].to_numpy()
                                               ).astype(np.float32) for x in c})
        if side:  # only the new columns, same rows as the main cache
            pd.DataFrame(extra).to_parquet(out_dir / day.name, index=False)
        else:
            _write_chunked(out_dir / day.name, ev, extra)
        spec_map.update({k: ("baseline" if k.endswith("__b") else "conserved") for k in extra})
        print(f"  baselines {ds}/{day.stem}: {len(ref)} reference days", flush=True)
        del ev, extra
    (out_dir / "specs.json").write_text(json.dumps(spec_map))


def flow_feature_columns(day: Path) -> list[str]:
    import pyarrow.parquet as pq

    cols = pq.read_schema(day).names
    return [c for c in cols if c.startswith("f_")] + [
        "dst_port", "proto", "duration_us", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes"]


def flow_features(day: Path) -> pd.DataFrame:
    return pd.read_parquet(day, columns=flow_feature_columns(day)).astype("float32")


def _as_parts(path) -> list[Path]:
    return list(path) if isinstance(path, (list, tuple)) else [path]


def score_batches(path, cols: list[str], batch: int = 1_000_000):
    """Feature matrices of ``cols`` for consecutive row batches of a parquet file, or of
    several files with disjoint columns and the same rows (``cache_parts``)."""
    import pyarrow.parquet as pq

    parts = []
    for p in _as_parts(path):
        have = [c for c in cols if c in _schema(p)]
        if have:
            parts.append(pq.ParquetFile(p).iter_batches(batch_size=batch, columns=have))
    for bs in zip(*parts):
        df = pd.concat([b.to_pandas() for b in bs], axis=1)
        yield df[cols].to_numpy(np.float32)


def read_rows(path, idx: np.ndarray, columns: list[str] | None = None,
              batch: int = 500_000) -> pd.DataFrame:
    """Rows ``idx`` (sorted positions) of a parquet file (or of several with disjoint
    columns, ``cache_parts``), reading it in batches so a large day never sits in
    memory in full."""
    import pyarrow.parquet as pq

    frames = []
    for p in _as_parts(path):
        names = _schema(p)
        cols = names if columns is None else [c for c in columns if c in names]
        if not cols:
            continue
        out, start = [], 0
        for b in pq.ParquetFile(p).iter_batches(batch_size=batch, columns=cols):
            lo, hi = np.searchsorted(idx, [start, start + b.num_rows])
            if hi > lo:
                out.append(b.take(idx[lo:hi] - start).to_pandas())
            start += b.num_rows
        frames.append(pd.concat(out, ignore_index=True))
    df = pd.concat(frames, axis=1)
    return df if columns is None else df[columns]


SUSPECT_MIN_DSTS = 100
SUSPECT_MIN_NO_REPLY = 0.5


def suspected_scanners(df: pd.DataFrame) -> np.ndarray:
    """Unlabelled background flows from sources that behave like scanners.

    Real captures (CTU-13) label most traffic "background" (unknown), and it contains
    real Internet scanners. A source is suspected when, over the capture, its
    background flows reach at least SUSPECT_MIN_DSTS distinct destinations and at
    least SUSPECT_MIN_NO_REPLY of them get no reply. Its flows are left out of the
    false-alarm count and of threshold calibration, and detections are reported
    separately. Labelled flows are never marked.
    """
    bg = (df["family"] == "background").to_numpy()
    if not bg.any():
        return np.zeros(len(df), dtype=bool)
    b = df.loc[bg, ["src_ip", "dst_ip"]].assign(no_reply=(df.loc[bg, "bwd_pkts"] == 0))
    g = b.groupby("src_ip", observed=True).agg(dsts=("dst_ip", "nunique"),
                                               no_reply=("no_reply", "mean"))
    sus = g.index[(g["dsts"] >= SUSPECT_MIN_DSTS) & (g["no_reply"] >= SUSPECT_MIN_NO_REPLY)]
    return bg & df["src_ip"].isin(sus).to_numpy()


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

# Class balance of the training set, chosen in main() (--balance):
# "cap": at most cap_attack flows per attack type and day, cap_benign clean flows per day,
#        class_weight="balanced" (default, as in earlier runs);
# "type": same sample, sample weights giving every attack type the same total weight and
#        the benign class as much as all attacks together;
# "type_entity": as "type", benign flows weighted by 1/sqrt(flows of their destination
#        host in the sample), so a few busy servers do not define what is normal;
# "none": proportional sample (natural class ratio) of about none_rows flows, no weights.
BALANCE = {"mode": "cap", "none_rows": 3_000_000}


def training_set(ds: str, rng: np.random.Generator, cap_attack=50_000, cap_benign=300_000,
                 only: list[str] | None = None):
    parts = []
    all_days = [d for d in days(ds) if not only or d.stem in only]
    frac = None
    if BALANCE["mode"] == "none":
        total = sum(len(evidence_b(ds, d, columns=["clean"])[0]) for d in all_days)
        frac = min(1.0, BALANCE["none_rows"] / max(total, 1))
    for day in all_days:
        ev, specs = evidence_b(ds, day, columns=["attack", "is_attack", "clean"])
        idx = []
        if frac is not None:
            keep = ev["is_attack"].to_numpy() | ev["clean"].to_numpy()
            pool = ev.index[keep].to_numpy()
            idx.append(rng.choice(pool, round(len(pool) * frac), replace=False))
        else:
            for _, g in ev[ev["is_attack"]].groupby("attack", observed=True):
                idx.append(rng.choice(g.index.to_numpy(), min(len(g), cap_attack), replace=False))
            clean = ev.index[ev["clean"]].to_numpy()
            idx.append(rng.choice(clean, min(len(clean), cap_benign), replace=False))
        idx = np.sort(np.concatenate(idx))
        del ev
        rows = read_rows(cache_parts(ds, day), idx)
        flow = read_rows(day, idx, flow_feature_columns(day)).astype("float32")
        parts.append(pd.concat([rows, flow.add_prefix("flow__")], axis=1))
        print(f"  train {ds}/{day.stem}: {len(idx):,} rows", flush=True)
    return pd.concat(parts, ignore_index=True), specs


# ---------------------------------------------------------------- detectors

# Unsupervised detectors fitted, for each test day, on clean benign traffic of the
# other days of the test network (no labels), like the local thresholds.
LOCAL = {"rate_rules_local": RateRules, "kitnet_local": KitNET}
UNSUPERVISED = (RateRules, KitNET, CalibratedMax)

CST = {"conserved": 1, "response": 1, "baseline": -1}


def hgb(cst: list[int] | None) -> HistGradientBoostingClassifier:
    return HistGradientBoostingClassifier(
        max_iter=300, learning_rate=0.1, max_leaf_nodes=31, l2_regularization=1.0,
        class_weight="balanced" if BALANCE["mode"] == "cap" else None,
        monotonic_cst=cst, random_state=0,
    )


def sample_weights(tr: pd.DataFrame) -> np.ndarray | None:
    """Training weights for the --balance modes "type" and "type_entity" (None otherwise).
    Total weight: every attack type the same; benign as much as all attacks."""
    mode = BALANCE["mode"]
    if mode not in ("type", "type_entity"):
        return None
    att = tr["is_attack"].to_numpy()
    w = np.zeros(len(tr))
    types = tr.loc[att, "attack"].astype(str)
    counts = types.map(types.value_counts()).to_numpy(np.float64)
    w[att] = 1.0 / counts  # each type sums to 1
    n_types = types.nunique()
    ben = ~att
    if mode == "type_entity":
        hosts = tr.loc[ben, "dst_ip"].astype(str)
        wb = 1.0 / np.sqrt(hosts.map(hosts.value_counts()).to_numpy(np.float64))
    else:
        wb = np.ones(int(ben.sum()))
    w[ben] = wb / wb.sum() * n_types  # benign total = attack total
    return w * (len(tr) / w.sum())  # mean weight 1


def detectors(specs: dict[str, str], flow_cols: list[str]) -> dict[str, tuple[list[str], object]]:
    """Name -> (columns, model). Monotone models: +1 on evidence and excess over
    baseline, -1 on the baseline itself (a busier entity needs more evidence)."""
    dst = [k for k, v in specs.items() if not k.startswith(("shost__", "spair__"))]
    src = [k for k in specs if k.startswith("shost__")]

    def raw_of(cols):
        return [k for k in cols
                if specs[k] == "conserved" and not k.endswith(("__b", "__x", "__xp"))]

    raw = raw_of(dst)
    excess = [k for k in dst if k.endswith("__x")]
    with_b = raw + [k for k in dst if k.endswith(("__b", "__x"))]
    rules = raw + excess
    long_tau = f"__t{int(max(DEFAULT_TAUS))}"
    long_rules = [k for k in rules if k.endswith(long_tau) or f"{long_tau}__" in k]
    src_rules = raw_of(src) + [k for k in src if k.endswith("__x")]
    src_long = [k for k in src_rules if k.endswith(long_tau) or f"{long_tau}__" in k]

    def cst(cols):
        return [CST[specs[c]] for c in cols]

    both = rules + src_rules
    both_long = long_rules + src_long
    # Evidence that connection reuse (many requests in one connection) cannot lower
    # either: payload bytes and distinct counts. Per-connection counts (flows, resets,
    # unanswered) and packets (handshakes saved) can drop under reuse.
    raw_all = [k for k in specs if not k.endswith(("__b", "__x", "__xp"))]
    reuse_long = [k for k in long_rules if k.split("__")[1] in REUSE_SAFE]
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
        "core_cert_r": (reuse_long, hgb(cst(reuse_long))),
        "core_mono_dst_b": (with_b, hgb(cst(with_b))),
        "core_free_dst_b": (with_b, hgb(None)),
        "rate_rules": (rules, RateRules()),
        "rate_rules_local": (rules, RateRules()),
        # Kitsune's detector on our damped per-entity statistics (its AfterImage
        # counterpart): every evidence feature of both sides, no baselines.
        "kitnet_local": (raw_all, KitNET()),
        "flow_clf": (flow_cols, hgb(None)),
        **proteus_detectors(specs, rules, src_rules, raw, raw_of, cst),
    }


def _tau(name: str) -> float:
    return float(name.rsplit("__t", 1)[1].split("__")[0])


def proteus_detectors(specs, rules, src_rules, raw, raw_of, cst) -> dict:
    """Evidence v3: calibrated maximum of sub-cores, each fitted on one kind of
    evidence and calibrated on local benign traffic (``CalibratedMax``):

    * destination evidence and its excess over the entity baselines,
    * source evidence and its excess,
    * source-service pair counters (raw: pairs are almost always new, so they have no
      baseline to poison),
    * destination raw counts alone, which bound what baseline poisoning can hide.

    ``proteus_cert`` keeps time scales of 10 minutes and more (slack 2Δ/τ <= 0.4)."""
    pair = raw_of([k for k in specs if k.startswith("spair__")])
    if not pair:
        return {}
    # Pair excess over the service's busiest normal pair (PROTEUS_PAIRBASE=1).
    pair = pair + [k for k in specs if k.startswith("spair__") and k.endswith("__x")]

    def calmax(parts, keep=lambda c: True, mono=True):
        parts = [[c for c in cols if keep(c)] for cols in parts]
        parts = [cols for cols in parts if cols]
        cols = list(dict.fromkeys(c for cs in parts for c in cs))
        return cols, CalibratedMax(cols, [(cs, hgb(cst(cs) if mono else None)) for cs in parts])

    peer = raw + [k for k in specs if k.endswith("__xp") and not k.startswith("shost__")]
    parts = [rules, src_rules, pair, peer if len(peer) > len(raw) else raw]
    return {
        "core_pair": (pair, hgb(cst(pair))),
        "proteus": calmax(parts),
        "proteus_cert": calmax(parts, keep=lambda c: _tau(c) >= 600),
        # The same four sub-cores without monotonicity constraints (price of
        # monotonicity for the combination itself, not only for one model).
        "proteus_free": calmax(parts, mono=False),
    }


def score(model, X: np.ndarray) -> np.ndarray:
    if isinstance(model, UNSUPERVISED):
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


def load_models(run: Path) -> dict:
    """``models.pkl`` of a run. Pickles written before ``RateRules`` moved to its own
    module reference it as ``__main__.RateRules``."""
    import __main__

    __main__.RateRules = RateRules
    with open(Path(run) / "models.pkl", "rb") as fh:
        return pickle.load(fh)


def alert_side(model, cols: list[str], X: np.ndarray) -> np.ndarray:
    """True where an alert would be about the flow's source host rather than its
    destination: the source sub-core gives the maximum (``MaxCore``), or the model only
    uses source evidence."""
    parts = getattr(model, "parts", None)
    if not parts:
        return np.full(len(X), bool(cols) and all(c.startswith("shost") for c in cols))
    subs = np.vstack([m.predict_proba(X[:, idx])[:, 1] for idx, m in parts])
    is_src = np.array([all(cols[i].startswith("shost") for i in idx) for idx, _ in parts])
    return is_src[subs.argmax(axis=0)]


ENTITY_BUCKET = "10min"


def evaluate(test: pd.DataFrame, scores: dict[str, np.ndarray], thresholds: dict,
             sides: dict[str, np.ndarray] | None = None) -> pd.DataFrame:
    camp = campaigns(test)
    hours = sum(
        (g["t_end"].max() - g["t_start"].min()).total_seconds() / 3600
        for _, g in test.groupby("day", observed=True)
    )
    clean = test["clean"].to_numpy()
    suspect = (test["suspect"].to_numpy() if "suspect" in test
               else np.zeros(len(test), dtype=bool))
    sus_src = test.loc[suspect, "src_ip"]
    rows = []
    for (model, fpr, kind), thr in thresholds.items():
        s = scores[model]
        alert = s >= thr
        fa = test.loc[clean & alert]
        alarm_groups = fa.groupby(["day", "dst_ip", fa["t_start"].dt.floor("min")],
                                  observed=True).ngroups
        # Entity alarms: the alerted entity (source or destination host, by the
        # sub-core that fires) per ENTITY_BUCKET window.
        side = (sides or {}).get(model.removesuffix("@certr").removesuffix("@cert"))
        is_src = (side[clean & alert] if side is not None
                  else np.zeros(len(fa), dtype=bool))
        ent = np.where(is_src, fa["src_ip"].astype(str), fa["dst_ip"].astype(str))
        entity_groups = pd.DataFrame({"d": fa["day"].astype(str).to_numpy(), "e": ent,
                                      "s": is_src,
                                      "b": fa["t_start"].dt.floor(ENTITY_BUCKET).to_numpy()}
                                     ).drop_duplicates().shape[0]
        base = {"model": model, "target_fpr": fpr, "threshold": kind,
                "benign_fpr": alert[clean].mean(), "alarms_per_hour": alarm_groups / hours,
                "entity_alarms_per_hour": entity_groups / hours,
                "suspect_sources": int(sus_src.nunique()),
                "suspect_detected": int(sus_src[alert[suspect]].nunique())}
        for day, attack, idx in camp:
            hit = alert[test.index.get_indexer(idx)]
            start = test.loc[idx, "t_start"].min()
            ttd = ((test.loc[idx[hit], "t_end"].min() - start).total_seconds()
                   if hit.any() else np.nan)
            rows.append({**base, "day": day, "attack": attack, "flows": len(idx),
                         "detected": bool(hit.any()), "flow_recall": hit.mean(), "ttd_s": ttd})
    return pd.DataFrame(rows)


def entity_threshold(tops: list[tuple], hours: float, budget: float) -> float:
    """Lowest threshold giving at most ``budget`` alarms per hour, an alarm being a
    (day, destination host, minute) group with a clean flow at or above it."""
    groups = []
    for i, (sc, key, minute) in enumerate(tops):
        if len(sc) == 0:
            continue
        g = pd.DataFrame({"s": sc, "k": key, "m": minute}).groupby(["k", "m"])["s"].max()
        groups.append(g.to_numpy())
    if not groups:
        return float("inf")
    g = np.sort(np.concatenate(groups))[::-1]
    allowed = int(np.floor(budget * hours))
    if allowed >= len(g):
        return float(g[-1])
    return float(np.nextafter(g[allowed], np.inf))


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
    ap.add_argument("--entity-budgets", nargs="*", type=float, default=[],
                    help="also calibrate thresholds to at most this many alarms per hour "
                         "(destination host, minute) on clean traffic of the other days; "
                         "reported with threshold='entity' and the budget as target_fpr")
    ap.add_argument("--train-days", nargs="*", default=None,
                    help="restrict training to these capture days (file stems)")
    ap.add_argument("--test-days", nargs="*", default=None,
                    help="restrict testing to these capture days (file stems)")
    ap.add_argument("--balance", choices=["cap", "type", "type_entity", "none"], default="cap",
                    help="class balance of the training set (see BALANCE)")
    ap.add_argument("--exclude-saturated", type=float, default=None,
                    help="calibrated maxima drop sub-cores that cannot reach this FPR on "
                         "local benign traffic (saturated); default keeps all")
    ap.add_argument("--reuse", type=Path, default=None,
                    help="evaluate the fitted models of this run instead of training; "
                         "--models may name combinations a+b (maximum, MaxCore)")
    ap.add_argument("--train-thresholds", action="store_true",
                    help="also evaluate thresholds calibrated on the training network "
                         "(known not to transfer; slow because of the many alerts)")
    args = ap.parse_args()
    BASELINE.update(mode=args.baseline, mask=args.mask)
    BALANCE.update(mode=args.balance)
    rng = np.random.default_rng(args.seed)
    out = args.out / f"{args.train}__{args.test}__{args.baseline}_{args.mask}"
    if args.tag:
        out = out.with_name(f"{out.name}__{args.tag}")
    out.mkdir(parents=True, exist_ok=True)

    t0 = time.time()
    if args.reuse is not None:
        from proteus.evaluation.poisoning import combined

        fitted = load_models(args.reuse)
        _, specs = evidence_b(args.test, days(args.test)[0], columns=["clean"])
        fresh = detectors(specs, [])  # local detectors are fitted per test day anyway
        models = {n: fresh[n] if (n not in fitted and n in fresh) else combined(fitted, n)
                  for n in (args.models or list(fitted))}
        thresholds = {}
    else:
        tr, specs = training_set(args.train, rng, only=args.train_days)
        flow_cols = [c for c in tr.columns if c.startswith("flow__")]
        # Held-out calibration benign flows (30%) are not used for fitting.
        calib = tr["clean"].to_numpy() & (rng.random(len(tr)) < 0.3)
        fit = ~calib
        y = tr["is_attack"].to_numpy()
        sw = sample_weights(tr)

        models, thresholds, checks = {}, {}, {}
        chosen = detectors(specs, flow_cols)
        if args.models:
            chosen = {k: v for k, v in chosen.items() if k in args.models}
        for name, (cols, model) in chosen.items():
            X = tr[cols].to_numpy(np.float32)
            if isinstance(model, CalibratedMax):
                # Sub-cores on the labelled training network; the benign CDFs are
                # refitted per test day on local traffic (pass 2).
                MaxCore.fit(model, X[fit], y[fit],
                            sample_weight=None if sw is None else sw[fit])
                model.fit(X[fit & tr["clean"].to_numpy()])
                checks[name] = monotonicity_violations(
                    lambda Z, m=model: m.predict_proba(Z)[:, 1], X[fit],
                    np.asarray(model.monotonic_cst), rng)
                print(f"  monotonicity {name}: {checks[name]}", flush=True)
            elif isinstance(model, UNSUPERVISED):
                model.fit(X[fit & tr["clean"].to_numpy()])
            else:
                model.fit(X[fit], y[fit], sample_weight=None if sw is None else sw[fit])
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

    if args.exclude_saturated is not None:
        for _, m in models.values():
            if isinstance(m, CalibratedMax):
                m.exclude_fpr = args.exclude_saturated
    # Pass 1: score every test day; keep a sample of clean benign scores per day.
    test_days = [d for d in days(args.test) if not args.test_days or d.stem in args.test_days]
    local = {n: c for n, (c, m) in models.items() if n in LOCAL or getattr(m, "local", False)}
    day_scores, benign_sample, benign_feats = {}, {}, {}
    spill = out / "_scores"
    spill.mkdir(parents=True, exist_ok=True)
    top_of: dict = {}  # day -> model -> (top clean scores, dst key, minute)
    day_sides: dict = {}  # day -> model -> alert about the source host
    hours_of: dict = {}
    for day in test_days:
        # Only metadata in full; every model is scored on its own columns, in batches
        # of rows (a 2018 day with every model's columns does not fit in memory).
        path = cache_parts(args.test, day)
        ev, _ = evidence_b(args.test, day, columns=sorted(set(META) | {"clean"}))
        flow = (flow_features(day).add_prefix("flow__")
                if any(c[0].startswith("flow__") for c, _ in models.values()) else None)
        scores, sides = {}, {}
        for n, (c, m) in models.items():
            if n in local:
                continue
            if c[0].startswith("flow__"):
                scores[n] = score(m, flow[c].to_numpy(np.float32)).astype(np.float32)
                continue
            mono = getattr(m, "monotonic_cst", None) is not None
            sl = slack(c, specs, EXPORT_TIMEOUT_S, TIMER_S).astype(np.float32) if mono else None
            cst = np.asarray(m.monotonic_cst) if mono else None
            acc: dict[str, list] = {"s": [], "side": [], "cert": [], "certr": []}
            for X in score_batches(path, c):
                acc["s"].append(score(m, X).astype(np.float32))
                acc["side"].append(alert_side(m, c, X))
                if mono:  # certified: worst case over every free-operation variant
                    acc["cert"].append(score(m, worst_case_features(X, cst, sl)).astype(np.float32))
                    if "cert" in n:  # also against connection reuse
                        acc["certr"].append(score(m, reuse_worst_case(X, c, cst, sl)
                                                  ).astype(np.float32))
            scores[n] = np.concatenate(acc["s"])
            sides[n] = np.concatenate(acc["side"])
            if acc["cert"]:
                scores[f"{n}@cert"] = np.concatenate(acc["cert"])
            if acc["certr"]:
                scores[f"{n}@certr"] = np.concatenate(acc["certr"])
        day_sides[day] = sides
        clean_idx = np.flatnonzero(ev["clean"].to_numpy())
        pick = rng.choice(clean_idx, min(len(clean_idx), 1_000_000), replace=False)
        benign_sample[day] = {n: s_[pick] for n, s_ in scores.items()
                              if not n.endswith(("@cert", "@certr"))}
        # Spilled to disk: ten 2018 days of scores (7 M rows x ~14 score columns each)
        # do not fit in memory next to everything else.
        np.savez(spill / f"{day.stem}.npz", **{k.replace("@", "__AT__"): v
                                                for k, v in scores.items()})
        day_scores[day] = spill / f"{day.stem}.npz"
        if args.entity_budgets:
            clean = ev["clean"].to_numpy()
            key = pd.util.hash_array(ev["dst_ip"].astype(str).to_numpy()).astype(np.uint64)
            minute = (ev["t_start"].astype("int64") // 60_000_000).to_numpy().astype(np.uint64)
            hours_of[day] = (ev["t_end"].max() - ev["t_start"].min()).total_seconds() / 3600
            top_of[day] = {}
            for n, s_ in scores.items():
                if n.endswith(("@cert", "@certr")):
                    continue
                sc = s_[clean]
                cut = np.quantile(sc, 0.99) if len(sc) else np.inf
                hi = sc >= cut
                top_of[day][n] = (sc[hi], key[clean][hi], minute[clean][hi])
        if local:
            sample = np.sort(pick[:200_000])
            # One sample per day with the union of the local detectors' columns; each
            # detector takes its own (ablation variants share most of them).
            union = sorted({c for cols in local.values() for c in cols})
            benign_feats[day] = read_rows(path, sample, union).astype(np.float32)
        print(f"  scored {args.test}/{day.stem} at {time.time() - t0:.0f}s", flush=True)
        del ev, flow

    # Caches written before the "suspect" column existed do not have it.
    import pyarrow.parquet as pq
    has_suspect = "suspect" in pq.read_schema(_bdir(args.test) / test_days[0].name).names
    meta_cols = [*META, "clean"] + (["suspect"] if has_suspect else [])

    # Pass 2: "local" thresholds come from clean benign flows of the *other* days of
    # the test network (no attack labels needed in deployment, only benign traffic).
    results = []
    for day in test_days:
        others = [d for d in test_days if d != day]
        ev, _ = evidence_b(args.test, day, columns=meta_cols)
        path = cache_parts(args.test, day)
        with np.load(day_scores.pop(day)) as z:
            scores = {k.replace("__AT__", "@"): z[k] for k in z.files}
        # Unsupervised detectors fitted on the test network's own benign traffic of the
        # other days; their reference scores are those of the same benign sample.
        refs = {}
        for n, c in local.items():
            m = copy.deepcopy(models[n][1]).fit(
                np.concatenate([benign_feats[d][c].to_numpy() for d in others]))
            if isinstance(m, RateRules) and getattr(m, "monotonic_cst", None) is None:
                # A maximum of per-feature benign CDFs is non-decreasing in every
                # feature, so rate thresholds are certifiable on conserved evidence.
                m.monotonic_cst = [CST[specs[k]] for k in c]
            mono = getattr(m, "monotonic_cst", None) is not None
            cst = np.asarray(m.monotonic_cst) if mono else None
            sl = slack(c, specs, EXPORT_TIMEOUT_S, TIMER_S).astype(np.float32) if mono else None
            acc: dict[str, list] = {"s": [], "cert": [], "certr": []}
            for X in score_batches(path, c):
                acc["s"].append(m.score(X))
                if mono:
                    acc["cert"].append(m.score(worst_case_features(X, cst, sl)))
                    if "cert" in n:
                        acc["certr"].append(m.score(reuse_worst_case(X, c, cst, sl)))
            scores[n] = np.concatenate(acc["s"])
            if acc["cert"]:
                scores[f"{n}@cert"] = np.concatenate(acc["cert"])
            if acc["certr"]:
                scores[f"{n}@certr"] = np.concatenate(acc["certr"])
            refs[n] = np.concatenate([m.score(benign_feats[d][c].to_numpy()) for d in others])
        th = {k: v for k, v in thresholds.items() if k[0] not in local}
        for n in [k for k in scores if not k.endswith(("@cert", "@certr"))]:
            if n in refs:
                ref = refs[n]
            else:
                ref = np.concatenate([benign_sample[d][n] for d in others])
            for fpr in FPRS:
                th[(n, fpr, "local")] = np.quantile(ref, 1 - fpr, method="higher")
        for n in top_of.get(day, {}):
            for budget in args.entity_budgets:
                th[(n, budget, "entity")] = entity_threshold(
                    [top_of[d][n] for d in others], sum(hours_of[d] for d in others), budget)
        # A certified alert uses the same threshold as the model it certifies.
        for (n, fpr, kind), v in list(th.items()):
            for suffix in ("@cert", "@certr"):
                if f"{n}{suffix}" in scores:
                    th[(f"{n}{suffix}", fpr, kind)] = v
        results.append(evaluate(ev, scores, th, day_sides.pop(day, None)))
        print(f"  evaluated {args.test}/{day.stem} at {time.time() - t0:.0f}s", flush=True)
        del ev

    import shutil

    shutil.rmtree(spill, ignore_errors=True)
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
          [["benign_fpr", "alarms_per_hour", "entity_alarms_per_hour", "suspect_sources",
            "suspect_detected"]]
          .first().groupby(level=[0, 1, 2]).agg({"benign_fpr": "mean", "alarms_per_hour": "mean",
                                                  "entity_alarms_per_hour": "mean",
                                                  "suspect_sources": "sum",
                                                  "suspect_detected": "sum"}))
    fa.to_csv(out / "false_alarms.csv")
    print(summary.to_string())
    print(fa.to_string())


if __name__ == "__main__":
    main()
