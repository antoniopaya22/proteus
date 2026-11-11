"""Evidence for captures too large for memory, from time-partitioned staging files.

A converter first *stages* its flows (common schema plus ``attack``, ``family``,
``is_attack`` and ``label_raw``) as ``<stage>/<YYYY-MM-DD>/<HH[MM]>/*.parquet``,
partitioned by the start of the time window that contains ``t_end``. ``process`` then
computes evidence window by window with a warm-up from the preceding windows (see
``proteus.evidence.chunked`` for the error bound: dropping old events can only lower
counters), drops exact duplicates, and stores every non-attack flow plus a sample of
attack flows (``attack_rate``). Counters always use every flow.
"""

from __future__ import annotations

import json
from collections import deque
from pathlib import Path

import numpy as np
import pandas as pd

from proteus.evidence.features import DEFAULT_TAUS, build

META = ["dataset", "day", "t_start", "t_end", "src_ip", "dst_ip", "dst_port", "proto",
        "attack", "family", "attempted", "is_attack"]
KEY = ["t_start", "t_end", "src_ip", "dst_ip", "src_port", "dst_port", "proto",
       "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes"]


def partition(stage_dir: Path, df: pd.DataFrame, stem: str, minutes: int = 60) -> None:
    """Write ``df`` into the staging partitions of its ``t_end`` windows."""
    win = df["t_end"].dt.floor(f"{minutes}min")
    for w, g in df.groupby(win):
        name = w.strftime("%H") if minutes == 60 else w.strftime("%H%M")
        p = stage_dir / w.strftime("%Y-%m-%d") / name
        p.mkdir(parents=True, exist_ok=True)
        g.to_parquet(p / f"{stem}.parquet", index=False)


def _window_start(day: str, name: str) -> pd.Timestamp:
    hh, mm = name[:2], name[2:4] or "00"
    return pd.Timestamp(f"{day} {hh}:{mm}:00")


def process(stage_dir: Path, out_dir: Path, dataset: str, attack_rate: float = 0.02,
            warmup_s: float = 1800.0, salt: int = 0, label=None,
            key: list[str] | None = None) -> list[dict]:
    """``label(df) -> (attack, family)`` relabels raw flows; ``None`` keeps the staged
    ``attack``/``family``/``is_attack`` columns."""
    key = key or KEY
    ev_dir = out_dir / "evidence"
    ev_dir.mkdir(parents=True, exist_ok=True)
    windows = sorted((d.name, w) for d in stage_dir.iterdir() if d.is_dir()
                     for w in d.iterdir() if w.is_dir())
    stats, specs, parts = [], None, []
    prev: deque[tuple[pd.Timestamp, pd.DataFrame]] = deque()
    current_day = None
    for day, wdir in windows:
        if current_day is not None and day != current_day and parts:
            _flush(dataset, current_day, parts, out_dir, ev_dir)
            parts = []
        current_day = day
        start = _window_start(day, wdir.name)
        cur = pd.concat([pd.read_parquet(f) for f in sorted(wdir.glob("*.parquet"))],
                        ignore_index=True)
        lo = start - pd.Timedelta(seconds=warmup_s)
        while prev and prev[0][1]["t_end"].max() < lo:
            prev.popleft()
        warm = [d[d["t_end"] >= lo] for _, d in prev]
        df = pd.concat([*warm, cur], ignore_index=True) if warm else cur
        df = df.drop_duplicates(subset=key).sort_values("t_end", kind="stable")
        df = df.reset_index(drop=True)
        if label is not None:
            attack, family = label(df)
            df["attack"], df["family"] = attack, family
            df["is_attack"] = family != "benign"
            df["attempted"] = False
        df["dataset"], df["day"] = dataset, day
        feats, specs = build(df, DEFAULT_TAUS)
        own = (df["t_end"] >= start).to_numpy()
        h = pd.util.hash_pandas_object(df[key], index=False).to_numpy()
        u = ((h ^ np.uint64(salt)) % np.uint64(1_000_000)).astype(np.float64) / 1e6
        keep = own & (~df["is_attack"].to_numpy() | (u < attack_rate))
        parts.append(pd.concat([df.loc[keep].reset_index(drop=True),
                                feats.loc[keep].reset_index(drop=True)], axis=1))
        stats.append({"day": day, "window": wdir.name, "flows": int(own.sum()),
                      "attacks": int(df.loc[own, "is_attack"].sum()),
                      "stored": int(keep.sum())})
        print(f"  {stats[-1]}", flush=True)
        prev.append((start, cur))
        del df, feats
    if parts:
        _flush(dataset, current_day, parts, out_dir, ev_dir)
    if specs is not None:
        (ev_dir / "specs.json").write_text(json.dumps({s.name: s.conservation for s in specs}))
    return stats


def _flush(dataset: str, day: str, parts: list, out_dir: Path, ev_dir: Path) -> None:
    from proteus.evaluation.h1 import clean_benign

    d = pd.concat(parts, ignore_index=True).sort_values("t_end", kind="stable")
    d = d.reset_index(drop=True)
    for c in d.columns:
        if c in ("src_ip", "dst_ip"):
            d[c] = d[c].astype("string")
        elif d[c].dtype == object or str(d[c].dtype) == "string":
            d[c] = d[c].astype("category")
    d["suspect"] = False
    d["clean"] = clean_benign(d)
    feat_cols = [c for c in d.columns if "__t" in c]
    raw_cols = [c for c in d.columns if c not in feat_cols and c not in ("suspect", "clean")]
    d[raw_cols].to_parquet(out_dir / f"{day}.parquet", index=False)
    d[META + feat_cols + ["suspect", "clean"]].to_parquet(ev_dir / f"{day}.parquet", index=False)
    print(f"  wrote {dataset}/{day}: {len(d):,} stored flows", flush=True)
