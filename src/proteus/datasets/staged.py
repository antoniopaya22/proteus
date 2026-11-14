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
from itertools import pairwise
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


def features_kept(df: pd.DataFrame, keep: np.ndarray, warmup_s: float,
                  dense_rows: int = 3_000_000, sub_s: float = 600.0
                  ) -> tuple[pd.DataFrame, list | None]:
    """Features of the rows of ``df`` (sorted by ``t_end``) where ``keep`` is true.

    A window with more than ``dense_rows`` flows (CIC-DDoS-2019 has an hour of 14.5 M)
    does not fit in memory at once: it is cut in ``sub_s`` sub-windows, each with a
    warm-up of at most ``sub_s``, and only sub-windows with kept flows are computed.
    Dropping older events can only lower counters (see ``proteus.evidence.chunked``).
    """
    if len(df) <= dense_rows:
        feats, specs = build(df, DEFAULT_TAUS)
        return feats.loc[keep].reset_index(drop=True), specs
    t = df["t_end"]
    step = pd.Timedelta(seconds=sub_s)
    warm = pd.Timedelta(seconds=min(warmup_s, sub_s))
    start, end = t.min().floor("s"), t.max()
    parts, specs = [], None
    while start <= end:
        hi = start + step
        lo_i, a_i, hi_i = (int(t.searchsorted(x, side="left")) for x in (start - warm, start, hi))
        k = keep[a_i:hi_i]
        if k.any():
            f, specs = build(df.iloc[lo_i:hi_i], DEFAULT_TAUS)
            parts.append(f.iloc[a_i - lo_i:].reset_index(drop=True)[k])
        start = hi
    feats = (pd.concat(parts, ignore_index=True) if parts
             else pd.DataFrame(index=pd.RangeIndex(0)))
    return feats, specs


def _rows(files: list[Path]) -> int:
    import pyarrow.parquet as pq

    return sum(pq.ParquetFile(f).metadata.num_rows for f in files)


def process(stage_dir: Path, out_dir: Path, dataset: str, attack_rate: float = 0.02,
            warmup_s: float = 1800.0, salt: int = 0, label=None,
            key: list[str] | None = None, dense_rows: int = 2_000_000) -> list[dict]:
    """``label(df) -> (attack, family)`` relabels raw flows; ``None`` keeps the staged
    ``attack``/``family``/``is_attack`` columns.

    Each window is read from disk together with its warm-up (from the preceding window
    only), so no window is held in memory for the next one. A window with more than
    ``dense_rows`` flows is computed in slices of about ``dense_rows`` flows each (cut by
    row count, since attacks come in bursts), each with a warm-up as long as the slice:
    CIC-DDoS-2019 has hours of up to 23.5 M flows. Shorter warm-ups can only lower
    counters."""
    import pyarrow as pa
    import pyarrow.dataset as pads

    key = key or KEY
    ev_dir = out_dir / "evidence"
    ev_dir.mkdir(parents=True, exist_ok=True)
    windows = sorted((d.name, w) for d in stage_dir.iterdir() if d.is_dir()
                     for w in d.iterdir() if w.is_dir())
    starts = [_window_start(d, w.name) for d, w in windows]
    gaps = [b - a for a, b in pairwise(starts) if b > a]
    base = min([*gaps, pd.Timedelta(hours=1)])  # window length of HHMM partitions
    stats, specs, parts = [], None, []
    current_day = None
    for i, (day, wdir) in enumerate(windows):
        if current_day is not None and day != current_day and parts:
            _flush(dataset, current_day, parts, out_dir, ev_dir)
            parts = []
        current_day = day
        start = starts[i]
        win = pd.Timedelta(hours=1) if len(wdir.name) == 2 else base
        own_files = sorted(wdir.glob("*.parquet"))
        n = _rows(own_files)
        full_warm = pd.Timedelta(seconds=warmup_s)
        if n <= dense_rows:
            bounds = [start, start + win]
        else:  # slices of at most ~dense_rows flows: attacks come in bursts
            tt = np.sort(pads.dataset([str(f) for f in own_files], format="parquet")
                         .to_table(columns=["t_end"]).column(0).to_numpy())
            bounds = sorted({start, start + win,
                             *(pd.Timestamp(x) for x in tt[dense_rows::dense_rows])})
            del tt
        files, j = list(own_files), i - 1
        while j >= 0 and starts[j] + pd.Timedelta(hours=1) > start - full_warm:
            files = sorted(windows[j][1].glob("*.parquet")) + files
            j -= 1
        ds = pads.dataset([str(f) for f in files], format="parquet")
        ttype = ds.schema.field("t_end").type
        tot = {"flows": 0, "attacks": 0, "stored": 0}
        for s_lo, e0 in pairwise(bounds):
            warm = full_warm if n <= dense_rows else min(full_warm, e0 - s_lo)
            f = ((pads.field("t_end") >= pa.scalar((s_lo - warm).to_datetime64(), type=ttype))
                 & (pads.field("t_end") < pa.scalar(e0.to_datetime64(), type=ttype)))
            df = ds.to_table(filter=f).to_pandas()
            if df.empty:
                continue
            df = df.drop_duplicates(subset=key).sort_values("t_end", kind="stable")
            df = df.reset_index(drop=True)
            if label is not None:
                attack, family = label(df)
                df["attack"], df["family"] = attack, family
                df["is_attack"] = family != "benign"
                df["attempted"] = False
            df["dataset"], df["day"] = dataset, day
            own = (df["t_end"] >= s_lo).to_numpy()
            if not own.any():
                continue
            h = pd.util.hash_pandas_object(df[key], index=False).to_numpy()
            u = ((h ^ np.uint64(salt)) % np.uint64(1_000_000)).astype(np.float64) / 1e6
            keep = own & (~df["is_attack"].to_numpy() | (u < attack_rate))
            feats, sp = features_kept(df, keep, warm.total_seconds())
            specs = sp or specs
            parts.append(pd.concat([df.loc[keep].reset_index(drop=True),
                                    feats.astype(np.float32)], axis=1))
            tot["flows"] += int(own.sum())
            tot["attacks"] += int(df.loc[own, "is_attack"].sum())
            tot["stored"] += int(keep.sum())
            del df, feats
        stats.append({"day": day, "window": wdir.name, **tot})
        print(f"  {stats[-1]}", flush=True)
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
