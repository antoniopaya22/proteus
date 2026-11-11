"""UGR'16 (Maciá-Fernández et al., Computers & Security 73, 2018): real ISP NetFlow.

Source: the Hugging Face mirror ``Lystea/UGR16-PARQUET`` (unofficial; the official site
returned HTTP 403 on 2026-11-11). One parquet per week, ~540 M unidirectional flows.

A week is far too large to hold in memory, so evidence is computed hour by hour with a
warm-up (see ``proteus.evidence.chunked``): counters use **every** flow, but only a
sample is stored: all attack flows and ``sample_rate`` of the background, chosen by a
deterministic hash of the row. The output goes straight to the evidence cache
(``data/processed/ugr16/evidence/<day>.parquet``) plus a small per-day parquet of the
stored flows, so the H1 pipeline can use it as any other dataset.

Notes:
* records are unidirectional: ``bwd_*`` are 0 and responder RSTs cannot be attributed
  (``f_bwd_rst_flags`` = 0); both choices can only lower evidence;
* labels: ``label_binary == "malicious"`` → attack, family from ``label_attack``;
  the rest is ``background`` (unknown, real ISP traffic), never benign;
* per-entity baselines are later computed from the stored sample only, so they are
  biased low (minutes where the entity was not sampled count as 0).
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.dataset as pads
import pyarrow.parquet as pq

from proteus.evidence.features import DEFAULT_TAUS, build

FAMILY = {"dos": "dos", "scan11": "portscan", "scan44": "portscan", "nerisbotnet": "botnet",
          "anomaly-spam": "spam", "anomaly-sshscan": "portscan", "anomaly-udpscan": "portscan",
          "blacklist": "background"}
COLS = ["ts_start", "ts_end", "src_ip", "dst_ip", "src_port", "dst_port", "l4_proto",
        "duration", "packets", "bytes", "label_binary", "label_attack"]
META = ["dataset", "day", "t_start", "t_end", "src_ip", "dst_ip", "dst_port", "proto",
        "attack", "family", "attempted", "is_attack"]


def _frame(tbl) -> pd.DataFrame:
    d = tbl.to_pandas()
    lab = d["label_attack"].fillna("").str.lower()
    mal = (d["label_binary"] == "malicious").to_numpy()
    family = np.where(mal, lab.map(FAMILY).fillna("other").to_numpy(), "background")
    family = np.where(mal & (family == "background"), "other", family)
    t_start = pd.to_datetime(d["ts_start"], unit="s").astype("datetime64[us]")
    t_end = pd.to_datetime(d["ts_end"], unit="s").astype("datetime64[us]")
    n = len(d)
    out = pd.DataFrame({
        "dataset": "ugr16",
        "t_start": t_start, "t_end": t_end,
        "src_ip": d["src_ip"].astype("string"), "dst_ip": d["dst_ip"].astype("string"),
        "src_port": d["src_port"].fillna(0).astype(np.int32),
        "dst_port": d["dst_port"].fillna(0).astype(np.int32),
        "proto": d["l4_proto"].fillna(0).astype(np.int16),
        "duration_us": (d["duration"].fillna(0) * 1e6).astype(np.int64).clip(lower=0),
        "fwd_pkts": d["packets"].fillna(0).astype(np.int64),
        "bwd_pkts": np.zeros(n, dtype=np.int64),
        "fwd_bytes": d["bytes"].fillna(0).astype(np.int64),
        "bwd_bytes": np.zeros(n, dtype=np.int64),
        "f_bwd_rst_flags": np.zeros(n, dtype=np.float32),
        "attack": np.where(mal, lab, "background"),
        "family": family,
        "attempted": False,
        "is_attack": mal,
    })
    out["day"] = out["t_end"].dt.strftime("%Y-%m-%d")
    return out.sort_values("t_end", kind="stable").reset_index(drop=True)


def _keep(df: pd.DataFrame, rate: float, salt: int) -> np.ndarray:
    key = pd.util.hash_pandas_object(df[["t_end", "src_ip", "dst_ip", "src_port", "dst_port"]],
                                     index=False).to_numpy()
    u = ((key ^ np.uint64(salt)) % np.uint64(1_000_000)).astype(np.float64) / 1e6
    return df["is_attack"].to_numpy() | (u < rate)


def convert_week(path: Path, out_dir: Path, sample_rate: float = 0.01,
                 window_s: float = 3600.0, warmup_s: float = 1800.0, salt: int = 0,
                 max_hours: float | None = None, start: float | None = None) -> list[dict]:
    ds = pads.dataset(path, format="parquet")
    md = pq.ParquetFile(path).metadata
    ci = md.schema.to_arrow_schema().names.index("ts_end")
    st = [md.row_group(i).column(ci).statistics for i in range(md.num_row_groups)]
    t_min, t_max = min(x.min for x in st), max(x.max for x in st)
    if start is not None:  # resume: windows start here, the warm-up still reads before it
        t_min = max(t_min, start)
    if max_hours is not None:
        t_max = min(t_max, t_min + max_hours * 3600)
    ev_dir = out_dir / "evidence"
    ev_dir.mkdir(parents=True, exist_ok=True)
    buffers: dict[str, list] = {}
    stats = []
    t = np.floor(t_min / window_s) * window_s
    specs = None
    while t <= t_max:
        lo, hi = t, t + window_s
        f = (pads.field("ts_end") >= lo - warmup_s) & (pads.field("ts_end") < hi)
        tbl = ds.to_table(columns=COLS, filter=f)
        df = _frame(tbl)
        del tbl
        if len(df):
            feats, specs = build(df, DEFAULT_TAUS)
            own = (df["t_end"] >= pd.Timestamp(lo, unit="s")).to_numpy()
            keep = own & _keep(df, sample_rate, salt)
            part = pd.concat([df.loc[keep].reset_index(drop=True),
                              feats.loc[keep].reset_index(drop=True)], axis=1)
            for day, g in part.groupby("day"):
                buffers.setdefault(day, []).append(g)
            stats.append({"window": pd.Timestamp(lo, unit="s").isoformat(), "flows": int(own.sum()),
                          "stored": int(keep.sum()), "attacks": int(df.loc[own, "is_attack"].sum())})
            print(f"  {stats[-1]}", flush=True)
            del df, feats, part
        t = hi
        # Flush days that can no longer receive flows (strictly before the window start).
        for day in [d for d in buffers if pd.Timestamp(d) + pd.Timedelta(days=1)
                    <= pd.Timestamp(lo, unit="s")]:
            _flush(day, buffers.pop(day), out_dir, ev_dir)
    for day, parts in list(buffers.items()):
        _flush(day, parts, out_dir, ev_dir)
    spec_map = {s.name: s.conservation for s in specs}
    (ev_dir / "specs.json").write_text(json.dumps(spec_map))
    return stats


def _flush(day: str, parts: list, out_dir: Path, ev_dir: Path) -> None:
    d = pd.concat(parts, ignore_index=True).sort_values("t_end", kind="stable")
    d = d.reset_index(drop=True)
    for c in ("dataset", "day", "attack", "family"):
        d[c] = d[c].astype("category")
    from proteus.evaluation.h1 import clean_benign

    d["suspect"] = False
    d["clean"] = clean_benign(d)
    raw_cols = META + ["src_port", "duration_us", "fwd_pkts", "bwd_pkts", "fwd_bytes",
                       "bwd_bytes", "f_bwd_rst_flags"]
    path_raw = out_dir / f"{day}.parquet"
    path_ev = ev_dir / f"{day}.parquet"
    if path_raw.exists():  # a day split across two weekly files
        d = pd.concat([pd.read_parquet(path_ev), d], ignore_index=True)
        d = d.sort_values("t_end", kind="stable").reset_index(drop=True)
        for c in ("dataset", "day", "attack", "family"):
            d[c] = d[c].astype("category")
    feat_cols = [c for c in d.columns if "__t" in c]
    d[raw_cols].to_parquet(path_raw, index=False)
    d[META + feat_cols + ["suspect", "clean"]].to_parquet(path_ev, index=False)
    print(f"  wrote {day}: {len(d):,} stored flows", flush=True)
