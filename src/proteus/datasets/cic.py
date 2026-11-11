"""Reader for the CNS 2022 improved CIC-IDS-2017 and CSE-CIC-IDS-2018 CSV files.

Both datasets share the same CICFlowMeter (fixed) header. Output is one Parquet
file per capture day with the common flow schema (see ``schema.py``).
"""

from __future__ import annotations

import re
from pathlib import Path

import numpy as np
import pandas as pd

from .labels import canonical

# Columns renamed to fixed names because later code relies on them.
_KEY_COLUMNS = {
    "Src IP": "src_ip",
    "Src Port": "src_port",
    "Dst IP": "dst_ip",
    "Dst Port": "dst_port",
    "Protocol": "proto",
    "Timestamp": "timestamp",
    "Flow Duration": "duration_us",
    "Total Fwd Packet": "fwd_pkts",
    "Total Bwd packets": "bwd_pkts",
    "Total Length of Fwd Packet": "fwd_bytes",
    "Total Length of Bwd Packet": "bwd_bytes",
    "Label": "label_raw",
    "Attempted Category": "attempted_category",
}
_DROP = {"id", "Flow ID"}


def _snake(name: str) -> str:
    s = re.sub(r"[^0-9a-zA-Z]+", "_", name.strip()).strip("_").lower()
    return s


def read_day(path: Path, dataset: str) -> pd.DataFrame:
    """Read one CIC CSV day file and return it in the common flow schema."""
    df = pd.read_csv(path, engine="pyarrow")
    df = df.drop(columns=[c for c in df.columns if c in _DROP])
    df = df.rename(columns={c: _KEY_COLUMNS.get(c, "f_" + _snake(c)) for c in df.columns})

    # Timestamps are flow start times in UTC with microsecond resolution.
    t_start = pd.to_datetime(df.pop("timestamp"), format="ISO8601")
    df.insert(0, "t_start", t_start.astype("datetime64[us]"))
    dur = pd.to_timedelta(df["duration_us"].clip(lower=0), unit="us")
    df.insert(1, "t_end", df["t_start"] + dur)

    labels = df["label_raw"].astype("string")
    mapping = {lab: canonical(lab) for lab in labels.unique()}
    df["attack"] = labels.map(lambda x: mapping[x][0]).astype("category")
    df["family"] = labels.map(lambda x: mapping[x][1]).astype("category")
    df["attempted"] = labels.map(lambda x: mapping[x][2]).astype(bool)
    df["is_attack"] = (df["family"] != "benign") & ~df["attempted"]
    df["label_raw"] = labels.astype("category")

    for c in ("src_ip", "dst_ip"):
        df[c] = df[c].astype("string")
    for c in ("src_port", "dst_port"):
        df[c] = df[c].astype("int32")
    df["proto"] = df["proto"].astype("int16")
    for c in ("fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes", "duration_us"):
        df[c] = df[c].astype("int64")

    # CICFlowMeter emits inf for rates of zero-duration flows.
    feat = [c for c in df.columns if c.startswith("f_")]
    df[feat] = df[feat].replace([np.inf, -np.inf], np.nan).astype("float32")

    df.insert(0, "day", path.stem.lower())
    df.insert(0, "dataset", dataset)
    df["day"] = df["day"].astype("category")
    df["dataset"] = df["dataset"].astype("category")
    return df.sort_values("t_end", kind="stable").reset_index(drop=True)


def convert(raw_dir: Path, out_dir: Path, dataset: str) -> pd.DataFrame:
    """Convert every CSV in ``raw_dir`` and return a per-day label summary."""
    out_dir.mkdir(parents=True, exist_ok=True)
    summaries = []
    for path in sorted(raw_dir.glob("*.csv")):
        df = read_day(path, dataset)
        df.to_parquet(out_dir / f"{path.stem.lower()}.parquet", index=False)
        s = (
            df.groupby(["attack", "attempted"], observed=True)
            .size()
            .rename("flows")
            .reset_index()
        )
        s.insert(0, "day", path.stem.lower())
        s["t_min"], s["t_max"] = df["t_start"].min(), df["t_end"].max()
        s["n_src"], s["n_dst"] = df["src_ip"].nunique(), df["dst_ip"].nunique()
        summaries.append(s)
        print(f"{dataset}/{path.name}: {len(df):,} flows", flush=True)
        del df
    return pd.concat(summaries, ignore_index=True)
