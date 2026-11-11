"""CIC-DDoS-2019 (Sharafaldin et al., ICCST 2019), CICFlowMeter CSV files.

Two capture days, one CSV per attack window (reflection and exploitation DDoS: DNS,
LDAP, MSSQL, NetBIOS, NTP, SNMP, SSDP, UDP, SYN, TFTP, UDP-lag, WebDDoS, Portmap), with
the old CICFlowMeter header (the same tool whose bugs were documented for CIC-IDS-2017).
The files are too large to hold in memory (the first day has ~50 M flows), so:

1. ``stage``: stream every CSV in chunks, keep the schema columns and write them to
   ``<stage>/<day>/<hour>/*.parquet``;
2. ``process``: compute evidence hour by hour with a 30-minute warm-up from the previous
   hour, drop exact duplicates across files, and store every benign flow plus a sample
   of attack flows (``attack_rate``). Counters always use every flow.

Responder RSTs cannot be told apart (only a total ``RST Flag Count``); the flag is used
when the flow has backward packets, which only approximates "the responder reset".
"""

from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd

from proteus.evidence.features import DEFAULT_TAUS, build

KEY = {"Source IP": "src_ip", "Source Port": "src_port", "Destination IP": "dst_ip",
       "Destination Port": "dst_port", "Protocol": "proto", "Timestamp": "timestamp",
       "Flow Duration": "duration_us", "Total Fwd Packets": "fwd_pkts",
       "Total Backward Packets": "bwd_pkts", "Total Length of Fwd Packets": "fwd_bytes",
       "Total Length of Bwd Packets": "bwd_bytes", "RST Flag Count": "rst_any",
       "Label": "label_raw"}
DROP = {"Unnamed: 0", "Flow ID", "SimillarHTTP", "Inbound"}
META = ["dataset", "day", "t_start", "t_end", "src_ip", "dst_ip", "dst_port", "proto",
        "attack", "family", "attempted", "is_attack"]


def _snake(name: str) -> str:
    return re.sub(r"[^0-9a-zA-Z]+", "_", name.strip()).strip("_").lower()


def _normalise(chunk: pd.DataFrame) -> pd.DataFrame:
    chunk.columns = [c.strip() for c in chunk.columns]
    chunk = chunk.drop(columns=[c for c in chunk.columns if c in DROP])
    chunk = chunk.rename(columns={c: KEY.get(c, "f_" + _snake(c)) for c in chunk.columns})
    t_start = pd.to_datetime(chunk.pop("timestamp"), format="mixed")
    dur = pd.to_numeric(chunk["duration_us"], errors="coerce").fillna(0).clip(lower=0)
    out = pd.DataFrame({
        "t_start": t_start.astype("datetime64[us]"),
        "t_end": (t_start + pd.to_timedelta(dur, unit="us")).astype("datetime64[us]"),
    })
    for c in ("src_ip", "dst_ip", "label_raw"):
        out[c] = chunk[c].astype(str).str.strip()
    for c in ("src_port", "dst_port"):
        out[c] = pd.to_numeric(chunk[c], errors="coerce").fillna(0).astype(np.int32)
    out["proto"] = pd.to_numeric(chunk["proto"], errors="coerce").fillna(0).astype(np.int16)
    out["duration_us"] = dur.astype(np.int64)
    for c in ("fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes"):
        out[c] = pd.to_numeric(chunk[c], errors="coerce").fillna(0).astype(np.int64)
    rst = pd.to_numeric(chunk["rst_any"], errors="coerce").fillna(0)
    out["f_bwd_rst_flags"] = ((rst > 0) & (out["bwd_pkts"] > 0)).astype(np.float32)
    feats = [c for c in chunk.columns if c.startswith("f_") and c != "f_bwd_rst_flags"]
    f = chunk[feats].apply(pd.to_numeric, errors="coerce").astype(np.float32)
    out[feats] = f.replace([np.inf, -np.inf], np.nan)
    return out


def stage(raw_dir: Path, stage_dir: Path, chunksize: int = 1_000_000) -> None:
    for zpath in sorted(raw_dir.glob("*.zip")):
        with zipfile.ZipFile(zpath) as z:
            for name in z.namelist():
                if not name.endswith(".csv") or "/." in name:
                    continue
                with z.open(name) as fh:
                    for k, chunk in enumerate(pd.read_csv(fh, chunksize=chunksize, dtype=str,
                                                          skipinitialspace=True,
                                                          low_memory=False)):
                        d = _normalise(chunk)
                        hours = d["t_end"].dt.floor("h")
                        for h, g in d.groupby(hours):
                            p = stage_dir / h.strftime("%Y-%m-%d") / h.strftime("%H")
                            p.mkdir(parents=True, exist_ok=True)
                            stem = Path(name).stem
                            g.to_parquet(p / f"{stem}-{k:04d}.parquet", index=False)
                        print(f"  staged {name} chunk {k}: {len(d):,}", flush=True)


def _label(raw: pd.Series) -> tuple[np.ndarray, np.ndarray]:
    lab = raw.str.strip().str.lower()
    benign = lab.eq("benign").to_numpy()
    attack = np.where(benign, "benign", "ddos_" + lab.str.replace(r"[^a-z0-9]+", "_",
                                                                  regex=True))
    family = np.where(benign, "benign", "ddos")
    return attack, family


def process(stage_dir: Path, out_dir: Path, attack_rate: float = 0.02,
            warmup_s: float = 1800.0, salt: int = 0) -> list[dict]:
    ev_dir = out_dir / "evidence"
    ev_dir.mkdir(parents=True, exist_ok=True)
    stats, specs = [], None
    for day_dir in sorted(p for p in stage_dir.iterdir() if p.is_dir()):
        hours = sorted(p for p in day_dir.iterdir() if p.is_dir())
        parts = []
        prev = None
        for hdir in hours:
            cur = pd.concat([pd.read_parquet(f) for f in sorted(hdir.glob("*.parquet"))],
                            ignore_index=True)
            hour_start = pd.Timestamp(f"{day_dir.name} {hdir.name}:00:00")
            if prev is not None:
                warm = prev[prev["t_end"] >= hour_start - pd.Timedelta(seconds=warmup_s)]
                df = pd.concat([warm, cur], ignore_index=True)
            else:
                df = cur
            key = ["t_start", "t_end", "src_ip", "dst_ip", "src_port", "dst_port", "proto",
                   "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes"]
            df = df.drop_duplicates(subset=key).sort_values("t_end", kind="stable")
            df = df.reset_index(drop=True)
            attack, family = _label(df["label_raw"])
            df["attack"], df["family"] = attack, family
            df["is_attack"] = family != "benign"
            df["attempted"] = False
            df["dataset"], df["day"] = "cicddos2019", day_dir.name
            feats, specs = build(df, DEFAULT_TAUS)
            own = (df["t_end"] >= hour_start).to_numpy()
            h = pd.util.hash_pandas_object(df[key], index=False).to_numpy()
            u = ((h ^ np.uint64(salt)) % np.uint64(1_000_000)).astype(np.float64) / 1e6
            keep = own & (~df["is_attack"].to_numpy() | (u < attack_rate))
            parts.append(pd.concat([df.loc[keep].reset_index(drop=True),
                                    feats.loc[keep].reset_index(drop=True)], axis=1))
            stats.append({"day": day_dir.name, "hour": hdir.name, "flows": int(own.sum()),
                          "attacks": int(df.loc[own, "is_attack"].sum()),
                          "stored": int(keep.sum())})
            print(f"  {stats[-1]}", flush=True)
            prev = cur
        if parts:
            _flush(day_dir.name, parts, out_dir, ev_dir)
    (ev_dir / "specs.json").write_text(json.dumps({s.name: s.conservation for s in specs}))
    return stats


def _flush(day: str, parts: list, out_dir: Path, ev_dir: Path) -> None:
    from proteus.evaluation.h1 import clean_benign

    d = pd.concat(parts, ignore_index=True).sort_values("t_end", kind="stable")
    d = d.reset_index(drop=True)
    for c in ("dataset", "day", "attack", "family", "label_raw"):
        d[c] = d[c].astype("category")
    for c in ("src_ip", "dst_ip"):
        d[c] = d[c].astype("string")
    d["suspect"] = False
    d["clean"] = clean_benign(d)
    feat_cols = [c for c in d.columns if "__t" in c]
    raw_cols = [c for c in d.columns if c not in feat_cols and c not in ("suspect", "clean")]
    d[raw_cols].to_parquet(out_dir / f"{day}.parquet", index=False)
    d[META + feat_cols + ["suspect", "clean"]].to_parquet(ev_dir / f"{day}.parquet", index=False)
    print(f"  wrote {day}: {len(d):,} stored flows", flush=True)
