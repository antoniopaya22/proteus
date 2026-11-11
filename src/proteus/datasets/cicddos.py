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

import re
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd

from proteus.datasets import staged

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
    return staged.process(stage_dir, out_dir, "cicddos2019", attack_rate=attack_rate,
                          warmup_s=warmup_s, salt=salt, label=lambda d: _label(d["label_raw"]))
