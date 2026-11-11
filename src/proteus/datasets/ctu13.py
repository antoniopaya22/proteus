"""Reader for CTU-13 (García et al., Computers & Security 45, 2014) Argus bidirectional flows.

Real traffic of the CTU university network (August 2011) with 13 botnet scenarios.
Output follows the common flow schema of ``cic.py``, with these differences:

* Argus gives total packets and source bytes only. Forward packets are estimated
  as ``TotPkts * SrcBytes / TotBytes`` (at least 1, at most TotPkts); the rest are
  backward packets. Byte counts are exact.
* A responder RST is read from the destination half of the TCP ``State`` field
  (e.g. ``S_RA``: the responder answered RST+ACK).
* Labels: ``flow=...Botnet...`` → attack; ``...Normal...`` → benign;
  ``...Background...`` → ``family = "background"`` (unknown, mostly benign real
  traffic; not used as ground-truth benign).
* Each scenario is one capture ("day"). The botnet behaviour per scenario follows
  Table 2 of the CTU-13 paper (from memory, to be checked against the paper):
  DDoS 4, 10, 11; port scan 3, 6, 8, 12; spam/click-fraud/C&C 1, 2, 7, 9, 13;
  fast-flux 5. The README of each scenario confirms 3, 4, 10, 11 and 12.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

BEHAVIOUR = {1: "spam", 2: "spam", 3: "portscan", 4: "ddos", 5: "fastflux", 6: "portscan",
             7: "spam", 8: "portscan", 9: "spam", 10: "ddos", 11: "ddos", 12: "portscan",
             13: "spam"}
PROTO = {"tcp": 6, "udp": 17, "icmp": 1}


def _port(s: pd.Series) -> np.ndarray:
    def conv(v):
        if v is None or v == "" or pd.isna(v):
            return 0
        v = str(v).strip()
        try:
            return int(v, 16) if v.startswith("0x") else int(v)
        except ValueError:
            return 0
    return s.map(conv).to_numpy(np.int32)


def read_scenario(path: Path, scenario: int) -> pd.DataFrame:
    raw = pd.read_csv(path, dtype=str, keep_default_na=False)
    t_start = pd.to_datetime(raw["StartTime"], format="%Y/%m/%d %H:%M:%S.%f")
    dur_us = (pd.to_numeric(raw["Dur"], errors="coerce").fillna(0) * 1e6).astype(np.int64)
    tot_pkts = pd.to_numeric(raw["TotPkts"], errors="coerce").fillna(0).astype(np.int64)
    tot_bytes = pd.to_numeric(raw["TotBytes"], errors="coerce").fillna(0).astype(np.int64)
    src_bytes = pd.to_numeric(raw["SrcBytes"], errors="coerce").fillna(0).astype(np.int64)
    share = np.where(tot_bytes > 0, src_bytes / np.maximum(tot_bytes, 1), 1.0)
    fwd_pkts = np.clip(np.rint(tot_pkts * share), 1, np.maximum(tot_pkts, 1)).astype(np.int64)
    proto = raw["Proto"].str.lower().map(PROTO).fillna(0).astype(np.int16)
    state = raw["State"].astype(str)
    dst_flags = state.str.split("_").str[1].fillna("")
    rst = ((proto == 6) & dst_flags.str.contains("R")).astype(np.float32)

    label = raw["Label"].astype(str)
    is_bot = label.str.contains("Botnet")
    is_normal = label.str.contains("Normal")
    family = np.where(is_bot, BEHAVIOUR[scenario], np.where(is_normal, "benign", "background"))
    attack = np.where(is_bot, f"ctu{scenario}_{BEHAVIOUR[scenario]}", family)

    df = pd.DataFrame({
        "dataset": "ctu13",
        "day": f"s{scenario:02d}",
        "t_start": t_start.astype("datetime64[us]"),
        "t_end": (t_start + pd.to_timedelta(dur_us, unit="us")).astype("datetime64[us]"),
        "src_ip": raw["SrcAddr"].astype("string"),
        "src_port": _port(raw["Sport"]),
        "dst_ip": raw["DstAddr"].astype("string"),
        "dst_port": _port(raw["Dport"]),
        "proto": proto,
        "duration_us": dur_us,
        "fwd_pkts": fwd_pkts,
        "bwd_pkts": (tot_pkts - fwd_pkts).clip(lower=0).astype(np.int64),
        "fwd_bytes": src_bytes,
        "bwd_bytes": (tot_bytes - src_bytes).clip(lower=0).astype(np.int64),
        "f_bwd_rst_flags": rst,
        "label_raw": label.astype("category"),
        "attack": pd.Categorical(attack),
        "family": pd.Categorical(family),
        "attempted": False,
        "is_attack": is_bot.to_numpy(),
    })
    for c in ("dataset", "day"):
        df[c] = df[c].astype("category")
    return df.sort_values("t_end", kind="stable").reset_index(drop=True)


def convert(raw_dir: Path, out_dir: Path) -> pd.DataFrame:
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for sdir in sorted((p for p in raw_dir.iterdir() if p.is_dir() and p.name.isdigit()),
                       key=lambda p: int(p.name)):
        n = int(sdir.name)
        path = next(sdir.glob("*.binetflow"))
        df = read_scenario(path, n)
        df.to_parquet(out_dir / f"s{n:02d}.parquet", index=False)
        s = df.groupby(["family"], observed=True).size().rename("flows").reset_index()
        s.insert(0, "day", f"s{n:02d}")
        s["t_min"], s["t_max"] = df["t_start"].min(), df["t_end"].max()
        rows.append(s)
        print(f"ctu13/s{n:02d}: {len(df):,} flows", flush=True)
    return pd.concat(rows, ignore_index=True)
