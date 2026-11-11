"""Reader for UNSW-NB15 (Moustafa and Slay, MilCIS 2015), official CSV files 1–4.

Argus/Bro features of two captures (22 Jan and 17–18 Feb 2015) of an IXIA testbed.
Output follows the common flow schema, with these notes:

* ``Stime``/``Ltime`` have 1-second resolution; ``t_end`` is
  ``max(Ltime, Stime + dur)``.
* Packets and bytes per direction are exact (``Spkts``/``Dpkts``, ``sbytes``/``dbytes``).
* Argus does not say which side reset a connection; ``f_bwd_rst_flags`` is 1 when the
  final state is ``RST`` (approximation).
* The remaining numeric Argus/Bro features are kept with an ``f_`` prefix so the
  per-flow shell can use them in-dataset. ``sttl``/``dttl`` are a known shortcut of this
  dataset (they almost identify the attack hosts) and are excluded from ``f_``.
* Each capture date is one "day".
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

COLUMNS = ["srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes", "dbytes",
           "sttl", "dttl", "sloss", "dloss", "service", "Sload", "Dload", "Spkts", "Dpkts",
           "swin", "dwin", "stcpb", "dtcpb", "smeansz", "dmeansz", "trans_depth",
           "res_bdy_len", "Sjit", "Djit", "Stime", "Ltime", "Sintpkt", "Dintpkt", "tcprtt",
           "synack", "ackdat", "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd",
           "is_ftp_login", "ct_ftp_cmd", "ct_srv_src", "ct_srv_dst", "ct_dst_ltm",
           "ct_src_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm",
           "attack_cat", "Label"]
FAMILY = {"": "benign", "normal": "benign", "dos": "dos", "reconnaissance": "portscan",
          "exploits": "exploits", "fuzzers": "fuzzers", "generic": "generic",
          "backdoor": "backdoor", "backdoors": "backdoor", "analysis": "analysis",
          "shellcode": "shellcode", "worms": "worms"}
PROTO = {"tcp": 6, "udp": 17, "icmp": 1}
# Identifiers, times, labels and the TTL shortcut are not per-flow features.
NOT_FEATURES = {"srcip", "sport", "dstip", "dsport", "proto", "state", "service", "Stime",
                "Ltime", "attack_cat", "Label", "sttl", "dttl", "ct_state_ttl", "dur", "sbytes",
                "dbytes", "Spkts", "Dpkts"}


def _port(s: pd.Series) -> np.ndarray:
    return pd.to_numeric(s.astype(str).str.strip().map(
        lambda v: int(v, 16) if v.startswith("0x") else v), errors="coerce"
    ).fillna(0).astype(np.int32).to_numpy()


def read_all(raw_dir: Path) -> pd.DataFrame:
    parts = [pd.read_csv(raw_dir / f"UNSW-NB15_{i}.csv", header=None, names=COLUMNS,
                         dtype=str, keep_default_na=False, encoding="utf-8-sig")
             for i in range(1, 5)]
    raw = pd.concat(parts, ignore_index=True)

    def num(c, dtype=np.float64):
        return pd.to_numeric(raw[c], errors="coerce").fillna(0).astype(dtype)

    stime = num("Stime", np.int64)
    dur_us = (num("dur") * 1e6).astype(np.int64).clip(lower=0)
    t_start = pd.to_datetime(stime, unit="s")
    t_end = pd.to_datetime(np.maximum(num("Ltime", np.int64) * 1_000_000,
                                      stime * 1_000_000 + dur_us), unit="us")
    cat = raw["attack_cat"].str.strip().str.lower()
    family = cat.map(FAMILY).fillna("other")
    is_attack = num("Label", np.int64).to_numpy() == 1
    family = np.where(is_attack, np.where(family == "benign", "other", family), "benign")

    df = pd.DataFrame({
        "dataset": "unsw_nb15",
        "day": t_start.dt.strftime("%Y-%m-%d"),
        "t_start": t_start.astype("datetime64[us]"),
        "t_end": t_end.astype("datetime64[us]"),
        "src_ip": raw["srcip"].astype("string"),
        "src_port": _port(raw["sport"]),
        "dst_ip": raw["dstip"].astype("string"),
        "dst_port": _port(raw["dsport"]),
        "proto": raw["proto"].str.lower().map(PROTO).fillna(0).astype(np.int16),
        "duration_us": dur_us,
        "fwd_pkts": num("Spkts", np.int64),
        "bwd_pkts": num("Dpkts", np.int64),
        "fwd_bytes": num("sbytes", np.int64),
        "bwd_bytes": num("dbytes", np.int64),
        "f_bwd_rst_flags": (raw["state"].str.strip().str.upper() == "RST").astype(np.float32),
        "label_raw": raw["attack_cat"].str.strip().astype("category"),
        "attack": pd.Categorical(np.where(is_attack, family, "benign")),
        "family": pd.Categorical(family),
        "attempted": False,
        "is_attack": is_attack,
    })
    for c in COLUMNS:
        if c not in NOT_FEATURES:
            df[f"f_{c.lower()}"] = num(c).astype(np.float32)
    return df


def convert(raw_dir: Path, out_dir: Path) -> pd.DataFrame:
    out_dir.mkdir(parents=True, exist_ok=True)
    df = read_all(raw_dir)
    rows = []
    # Captures are separated by weeks; a calendar date is one capture day (the
    # February capture crosses midnight and is split, which is harmless for counters
    # with time constants of at most 10 minutes).
    for day, g in df.groupby("day", sort=True):
        g = g.sort_values("t_end", kind="stable").reset_index(drop=True)
        g["day"] = g["day"].astype("category")
        g["dataset"] = g["dataset"].astype("category")
        g.to_parquet(out_dir / f"{day}.parquet", index=False)
        s = g.groupby("family", observed=True).size().rename("flows").reset_index()
        s.insert(0, "day", day)
        rows.append(s)
        print(f"unsw_nb15/{day}: {len(g):,} flows", flush=True)
    return pd.concat(rows, ignore_index=True)
