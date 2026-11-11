"""Reader for CTU-SME-11 (Bendl, Valeros, Garcia, Zenodo 10.5281/zenodo.7958259, 2023).

Real traffic of 11 devices (IoT, desktops, phones, VMs; some infected with malware,
some exposed to the Internet as honeypots) captured for 7 days (2023-02-20..26) in a
network that mimics a small enterprise. One Zeek ``conn.log.labeled`` per device and
day, labelled by experts with rules (``artifacts/labels.config``).

Mapping to the common flow schema:

* event time ``t_end = ts + duration``. Zeek has no active timeout: a long connection
  is a single record logged when it ends, so the exporter slack Δ of the guarantee is
  not bounded for this dataset (it is for NetFlow/IPFIX exporters);
* forward/backward = originator/responder; bytes are payload bytes (``orig_bytes``,
  ``resp_bytes``), as in CICFlowMeter's "Total Length of Fwd Packets";
* responder reset: ``r`` in Zeek's ``history`` (lower case = responder);
* labels: ``label == "Malicious"`` → attack; the family comes from the last part of
  ``detailedlabel`` (``From_malicious-To_benign-Discovery`` → ``discovery``).
  Benign flows were labelled by experts and are used as benign;
* every capture holds one device; all devices of a day are merged into one "network"
  day, removing flows seen by two captures.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

PROTO = {"tcp": 6, "udp": 17, "icmp": 1}
FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service",
          "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp",
          "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts",
          "resp_ip_bytes", "tunnel_parents", "label", "detailedlabel"]
# detailedlabel suffix → family used across datasets
FAMILY = {"discovery": "portscan", "portscan": "portscan", "scan": "portscan",
          "ddos": "ddos", "dos": "dos", "spam": "spam", "bruteforce": "bruteforce",
          "c&c": "botnet", "cc": "botnet", "c2": "botnet", "heartbeat": "botnet"}


def _fields(path: Path) -> list[str]:
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("#fields"):
                return line.rstrip("\n").split("\t")[1:]
            if not line.startswith("#"):
                break
    return FIELDS


def _num(s: pd.Series, kind=np.int64) -> np.ndarray:
    return pd.to_numeric(s.replace("-", np.nan), errors="coerce").fillna(0).to_numpy(kind)


def read_conn(path: Path, device: str) -> pd.DataFrame:
    # Zeek header and the trailing "#close" line start with '#'; no field contains it.
    raw = pd.read_csv(path, sep="\t", names=_fields(path), dtype=str, comment="#",
                      keep_default_na=False, quoting=3, encoding_errors="replace")
    ts = pd.to_numeric(raw["ts"], errors="coerce")
    raw, ts = raw[ts.notna()], ts[ts.notna()]
    dur_s = _num(raw["duration"], np.float64).clip(min=0)
    t_start = pd.to_datetime(ts.to_numpy(), unit="s")
    proto = raw["proto"].str.lower().map(PROTO).fillna(0).astype(np.int16).to_numpy()
    history = raw["history"].astype(str)
    label = raw["label"].astype(str).str.strip()
    detail = raw["detailedlabel"].astype(str).str.strip()
    suffix = detail.str.split("-").str[-1].str.lower()
    mal = label.str.lower().eq("malicious").to_numpy()
    fam = suffix.map(FAMILY).fillna(suffix).to_numpy()
    family = np.where(mal, fam, "benign")
    attack = np.where(mal, "sme_" + suffix.str.replace(r"[^a-z0-9]+", "_", regex=True), "benign")
    df = pd.DataFrame({
        "dataset": "ctusme11",
        "device": device,
        "t_start": t_start.astype("datetime64[us]"),
        "t_end": (t_start + pd.to_timedelta(dur_s, unit="s")).astype("datetime64[us]"),
        "src_ip": raw["id.orig_h"].astype("string").to_numpy(),
        "src_port": _num(raw["id.orig_p"], np.int32),
        "dst_ip": raw["id.resp_h"].astype("string").to_numpy(),
        "dst_port": _num(raw["id.resp_p"], np.int32),
        "proto": proto,
        "duration_us": (dur_s * 1e6).astype(np.int64),
        "fwd_pkts": _num(raw["orig_pkts"]),
        "bwd_pkts": _num(raw["resp_pkts"]),
        "fwd_bytes": _num(raw["orig_bytes"]),
        "bwd_bytes": _num(raw["resp_bytes"]),
        "f_bwd_rst_flags": ((proto == 6) & history.str.contains("r").to_numpy()).astype(np.float32),
        "label_raw": detail.to_numpy(),
        "attack": attack,
        "family": family,
        "attempted": False,
        "is_attack": mal,
    })
    return df


KEY = ["t_start", "src_ip", "src_port", "dst_ip", "dst_port", "proto"]


def convert(raw_dir: Path, out_dir: Path) -> pd.DataFrame:
    """``raw_dir`` holds ``CTU-SME-11/<device>/<YYYY-MM-DD>/zeek/conn.log.labeled``."""
    out_dir.mkdir(parents=True, exist_ok=True)
    logs = sorted(raw_dir.glob("**/zeek/conn.log.labeled"))
    by_day: dict[str, list[pd.DataFrame]] = {}
    for p in logs:
        device = p.parents[2].name
        df = read_conn(p, device)
        for day, g in df.groupby(df["t_end"].dt.strftime("%Y-%m-%d")):
            by_day.setdefault(day, []).append(g)
        print(f"  {device}/{p.parents[1].name}: {len(df):,} flows", flush=True)
    rows = []
    for day, parts in sorted(by_day.items()):
        d = pd.concat(parts, ignore_index=True)
        n = len(d)
        # Flows between two monitored devices appear in both captures; keep one, timestamps
        # rounded to 1 ms because the two sniffers stamp packets independently.
        d["_t"] = d["t_start"].dt.round("ms")
        d = d.drop_duplicates(subset=["_t"] + KEY[1:]).drop(columns="_t")
        d = d.sort_values("t_end", kind="stable").reset_index(drop=True)
        d["day"] = day
        for c in ("dataset", "day", "device", "attack", "family", "label_raw"):
            d[c] = d[c].astype("category")
        d.to_parquet(out_dir / f"{day}.parquet", index=False)
        s = d.groupby("family", observed=True).size().rename("flows").reset_index()
        s.insert(0, "day", day)
        s["duplicates"] = n - len(d)
        rows.append(s)
        print(f"ctusme11/{day}: {len(d):,} flows ({n - len(d):,} duplicates)", flush=True)
    return pd.concat(rows, ignore_index=True)
