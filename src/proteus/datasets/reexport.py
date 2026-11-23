"""CIC-IDS-2017 re-exported from its packet captures by an exporter whose timeouts we set.

The benchmark records were produced by CICFlowMeter, whose accounting assumption (A1)
of the certificate describes but which we could not check. Here the published pcaps go
through NFStream with a known active timeout Δ and idle timeout, bytes counted as
payload (as CICFlowMeter's "Total Length of Fwd Packet"), and each record takes the
label of the CIC record (CNS 2022 corrected labels) of the same 5-tuple whose time
interval overlaps it. Days are written in the common flow schema, so the evaluation
reads them like any other dataset.
"""

from __future__ import annotations

import re
from pathlib import Path

import numpy as np
import pandas as pd

LABEL_COLS = ["attack", "family", "attempted", "is_attack", "label_raw"]
BENIGN_LABEL = ("benign", "benign", False, False, "BENIGN")


def _key(df: pd.DataFrame) -> np.ndarray:
    """Direction-free 5-tuple: the two endpoints in a fixed order, plus the protocol."""
    a = (df["src_ip"].astype(str) + ":" + df["src_port"].astype(str)).to_numpy(object)
    b = (df["dst_ip"].astype(str) + ":" + df["dst_port"].astype(str)).to_numpy(object)
    lo = np.where(a < b, a, b)
    hi = np.where(a < b, b, a)
    return lo + "|" + hi + "|" + df["proto"].astype(str).to_numpy(object)


def _matches(nf: pd.DataFrame, cic: pd.DataFrame, tol_s: float, offset_s: float) -> pd.DataFrame:
    """Pairs (nf row, cic row) with the same 5-tuple and overlapping intervals, the CIC
    times shifted by ``offset_s``. Processed an hour of ``nf`` at a time so that a
    5-tuple repeated all day (NetBIOS, NTP) does not multiply out."""
    off = pd.Timedelta(seconds=offset_s)
    tol = pd.Timedelta(seconds=tol_s)
    c = pd.DataFrame({"key": _key(cic), "c_start": cic["t_start"] + off,
                      "c_end": cic["t_end"] + off, "c_row": np.arange(len(cic))})
    n = pd.DataFrame({"key": _key(nf), "n_start": nf["t_start"], "n_end": nf["t_end"],
                      "n_row": np.arange(len(nf))})
    out = []
    for _, g in n.groupby(n["n_start"].dt.floor("h"), sort=False):
        lo, hi = g["n_start"].min() - tol, g["n_end"].max() + tol
        cc = c[(c["c_end"] >= lo) & (c["c_start"] <= hi)]
        m = g.merge(cc, on="key")
        m = m[(m["c_start"] <= m["n_end"] + tol) & (m["c_end"] >= m["n_start"] - tol)]
        out.append(m[["n_row", "c_row"]])
    if not out:
        return pd.DataFrame({"n_row": [], "c_row": []}, dtype=np.int64)
    return pd.concat(out, ignore_index=True)


def best_offset(nf: pd.DataFrame, cic: pd.DataFrame, candidates_h=range(-12, 13),
                sample: int = 20_000, tol_s: float = 1.0, seed: int = 0) -> tuple[float, float]:
    """The whole-hour clock offset between the CIC records and the pcap that matches the
    most records of a sample of ``nf``, and the share it matches."""
    rng = np.random.default_rng(seed)
    idx = rng.choice(len(nf), size=min(sample, len(nf)), replace=False)
    s = nf.iloc[np.sort(idx)].reset_index(drop=True)
    best = (0.0, -1.0)
    for h in candidates_h:
        m = _matches(s, cic, tol_s, 3600.0 * h)
        share = m["n_row"].nunique() / max(len(s), 1)
        if share > best[1]:
            best = (3600.0 * h, share)
    return best


def transfer_labels(nf: pd.DataFrame, cic: pd.DataFrame, tol_s: float = 1.0,
                    offset_s: float = 0.0) -> tuple[pd.DataFrame, np.ndarray]:
    """Labels of ``cic`` carried over to ``nf``: a record takes the label of an
    overlapping CIC record of its 5-tuple, an attack (not attempted) before an attempted
    attack before benign; a record that matches none is benign. Returns the label
    columns and a mask of the records that matched."""
    m = _matches(nf, cic, tol_s, offset_s)
    lab = cic[LABEL_COLS].reset_index(drop=True)
    prio = lab["is_attack"].astype(int).to_numpy() * 2 + (
        (lab["family"].astype(str) != "benign") & lab["attempted"].astype(bool)).to_numpy()
    m = m.assign(prio=prio[m["c_row"].to_numpy()])
    m = m.sort_values(["n_row", "prio", "c_row"], ascending=[True, False, True])
    first = m.drop_duplicates("n_row")
    out = pd.DataFrame({c: [v] * len(nf) for c, v in zip(LABEL_COLS, BENIGN_LABEL)})
    rows = first["n_row"].to_numpy()
    for c in LABEL_COLS:
        vals = lab[c].astype(object).to_numpy()[first["c_row"].to_numpy()]
        col = np.array(out[c].astype(object).to_numpy(), dtype=object)
        col[rows] = vals
        out[c] = col
    out["attempted"] = out["attempted"].astype(bool)
    out["is_attack"] = out["is_attack"].astype(bool)
    for c in ("attack", "family", "label_raw"):
        out[c] = out[c].astype("category")
    matched = np.zeros(len(nf), dtype=bool)
    matched[rows] = True
    return out, matched


def cic_day(cic_dir: Path, pcap_stem: str) -> Path | None:
    """The processed CIC day of a pcap: same stem, or the only day that starts with the
    pcap's weekday (``Monday-WorkingHours.pcap`` -> ``monday.parquet``)."""
    exact = cic_dir / f"{pcap_stem.lower()}.parquet"
    if exact.exists():
        return exact
    wd = re.split(r"[-_ ]", pcap_stem.lower())[0]
    hits = [p for p in cic_dir.glob("*.parquet") if p.stem.lower().startswith(wd)]
    return hits[0] if len(hits) == 1 else None


def convert(pcap_dir: Path, cic_dir: Path, out_dir: Path, dataset: str = "cicids2017nf",
            active_s: float = 120.0, idle_s: float = 120.0, accounting_mode: int = 3,
            tol_s: float = 1.0) -> pd.DataFrame:
    """Every ``<day>.pcap`` of ``pcap_dir`` exported by NFStream and labelled from
    ``cic_dir/<day>.parquet`` (the processed CIC records of that day)."""
    from proteus.packets.external import export_nfstream

    out_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for pcap in sorted(pcap_dir.glob("*.pcap")):
        cic_path = cic_day(cic_dir, pcap.stem)
        if cic_path is None:
            print(f"{pcap.name}: no single CIC day matches, skipped", flush=True)
            continue
        day = cic_path.stem
        nf = export_nfstream(pcap, active_s=active_s, idle_s=idle_s,
                             accounting_mode=accounting_mode)
        cic = pd.read_parquet(cic_path, columns=["t_start", "t_end", "src_ip", "src_port",
                                                 "dst_ip", "dst_port", "proto", *LABEL_COLS])
        offset, share = best_offset(nf, cic, tol_s=tol_s)
        lab, matched = transfer_labels(nf, cic, tol_s=tol_s, offset_s=offset)
        df = pd.concat([nf.reset_index(drop=True), lab], axis=1)
        df.insert(0, "day", day)
        df.insert(0, "dataset", dataset)
        df["day"] = df["day"].astype("category")
        df["dataset"] = df["dataset"].astype("category")
        df = df.sort_values("t_end", kind="stable").reset_index(drop=True)
        df.to_parquet(out_dir / f"{day}.parquet", index=False)
        cic_att = int(cic["is_attack"].sum())
        rows.append({"day": day, "flows": len(df), "cic_flows": len(cic),
                     "offset_h": offset / 3600, "sample_match": round(share, 4),
                     "matched": round(float(matched.mean()), 4),
                     "attacks": int(df["is_attack"].sum()), "cic_attacks": cic_att,
                     "active_s": active_s, "idle_s": idle_s,
                     "accounting_mode": accounting_mode})
        print(rows[-1], flush=True)
        del nf, cic, df
    return pd.DataFrame(rows)
