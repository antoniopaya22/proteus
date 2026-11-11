"""Per-entity baselines from other days of the same network, without labels.

For an entity e and an evidence feature x (a log decayed counter), the baseline is
the q-quantile of x over *every minute* of the reference period, taking the
per-minute maximum when the entity was active and 0 when it was not. A service
that is rarely used therefore has baseline 0, and a busy DNS server a high one.

Reference days are either the previous days (``prior``, causal) or every other
day of the same network (``loo``, leave-one-day-out). The datasets have 5-10 days
and attacks on the first day, so ``loo`` is the main setting; in deployment the
reference is past traffic. Minutes in which the entity was under attack can be
masked out (see ``masked_minutes``).

The baseline is fixed while a day is being scored, so the guarantee for free
attacker operations is unaffected: the excess x - b is increasing in x. The
attacker can only influence b by acting on earlier days (baseline poisoning),
which is an adaptive attack evaluated separately.

Entity keys are strings stable across days: "dst_ip" for dhost and
"dst_ip:dst_port/proto" for dsvc. ``KeyCodes`` turns them into integers shared by
all days to keep the per-minute tables small.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

# Counters that get a baseline, per destination entity.
COUNTERS = {
    "dsvc": ("flows", "fpkts", "fbytes", "rst", "conn_s", "n_src"),
    "dhost": ("flows", "fpkts", "fbytes", "rst", "conn_s", "n_src", "n_dport"),
}
QUANTILE = 0.95


def baseline_columns(names: list[str]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for ent, counters in COUNTERS.items():
        out[ent] = [n for n in names if n.split("__")[0] == ent and n.split("__")[1] in counters]
    return out


def entity_keys(ev: pd.DataFrame) -> dict[str, pd.Series]:
    dhost = ev["dst_ip"].astype("string")
    dsvc = dhost + ":" + ev["dst_port"].astype("string") + "/" + ev["proto"].astype("string")
    return {"dsvc": dsvc, "dhost": dhost}


class KeyCodes:
    """Integer codes for entity keys, stable across days."""

    def __init__(self) -> None:
        self.index = pd.Index([], dtype="string")

    def encode(self, key: pd.Series, grow: bool = True) -> np.ndarray:
        if grow:
            uniq = pd.Index(key.unique(), dtype="string")
            new = uniq[~uniq.isin(self.index)]
            if len(new):
                self.index = self.index.append(new)
        return self.index.get_indexer(key).astype(np.int64)  # -1: unseen key


def minute_table(ev: pd.DataFrame, cols: list[str], key: pd.Series) -> pd.DataFrame:
    """Per (entity key, minute) maximum of each column for one day."""
    minute = ev["t_end"].astype("int64") // 60_000_000
    t = ev[cols].copy()
    t["key"] = key.to_numpy()
    t["minute"] = minute.to_numpy()
    return t.groupby(["key", "minute"], sort=False, observed=True)[cols].max().reset_index()


MASK_AFTER_MIN = 10  # decayed counters (tau up to 600 s) carry an attack for minutes


def quantile_with_zeros(codes: np.ndarray, values: np.ndarray, n_groups: int,
                        total_minutes, q: float = QUANTILE) -> np.ndarray:
    """q-quantile per group over ``total_minutes`` values; the missing ones are 0.

    ``total_minutes`` is a scalar or one value per group (reference minutes minus
    the group's masked minutes).
    """
    o = np.lexsort((values, codes))
    k, v = codes[o], values[o]
    counts = np.bincount(k, minlength=n_groups)
    starts = np.concatenate([[0], np.cumsum(counts)[:-1]])
    total = np.broadcast_to(np.asarray(total_minutes, dtype=np.int64), counts.shape)
    total = np.maximum(total, counts)  # minute-boundary rounding can add one active minute
    p = np.ceil(q * total).astype(np.int64)  # 1-indexed rank among all minutes
    r = p - (total - counts)  # rank among the active minutes
    out = np.zeros(n_groups, dtype=np.float64)
    ok = (r >= 1) & (total > 0)
    out[ok] = v[starts[ok] + r[ok] - 1]
    return out


def masked_minutes(ev: pd.DataFrame, key: pd.Series, malicious: np.ndarray) -> pd.DataFrame:
    """(key, minute) pairs to leave out of the baseline: attack activity on the entity
    and the following MASK_AFTER_MIN minutes. Models a baseline that only learns from
    alert-free periods, with perfect alerts (labels) as an upper bound."""
    minute = (ev["t_end"].astype("int64") // 60_000_000).to_numpy()
    k = key.to_numpy()[malicious]
    m = minute[malicious]
    base = pd.DataFrame({"key": k, "minute": m}).drop_duplicates()
    parts = [base.assign(minute=base["minute"] + d) for d in range(MASK_AFTER_MIN + 1)]
    return pd.concat(parts, ignore_index=True).drop_duplicates()


@dataclass
class DayTable:
    """Per-minute maxima of one day for one entity type, with masked minutes removed."""

    table: pd.DataFrame  # columns: key, minute, <features>
    masked: pd.Series  # key -> number of masked minutes
    minutes: int  # minutes in the capture day


def day_table(ev: pd.DataFrame, cols: list[str], key: pd.Series,
              malicious: np.ndarray | None, minutes: int) -> DayTable:
    t = minute_table(ev, cols, key)
    if malicious is None or not malicious.any():
        return DayTable(t, pd.Series(dtype=np.int64), minutes)
    mask = masked_minutes(ev, key, malicious)
    hit = pd.MultiIndex.from_frame(t[["key", "minute"]]).isin(
        pd.MultiIndex.from_frame(mask[["key", "minute"]]))
    first = (ev["t_end"].min().value // 60_000_000)
    inside = mask[(mask["minute"] >= first) & (mask["minute"] < first + minutes)]
    return DayTable(t[~hit].reset_index(drop=True), inside.groupby("key").size(), minutes)


def baseline(days: list[DayTable], cols: list[str]) -> pd.DataFrame:
    """Baseline per entity key from the minute tables of the reference days."""
    t = pd.concat([d.table for d in days], ignore_index=True)
    codes, keys = pd.factorize(t["key"])
    total = sum(d.minutes for d in days)
    masked = pd.concat([d.masked for d in days]).groupby(level=0).sum() if days else None
    per_key = np.full(len(keys), total, dtype=np.int64)
    if masked is not None and len(masked):
        per_key -= masked.reindex(keys, fill_value=0).to_numpy(np.int64)
    out = {c: quantile_with_zeros(codes, t[c].to_numpy(np.float64), len(keys), per_key)
           for c in cols}
    return pd.DataFrame(out, index=pd.Index(keys, name="key"))


def attach(ev: pd.DataFrame, ent: str, cols: list[str], key: pd.Series,
           base: pd.DataFrame | None) -> dict[str, np.ndarray]:
    """Baseline (``__b``) and excess (``__x``) columns for every flow of a day.

    Without history (first day) both are NaN. Entities never seen before get
    baseline 0: they had no activity in any reference minute.
    """
    n = len(ev)
    res: dict[str, np.ndarray] = {}
    if base is None:
        for c in cols:
            res[f"{c}__b"] = np.full(n, np.nan, dtype=np.float32)
            res[f"{c}__x"] = np.full(n, np.nan, dtype=np.float32)
        return res
    idx = base.index.get_indexer(key)
    for c in cols:
        b = np.where(idx >= 0, base[c].to_numpy()[np.maximum(idx, 0)], 0.0)
        res[f"{c}__b"] = b.astype(np.float32)
        res[f"{c}__x"] = (ev[c].to_numpy(np.float64) - b).astype(np.float32)
    return res
