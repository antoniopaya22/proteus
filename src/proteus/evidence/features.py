"""Evidence features per flow event: decayed counters of the flow's entities.

Prototype (phase 1) entity set: destination service (dst ip, dst port, proto),
destination host and source host. Event time is the flow end, when a flow
exporter would emit the record.

Each feature carries a conservation class, which decides whether it may enter
the monotone core:

* ``conserved``: free attacker operations (padding, packet insertion, decoy flows,
  flow splitting, source-port changes) can only increase it.
* ``response``: produced by the victim; the attacker can lower it by changing
  requests (e.g. asking for small resources), so it is excluded from the strict core.

``flows`` is conserved under the operations above but not under connection reuse
(many requests in one connection lowers the flow count while forward packets stay).
That operation is outside the phase-1 transformation model and is tracked as a
known gap.

Evidence version ``v2`` (``PROTEUS_EVIDENCE=v2``, default ``v1``) adds unanswered
flows (no backward packet), per entity, and the distinct destinations a source
reached without an answer. Given the destinations, no free operation turns an
unanswered flow into an answered one (the attacker does not control the victim's
responses), so both are conserved. An attacker can lower them only by choosing
destinations it already knows to be alive, which defeats the purpose of a scan.
For unidirectional records (UGR'16) every flow counts as unanswered.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

import numpy as np
import pandas as pd

from .counters import decayed_distinct, decayed_sum

DEFAULT_TAUS = (10.0, 60.0, 600.0)
EVIDENCE_VERSION = os.environ.get("PROTEUS_EVIDENCE", "v1")


@dataclass(frozen=True)
class FeatureSpec:
    name: str
    conservation: str  # "conserved" | "response"


def _codes(*cols: pd.Series) -> np.ndarray:
    if len(cols) == 1:
        return pd.factorize(cols[0])[0].astype(np.int64)
    return (
        pd.DataFrame({i: c for i, c in enumerate(cols)})
        .groupby(list(range(len(cols))), sort=False, observed=True)
        .ngroup()
        .to_numpy(np.int64)
    )


def build(df: pd.DataFrame, taus=DEFAULT_TAUS, version: str | None = None
          ) -> tuple[pd.DataFrame, list[FeatureSpec]]:
    """Compute evidence features for every flow of one capture (one day)."""
    version = version or EVIDENCE_VERSION
    t = (df["t_end"] - df["t_end"].min()).dt.total_seconds().to_numpy(np.float64)
    ent = {
        "dsvc": _codes(df["dst_ip"], df["dst_port"], df["proto"]),
        "dhost": _codes(df["dst_ip"]),
        "shost": _codes(df["src_ip"]),
    }
    item = {
        "src": _codes(df["src_ip"]),
        "dport": _codes(df["dst_port"]),
        "dhost": ent["dhost"],
        "dsvc": ent["dsvc"],
    }
    n = len(df)
    weights = {
        "flows": (np.ones(n), "conserved"),
        "fpkts": (df["fwd_pkts"].to_numpy(np.float64), "conserved"),
        "fbytes": (df["fwd_bytes"].to_numpy(np.float64), "conserved"),
        "rst": ((df["f_bwd_rst_flags"].fillna(0).to_numpy() > 0).astype(np.float64), "conserved"),
        # Connection-seconds held: what slow DoS cannot stop doing. Padding and
        # splitting cannot shorten it; closing connections earlier weakens the attack.
        "conn_s": (df["duration_us"].clip(lower=0).to_numpy(np.float64) / 1e6, "conserved"),
        "bpkts": (df["bwd_pkts"].to_numpy(np.float64), "response"),
        "bbytes": (df["bwd_bytes"].to_numpy(np.float64), "response"),
    }
    distinct = {
        "dsvc": ["src"],
        "dhost": ["src", "dport"],
        "shost": ["dhost", "dsvc"],
    }
    item_w: dict[str, np.ndarray] = {}
    if version == "v2":
        noreply = df["bwd_pkts"].to_numpy() == 0
        weights["noreply"] = (noreply.astype(np.float64), "conserved")
        # Answered flows only read the state: zero weight and an item no event uses.
        item["dhost_nr"] = np.where(noreply, ent["dhost"], -1 - np.arange(n, dtype=np.int64))
        item_w["dhost_nr"] = noreply.astype(np.float64)
        distinct["shost"] = distinct["shost"] + ["dhost_nr"]
    elif version != "v1":
        raise ValueError(f"unknown evidence version {version!r}")

    cols: dict[str, np.ndarray] = {}
    specs: list[FeatureSpec] = []

    def add(prefix: str, values: np.ndarray, conservation: str) -> None:
        for j, tau in enumerate(taus):
            name = f"{prefix}__t{int(tau)}"
            cols[name] = np.log1p(values[:, j]).astype(np.float32)
            specs.append(FeatureSpec(name, conservation))

    for e, codes in ent.items():
        for w_name, (w, cons) in weights.items():
            add(f"{e}__{w_name}", decayed_sum(t, codes, w, taus), cons)
        for it in distinct[e]:
            add(f"{e}__n_{it}", decayed_distinct(t, codes, item[it], taus, item_w.get(it)),
                "conserved")

    return pd.DataFrame(cols, index=df.index), specs
