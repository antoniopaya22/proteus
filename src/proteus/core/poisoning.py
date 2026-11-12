"""Baseline poisoning: how far an attacker raises the frontier by acting on earlier days.

The baseline of an entity is the q-quantile of its per-minute evidence over the
reference period (``proteus.evidence.baseline``). Free operations cannot lower the
evidence of the day being scored, but an attacker who sends traffic on the
reference days raises the baseline and so lowers the excess features the next day.

Model of the strongest such attacker. In deployment, minutes that raised an alert
are left out of the baseline, so poisoning traffic must stay below the frontier.
The attacker therefore sends, on every reference minute, the attack at just below
the current frontier; the new baseline of each entity the attack touches is the
q-quantile of its per-minute evidence under that traffic (never below the old one).
Iterating gives the frontier after k refreshes of the baseline (days).

Two things bound it:

* **ceiling**: the cores use the raw conserved counters as well as the excess, with
  monotone constraints, so even an infinite baseline leaves the raw evidence; the
  frontier with baseline -> infinity is a hard limit on poisoning;
* **growth cap**: ``cap`` limits how much a baseline may rise per refresh (in the log
  units of the counters), which bounds the rate of poisoning per day.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from proteus.core.frontier import Scenario, nested_attack
from proteus.evidence import baseline as bl
from proteus.evidence.features import build

INFINITE = 1e6  # baseline that makes every excess feature minimal


def touched_keys(attack: pd.DataFrame) -> dict[str, list[str]]:
    """Entity keys of every entity type the attack flows belong to."""
    keys = bl.entity_keys(attack)
    return {ent: sorted(pd.unique(k.astype(str))) for ent, k in keys.items()}


def entity_levels(flows: pd.DataFrame, cols: dict[str, list[str]],
                  keys: dict[str, list[str]], t0: pd.Timestamp, t1: pd.Timestamp,
                  q: float = bl.QUANTILE) -> dict[str, pd.DataFrame]:
    """Baseline the entities in ``keys`` would get if every reference minute looked
    like the minutes of ``flows`` in [t0, t1): per key, the q-quantile of the
    per-minute maximum, counting minutes without activity as 0."""
    feats, _ = build(flows)
    ek = bl.entity_keys(flows)
    win = ((flows["t_end"] >= t0) & (flows["t_end"] < t1)).to_numpy()
    minutes = int(np.ceil((t1 - t0).total_seconds() / 60))
    out = {}
    for ent, cs in cols.items():
        cs = [c for c in cs if c in feats.columns]
        want = keys.get(ent, [])
        if not cs or not want:
            continue
        key = ek[ent].astype(str)
        sel = win & key.isin(want).to_numpy()
        ev = pd.concat([flows.loc[sel, ["t_end"]], feats.loc[sel, cs]], axis=1)
        t = bl.minute_table(ev, cs, key[sel])
        codes, uniq = pd.factorize(t["key"])
        vals = {c: bl.quantile_with_zeros(codes, t[c].to_numpy(np.float64), len(uniq), minutes, q)
                for c in cs}
        out[ent] = pd.DataFrame(vals, index=pd.Index(uniq, name="key"))
    return out


def raise_baseline(base: dict[str, pd.DataFrame], levels: dict[str, pd.DataFrame],
                   cap: float | None = None) -> dict[str, pd.DataFrame]:
    """New baseline: max(old, level), at most ``cap`` above the old one per refresh.
    Entities absent from the old baseline had baseline 0."""
    new = {e: b.copy() for e, b in base.items()}
    for ent, lv in levels.items():
        b = new.get(ent, pd.DataFrame())
        cols = list(dict.fromkeys([*b.columns, *lv.columns]))
        b = b.reindex(index=b.index.union(lv.index), columns=cols).astype(np.float64).fillna(0.0)
        old = b.loc[lv.index, lv.columns]
        up = np.maximum(old, lv)
        if cap is not None:
            up = np.minimum(up, old + cap)
        b.loc[lv.index, lv.columns] = up
        new[ent] = b
    return new


def saturate(base: dict[str, pd.DataFrame], keys: dict[str, list[str]],
             cols: dict[str, list[str]]) -> dict[str, pd.DataFrame]:
    """Baseline set to ``INFINITE`` on the touched entities (the poisoning ceiling)."""
    lv = {ent: pd.DataFrame(INFINITE, index=pd.Index(keys[ent], name="key"), columns=cs)
          for ent, cs in cols.items() if cs and keys.get(ent)}
    return raise_baseline(base, lv)


def poisoning_traffic(sc: Scenario, rate: float, rng: np.random.Generator) -> pd.DataFrame:
    """Background plus attack at ``rate`` flows/s (the traffic of one poisoned period)."""
    a = nested_attack(sc, rate, rng).drop(columns=["u"])
    return pd.concat([sc.background, a], ignore_index=True)
