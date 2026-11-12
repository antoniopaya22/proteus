"""Rules declared by the operator, as the domain-knowledge axis of METIS.

A rule bounds a conserved counter, optionally for one entity: "at most 100 unanswered
destinations per source in an hour", "the honeypot 10.0.0.99 receives no flows",
"192.168.10.50:22 gets fewer than 30 connections in ten minutes". Rules are written
in counts, not in the log scale of the features, and are never estimated from data.

Each rule is an indicator ``x >= threshold`` on a conserved feature, so it is monotone
and its alerts are certified the same way as the core's: a rule that fires on the
worst case ``x - s`` fires on every free-operation variant, at most Δ later. Rule
alerts are reported apart from the learned core (as METIS reports its rules apart
from the score), with the share of benign flows that violate each rule and its Wilson
interval, so a rule that the network itself breaks is visible as such.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from proteus.core.certify import slack, worst_case_features


@dataclass
class Rule:
    name: str
    feature: str  # e.g. "shost__n_dhost_nr__t3600"
    max_count: float  # alert when the decayed count reaches this value
    where: dict = field(default_factory=dict)  # optional equality filters on flow metadata

    @property
    def threshold(self) -> float:
        return float(np.log1p(self.max_count))  # features are log1p of counts


def applies(rule: Rule, meta: pd.DataFrame) -> np.ndarray:
    ok = np.ones(len(meta), dtype=bool)
    for col, val in rule.where.items():
        ok &= (meta[col].astype(str) == str(val)).to_numpy()
    return ok


def fire(rules: list[Rule], ev: pd.DataFrame, specs: dict[str, str] | None = None,
         delta_s: float | None = None) -> pd.DataFrame:
    """Boolean frame (flows x rules): the rule fires on the flow's evidence, or, with
    ``delta_s``, on its certified worst case."""
    out = {}
    for r in rules:
        x = ev[[r.feature]].to_numpy(np.float64)
        if delta_s is not None:
            x = worst_case_features(x, np.array([1]), slack([r.feature], specs, delta_s))
        out[r.name] = (x[:, 0] >= r.threshold) & applies(r, ev)
    return pd.DataFrame(out, index=ev.index)


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (np.nan, np.nan)
    p, d = k / n, 1 + z * z / n
    c, h = (p + z * z / (2 * n)) / d, z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def report(rules: list[Rule], ev: pd.DataFrame, benign: np.ndarray) -> pd.DataFrame:
    """Per rule: flows where it applies, benign violation rate with its Wilson interval
    (a rule the benign traffic breaks needs revising), and attack flows it catches."""
    f = fire(rules, ev)
    rows = []
    for r in rules:
        app = applies(r, ev)
        b = app & benign
        k, n = int(f[r.name][b].sum()), int(b.sum())
        lo, hi = wilson(k, n)
        att = app & ~benign
        rows.append({"rule": r.name, "applies": int(app.sum()), "benign_violation": k / n if n
                     else np.nan, "benign_lo": lo, "benign_hi": hi,
                     "attack_flows_caught": int(f[r.name][att].sum()),
                     "attack_flows": int(att.sum())})
    return pd.DataFrame(rows)
