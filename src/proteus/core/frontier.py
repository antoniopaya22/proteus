"""Harm frontier: the highest attack rate that raises no alert (doc 04 §4.4.3).

An attack is modelled by its flow shapes (sampled from a real campaign) replayed
at rate r against a target over the real background traffic of that target.
Attacks at different rates are *nested*: events are drawn once at r_max with a
uniform mark u, and the attack at rate r keeps the events with u < r / r_max. A
higher rate is therefore a superset of a lower one. Adding events never lowers the
evidence of existing flows, and the core is monotone, so "some attack flow alerts"
is monotone in r and binary search finds the frontier exactly (up to resolution).

The certified frontier scores worst-case features (``proteus.core.certify``): it
bounds what the attacker can reach even when combining the rate with any free
operation.

The core only uses destination entities, so only flows towards the target host
are needed.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

from proteus.core.certify import slack, worst_case_features
from proteus.evidence import baseline as bl
from proteus.evidence.features import build

US = 1_000_000


@dataclass
class Scenario:
    background: pd.DataFrame  # benign flows to the target host (common schema)
    template: pd.DataFrame  # attack flows whose shapes are replayed
    target_ip: str
    target_port: int
    proto: int
    start: pd.Timestamp
    duration_s: float
    n_sources: int = 1
    keep_ports: bool = False  # scans: keep each probe's destination port


def nested_attack(sc: Scenario, r_max: float, rng: np.random.Generator) -> pd.DataFrame:
    """Attack flows at rate r_max (flows/s) with a nesting mark ``u``."""
    n = int(rng.poisson(r_max * sc.duration_s))
    rows = sc.template.sample(n=n, replace=True, random_state=int(rng.integers(2**31)))
    rows = rows.reset_index(drop=True)
    offs = np.sort(rng.uniform(0, sc.duration_s, n))
    start = sc.start + pd.to_timedelta(offs, unit="s")
    rows["t_start"] = start.astype("datetime64[us]")
    rows["t_end"] = rows["t_start"] + pd.to_timedelta(rows["duration_us"], unit="us")
    rows["dst_ip"] = pd.array([sc.target_ip] * n, dtype=sc.background["dst_ip"].dtype)
    if not sc.keep_ports:
        rows["dst_port"] = np.int32(sc.target_port)
    rows["proto"] = np.int16(sc.proto)
    srcs = [f"203.0.113.{i % 250 + 1}" for i in range(sc.n_sources)]  # TEST-NET-3
    rows["src_ip"] = pd.array(rng.choice(srcs, n), dtype=sc.background["src_ip"].dtype)
    rows["src_port"] = rng.integers(1024, 65536, n).astype(np.int32)
    rows["u"] = rng.random(n)
    return rows


def _features(flows: pd.DataFrame, cols: list[str], base: dict[str, pd.DataFrame]) -> pd.DataFrame:
    feats, _ = build(flows)
    keys = bl.entity_keys(flows)
    out = {}
    for c in cols:
        if c.endswith("__x"):
            raw = c[: -len("__x")]
            ent = raw.split("__")[0]
            b = base[ent][raw].reindex(keys[ent].to_numpy()).fillna(0.0).to_numpy()
            out[c] = feats[raw].to_numpy(np.float64) - b
        elif c.endswith("__b"):
            raw = c[: -len("__b")]
            ent = raw.split("__")[0]
            out[c] = base[ent][raw].reindex(keys[ent].to_numpy()).fillna(0.0).to_numpy()
        else:
            out[c] = feats[c].to_numpy(np.float64)
    return pd.DataFrame(out, index=flows.index)


def attack_scores(sc: Scenario, attack: pd.DataFrame, model, cols: list[str],
                  specs: dict[str, str], base: dict[str, pd.DataFrame],
                  delta_s: float | None) -> np.ndarray:
    """Scores of the attack flows when mixed with the background."""
    flows = pd.concat([sc.background.assign(_atk=False), attack.assign(_atk=True)],
                      ignore_index=True)
    X = _features(flows, cols, base)[cols].to_numpy(np.float64)
    if delta_s is not None:
        X = worst_case_features(X, np.asarray(model.monotonic_cst), slack(cols, specs, delta_s))
    s = model.predict_proba(X)[:, 1]
    return s[flows["_atk"].to_numpy()]


def frontier(sc: Scenario, model, cols, specs, base, threshold: float, rng,
             r_min: float = 1e-3, r_max: float = 100.0, iters: int = 18,
             delta_s: float | None = None) -> dict:
    """Highest rate (flows/s) with no alert on any attack flow."""
    attack = nested_attack(sc, r_max, rng)

    def alerts(r: float) -> bool:
        a = attack[attack["u"] < r / r_max]
        if a.empty:
            return False
        return bool((attack_scores(sc, a, model, cols, specs, base, delta_s) >= threshold).any())

    if alerts(r_min):
        return {"rate": 0.0, "bounded": "below r_min"}
    if not alerts(r_max):
        return {"rate": np.inf, "bounded": "above r_max"}
    lo, hi = np.log(r_min), np.log(r_max)
    for _ in range(iters):
        mid = (lo + hi) / 2
        if alerts(float(np.exp(mid))):
            hi = mid
        else:
            lo = mid
    return {"rate": float(np.exp(lo)), "rate_alert": float(np.exp(hi)), "bounded": "ok"}
