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

Two shapes of scenario:

* destination side (DoS, brute force, vertical scan): every attack flow goes to one
  target; the background is the real traffic towards that target;
* source side (horizontal scan): one fresh source replays the real probes, keeping
  their destinations and ports (``src_ip`` set, ``keep_dst``); the background is the
  real traffic towards those destinations.

The features of an attack flow depend only on flows that share its service, its
destination host or its source, so this background is exact for the attack flows.
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
    src_ip: str | None = None  # source-side scenario: one fixed attacker source
    keep_dst: bool = False  # source-side scenario: keep each probe's destination host


def nested_attack(sc: Scenario, r_max: float, rng: np.random.Generator) -> pd.DataFrame:
    """Attack flows at rate r_max (flows/s) with a nesting mark ``u``."""
    n = int(rng.poisson(r_max * sc.duration_s))
    rows = sc.template.sample(n=n, replace=(not sc.keep_dst) or n > len(sc.template),
                              random_state=int(rng.integers(2**31)))
    rows = rows.reset_index(drop=True)
    offs = np.sort(rng.uniform(0, sc.duration_s, n))
    start = sc.start + pd.to_timedelta(offs, unit="s")
    rows["t_start"] = start.astype("datetime64[us]")
    rows["t_end"] = rows["t_start"] + pd.to_timedelta(rows["duration_us"], unit="us")
    if sc.keep_dst:
        rows["dst_ip"] = rows["dst_ip"].astype(sc.background["dst_ip"].dtype)
    else:
        rows["dst_ip"] = pd.array([sc.target_ip] * n, dtype=sc.background["dst_ip"].dtype)
        if not sc.keep_ports:
            rows["dst_port"] = np.int32(sc.target_port)
        rows["proto"] = np.int16(sc.proto)
    srcs = ([sc.src_ip] if sc.src_ip is not None
            else [f"203.0.113.{i % 250 + 1}" for i in range(sc.n_sources)])  # TEST-NET-3
    rows["src_ip"] = pd.array(rng.choice(srcs, n), dtype=sc.background["src_ip"].dtype)
    rows["src_port"] = rng.integers(1024, 65536, n).astype(np.int32)
    rows["u"] = rng.random(n)
    return rows


def _features(flows: pd.DataFrame, cols: list[str], base: dict[str, pd.DataFrame]) -> pd.DataFrame:
    feats, _ = build(flows)
    keys = bl.entity_keys(flows)
    out = {}
    pops: dict[str, pd.DataFrame] = {}
    for c in cols:
        if c.endswith("__xp"):
            raw = c[: -len("__xp")]
            ent = raw.split("__")[0]
            if ent not in pops:
                pops[ent] = bl.population_for(ent, base[ent], keys[ent])
            out[c] = feats[raw].to_numpy(np.float64) - pops[ent][raw].to_numpy()
        elif c.endswith("__x"):
            raw = c[: -len("__x")]
            ent = bl.entity_of(raw)
            b = base[ent][raw].reindex(keys[ent].to_numpy()).fillna(0.0).to_numpy()
            out[c] = feats[raw].to_numpy(np.float64) - b
        elif c.endswith("__b"):
            raw = c[: -len("__b")]
            ent = bl.entity_of(raw)
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


def _scores_all(flows: pd.DataFrame, model, cols, specs, base, delta_s) -> np.ndarray:
    X = _features(flows, cols, base)[cols].to_numpy(np.float64)
    if delta_s is not None:
        X = worst_case_features(X, np.asarray(model.monotonic_cst), slack(cols, specs, delta_s))
    return model.predict_proba(X)[:, 1]


def noisy_minutes(sc: Scenario, model, cols, specs, base, threshold: float,
                  delta_s: float | None = None) -> np.ndarray:
    """Minutes (int64, since epoch) in which the background alone raises an alert."""
    s = _scores_all(sc.background, model, cols, specs, base, delta_s)
    m = sc.background["t_end"].astype("int64").to_numpy() // (60 * US)
    return np.unique(m[s >= threshold])


def attributable_alert(sc: Scenario, attack: pd.DataFrame, model, cols, specs, base,
                       threshold: float, noisy: np.ndarray, delta_s: float | None) -> bool:
    """The attack gets the victim alerted: some flow (attack or background, whose
    evidence the attack raised) alerts in a minute where the background alone does
    not. Adding attack flows only raises evidence, so this is monotone in the rate."""
    flows = pd.concat([sc.background, attack], ignore_index=True)
    s = _scores_all(flows, model, cols, specs, base, delta_s)
    m = flows["t_end"].astype("int64").to_numpy() // (60 * US)
    return bool(((s >= threshold) & ~np.isin(m, noisy)).any())


def frontier(sc: Scenario, model, cols, specs, base, threshold: float, rng,
             r_min: float = 1e-3, r_max: float = 100.0, iters: int = 18,
             delta_s: float | None = None) -> dict:
    """Highest rate (flows/s) at which the attack raises no alert of its own.

    Alerts in minutes where the victim's background alone is alerted (benign false
    positives) are not attributed to the attack; otherwise a busy victim near its
    threshold would give a frontier of zero that says nothing about the attack."""
    attack = nested_attack(sc, r_max, rng)
    noisy = noisy_minutes(sc, model, cols, specs, base, threshold, delta_s)

    def alerts(r: float) -> bool:
        a = attack[attack["u"] < r / r_max].drop(columns=["u"])
        if a.empty:
            return False
        return attributable_alert(sc, a, model, cols, specs, base, threshold, noisy, delta_s)

    if alerts(r_min):
        return {"rate": 0.0, "bounded": "below r_min", "noisy_minutes": len(noisy)}
    if not alerts(r_max):
        return {"rate": np.inf, "bounded": "above r_max", "noisy_minutes": len(noisy)}
    lo, hi = np.log(r_min), np.log(r_max)
    for _ in range(iters):
        mid = (lo + hi) / 2
        if alerts(float(np.exp(mid))):
            hi = mid
        else:
            lo = mid
    return {"rate": float(np.exp(lo)), "rate_alert": float(np.exp(hi)), "bounded": "ok",
            "noisy_minutes": len(noisy)}
