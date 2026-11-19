"""Per-entity envelope calibrated to a budget of alarms, without attack examples.

For a witness, the reference level of an entity is the highest value its own windows
reached on the reference days. An entity-window alerts when the witness exceeds
``lam * max(reference, floor)``; ``lam`` is one number per witness, set on the pooled
scores ``value / max(reference, floor)`` of every entity with a reference so that the
windows over it are the budget (split conformal calibration on normalised scores).

Entities seen on fewer than ``min_days`` reference days have no reference. They are
held to one network-wide level per witness (``fallback``), set the same way on their
pooled values with a share of the budget, so every entity has a bound: its own where
it has a history, the network's otherwise. With ``per_entity`` off no entity has a
reference and the whole budget goes to the network-wide level: a rate rule on the same
witness.

Two protocols: ``loo`` (reference and levels from the other days, leaving out the
windows labelled as attack: the protocol of the benchmark tables) and ``causal`` (from
the earlier days only, leaving out only the windows that alerted and the analyst
confirmed: no label enters). In ``causal`` the first day raises no alert, and the
levels of the second come from the first split in two halves.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from proteus.envelope.witness import FLOORS

FALLBACK_SHARE = 0.5  # of each witness's budget, for the entities without a reference


@dataclass
class Envelope:
    ref: dict[str, pd.Series]  # witness -> reference level of each entity that has one
    lam: dict[str, float] = field(default_factory=dict)
    fallback: dict[str, float] = field(default_factory=dict)  # level for the other entities
    floors: dict[str, float] = field(default_factory=lambda: dict(FLOORS))

    def base(self, witness: str, keys: np.ndarray) -> np.ndarray:
        """Scale of the witness for each entity (NaN: no reference)."""
        r = self.ref[witness].reindex(keys).to_numpy(np.float64)
        return np.where(np.isnan(r), np.nan, np.maximum(r, self.floors[witness]))

    def monitored(self, witness: str, keys: np.ndarray) -> np.ndarray:
        return ~np.isnan(self.base(witness, keys))

    def thresholds(self, witness: str, keys: np.ndarray) -> np.ndarray:
        """Alert level of each entity: its own, or the network-wide one."""
        b = self.base(witness, keys)
        own = np.maximum(self.lam.get(witness, np.inf) * np.where(np.isnan(b), 1.0, b),
                         self.floors[witness])
        return np.where(np.isnan(b), self.fallback.get(witness, np.inf), own)

    def alerts(self, table: pd.DataFrame, witnesses) -> pd.DataFrame:
        keys = table["key"].to_numpy()
        return pd.DataFrame({w: table[w].to_numpy() > self.thresholds(w, keys)
                             for w in witnesses}, index=table.index)


def day_max(table: pd.DataFrame, witness: str, skip: np.ndarray) -> pd.Series:
    """Highest value of the witness per entity over the windows not skipped."""
    t = table.loc[~skip, ["key", witness]]
    return t.groupby("key", sort=False)[witness].max()


def _daily(maxima: list[pd.Series]) -> tuple[np.ndarray, np.ndarray]:
    """Entities and their daily maxima as a matrix (entity, day); -inf where absent."""
    key = np.concatenate([m.index.to_numpy() for m in maxima])
    code, uniq = pd.factorize(key)
    day = np.concatenate([np.full(len(m), i) for i, m in enumerate(maxima)])
    mat = np.full((len(uniq), len(maxima)), -np.inf)
    mat[code, day] = np.concatenate([m.to_numpy(np.float64) for m in maxima])
    return uniq, mat


def _ranked(uniq: np.ndarray, mat: np.ndarray, min_days: int, rank: int) -> pd.Series:
    """The ``rank``-th highest day of each entity seen on enough days."""
    seen = np.isfinite(mat).sum(axis=1)
    ok = seen >= max(min_days, rank)
    m = mat[ok]
    v = m.max(axis=1) if rank == 1 else -np.partition(-m, rank - 1, axis=1)[:, rank - 1]
    return pd.Series(v, index=uniq[ok])


def reference(maxima: list[pd.Series], min_days: int, rank: int = 1) -> pd.Series:
    """Reference level per entity from per-day maxima: its highest day, or with
    ``rank`` above one its ``rank``-th highest, which a single day cannot move.
    Entities on fewer than ``min_days`` (or ``rank``) of those days get none."""
    if not sum(len(m) for m in maxima):
        return pd.Series(dtype=np.float64)
    return _ranked(*_daily(maxima), min_days, rank)


def scores(table: pd.DataFrame, witness: str, env: Envelope,
           skip: np.ndarray | None = None) -> tuple[np.ndarray, np.ndarray]:
    """Normalised score of every row not skipped, and whether its entity has a
    reference (the others are scored against the floor)."""
    keys, v = table["key"].to_numpy(), table[witness].to_numpy()
    if skip is not None:
        keys, v = keys[~skip], v[~skip]
    b = env.base(witness, keys)
    mon = ~np.isnan(b)
    return (v / np.where(mon, b, env.floors[witness])).astype(np.float32), mon


def fit_lambda(pooled: np.ndarray, hours: float, budget: float) -> float:
    """Largest-score level that at most ``budget * hours`` pooled scores exceed."""
    k = int(budget * hours)
    if len(pooled) <= k:
        return 0.0
    return float(np.partition(pooled, len(pooled) - 1 - k)[len(pooled) - 1 - k])


def _levels(env: Envelope, pooled: dict[str, list], hours: float, budget: float,
            per_entity: bool) -> None:
    """Set ``lam`` and ``fallback`` of ``env`` from pooled (score, monitored) pairs."""
    share = FALLBACK_SHARE if per_entity else 1.0
    for w, parts in pooled.items():
        s = np.concatenate([p[0] for p in parts]) if parts else np.array([])
        m = np.concatenate([p[1] for p in parts]) if parts else np.array([], bool)
        env.lam[w] = fit_lambda(s[m], hours, budget * (1 - share)) if per_entity else np.inf
        env.fallback[w] = env.floors[w] * max(fit_lambda(s[~m], hours, budget * share), 1.0)


def _refs(maxima: list[dict[str, pd.Series]], witnesses, min_days: int,
          per_entity: bool, rank: int = 1) -> dict[str, pd.Series]:
    if not per_entity:
        return {w: pd.Series(dtype=np.float64) for w in witnesses}
    return {w: reference([m[w] for m in maxima], min_days, rank) for w in witnesses}


def references_without(maxima: list[pd.Series], min_days: int, rank: int = 1) -> list[pd.Series]:
    """For each day, the reference from the other days: what ``reference`` gives on
    the list without that day."""
    if not sum(len(m) for m in maxima):
        return [pd.Series(dtype=np.float64) for _ in maxima]
    uniq, mat = _daily(maxima)
    out = []
    for i in range(len(maxima)):
        col = mat[:, i].copy()
        mat[:, i] = -np.inf
        out.append(_ranked(uniq, mat, min_days, rank))
        mat[:, i] = col
    return out


def loo(tables: dict[str, pd.DataFrame], hours: dict[str, float], witnesses,
        budget: float, per_entity: bool = True, min_days: int = 2,
        floors: dict[str, float] = FLOORS, rank: int = 1) -> dict[str, Envelope]:
    """Envelope of each day from the other days; ``budget`` is alarms per hour and
    witness."""
    days = list(tables)
    dirty = {d: tables[d]["dirty"].to_numpy() for d in days}
    refs: dict[str, list[pd.Series]] = {}
    for w in witnesses:
        if per_entity:
            refs[w] = references_without([day_max(tables[d], w, dirty[d]) for d in days],
                                         min_days, rank)
        else:
            refs[w] = [pd.Series(dtype=np.float64)] * len(days)
    env = {d: Envelope({w: refs[w][i] for w in witnesses}, floors=dict(floors))
           for i, d in enumerate(days)}
    s = {d: {w: scores(tables[d], w, env[d], dirty[d]) for w in witnesses} for d in days}
    for d in days:
        others = [j for j in days if j != d]
        _levels(env[d], {w: [s[j][w] for j in others] for w in witnesses},
                sum(hours[j] for j in others), budget, per_entity)
    return env


def _first_levels(env: Envelope, first: pd.DataFrame, hours: float, witnesses, budget: float,
                  per_entity: bool) -> None:
    """Levels for the second day, when one day is all there is: the reference of each
    entity from the first half of that day and the scores from its second half."""
    mid = (int(first["win"].min()) + int(first["win"].max()) + 1) // 2
    early = (first["win"] < mid).to_numpy()
    half = Envelope(_refs([{w: day_max(first, w, ~early) for w in witnesses}], witnesses, 1,
                          per_entity), floors=env.floors)
    _levels(env, {w: [scores(first, w, half, early)] for w in witnesses}, hours / 2, budget,
            per_entity)


def causal(tables: dict[str, pd.DataFrame], hours: dict[str, float], witnesses,
           budget: float, per_entity: bool = True, min_days: int = 2,
           floors: dict[str, float] = FLOORS, rank: int = 1) -> dict[str, Envelope]:
    """Envelope of each day from the earlier days only (``tables`` in time order). The
    only feedback is the analyst's verdict: a window that alerted and holds an attack
    is left out of later references; every other window stays in, attacks included.
    The first day has no envelope. The second has the first as reference and levels
    from the first alone, split in two halves; from the third on, the levels come from
    the scores of the days after the first."""
    days = list(tables)
    mx: dict[str, dict[str, pd.Series]] = {}
    s: dict[str, dict[str, tuple]] = {}
    env: dict[str, Envelope] = {}
    for i, d in enumerate(days):
        t = tables[d]
        confirmed = np.zeros(len(t), bool)
        if i:
            past = days[:i]
            e = Envelope(_refs([mx[j] for j in past], witnesses, min(min_days, i), per_entity,
                               min(rank, i)), floors=dict(floors))
            if i > 1:
                _levels(e, {w: [s[j][w] for j in past[1:]] for w in witnesses},
                        sum(hours[j] for j in past[1:]), budget, per_entity)
            else:
                _first_levels(e, tables[past[0]], hours[past[0]], witnesses, budget, per_entity)
            env[d] = e
            confirmed = e.alerts(t, witnesses).any(axis=1).to_numpy() & t["dirty"].to_numpy()
            s[d] = {w: scores(t, w, e, confirmed) for w in witnesses}
        mx[d] = {w: day_max(t, w, confirmed) for w in witnesses}
    return env
