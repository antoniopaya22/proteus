"""A query attacker in the traffic space: black-box search with hard labels.

    python -m proteus.evaluation.query_attack \
        --run experiments/outputs/h1/csecicids2018__cicids2017__loo_labels__r2 \
        --test cicids2017 --targets proteus proteus_sys_r rate_rules_local

``evaluation.adaptive`` tries a fixed list of plans on a grid of rates. This attacker
instead *searches*. It knows nothing about the detector. For each scenario it may
submit variants of its own traffic and observe one bit per query: whether any of its
flows was alerted. A variant is a *shape* (padding, inserted packets, flow splitting,
decoys, source-port changes, requests per connection, bursts and, as a costly option,
the number of sources) and a rate. Its damage is the highest rate at which a query
came back quiet, so every reported value is backed by one real query.

The search is a (1+1) hill-climb with rate racing:

1. bisect the rate of the plain attack (a few queries);
2. mutate one or two parameters of the best shape and query it one rate step above
   the best quiet rate: a quiet answer means the candidate is strictly better, and its
   rate is then pushed up by doubling steps and bisection; an alert costs one query.

A target may be a detector or a union of detectors (``h1.UNIONS``), which is quiet
only when every member is. Thresholds, local detectors and the notion of a quiet
query are those of ``evaluation.adaptive`` (``Oracle``).
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
from pathlib import Path

import numpy as np
import pandas as pd

from proteus.attacks import operators as op
from proteus.core.frontier import nested_attack
from proteus.evaluation import h1
from proteus.evaluation.adaptive import Oracle, day_models
from proteus.evaluation.frontier_exp import ATTACKS, FLOW_COLS, Baselines, scenarios
from proteus.evaluation.poisoning import combined


@dataclass(frozen=True)
class Shape:
    """How the attacker sends its flows, apart from their rate."""

    pad: int = 0  # padding bytes per forward packet
    ins: int = 0  # packets inserted per flow
    split: int = 1  # pieces each selected flow is split into
    split_frac: float = 0.0  # share of the flows that are split
    decoys: int = 0  # decoy flows to other destinations
    ports: bool = False  # fresh source ports
    reuse: int = 1  # requests per connection
    duty: float = 1.0  # share of every period in which flows are sent (1 = no bursts)
    period: float = 60.0  # burst period in seconds
    sources: int = 1  # sources the flows are spread over (costly when > 1)


CHOICES: dict[str, tuple] = {
    "pad": (0, 40, 400, 1400), "ins": (0, 1, 5, 20), "split": (1, 2, 5),
    "split_frac": (0.0, 0.05, 0.2, 1.0), "decoys": (0, 100, 1000), "ports": (False, True),
    "reuse": (1, 2, 5, 20, 100), "duty": (1.0, 0.5, 0.1), "period": (10.0, 60.0, 300.0),
    "sources": (1, 10, 100),
}
FREE = tuple(k for k in CHOICES if k != "sources")


def mutate(shape: Shape, rng: np.random.Generator, costly: bool = False) -> Shape:
    """A neighbour of ``shape``: one or two parameters redrawn from their choices."""
    keys = list(CHOICES if costly else FREE)
    out = shape
    while out == shape:
        for k in rng.choice(keys, size=int(rng.integers(1, 3)), replace=False):
            options = [v for v in CHOICES[k] if v != getattr(out, k)]
            out = replace(out, **{k: options[int(rng.integers(len(options)))]})
    return out


def apply(df: pd.DataFrame, shape: Shape, victim: str, port: int,
          rng: np.random.Generator) -> pd.DataFrame:
    """The traffic ``df`` (attacker flows marked ``_atk``) sent with ``shape``."""
    out = df
    if shape.duty < 1.0:
        out = op.pulse(out, out["_atk"].to_numpy(), shape.period, shape.duty)
    if shape.sources > 1:
        out = op.spread_sources(out, out["_atk"].to_numpy(), shape.sources, rng)
    if shape.pad:
        out = op.pad(out, out["_atk"].to_numpy(), shape.pad)
    if shape.ins:
        out = op.insert_packets(out, out["_atk"].to_numpy(), shape.ins, 60)
    if shape.ports:
        out = op.change_src_ports(out, out["_atk"].to_numpy(), rng)
    if shape.split > 1 and shape.split_frac > 0:
        atk = out["_atk"].to_numpy()
        out = op.split_flows(out, atk & (rng.random(len(out)) < shape.split_frac),
                             shape.split, rng)
    if shape.reuse > 1:
        out = op.reuse_connections(out, out["_atk"].to_numpy(), shape.reuse,
                                   h1.EXPORT_TIMEOUT_S)
    if shape.decoys:
        srcs = df.loc[df["_atk"].to_numpy(), "src_ip"].astype(str).unique()
        out = op.add_decoys(out, shape.decoys, rng, srcs, [victim, "192.0.2.1"], [port, 443])
        out["_atk"] = out["_atk"].where(out["orig_id"] >= 0, True).astype(bool)
    return out.sort_values("t_end", kind="stable").reset_index(drop=True)


def search(quiet: Callable[[Shape, int], bool], n_rates: int, budget: int,
           rng: np.random.Generator, costly: bool = False,
           start: Shape | None = None) -> dict:
    """Highest rate index answered quiet within ``budget`` queries.

    ``quiet(shape, i)`` submits the attack with ``shape`` at the ``i``-th rate of an
    increasing grid and returns the hard label. Returns the best index (-1 if no query
    was quiet), its shape, the queries used and the improving steps."""
    used = 0

    def ask(shape: Shape, i: int) -> bool:
        nonlocal used
        used += 1
        return bool(quiet(shape, i))

    def climb(shape: Shape, i: int) -> int:
        """Largest quiet index of ``shape`` found from the quiet index ``i``: doubling
        steps up, then bisection."""
        step, hi = 1, None
        while i + step < n_rates and used < budget:
            if ask(shape, i + step):
                i, step = i + step, step * 2
            else:
                hi = i + step
                break
        hi = n_rates if hi is None else hi
        while hi - i > 1 and used < budget:
            mid = (i + hi) // 2
            if ask(shape, mid):
                i = mid
            else:
                hi = mid
        return i

    best = start or Shape()
    lo, hi = -1, n_rates
    while hi - lo > 1 and used < budget:  # the plain attack: bisect its rate
        mid = (lo + hi) // 2
        if ask(best, mid):
            lo = mid
        else:
            hi = mid
    best_i, trace = lo, [{"queries": used, "index": lo, "shape": asdict(best)}]
    while used < budget and best_i < n_rates - 1:
        cand = mutate(best, rng, costly)
        if ask(cand, best_i + 1):
            best, best_i = cand, climb(cand, best_i + 1)
            trace.append({"queries": used, "index": best_i, "shape": asdict(best)})
    return {"index": best_i, "shape": best, "queries": used, "trace": trace}


def submit(full: pd.DataFrame, sc, oracle: Oracle, rates: np.ndarray, rmax: float,
           members: list[str], sent: dict[int, int]) -> Callable[[Shape, int], bool]:
    """The attacker's query for one scenario and target: send the nested attack
    ``full`` at the ``i``-th rate with a shape and read whether every member detector
    stays quiet. ``sent`` records how many attack flows each rate index carries."""

    def quiet(shape: Shape, i: int) -> bool:
        a = full[full["u"] < rates[i] / rmax].drop(columns=["u"])
        sent[i] = len(a)
        if a.empty:
            return True  # nothing sent: quiet, and worth nothing
        df = pd.concat([sc.background.assign(_atk=False), a.assign(_atk=True)],
                       ignore_index=True)
        df["orig_id"] = np.arange(len(df))
        v = apply(df, shape, sc.target_ip, sc.target_port, np.random.default_rng(3000))
        q, _ = oracle.query(v, members)
        return all(q.values())

    return quiet


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", type=Path, required=True)
    ap.add_argument("--test", required=True)
    ap.add_argument("--targets", nargs="+", required=True,
                    help="fitted or local detectors, or unions of them (h1.UNIONS)")
    ap.add_argument("--extra-runs", type=Path, nargs="*", default=[])
    ap.add_argument("--local", nargs="*", default=["rate_rules_local", "kitnet_local"],
                    help="targets fitted per day on local benign traffic")
    ap.add_argument("--fpr", type=float, default=1e-3)
    ap.add_argument("--budget", type=int, default=100, help="queries per target and scenario")
    ap.add_argument("--grid", type=int, default=60, help="rates between --rmin and --rmax")
    ap.add_argument("--rmin", type=float, default=1e-3)
    ap.add_argument("--rmax", type=float, default=200.0)
    ap.add_argument("--attacks", nargs="*", default=None)
    ap.add_argument("--days", nargs="*", default=None, help="test days (file stems)")
    ap.add_argument("--costly", action="store_true",
                    help="also let the attacker spread over sources (reported apart)")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--tag", default="")
    args = ap.parse_args()
    rng = np.random.default_rng(args.seed)
    fitted = h1.load_models(args.run)
    for extra in args.extra_runs:
        fitted = {**h1.load_models(extra), **fitted}
    members = {t: h1.UNIONS.get(t, (t,)) for t in args.targets}
    names = list(dict.fromkeys(n for ms in members.values() for n in ms))
    _, specs = h1.evidence_b(args.test, h1.days(args.test)[0], columns=["clean"])
    fresh = h1.detectors(specs, [])
    dets = {n: fresh[n] if n in args.local else combined(fitted, n) for n in names}
    rates = np.geomspace(args.rmin, args.rmax, args.grid)
    baselines = Baselines(args.test)
    rows, traces = [], []
    for day in h1.days(args.test):
        if args.days and day.stem not in args.days:
            continue
        flows = pd.read_parquet(day, columns=FLOW_COLS)
        want = args.attacks or ATTACKS
        present = [a for a in want if (flows["is_attack"] & (flows["attack"] == a)).any()]
        if not present:
            continue
        base = baselines.for_day(day)
        models, thr = day_models(args.test, day, dets, args.local, args.fpr, rng)
        for attack, sc, A in scenarios(flows, present):
            span = max((A["t_end"].max() - A["t_start"].min()).total_seconds(), 1.0)
            full = nested_attack(sc, args.rmax, np.random.default_rng(args.seed))
            oracle = Oracle(sc, models, thr, base, specs)
            for target, ms in members.items():
                for costly in ([False, True] if args.costly else [False]):
                    sent: dict[int, int] = {}
                    quiet = submit(full, sc, oracle, rates, args.rmax, list(ms), sent)
                    res = search(quiet, len(rates), args.budget,
                                 np.random.default_rng(args.seed + 1), costly=costly)
                    ok = res["index"] >= 0 and sent.get(res["index"], 0) > 0
                    rate = float(rates[res["index"]]) if ok else 0.0
                    rows.append({"day": day.stem, "attack": attack, "target": target,
                                 "costly": costly, "threshold_fpr": args.fpr,
                                 "real_flows_per_h": len(A) / span * 3600,
                                 "query_flows_per_h": rate * 3600,
                                 "queries": res["queries"],
                                 "shape": json.dumps(asdict(res["shape"])),
                                 "rmax_flows_per_h": args.rmax * 3600})
                    print(rows[-1], flush=True)
                    traces += [{"day": day.stem, "attack": attack, "target": target,
                                "costly": costly, "queries": t["queries"],
                                "flows_per_h": (float(rates[t["index"]]) * 3600
                                                if t["index"] >= 0 else 0.0),
                                "shape": json.dumps(t["shape"])} for t in res["trace"]]
    tag = f"_{args.tag}" if args.tag else ""
    out = pd.DataFrame(rows)
    out.to_csv(args.run / f"query_attack_{args.fpr:g}{tag}.csv", index=False)
    pd.DataFrame(traces).to_csv(args.run / f"query_attack_trace_{args.fpr:g}{tag}.csv",
                                index=False)
    if len(out):
        print(out.pivot_table(index=["day", "attack"], columns=["target", "costly"],
                              values="query_flows_per_h").round(0).to_string())


if __name__ == "__main__":
    main()
