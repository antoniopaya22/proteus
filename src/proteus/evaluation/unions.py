"""Compare candidate systems: any union of detectors, from their per-flow alerts.

    python -m proteus.evaluation.unions --test cicids2017 \
        --alerts RUN_A RUN_B --union sys3=proteus,proteus_cert,proteus_cert_r \
        --union pw=proteus,window_fidelity --out experiments/outputs/h1/<name>

``h1 --export-alerts`` and ``window_fidelity`` write, per test day, the alert of every
flow for each detector at each threshold kind (local false-positive rate, alarm budget
per entity). A candidate system alerts on a flow when any of its members does, every
member at the same target. This module computes, for every detector found and every
union asked for, the metrics of ``h1`` (campaigns, strict criterion, alarms per alerted
entity), so that candidates can be compared without scoring anything again. A member
that has no alerts for a kind (the window-fidelity complement has no alarm budget)
takes part with its alerts at the laxer local rate.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from proteus.evaluation import h1


def targets_of(alerts: dict[str, np.ndarray]) -> list[tuple[str, float]]:
    """(kind, target) pairs present in a day's alerts, e.g. ("local", 0.001)."""
    out = set()
    for key in alerts:
        _, _, tail = key.rpartition("__")
        for kind in ("local", "entity"):
            if tail.startswith(kind):
                out.add((kind, float(tail[len(kind):])))
    return sorted(out)


def member(alerts: dict[str, np.ndarray], name: str, kind: str,
           target: float) -> tuple[np.ndarray, np.ndarray | None] | None:
    """Alert and side of a detector at a target; without that kind, at the laxer local rate."""
    key = f"{name}__{kind}{target:g}"
    if key not in alerts:
        key = f"{name}__local{h1.FPRS[0]:g}"
        if key not in alerts:
            return None
    return alerts[key].astype(bool), alerts.get(f"{name}__side")


def union(members: list[tuple[np.ndarray, np.ndarray | None]]) -> tuple[np.ndarray, np.ndarray]:
    """Alert of any member; the side is that of the first member that alerts."""
    alert = np.logical_or.reduce([a for a, _ in members])
    side, done = np.zeros(len(alert), dtype=bool), np.zeros(len(alert), dtype=bool)
    for a, sd in members:
        if sd is not None:
            side[a & ~done] = sd.astype(bool)[a & ~done]
        done |= a
    return alert, side


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--test", required=True)
    ap.add_argument("--alerts", type=Path, nargs="+", required=True,
                    help="runs with an alerts/ directory (h1 --export-alerts, window_fidelity)")
    ap.add_argument("--union", action="append", default=[], metavar="NAME=A,B,...")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    unions = {u.split("=")[0]: u.split("=")[1].split(",") for u in args.union}
    results = []
    for day in h1.days(args.test):
        alerts: dict[str, np.ndarray] = {}
        for run in args.alerts:
            for name in (f"{day.stem}.npz", f"{day.stem}.budgets.npz"):
                if (run / "alerts" / name).exists():
                    alerts.update(h1.load_alerts(run / "alerts" / name))
        singles = sorted({k.rpartition("__")[0] for k in alerts if not k.endswith("__side")}
                         - set(h1.UNIONS))
        ev, _ = h1.evidence_b(args.test, day, columns=sorted(set(h1.META) | {"clean"}))
        for kind, target in targets_of(alerts):
            scores, sides = {}, {}
            for name in singles:
                got = member(alerts, name, kind, target)
                if got is not None and f"{name}__{kind}{target:g}" in alerts:
                    scores[name], sides[name] = got[0].astype(np.float64), got[1]
            for name, names in unions.items():
                got = [member(alerts, n, kind, target) for n in names]
                if any(g is None for g in got):
                    continue
                a, sd = union(got)
                scores[name], sides[name] = a.astype(np.float64), sd
            th = {(name, target, kind): 0.5 for name in scores}
            # h1.UNIONS are formed by evaluate itself from the members present.
            results.append(h1.evaluate(ev, scores, th, {k: v for k, v in sides.items() if v is not None}))
        print(f"  evaluated {day.stem}", flush=True)
        del ev
    args.out.mkdir(parents=True, exist_ok=True)
    h1.write_results(pd.concat(results, ignore_index=True), args.out)


if __name__ == "__main__":
    main()
