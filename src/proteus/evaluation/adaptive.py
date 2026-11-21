"""Damage under an adaptive attacker: Proteus against detectors without guarantees.

    python -m proteus.evaluation.adaptive \
        --run experiments/outputs/h1/csecicids2018__cicids2017__loo_labels__cert \
        --test cicids2017 --models core_cert core_mono_dst_x core_free_dst_b \
        --local rate_rules_local kitnet_local

For every attack scenario of ``frontier_exp`` (real victim, its real background, the
real campaign's flow shapes) the attacker chooses a rate and a combination of free
operations. Its damage is the highest rate (flows/h) at which no attacker flow is
alerted, maximised over

* the plain attack,
* random combinations of free operations (``free_ops.variant``), and
* mimicry: padding and inserted packets until each attack flow reaches the median
  forward packets and bytes per packet of the victim's benign traffic (only adding,
  never removing),
* structured plans (``STRUCTURED``): connection reuse (20 requests per connection),
  bursts (the same mean rate sent in the first tenth of every minute) and both,
* the same plans with minimal requests (``operators.shrink_requests``: as few payload
  bytes as the service allows). It costs the attacker nothing and lowers evidence, so
  no certificate covers it; it is reported apart (``shrink_flows_per_h``), and
* the same plans spread over 100 sources, a costly operation reported apart
  (``spread_flows_per_h``).

Only alerts in minutes where the victim's background alone raises none count against
the attacker (benign false positives are not the attack's doing). Rates are scanned on
a geometric grid. The attacker needs one quiet rate, and detectors without constraints
can alert at a middle rate and be quiet at a higher one, so they are scored at every
rate. A monotone detector that alerted at two consecutive rates is not scored at the
higher ones: the attack is nested, so more flows only add evidence (``--full-scan``
scores it anyway). For monotone detectors free operations only
raise evidence, so the best variant is the plain attack, and for ``--certify``
models the certified frontier (worst case over all free operations) is reported too.
Thresholds are local (FPR on clean benign traffic of the other days); ``--local``
detectors are fitted, per day, on that same traffic.
"""

from __future__ import annotations

import argparse
import copy
from pathlib import Path

import numpy as np
import pandas as pd

from proteus.attacks import operators as op
from proteus.core.certify import slack, worst_case_features
from proteus.core.frontier import _features, nested_attack
from proteus.evaluation import h1
from proteus.evaluation.free_ops import variant
from proteus.evaluation.frontier_exp import ATTACKS, FLOW_COLS, Baselines, scenarios
from proteus.evaluation.poisoning import combined, local_benign

STOP_AFTER = 2  # stop scanning once every detector alerts on every variant this many rates
REUSE_K, SOURCES, PULSE = 20, 100, (60.0, 0.1)
# name -> (requests per connection, sources, bursts, minimal requests); sources > 1 is
# a costly operation
STRUCTURED = {"reuse": (REUSE_K, 1, False, False), "pulse": (1, 1, True, False),
              "reuse+pulse": (REUSE_K, 1, True, False),
              "shrink": (1, 1, False, True), "shrink+reuse": (REUSE_K, 1, False, True),
              "shrink+reuse+pulse": (REUSE_K, 1, True, True),
              "spread": (1, SOURCES, False, False), "spread+reuse": (REUSE_K, SOURCES, False, False),
              "spread+pulse": (1, SOURCES, True, False)}


def structured(df: pd.DataFrame, plan: str, rng: np.random.Generator) -> pd.DataFrame:
    """One structured plan applied to the attack flows of ``df`` (column ``_atk``)."""
    k, n, bursts, shrink = STRUCTURED[plan]
    out = df
    if shrink:
        out = op.shrink_requests(out, out["_atk"].to_numpy())
    if bursts:
        out = op.pulse(out, out["_atk"].to_numpy(), *PULSE)
    if n > 1:
        out = op.spread_sources(out, out["_atk"].to_numpy(), n, rng)
    if k > 1:
        out = op.reuse_connections(out, out["_atk"].to_numpy(), k, h1.EXPORT_TIMEOUT_S)
    return out.sort_values("t_end", kind="stable").reset_index(drop=True)


class Scored:
    """``predict_proba`` view of a detector that only has ``score`` (rate rules,
    KitNET): column 1 is the raw score, which is all thresholds compare."""

    def __init__(self, model) -> None:
        self.model = model
        self.monotonic_cst = getattr(model, "monotonic_cst", None)

    def predict_proba(self, X):
        s = np.asarray(self.model.score(X), dtype=np.float64)
        return np.stack([1 - s, s], axis=1)


def mimic(df: pd.DataFrame, bg: pd.DataFrame) -> pd.DataFrame:
    """Raise every attack flow to the victim's median benign forward packets and bytes
    per packet. Only adds packets and padding (free operations)."""
    out = df.copy()
    atk = out["_atk"].to_numpy()
    med_pkts = float(np.median(bg["fwd_pkts"])) if len(bg) else 0.0
    per_pkt = (bg["fwd_bytes"] / bg["fwd_pkts"].clip(lower=1)) if len(bg) else pd.Series([0.0])
    med_bpp = float(np.median(per_pkt))
    pk = out.loc[atk, "fwd_pkts"].to_numpy(np.int64)
    new_pk = np.maximum(pk, int(np.ceil(med_pkts)))
    by = out.loc[atk, "fwd_bytes"].to_numpy(np.int64)
    new_by = np.maximum(by + (new_pk - pk) * 60, np.ceil(new_pk * med_bpp).astype(np.int64))
    out.loc[atk, "fwd_pkts"] = new_pk
    out.loc[atk, "fwd_bytes"] = new_by
    return out


_BUDGET_CACHE: dict = {}  # candidate flows of every day, per detector (h1.budget_threshold)


def day_models(test: str, day: Path, dets: dict, local: list[str], fpr: float,
               rng: np.random.Generator, budget: float | None = None) -> tuple[dict, dict[str, float]]:
    """Detectors as deployed on one test day: the local ones fitted on clean benign
    traffic of the other days, and every threshold at ``fpr`` on that same traffic,
    or, with ``budget``, at that many alarms per hour (``h1.budget_threshold``)."""
    models, thr = {}, {}
    for n, (cols, m) in dets.items():
        ref = local_benign(test, day, cols, rng)
        if n in local or n in h1.LOCAL or getattr(m, "local", False):
            m = copy.deepcopy(m).fit(ref)
        if not hasattr(m, "predict_proba"):
            m = Scored(m)
        models[n] = (cols, m)
        if budget is None:
            thr[n] = float(np.quantile(m.predict_proba(ref)[:, 1], 1 - fpr, method="higher"))
        else:  # on the scale the oracle compares with (predict_proba), not h1's raw score
            thr[n] = h1.budget_threshold(test, day, cols, getattr(m, "model", m), budget,
                                         lambda X, m=m: m.predict_proba(X)[:, 1],
                                         cache=_BUDGET_CACHE, key=f"{test}:{n}")
    return models, thr


def threshold_label(fpr: float, budget: float | None) -> str:
    """How the output files name the operating point: the FPR, or ``b<budget>``."""
    return f"{fpr:g}" if budget is None else f"b{budget:g}"


class Oracle:
    """What an attacker can observe about one scenario: for a variant of its traffic,
    whether each detector stays quiet. Only alerts on attacker flows in minutes where
    the victim's background alone raises none count (benign false positives are not
    the attack's doing). ``queries`` counts the variants submitted."""

    def __init__(self, sc, models: dict, thr: dict[str, float], base: dict, specs: dict,
                 certify: tuple[str, ...] = (), delta: float = h1.EXPORT_TIMEOUT_S,
                 retime: float = 0.0) -> None:
        self.models, self.thr, self.base, self.specs = models, thr, base, specs
        self.certify = tuple(n for n in certify if n in models)
        self.delta = delta
        self.retime = retime  # flows moved by up to this many seconds: slack (2Δ + d)/τ
        self.cols = list(dict.fromkeys(c for cols, _ in models.values() for c in cols))
        self.queries = 0
        bg_feats = _features(sc.background, self.cols, base) if self.cols else None
        bg_min = sc.background["t_end"].astype("int64").to_numpy() // 60_000_000
        self.noisy, self.noisy_cert = {}, {}
        for n, (cols, m) in models.items():
            if hasattr(m, "flow_alerts"):  # scores raw flow records, not evidence features
                self.noisy[n] = np.unique(bg_min[m.flow_alerts(sc.background)])
                continue
            X = bg_feats[cols].to_numpy(np.float64)
            self.noisy[n] = np.unique(bg_min[m.predict_proba(X)[:, 1] >= thr[n]])
            if n in self.certify:
                self.noisy_cert[n] = np.unique(bg_min[self._worst(n, X) >= thr[n]])

    def _worst(self, n: str, X: np.ndarray) -> np.ndarray:
        cols, m = self.models[n]
        W = worst_case_features(X, np.asarray(m.monotonic_cst),
                                slack(cols, self.specs, self.delta, self.retime))
        return m.predict_proba(W)[:, 1]

    def query(self, v: pd.DataFrame, names: list[str] | None = None,
              certified: bool = False) -> tuple[dict[str, bool], dict[str, bool]]:
        """Quiet or not, per detector, on the traffic ``v``; with ``certified``, also
        whether the certified alerts of the ``certify`` detectors stay quiet."""
        names = list(self.models) if names is None else names
        cols = list(dict.fromkeys(c for n in names for c in self.models[n][0]))
        feats = _features(v, cols, self.base) if cols else None
        minute = v["t_end"].astype("int64").to_numpy() // 60_000_000
        self.queries += 1
        quiet, cert = {}, {}
        for n in names:
            mcols, m = self.models[n]
            if hasattr(m, "flow_alerts"):
                quiet[n] = not (m.flow_alerts(v) & ~np.isin(minute, self.noisy[n])).any()
                continue
            X = feats[mcols].to_numpy(np.float64)
            hit = m.predict_proba(X)[:, 1] >= self.thr[n]
            quiet[n] = not (hit & ~np.isin(minute, self.noisy[n])).any()
            if certified and n in self.certify:
                hit = self._worst(n, X) >= self.thr[n]
                cert[n] = not (hit & ~np.isin(minute, self.noisy_cert[n])).any()
        return quiet, cert

    def margin(self, v: pd.DataFrame, names: list[str]) -> float:
        """How far the traffic ``v`` is from an alert: the highest score over its
        threshold among the detectors ``names``, in the minutes that count for
        ``query`` (negative exactly when ``query`` finds every one of them quiet). This
        is what an attacker that knows the detectors and their thresholds can compute."""
        cols = list(dict.fromkeys(c for n in names for c in self.models[n][0]))
        feats = _features(v, cols, self.base) if cols else None
        minute = v["t_end"].astype("int64").to_numpy() // 60_000_000
        self.queries += 1
        worst = -np.inf
        for n in names:
            mcols, m = self.models[n]
            keep = ~np.isin(minute, self.noisy[n])
            if hasattr(m, "flow_alerts"):  # no score to read: alerted or not
                worst = max(worst, 0.0 if (m.flow_alerts(v) & keep).any() else -1.0)
            elif keep.any():
                s = m.predict_proba(feats[mcols].to_numpy(np.float64))[:, 1]
                worst = max(worst, float(s[keep].max() - self.thr[n]))
        return worst


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", type=Path, required=True)
    ap.add_argument("--test", required=True)
    ap.add_argument("--models", nargs="*", default=["core_cert", "core_mono_dst_x"],
                    help="fitted models of the run (or a+b / a|b combinations)")
    ap.add_argument("--extra-runs", type=Path, nargs="*", default=[],
                    help="more runs of the same train/test pair to take models from")
    ap.add_argument("--local", nargs="*", default=["rate_rules_local", "kitnet_local"],
                    help="unsupervised detectors fitted per day on local benign traffic")
    ap.add_argument("--certify", nargs="*", default=["core_cert"])
    ap.add_argument("--fpr", type=float, default=1e-3)
    ap.add_argument("--alarm-budget", type=float, default=None,
                    help="thresholds at this many alarms per hour instead of --fpr")
    ap.add_argument("--variants", type=int, default=4, help="random free-operation variants")
    ap.add_argument("--grid", type=int, default=20)
    ap.add_argument("--rmin", type=float, default=1e-3)
    ap.add_argument("--rmax", type=float, default=200.0)
    ap.add_argument("--attacks", nargs="*", default=None)
    ap.add_argument("--no-structured", action="store_true",
                    help="skip the structured plans (reuse, bursts, spreading)")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--tag", default="", help="suffix of the output files")
    ap.add_argument("--days", nargs="*", default=None, help="test days (file stems)")
    ap.add_argument("--full-scan", action="store_true",
                    help="score every detector at every rate (no per-detector stop)")
    ap.add_argument("--resume", action="store_true",
                    help="keep the scenarios already in the output files and skip them")
    ap.add_argument("--retime-s", type=float, default=0.0,
                    help="certified frontier also against re-timing flows by up to this "
                         "many seconds (bursts): slack (2Δ + d)/τ")
    args = ap.parse_args()
    rng = np.random.default_rng(args.seed)
    fitted = h1.load_models(args.run)
    for extra in args.extra_runs:  # same train/test pair, other detectors
        fitted = {**h1.load_models(extra), **fitted}
    _, specs = h1.evidence_b(args.test, h1.days(args.test)[0], columns=["clean"])
    dets = {n: combined(fitted, n) for n in args.models}
    fresh = h1.detectors(specs, [])
    dets.update({n: fresh[n] for n in args.local})
    rates = np.geomspace(args.rmin, args.rmax, args.grid)
    delta = h1.EXPORT_TIMEOUT_S
    baselines = Baselines(args.test)
    label = threshold_label(args.fpr, args.alarm_budget)
    tag = f"_{args.tag}" if args.tag else ""
    out_rows = args.run / f"adaptive_{label}{tag}.csv"
    out_ladder = args.run / f"adaptive_ladder_{label}{tag}.csv"
    rows, ladder, done = [], [], set()
    if args.resume and out_rows.exists() and out_ladder.exists():
        rows = pd.read_csv(out_rows).to_dict("records")
        ladder = pd.read_csv(out_ladder).to_dict("records")
        done = {(r["day"], r["attack"]) for r in rows}
        print(f"resuming: {len(done)} scenarios already done", flush=True)

    def save() -> None:
        """Results so far, written after every scenario (a long run can be killed)."""
        pd.DataFrame(rows).to_csv(out_rows, index=False)
        pd.DataFrame(ladder).to_csv(out_ladder, index=False)

    for day in h1.days(args.test):
        if args.days and day.stem not in args.days:
            continue
        flows = pd.read_parquet(day, columns=FLOW_COLS)
        want = args.attacks or ATTACKS
        present = [a for a in want if (flows["is_attack"] & (flows["attack"] == a)).any()
                   and (day.stem, a) not in done]
        if not present:
            continue
        base = baselines.for_day(day)
        models, thr = day_models(args.test, day, dets, args.local, args.fpr, rng, args.alarm_budget)
        for attack, sc, A in scenarios(flows, present):
            span = max((A["t_end"].max() - A["t_start"].min()).total_seconds(), 1.0)
            full = nested_attack(sc, args.rmax, np.random.default_rng(args.seed))
            plans = [("plain", None), ("mimic", None)] + [
                (f"random{k}", k) for k in range(args.variants)] + [
                (name, None) for name in STRUCTURED if not args.no_structured]
            oracle = Oracle(sc, models, thr, base, specs, tuple(args.certify), delta,
                            args.retime_s)
            noisy = oracle.noisy
            best = {n: {"rate": 0.0, "plan": None} for n in models}
            spread = {n: {"rate": 0.0, "plan": None} for n in models}
            shrunk = {n: {"rate": 0.0, "plan": None} for n in models}
            plain = {n: 0.0 for n in models}
            cert = {n: 0.0 for n in args.certify if n in models}
            streak = {n: 0 for n in models}  # consecutive rates where every variant alerts
            mono = {n: getattr(m, "monotonic_cst", None) is not None
                    for n, (_, m) in models.items()}
            for r in rates:
                if all(v >= STOP_AFTER for v in streak.values()):
                    break  # higher rates are only more evidence: stop paying for them
                quiet_any = {n: False for n in models}
                # A monotone detector that alerted at the last STOP_AFTER rates alerts at
                # every higher one (the attack is nested: more flows only add evidence),
                # so it is no longer scored. Detectors without that property are.
                done = set() if args.full_scan else {
                    n for n in models if mono[n] and streak[n] >= STOP_AFTER}
                active = [n for n in models if n not in done]
                a = full[full["u"] < r / args.rmax].drop(columns=["u"])
                if a.empty:
                    continue
                df = pd.concat([sc.background.assign(_atk=False), a.assign(_atk=True)],
                               ignore_index=True)
                df["orig_id"] = np.arange(len(df))
                for plan, k in plans:
                    if plan == "plain":
                        v = df
                    elif plan == "mimic":
                        v = mimic(df, sc.background)
                    elif plan in STRUCTURED:
                        v = structured(df, plan, np.random.default_rng(2000))
                    else:
                        v, _ = variant(df, np.random.default_rng(1000 + k), sc.target_ip,
                                       sc.target_port, retime=bool(k % 2))
                    quiet_of, cert_of = oracle.query(v, active, certified=plan == "plain")
                    for n in done:
                        ladder.append({"day": day.stem, "attack": attack, "detector": n,
                                       "plan": plan, "flows_per_h": float(r) * 3600,
                                       "detected": True, "assumed": True})
                    for n in active:
                        quiet = quiet_of[n]
                        quiet_any[n] = quiet_any[n] or quiet
                        ladder.append({"day": day.stem, "attack": attack, "detector": n,
                                       "plan": plan, "flows_per_h": float(r) * 3600,
                                       "detected": not quiet, "assumed": False})
                        costly, small = plan.startswith("spread"), plan.startswith("shrink")
                        if quiet and not small and r > spread[n]["rate"]:
                            spread[n] = {"rate": float(r), "plan": plan}
                        if quiet and not costly and r > shrunk[n]["rate"]:
                            shrunk[n] = {"rate": float(r), "plan": plan}
                        if quiet and not costly and not small and r > best[n]["rate"]:
                            best[n] = {"rate": float(r), "plan": plan}
                        if quiet and plan == "plain":
                            plain[n] = max(plain[n], float(r))
                        if cert_of.get(n):
                            cert[n] = max(cert[n], float(r))
                            quiet_any[n] = True  # keep scanning for the certified frontier
                for n in models:
                    streak[n] = 0 if quiet_any[n] else streak[n] + 1
            for n in models:
                rows.append({"day": day.stem, "attack": attack, "detector": n,
                             "threshold": thr[n], "noisy_minutes": len(noisy[n]), "real_flows_per_h": len(A) / span * 3600,
                             "plain_flows_per_h": plain[n] * 3600,
                             "adaptive_flows_per_h": best[n]["rate"] * 3600,
                             "best_plan": best[n]["plan"],
                             "spread_flows_per_h": spread[n]["rate"] * 3600,
                             "spread_plan": spread[n]["plan"],
                             "shrink_flows_per_h": shrunk[n]["rate"] * 3600,
                             "shrink_plan": shrunk[n]["plan"],
                             "certified_flows_per_h": cert[n] * 3600 if n in cert else np.nan,
                             "rmax_flows_per_h": args.rmax * 3600})
                print(rows[-1], flush=True)
            save()
    save()  # the ladder (METIS-style dose ladder): detection at every rate and plan
    out = pd.DataFrame(rows)
    print(out.pivot_table(index=["day", "attack"], columns="detector",
                          values="adaptive_flows_per_h").round(0).to_string())


if __name__ == "__main__":
    main()
