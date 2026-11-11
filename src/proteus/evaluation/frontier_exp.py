"""Harm frontier per attack type on the test network.

    python -m proteus.evaluation.frontier_exp \
        --run experiments/outputs/h1/csecicids2018__cicids2017__loo_labels \
        --test cicids2017 --model core_mono_dst_x --fpr 1e-3

For every attack type of the test network: target = the real victim, background =
its real benign traffic that day, flow shapes = the real campaign, model and local
threshold as in the H1 experiment. Reports the frontier (flows/s, flows/h, forward
packets/h), the certified frontier and the rate the real campaign used.
"""

from __future__ import annotations

import argparse
import pickle
from pathlib import Path

import numpy as np
import pandas as pd

from proteus.core.frontier import Scenario, frontier
from proteus.evaluation import h1
from proteus.evidence import baseline as bl

FLOW_COLS = ["t_start", "t_end", "duration_us", "src_ip", "src_port", "dst_ip", "dst_port",
             "proto", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes", "f_bwd_rst_flags",
             "attack", "family", "is_attack"]
ATTACKS = ["bf_ssh", "bf_ftp", "portscan", "dos_hulk", "dos_goldeneye", "dos_slowloris",
           "dos_slowhttptest", "ddos_loic_http", "ddos_hoic", "ddos_loic_udp"]
WINDOW_S = 3600.0


class Baselines:
    """Per-minute tables of every day, computed once; baseline per day on demand."""

    def __init__(self, ds: str) -> None:
        self.days = h1.days(ds)
        self.codes = {e: bl.KeyCodes() for e in bl.COUNTERS}
        self.tables: dict[Path, dict[str, bl.DayTable]] = {}
        self.cols: dict[str, list[str]] = {}
        for day in self.days:
            ev, specs = h1.evidence(ds, day)
            self.cols = bl.baseline_columns(list(specs))
            keys = bl.entity_keys(ev)
            mal = (h1.malicious_mask(ev)
                   if h1.BASELINE["mask"] == "labels" else None)
            minutes = int(np.ceil((ev["t_end"].max() - ev["t_start"].min()).total_seconds() / 60))
            self.tables[day] = {}
            for ent, c in self.cols.items():
                k = pd.Series(self.codes[ent].encode(keys[ent]), index=ev.index)
                self.tables[day][ent] = bl.day_table(ev, c, k, mal, minutes)
            del ev

    def for_day(self, day: Path) -> dict[str, pd.DataFrame]:
        """Baseline per entity key (string) for ``day``, as in the H1 setting."""
        i = self.days.index(day)
        ref = (self.days[:i] if h1.BASELINE["mode"] == "prior"
               else self.days[:i] + self.days[i + 1:])
        out = {}
        for ent, c in self.cols.items():
            b = bl.baseline([self.tables[d][ent] for d in ref], c)
            b.index = self.codes[ent].index[b.index.to_numpy()]
            out[ent] = b
        return out


def local_threshold(ds: str, day: Path, model, cols: list[str], fpr: float,
                    rng: np.random.Generator) -> float:
    ref = []
    for d in h1.days(ds):
        if d == day:
            continue
        ev, _ = h1.evidence_b(ds, d, columns=[*cols, "clean"])
        X = ev.loc[ev["clean"], cols].to_numpy(np.float32)
        X = X[rng.choice(len(X), min(len(X), 300_000), replace=False)]
        ref.append(model.predict_proba(X)[:, 1])
    return float(np.quantile(np.concatenate(ref), 1 - fpr, method="higher"))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", type=Path, required=True)
    ap.add_argument("--test", required=True)
    ap.add_argument("--model", default="core_mono_dst_x")
    ap.add_argument("--fpr", type=float, default=1e-3)
    ap.add_argument("--delta", type=float, default=h1.EXPORT_TIMEOUT_S)
    ap.add_argument("--rmax", type=float, default=100.0, help="highest rate tried (flows/s)")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    rng = np.random.default_rng(args.seed)
    import __main__
    from proteus.baselines.rate_rules import RateRules

    # Pickles written before RateRules moved to its own module reference __main__.
    __main__.RateRules = RateRules
    with open(args.run / "models.pkl", "rb") as fh:
        cols, model = pickle.load(fh)[args.model]
    _, specs = h1.evidence_b(args.test, h1.days(args.test)[0], columns=["clean"])

    baselines = Baselines(args.test)
    rows = []
    for day in h1.days(args.test):
        flows = pd.read_parquet(day, columns=FLOW_COLS)
        present = [a for a in ATTACKS if (flows["is_attack"] & (flows["attack"] == a)).any()]
        if not present:
            continue
        base = baselines.for_day(day)
        thr = local_threshold(args.test, day, model, cols, args.fpr, rng)
        for attack in present:
            A = flows[flows["is_attack"] & (flows["attack"] == attack)]
            target = A["dst_ip"].mode().iloc[0]
            A = A[A["dst_ip"] == target]
            port = int(A["dst_port"].mode().iloc[0])
            proto = int(A["proto"].mode().iloc[0])
            span = max((A["t_end"].max() - A["t_start"].min()).total_seconds(), 1.0)
            bg = flows[(flows["dst_ip"] == target) & (flows["family"] == "benign")]
            start = bg["t_start"].min() + (bg["t_end"].max() - bg["t_start"].min()) / 2
            lo, hi = start - pd.Timedelta(hours=1), start + pd.Timedelta(seconds=WINDOW_S + 3600)
            bg = bg[(bg["t_end"] >= lo) & (bg["t_start"] <= hi)].drop(
                columns=["attack", "family", "is_attack"])
            template = A.drop(columns=["attack", "family", "is_attack"])
            sc = Scenario(bg, template, target, port, proto, start, WINDOW_S,
                          n_sources=int(A["src_ip"].nunique()),
                          keep_ports=attack == "portscan")
            res = {}
            for kind, delta in (("plain", None), ("certified", args.delta)):
                res[kind] = frontier(sc, model, cols, specs, base, thr,
                                     np.random.default_rng(args.seed), r_max=args.rmax,
                                     delta_s=delta)
            pk = float(template["fwd_pkts"].mean())
            row = {"day": day.stem, "attack": attack, "target": f"{target}:{port}",
                   "threshold": thr, "background_flows": len(bg),
                   "real_flows_per_h": len(A) / span * 3600,
                   "fwd_pkts_per_flow": pk}
            for kind, r in res.items():
                row[f"{kind}_flows_per_h"] = r["rate"] * 3600
                row[f"{kind}_status"] = r["bounded"]
            rows.append(row)
            print(row, flush=True)
    out = pd.DataFrame(rows)
    path = args.run / f"frontier_{args.model}_{args.fpr:g}.csv"
    out.to_csv(path, index=False)
    print(out.to_string())


if __name__ == "__main__":
    main()
