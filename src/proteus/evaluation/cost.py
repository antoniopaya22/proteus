"""Cost of Proteus: evidence throughput, scoring throughput and state per entity.

    PROTEUS_EVIDENCE=v3 python -m proteus.evaluation.cost \
        --run experiments/outputs/h1/csecicids2018__cicids2017__loo_labels__v3 \
        --test cicids2017 --day wednesday --models proteus proteus_cert

Measures on one capture day: flows per second to compute the evidence (batch
implementation, single process), flows per second to score each detector (and its
certified worst case, one extra evaluation), and the state a streaming deployment keeps:
for every entity, one decayed value per counter and time scale, plus one last-seen time
per (entity, item) for distinct counts.
"""

from __future__ import annotations

import argparse
import copy
import time
from pathlib import Path

import numpy as np
import pandas as pd

from proteus.core.certify import slack, worst_case_features
from proteus.evaluation import h1
from proteus.evidence.features import build


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", type=Path, required=True)
    ap.add_argument("--test", required=True)
    ap.add_argument("--day", required=True)
    ap.add_argument("--models", nargs="+", default=["proteus", "proteus_cert"])
    ap.add_argument("--rows", type=int, default=2_000_000)
    args = ap.parse_args()
    day = next(d for d in h1.days(args.test) if d.stem == args.day)
    df = pd.read_parquet(day, columns=h1.META + ["fwd_pkts", "fwd_bytes", "bwd_pkts",
                                                 "bwd_bytes", "f_bwd_rst_flags",
                                                 "duration_us"]).head(args.rows)
    t0 = time.perf_counter()
    feats, specs = build(df)
    t_ev = time.perf_counter() - t0
    rows = [{"stage": "evidence", "flows": len(df), "seconds": t_ev,
             "flows_per_s": len(df) / t_ev, "features": feats.shape[1]}]
    # State of a streaming deployment.
    ents = {"dsvc": ["dst_ip", "dst_port", "proto"], "dhost": ["dst_ip"], "shost": ["src_ip"],
            "spair": ["src_ip", "dst_ip", "dst_port", "proto"]}
    for e, key in ents.items():
        n_ent = len(df.drop_duplicates(key))
        n_cnt = sum(1 for s in specs if s.name.startswith(e + "__"))
        rows.append({"stage": f"state_{e}", "entities": n_ent, "values_per_entity": n_cnt,
                     "bytes": n_ent * n_cnt * 8})
    models = h1.load_models(args.run)
    need = sorted({c for n in args.models for c in models[n][0]})
    ev, spec_map = h1.evidence_b(args.test, day, columns=need)
    ev = ev.head(args.rows)
    rng = np.random.default_rng(0)
    for name in args.models:
        cols, m = models[name]
        X = ev[cols].to_numpy(np.float32)
        if getattr(m, "local", False):
            m = copy.deepcopy(m).fit(X[rng.choice(len(X), min(len(X), 200_000), replace=False)])
        t0 = time.perf_counter()
        h1.score(m, X)
        t_s = time.perf_counter() - t0
        row = {"stage": f"score_{name}", "flows": len(X), "seconds": t_s,
               "flows_per_s": len(X) / t_s, "features": len(cols)}
        if getattr(m, "monotonic_cst", None) is not None:
            t0 = time.perf_counter()
            W = worst_case_features(X, np.asarray(m.monotonic_cst),
                                    slack(cols, spec_map, h1.EXPORT_TIMEOUT_S))
            h1.score(m, W)
            row["certify_seconds"] = time.perf_counter() - t0
        rows.append(row)
    out = pd.DataFrame(rows)
    out.to_csv(args.run / f"cost_{args.test}_{args.day}.csv", index=False)
    print(out.to_string())


if __name__ == "__main__":
    main()
