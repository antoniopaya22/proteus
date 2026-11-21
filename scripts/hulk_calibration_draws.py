"""Hulk 2017->2018 against proteus_cert_r: does the plain trace pass at 91k because of
the benign sample its per-day calibration (CalibratedMax, fitted in day_models) drew?
(a) replay the rng path of query_attack (day_models on every attack day in order,
rng(0)); (b) fresh samples, rng seeds 1..4. Plain shape, quiet at several rates."""
import numpy as np, pandas as pd
from pathlib import Path
from proteus.core.frontier import nested_attack
from proteus.evaluation import h1
from proteus.evaluation.adaptive import Oracle, day_models
from proteus.evaluation.frontier_exp import ATTACKS, FLOW_COLS, Baselines, scenarios
from proteus.evaluation.poisoning import combined

B = Path("experiments/outputs/h1/cicids2017__csecicids2018__loo_labels__r2")
test = "csecicids2018"
fitted = h1.load_models(B)
fitted = {**h1.load_models(Path(str(B) + "_p2")), **fitted}
names = ["proteus", "proteus_cert_r", "rate_rules_local", "rate_rules_sel"]
_, specs = h1.evidence_b(test, h1.days(test)[0], columns=["clean"])
fresh = h1.detectors(specs, [])
local = ["rate_rules_local"]
dets = {n: fresh[n] if n in local else combined(fitted, n) for n in names}
only = {"proteus_cert_r": dets["proteus_cert_r"]}
baselines = Baselines(test)
RATES = [12311.8, 18000.0, 28000.0, 41000.0, 60139.1, 90960.5]

def probe(label, day, flows, present, models, thr):
    base = baselines.for_day(day)
    for attack, sc, A in scenarios(flows, present):
        if attack != "dos_hulk":
            continue
        full = nested_attack(sc, 200.0, np.random.default_rng(0))
        oracle = Oracle(sc, models, thr, base, specs)
        out = []
        for r_h in RATES:
            a = full[full["u"] < r_h / 3600 / 200.0].drop(columns=["u"])
            df = pd.concat([sc.background.assign(_atk=False), a.assign(_atk=True)], ignore_index=True)
            df["orig_id"] = np.arange(len(df))
            q, _ = oracle.query(df, ["proteus_cert_r"])
            out.append(bool(q["proteus_cert_r"]))
        print(label, "thr", round(float(thr["proteus_cert_r"]), 6), dict(zip(map(int, RATES), out)), flush=True)

rng = np.random.default_rng(0)
for day in h1.days(test):
    flows = pd.read_parquet(day, columns=FLOW_COLS)
    present = [a for a in ATTACKS if (flows["is_attack"] & (flows["attack"] == a)).any()]
    if not present:
        continue
    models, thr = day_models(test, day, dets, local, 1e-3, rng, 0.5)
    if day.stem == "friday-16-02-2018":
        probe("query-path", day, flows, present, models, thr)
        for s in range(1, 5):
            m2, t2 = day_models(test, day, only, local, 1e-3, np.random.default_rng(s), 0.5)
            probe(f"seed{s}", day, flows, present, m2, t2)
        break
