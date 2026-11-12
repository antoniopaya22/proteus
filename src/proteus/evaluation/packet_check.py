"""Check the certificate on packets: free operations applied to real attack packets,
exported to flow records, never lower the victim's evidence beyond the slack.

    python -m proteus.evaluation.packet_check \
        --pcap data/raw/cicids2017_pcap/Friday-WorkingHours.pcap \
        --victim 192.168.10.50 --attackers 172.16.0.1 --port 80 \
        --start 1499457600 --minutes 20

The theorem (``proteus.core.certify``): with an exporter whose active timeout is Δ,
for every decayed counter E with time constant τ and every variant X' of a trace X
obtained by free operations,  E_X'(t + Δ) >= exp(-2Δ/τ) E_X(t)  for all t.

Here X is a window of a real capture, X' are packet-level variants (padding, extra
packets, source-port hopping that splits flows, SYN decoys, and combinations), both
are exported with ``proteus.packets.exporter`` and turned into evidence with
``proteus.evidence.features.build``. For the victim's destination-service and
destination-host counters the inequality is checked at every flow end of X. The
script reports violations (expected: none) and the tightest ratio E'(t+Δ)/E(t).
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from proteus.evidence.features import build
from proteus.packets import exporter, ops, pcap


def counter_at(feats: pd.DataFrame, t_end: np.ndarray, rows: np.ndarray, col: str,
               tau: float, q: np.ndarray) -> np.ndarray:
    """Value of an entity's decayed counter at query times ``q``: the value right after
    its last event at or before q, decayed to q (0 before its first event)."""
    te = t_end[rows]
    v = np.expm1(feats[col].to_numpy(np.float64)[rows])
    j = np.searchsorted(te, q, side="right") - 1
    out = np.zeros(len(q))
    ok = j >= 0
    out[ok] = v[j[ok]] * np.exp(-(q[ok] - te[j[ok]]) / tau)
    return out


def check(base: pd.DataFrame, var: pd.DataFrame, victim: str, port: int, delta: float,
          taus) -> pd.DataFrame:
    fb, specs = build(base, taus)
    fv, _ = build(var, taus)
    tb = base["t_end"].astype("int64").to_numpy() / 1e6
    tv = var["t_end"].astype("int64").to_numpy() / 1e6
    ents = {
        "dsvc": lambda d: ((d["dst_ip"].astype(str) == victim) & (d["dst_port"] == port)
                           ).to_numpy(),
        "dhost": lambda d: (d["dst_ip"].astype(str) == victim).to_numpy(),
    }
    rows = []
    for ent, sel in ents.items():
        rb, rv = np.flatnonzero(sel(base)), np.flatnonzero(sel(var))
        q = tb[rb]
        for s in specs:
            if not s.name.startswith(ent + "__") or s.conservation != "conserved":
                continue
            tau = float(s.name.rsplit("__t", 1)[1])
            e = counter_at(fb, tb, rb, s.name, tau, q)
            e2 = counter_at(fv, tv, rv, s.name, tau, q + delta)
            bound = np.exp(-2 * delta / tau) * e
            pos = e > 1e-9
            rows.append({"counter": s.name, "points": int(pos.sum()),
                         "violations": int((e2[pos] < bound[pos] * (1 - 1e-6) - 1e-9).sum()),
                         "min_ratio": float((e2[pos] / e[pos]).min()) if pos.any() else np.nan,
                         "bound": float(np.exp(-2 * delta / tau))})
    return pd.DataFrame(rows)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", type=Path, required=True)
    ap.add_argument("--packets", type=Path, default=None,
                    help="cache of the filtered packets (parquet); read from it if present")
    ap.add_argument("--victim", required=True)
    ap.add_argument("--attackers", nargs="+", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--start", type=float, required=True, help="window start (epoch s)")
    ap.add_argument("--minutes", type=float, default=20)
    ap.add_argument("--delta", type=float, default=120.0, help="exporter active timeout")
    ap.add_argument("--variants", type=int, default=12)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", type=Path, default=Path("experiments/outputs/packet_check"))
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    if args.packets is not None and args.packets.exists():
        pk = pd.read_parquet(args.packets)
    else:
        pk = pcap.read(args.pcap, {args.victim}, args.start, args.start + args.minutes * 60)
        if args.packets is not None:
            pk.to_parquet(args.packets, index=False)
    print(f"{len(pk):,} packets", flush=True)
    atk = pk["src"].isin(args.attackers).to_numpy()
    base = exporter.export(pk, active_s=args.delta)
    print(f"{len(base):,} flows, {int(atk.sum()):,} attacker packets", flush=True)
    taus = (10.0, 60.0, 600.0, 3600.0)
    rng = np.random.default_rng(args.seed)
    results = []
    for k in range(args.variants):
        p = {"pad": int(rng.choice([0, 40, 400])), "insert": float(rng.choice([0, 0.2, 1.0])),
             "hop": int(rng.choice([0, 3, 20])), "decoys": int(rng.choice([0, 500, 5000]))}
        if k == 0:
            p = {"pad": 0, "insert": 0.0, "hop": 0, "decoys": 0}  # identity: sanity check
        v = pk
        if p["pad"]:
            v = ops.pad(v, v["src"].isin(args.attackers).to_numpy(), p["pad"])
        if p["insert"]:
            v = ops.insert(v, v["src"].isin(args.attackers).to_numpy(), rng, p["insert"])
        if p["hop"]:
            v = ops.hop_ports(v, v["src"].isin(args.attackers).to_numpy(), rng, p["hop"])
        if p["decoys"]:
            v = ops.decoys(v, args.attackers, [(args.victim, args.port), (args.victim, 22)],
                           p["decoys"], rng)
        var = exporter.export(v, active_s=args.delta)
        r = check(base, var, args.victim, args.port, args.delta, taus)
        r["variant"], r["flows"] = k, len(var)
        for key, val in p.items():
            r[key] = val
        results.append(r)
        print(f"variant {k} {p}: {len(var):,} flows, violations {int(r['violations'].sum())}, "
              f"min ratio / bound {float((r['min_ratio'] / r['bound']).min()):.3f}", flush=True)
    res = pd.concat(results, ignore_index=True)
    res.to_csv(args.out / f"packet_check_{args.victim}_{args.port}.csv", index=False)
    print(res.groupby("counter")[["violations", "min_ratio", "bound"]]
          .agg({"violations": "sum", "min_ratio": "min", "bound": "first"}).to_string())


if __name__ == "__main__":
    main()
