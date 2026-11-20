"""Data for the released code of CertTA (Yan et al., USENIX Security 2025) on real
attack packets and their free-operation variants.

    python -m proteus.evaluation.certta_export \
        --packets experiments/outputs/packet_check/loic_packets.parquet \
        --victim 192.168.10.50 --attackers 172.16.0.1 --port 80 \
        --out experiments/outputs/certta/datasets

From the packet table of ``packet_check`` (one capture window around an attack), the
flows of ``packets.sequences`` (the flows of ``packets.exporter``) become a CertTA
dataset ``<name>/``: ``json/{train,test,valid}.json`` and ``json/statistics.json`` in
CertTA's format (``timestamp`` relative to the first packet in seconds,
``direction_length`` signed by direction, the first ``--max-len`` packets as in
CertTA's datasets) and ``labels.json``. A flow is an attack flow (label 1) when an
attacker initiated it. The same number of flows of each class with at least
``--min-packets`` packets (``--per-class``, or fewer if a class has fewer) are drawn
and split 0.8/0.1/0.1 within each class.

Then the whole table goes through the ``--variants`` combinations of free operations
of ``packet_check`` (same seed, same draws; variant 0 is the identity) and is turned
into flows again. For every attack flow of the test split, the flows of a variant
that hold any of its packets are its pieces (several when port hopping splits it);
flows holding only packets the attacker added after its packets are spawned by it;
SYN decoys are flows of their own. ``<name>_vNN/json/test.json`` holds, labelled 1,
the pieces and spawned flows of every test attack flow and up to ``--max-decoys``
decoy flows. ``perturbations.json`` records, for every test attack flow, variant and
piece, the edit from the flow to the piece in the terms of CertTA's robustness region:

* ``n_ins``: packets in the piece's first ``--max-len`` packets that are not packets
  of the flow (added by the attacker, or of another flow);
* ``n_del``: packets among the flow's first ``--max-len`` that the piece does not
  hold at all (moved to another piece);
* ``n_trunc``: packets of the flow the piece holds but beyond its first
  ``--max-len`` packets, pushed out by insertions (CertTA truncates adversarial flows
  the same way and does not count them as deletions);
* ``adds``: for every packet of the flow in the piece's window whose size and
  inter-arrival time did not decrease and one of them grew, the bytes added and the
  added inter-arrival time in ms (CertTA's padding and delay);
* ``n_neg``: packets of the flow in the window whose size or inter-arrival time
  decreased (an extra packet just before it shortens its gap), which only a
  substitution covers in CertTA's region;
* ``pad_bytes`` (L1 change of the sizes of the flow's packets) and ``ins_bytes``.

``scripts/external/certta_region.py`` reads this file with CertTA's results.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

from proteus.evaluation.packet_check import apply, combination
from proteus.packets.sequences import sequences

LABELS = {"Benign": 0, "LOIC-HTTP": 1}


def record(ts: np.ndarray, length: np.ndarray, label: int, name: str, max_len: int) -> dict:
    """A flow in CertTA's format, cut to its first ``max_len`` packets."""
    ts, length = ts[:max_len], length[:max_len]
    if len(length) and length[0] < 0:
        length = -length
    return {"timestamp": [round(float(t), 6) for t in ts],
            "direction_length": [int(x) for x in length], "packet_num": len(ts),
            "label": int(label), "source_file": f"./{name}"}


def edit(orig_ts: np.ndarray, orig_len: np.ndarray, orig_pid: np.ndarray, ts: np.ndarray,
         length: np.ndarray, pid: np.ndarray, max_len: int) -> dict:
    """Edit from a flow to a piece of a variant, both as time-ordered packets with
    their packet ids (-1 for packets that are not original packets of the flow)."""
    w_pid = orig_pid[:max_len]
    pos = {int(p): j for j, p in enumerate(w_pid)}
    in_piece = np.isin(w_pid, pid)
    win = slice(0, max_len)
    p_pid, p_ts, p_len = pid[win], ts[win], np.abs(length[win])
    mine = np.array([int(p) in pos for p in p_pid], dtype=bool)
    o_iat = np.diff(orig_ts, prepend=orig_ts[0]) * 1e3
    p_iat = np.diff(p_ts, prepend=p_ts[0]) * 1e3 if len(p_ts) else p_ts
    adds, n_neg, pad = [], 0, 0
    for i in np.flatnonzero(mine):
        j = pos[int(p_pid[i])]
        dl = int(p_len[i] - abs(orig_len[j]))
        dt = float(p_iat[i] - o_iat[j])
        dt = 0.0 if abs(dt) < 1e-3 else dt
        pad += abs(dl)
        if dl < 0 or dt < 0:
            n_neg += 1
        elif dl > 0 or dt > 0:
            adds.append([dl, round(dt, 3)])
    return {"n_ins": int((~mine).sum()), "n_del": int((~in_piece).sum()),
            "n_trunc": int(in_piece.sum() - mine.sum()), "n_neg": n_neg, "adds": adds,
            "pad_bytes": pad, "ins_bytes": int(p_len[~mine].sum()),
            "packets": len(ts), "first": bool(len(p_pid) and p_pid[0] == w_pid[0])}


def write_dataset(path: Path, splits: dict[str, list[dict]]) -> None:
    (path / "json").mkdir(parents=True, exist_ok=True)
    stats: dict = {"train:test:valid": "0.8:0.1:0.1", "label_num": len(LABELS)}
    for split, recs in splits.items():
        with open(path / "json" / f"{split}.json", "w") as fh:
            json.dump(recs, fh)
        labels = pd.Series([r["label"] for r in recs], dtype=np.int64)
        stats[f"{split}.json"] = {"total": len(recs),
                                  **{str(k): int((labels == k).sum()) for k in LABELS.values()}}
    with open(path / "json" / "statistics.json", "w") as fh:
        json.dump(stats, fh, indent=1)
    with open(path / "labels.json", "w") as fh:
        json.dump(LABELS, fh, indent=1)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--packets", type=Path, required=True, help="packet table (parquet)")
    ap.add_argument("--victim", required=True)
    ap.add_argument("--attackers", nargs="+", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--name", default="LOIC", help="CertTA dataset name")
    ap.add_argument("--per-class", type=int, default=3000)
    ap.add_argument("--min-packets", type=int, default=3)
    ap.add_argument("--max-len", type=int, default=100, help="CertTA's max_flow_length")
    ap.add_argument("--variants", type=int, default=12)
    ap.add_argument("--max-decoys", type=int, default=300)
    ap.add_argument("--delta", type=float, default=120.0, help="exporter active timeout")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", type=Path, default=Path("experiments/outputs/certta/datasets"))
    args = ap.parse_args()

    pk = pd.read_parquet(args.packets).reset_index(drop=True)
    pk["pid"] = np.arange(len(pk), dtype=np.int64)
    base = sequences(pk, active_s=args.delta)
    base_pid = [pk["pid"].to_numpy()[r] for r in base["rows"]]
    flow_of = np.empty(len(pk), dtype=np.int64)
    for i, p in enumerate(base_pid):
        flow_of[p] = i
    label = base["src"].isin(args.attackers).to_numpy().astype(int)
    print(f"{len(pk):,} packets, {len(base):,} flows, {int(label.sum()):,} attack flows",
          flush=True)

    rng = np.random.default_rng(args.seed)
    eligible = (base["packets"] >= args.min_packets).to_numpy()
    splits: dict[str, list[dict]] = {"train": [], "test": [], "valid": []}
    test_attack: list[int] = []
    size = min([args.per_class] + [int((eligible & (label == y)).sum()) for y in LABELS.values()])
    for name, y in LABELS.items():
        idx = np.flatnonzero(eligible & (label == y))
        idx = np.sort(rng.choice(idx, size, replace=False))
        rng.shuffle(idx)
        n_tr, n_te = int(0.8 * len(idx)), int(0.1 * len(idx))
        for split, part in (("train", idx[:n_tr]), ("test", idx[n_tr:n_tr + n_te]),
                            ("valid", idx[n_tr + n_te:])):
            for i in part:
                splits[split].append(record(base["ts"][i], base["length"][i], y,
                                            f"{args.name}/{name}/flow_{i:07d}", args.max_len))
            if split == "test" and y == 1:
                test_attack = sorted(int(i) for i in part)
        print(f"{name}: {len(idx)} flows", flush=True)
    write_dataset(args.out / args.name, splits)
    names = {i: f"./{args.name}/LOIC-HTTP/flow_{i:07d}" for i in test_attack}
    pk_cols = ["ts", "src", "dst", "sport", "dport", "proto", "size", "flags", "pid"]

    rng = np.random.default_rng(args.seed)
    perturb: list[dict] = []
    params: list[dict] = []
    for k in range(args.variants):
        p = combination(rng, k)
        v = apply(pk[pk_cols], p, rng, args.attackers, args.victim, args.port)
        v = v.reset_index(drop=True)
        decoy = v["pid"].isna().to_numpy()
        vpid = v["pid"].fillna(-1).to_numpy(np.int64)
        order = np.lexsort((v["ts"].to_numpy(), vpid))
        first = np.empty(len(v), dtype=bool)
        first[order] = ~np.r_[False, vpid[order][1:] == vpid[order][:-1]]
        first |= decoy
        parent = np.where(decoy, -1, flow_of[np.maximum(vpid, 0)])
        own = np.where(first, vpid, -1)
        seq = sequences(v, active_s=args.delta)
        test_set = set(test_attack)
        by_flow: dict[int, list[int]] = {i: [] for i in test_attack}
        spawned: dict[int, list[int]] = {i: [] for i in test_attack}
        decoy_flows = []
        for f, rows in enumerate(seq["rows"]):
            par = parent[rows]
            owned = set(par[first[rows] & ~decoy[rows]].tolist())
            hit = owned & test_set
            for t in hit:
                by_flow[t].append(f)
            if not owned:
                if decoy[rows].all():
                    decoy_flows.append(f)
                for t in set(par[~decoy[rows]].tolist()) & test_set:
                    spawned[t].append(f)
        recs = []
        for t in test_attack:
            o_rows = base["rows"][t]
            entry = {"flow": names[t], "variant": k, "packets": int(base["packets"][t]),
                     "pieces": [], "spawned": []}
            for j, f in enumerate(sorted(by_flow[t])):
                rows = seq["rows"][f]
                pid = np.where(parent[rows] == t, own[rows], -1)
                e = edit(base["ts"][t], base["length"][t], pk["pid"].to_numpy()[o_rows],
                         seq["ts"][f], seq["length"][f], pid, args.max_len)
                e["source_file"] = f"{names[t]}/v{k:02d}/piece_{j}"
                entry["pieces"].append(e)
                recs.append(record(seq["ts"][f], seq["length"][f], 1,
                                   e["source_file"][2:], args.max_len))
            for j, f in enumerate(sorted(spawned[t])):
                name = f"{names[t]}/v{k:02d}/spawned_{j}"
                entry["spawned"].append({"source_file": name, "packets": int(seq["packets"][f])})
                recs.append(record(seq["ts"][f], seq["length"][f], 1, name[2:], args.max_len))
            main = [e for e in entry["pieces"] if e["first"]]
            m = main[0] if main else None
            entry.update({"n_ins": m["n_ins"] if m else None,
                          "bytes_added": m["pad_bytes"] if m else None,
                          "removed": any(e["n_del"] > 0 for e in entry["pieces"]),
                          "n_pieces": len(entry["pieces"])})
            perturb.append(entry)
        sub = np.random.default_rng(args.seed + 1 + k)
        pick = sub.choice(len(decoy_flows), min(len(decoy_flows), args.max_decoys),
                          replace=False) if decoy_flows else []
        for j in sorted(int(x) for x in pick):
            f = decoy_flows[j]
            recs.append(record(seq["ts"][f], seq["length"][f], 1,
                               f"{args.name}_v{k:02d}/decoy/flow_{f:07d}", args.max_len))
        write_dataset(args.out / f"{args.name}_v{k:02d}", {"test": recs})
        n_pieces = sum(len(by_flow[t]) for t in test_attack)
        n_spawn = sum(len(spawned[t]) for t in test_attack)
        params.append({"variant": k, **p, "test_attack_flows": len(test_attack),
                       "pieces": n_pieces, "spawned": n_spawn, "decoy_flows": len(decoy_flows),
                       "decoys_in_test": len(pick)})
        print(f"variant {k} {p}: {len(seq):,} flows, {n_pieces} pieces, {n_spawn} spawned, "
              f"{len(decoy_flows)} decoy flows", flush=True)
    with open(args.out / "perturbations.json", "w") as fh:
        json.dump({"name": args.name, "max_len": args.max_len, "variants": params,
                   "flows": perturb}, fh)


if __name__ == "__main__":
    main()
