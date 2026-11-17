"""Kitsune as published, on the packets of a capture day, against the free operations.

    python -m proteus.evaluation.kitsune_pcap \
        --pcap data/raw/cicids2017_pcap/Friday-WorkingHours.pcap \
        --flows data/processed/cicids2017/friday.parquet --attacker 172.16.0.1

The comparison detectors of the cross-network evaluation are fed Proteus's counters.
Here Kitsune runs on what it was designed for: every packet of the capture, through its
own feature extractor (``baselines.kitsune.AfterImage``) and KitNET, trained online on
the first ``--train-packets`` packets of the day (benign in CIC-IDS-2017: the first
attack starts later), as in the original. Then:

1. Calibration: the threshold is set, as for every detector of the paper, to an alarm
   budget (``--alarm-budget`` alarms per hour, an alarm being a destination host in one
   minute) on the benign packets of the next ``--calib-minutes`` minutes.
2. Detection: every campaign of the day (attack flows of the day file, episodes more
   than ten minutes apart) is detected when at least five of its packets, and 1% of
   them, are alerted; false alarms are counted on the packets of host pairs that no
   attack involves.
3. Free operations: the campaigns of ``--attacker`` are replayed, from ``--warmup``
   minutes before them, with the packet-level operations of the certificate check
   (``packets.ops``: padding, inserted packets, source-port hopping that splits flows,
   SYN decoys) and with mimicry (attacker packets padded up to the median size of the
   victim's benign packets), and scored by the same trained detector.

Labels: a packet belongs to a campaign when its two hosts are the two ends of one of the
campaign's attack flows and its time is within the campaign; the offset between capture
times and the day file is found as the whole number of hours that matches most packets.
"""

from __future__ import annotations

import argparse
import socket
import struct
from pathlib import Path

import numpy as np
import pandas as pd

from proteus.baselines.kitnet import KitNET
from proteus.baselines.kitsune import N_FEATURES, AfterImage
from proteus.evaluation import h1
from proteus.packets import ops, pcap

GAP_S = 600.0  # campaigns: attack flows of one type more than ten minutes apart


def ip_int(ip: str) -> int:
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def campaigns(flows: pd.DataFrame) -> pd.DataFrame:
    """Campaigns of the day file: per attack type, episodes more than GAP_S apart,
    with their time span (epoch seconds of the file) and the host pairs of their flows."""
    a = flows[flows["is_attack"]].sort_values("t_start")
    rows = []
    for attack, g in a.groupby("attack"):
        t0 = g["t_start"].astype("int64").to_numpy() / 1e6
        t1 = g["t_end"].astype("int64").to_numpy() / 1e6
        cut = np.r_[0, np.flatnonzero(t0[1:] - np.maximum.accumulate(t1)[:-1] > GAP_S) + 1, len(g)]
        for k in range(len(cut) - 1):
            part = g.iloc[cut[k]:cut[k + 1]]
            pairs = {tuple(sorted((ip_int(s), ip_int(d))))
                     for s, d in zip(part["src_ip"].astype(str), part["dst_ip"].astype(str), strict=True)}
            rows.append({"attack": attack, "episode": k, "t0": t0[cut[k]:cut[k + 1]].min(),
                         "t1": t1[cut[k]:cut[k + 1]].max(), "pairs": pairs,
                         "flows": len(part)})
    return pd.DataFrame(rows)


def label(ts: np.ndarray, src: np.ndarray, dst: np.ndarray, camps: pd.DataFrame,
          shift: float) -> np.ndarray:
    """Campaign index of every packet (-1: none), with capture time + shift = file time."""
    out = np.full(len(ts), -1, dtype=np.int32)
    lo, hi = np.minimum(src, dst).astype(np.uint64), np.maximum(src, dst).astype(np.uint64)
    pair = (lo << np.uint64(32)) | hi
    t = ts + shift
    for i, c in camps.iterrows():
        keys = np.array([(np.uint64(a) << np.uint64(32)) | np.uint64(b) for a, b in c["pairs"]],
                        dtype=np.uint64)
        m = np.isin(pair, keys) & (t >= c["t0"] - 1) & (t <= c["t1"] + 1)
        out[m & (out < 0)] = i
    return out


def best_shift(ts: np.ndarray, src: np.ndarray, dst: np.ndarray, camps: pd.DataFrame) -> float:
    """Whole hours to add to capture times so that most attack-pair packets fall inside
    their campaigns (capture files and flow files of CIC-IDS-2017 use different zones)."""
    shifts = np.arange(-14, 15) * 3600.0
    hits = [int((label(ts, src, dst, camps, s) >= 0).sum()) for s in shifts]
    return float(shifts[int(np.argmax(hits))])


def stream(path: Path, train_packets: int, chunk: int = 50_000, seed: int = 0):
    """One pass over the capture: AfterImage features of every IPv4 TCP/UDP packet;
    KitNET fitted on the first ``train_packets``; returns the detector, the feature
    extractor's lambdas and, per packet, time, hosts and score (training packets: NaN)."""
    import dpkt

    fe = AfterImage()
    ts, src, dst, score = [], [], [], []
    buf, model = [], None

    def flush() -> None:
        nonlocal buf
        if buf:
            score.extend(model.score(np.asarray(buf, dtype=np.float32)).tolist())
            buf = []

    train = np.empty((train_packets, N_FEATURES), dtype=np.float32)
    n = 0
    with open(path, "rb") as fh:
        ng = fh.read(4) == b"\x0a\x0d\x0d\x0a"
        fh.seek(0)
        reader = dpkt.pcapng.Reader(fh) if ng else dpkt.pcap.Reader(fh)
        for t, raw in reader:
            try:
                ip = dpkt.ethernet.Ethernet(raw).data
            except (dpkt.UnpackError, ValueError):
                continue
            if not isinstance(ip, dpkt.ip.IP) or not isinstance(ip.data, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                continue
            s, d = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)
            x = fe.update(float(t), s, d, ip.data.sport, ip.data.dport,
                          float(max(ip.len - ip.hl * 4, 0)))
            ts.append(float(t))
            src.append(struct.unpack("!I", ip.src)[0])
            dst.append(struct.unpack("!I", ip.dst)[0])
            if n < train_packets:
                train[n] = x
                score.append(np.nan)
                if n == train_packets - 1:
                    model = KitNET(seed=seed).fit(train)
                    print(f"  KitNET fitted on {train_packets:,} packets", flush=True)
            else:
                buf.append(x)
                if len(buf) >= chunk:
                    flush()
            n += 1
            if n % 1_000_000 == 0:
                print(f"  {n:,} packets", flush=True)
    flush()
    return model, np.asarray(ts), np.asarray(src, dtype=np.uint32), np.asarray(dst, dtype=np.uint32), \
        np.asarray(score)


def budget_threshold(scores: np.ndarray, dst: np.ndarray, ts: np.ndarray, budget: float) -> float:
    """Lowest threshold with at most ``budget`` alarms per hour, an alarm being a
    destination host in one minute with a packet at or above it."""
    hours = max((ts.max() - ts.min()) / 3600.0, 1e-9)
    minute = (ts // 60).astype(np.int64)
    return h1.entity_threshold([(scores, dst.astype(np.uint64), minute.astype(np.uint64))], hours, budget)


def detection(scores, camp, thr, ncamp: int) -> list[dict]:
    rows = []
    for i in range(ncamp):
        m = camp == i
        n, k = int(m.sum()), int((scores[m] >= thr).sum())
        rows.append({"campaign": i, "packets": n, "alerted": k,
                     "detected": n > 0 and k >= 5 and k >= 0.01 * n})
    return rows


def alarms(scores, dst, ts, thr, benign) -> dict:
    """False alarms on benign packets: destination hosts per minute, and destination
    hosts per ten-minute window (the alerted entities), both per hour."""
    s, d, t = scores[benign], dst[benign], ts[benign]
    hours = max((t.max() - t.min()) / 3600.0, 1e-9) if len(t) else 1.0
    hit = s >= thr
    per_min = len({(a, b) for a, b in zip(d[hit], (t[hit] // 60).astype(np.int64), strict=True)})
    per_ent = len({(a, b) for a, b in zip(d[hit], (t[hit] // 600).astype(np.int64), strict=True)})
    return {"alarms_per_hour": per_min / hours, "entity_alarms_per_hour": per_ent / hours,
            "benign_packets": int(benign.sum()), "hours": hours}


def mimic(pk: pd.DataFrame, sel: np.ndarray, victim: str) -> pd.DataFrame:
    """Pad every attacker packet up to the median size of the victim's benign packets
    (only adding, never removing)."""
    out = pk.copy()
    ref = out.loc[~sel & ((out["src"] == victim) | (out["dst"] == victim)), "size"]
    target = int(ref.median()) if len(ref) else 0
    out.loc[sel, "size"] = np.maximum(out.loc[sel, "size"].to_numpy(), target)
    return out


def variants(pk: pd.DataFrame, attacker: str, victim: str, port: int, n: int,
             rng: np.random.Generator) -> list[tuple[str, pd.DataFrame]]:
    """The identity, mimicry, and ``n`` random combinations of the packet operations of
    the certificate check, all on the attacker's own packets."""
    sel = lambda v: (v["src"] == attacker).to_numpy()
    out = [("identity", pk), ("mimic", mimic(pk, sel(pk), victim))]
    for k in range(n):
        p = {"pad": int(rng.choice([0, 40, 400])), "insert": float(rng.choice([0, 0.2, 1.0])),
             "hop": int(rng.choice([0, 3, 20])), "decoys": int(rng.choice([0, 500, 5000]))}
        v = pk
        if p["pad"]:
            v = ops.pad(v, sel(v), p["pad"])
        if p["insert"]:
            v = ops.insert(v, sel(v), rng, p["insert"])
        if p["hop"]:
            v = ops.hop_ports(v, sel(v), rng, p["hop"])
        if p["decoys"]:
            v = ops.decoys(v, [attacker], [(victim, port), (victim, 22)], p["decoys"], rng)
        out.append(("+".join(f"{k}{val}" for k, val in p.items() if val) or "identity2", v))
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap", type=Path, required=True)
    ap.add_argument("--flows", type=Path, required=True, help="the day file of the same capture")
    ap.add_argument("--attacker", default="172.16.0.1", help="source of the campaigns replayed")
    ap.add_argument("--train-packets", type=int, default=100_000)
    ap.add_argument("--calib-minutes", type=float, default=60.0)
    ap.add_argument("--alarm-budget", type=float, default=0.5)
    ap.add_argument("--warmup", type=float, default=30.0, help="minutes before a replayed campaign")
    ap.add_argument("--variants", type=int, default=10)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", type=Path, default=Path("experiments/outputs/kitsune"))
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    flows = pd.read_parquet(args.flows, columns=["t_start", "t_end", "src_ip", "dst_ip", "dst_port",
                                                 "attack", "is_attack"])
    camps = campaigns(flows)
    print(camps[["attack", "episode", "flows"]].to_string(), flush=True)

    model, ts, src, dst, score = stream(args.pcap, args.train_packets, seed=args.seed)
    shift = best_shift(ts, src, dst, camps)
    camp = label(ts, src, dst, camps, shift)
    attack_pairs = set().union(*camps["pairs"]) if len(camps) else set()
    lo, hi = np.minimum(src, dst).astype(np.uint64), np.maximum(src, dst).astype(np.uint64)
    pair_keys = np.array([(np.uint64(a) << np.uint64(32)) | np.uint64(b) for a, b in attack_pairs],
                         dtype=np.uint64)
    benign = ~np.isin((lo << np.uint64(32)) | hi, pair_keys) & ~np.isnan(score)
    t_train_end = ts[min(args.train_packets, len(ts) - 1)]
    calib = benign & (ts < t_train_end + args.calib_minutes * 60)
    test = benign & ~calib
    thr = budget_threshold(score[calib], dst[calib], ts[calib], args.alarm_budget)
    print(f"capture shift {shift / 3600:+.0f} h, threshold {thr:.6g}", flush=True)
    det = pd.DataFrame(detection(score, camp, thr, len(camps)))
    det = pd.concat([camps[["attack", "episode", "flows", "t0", "t1"]].reset_index(drop=True), det], axis=1)
    fa = alarms(score, dst, ts, thr, test)
    det.to_csv(args.out / "kitsune_detection.csv", index=False)
    pd.DataFrame([{"threshold": thr, "shift_h": shift / 3600, **fa}]).to_csv(
        args.out / "kitsune_alarms.csv", index=False)
    print(det.to_string(), flush=True)
    print(fa, flush=True)

    # Free operations on the attacker's campaigns, replayed from a warm-up before them.
    rows = []
    rng = np.random.default_rng(args.seed)
    a_int = ip_int(args.attacker)
    for i, c in camps.iterrows():
        if not any(a_int in p for p in c["pairs"]):
            continue
        victim_int = next(b if a == a_int else a for a, b in c["pairs"] if a_int in (a, b))
        victim = socket.inet_ntoa(struct.pack("!I", victim_int))
        t0, t1 = c["t0"] - shift - args.warmup * 60, c["t1"] - shift
        pk = pcap.read(args.pcap, {args.attacker, victim}, t0, t1 + 1)
        port = int(flows.loc[flows["is_attack"] & (flows["attack"] == c["attack"]), "dst_port"].mode().iloc[0])
        print(f"{c['attack']} episode {c['episode']}: {len(pk):,} packets of {args.attacker} and {victim}",
              flush=True)
        for name, v in variants(pk, args.attacker, victim, port, args.variants, rng):
            v = v.sort_values("ts", kind="stable").reset_index(drop=True)
            s = model.score(AfterImage().features(v))
            src_v = np.array([ip_int(x) for x in v["src"].astype(str)], dtype=np.uint32)
            dst_v = np.array([ip_int(x) for x in v["dst"].astype(str)], dtype=np.uint32)
            lab = label(v["ts"].to_numpy(np.float64), src_v, dst_v, camps.iloc[[i]], shift) >= 0
            n, k = int(lab.sum()), int((s[lab] >= thr).sum())
            rows.append({"attack": c["attack"], "episode": c["episode"], "variant": name,
                         "packets": n, "alerted": k, "detected": n > 0 and k >= 5 and k >= 0.01 * n,
                         "alerted_share": k / n if n else np.nan})
            print("  ", rows[-1], flush=True)
            pd.DataFrame(rows).to_csv(args.out / "kitsune_free_ops.csv", index=False)


if __name__ == "__main__":
    main()
