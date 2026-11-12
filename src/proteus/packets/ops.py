"""Free operations on the attacker's own packets (host space).

``sel`` marks packets the attacker sends. None of these operations removes or
delays an attacker packet; they add bytes, add packets, or change header fields the
attacker controls, which may change how packets are grouped into flows.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from .exporter import FIN, RST, SYN


def pad(pk: pd.DataFrame, sel: np.ndarray, nbytes: int) -> pd.DataFrame:
    out = pk.copy()
    out.loc[sel, "size"] += nbytes
    return out


def insert(pk: pd.DataFrame, sel: np.ndarray, rng: np.random.Generator, share: float,
           size: int = 20, gap_s: float = 0.001) -> pd.DataFrame:
    """After a random ``share`` of the attacker's packets, send one more packet of the
    same connection (e.g. a duplicate ACK or a keep-alive) ``gap_s`` later."""
    pick = np.flatnonzero(sel & (rng.random(len(pk)) < share))
    extra = pk.iloc[pick].copy()
    extra["ts"] = extra["ts"] + gap_s
    extra["size"] = size
    extra["flags"] = (extra["flags"] & ~(FIN | RST | SYN)).astype(np.int16)
    return pd.concat([pk, extra], ignore_index=True).sort_values("ts", kind="stable")


def hop_ports(pk: pd.DataFrame, sel: np.ndarray, rng: np.random.Generator,
              every: int) -> pd.DataFrame:
    """Move each attacker connection to a fresh source port every ``every`` of its
    packets (the replies follow the new port). A flow record is split into several."""
    out = pk.copy().reset_index(drop=True)
    sel = np.asarray(sel)
    conn = list(zip(out["src"], out["sport"], out["dst"], out["dport"], out["proto"]))
    count: dict = {}
    remap: dict = {}
    sport = out["sport"].to_numpy().copy()
    dport = out["dport"].to_numpy().copy()
    for i, (s, spt, d, dpt, p) in enumerate(conn):
        if sel[i]:
            k = (s, spt, d, dpt, p)
            n = count.get(k, 0)
            if n % every == 0:
                remap[k] = int(rng.integers(1024, 65536))
            count[k] = n + 1
            sport[i] = remap[k]
        else:
            k = (d, dpt, s, spt, p)  # reply to an attacker connection
            if k in remap:
                dport[i] = remap[k]
    out["sport"], out["dport"] = sport.astype(np.int32), dport.astype(np.int32)
    return out


def decoys(pk: pd.DataFrame, attackers: list[str], targets: list[tuple[str, int]], n: int,
           rng: np.random.Generator) -> pd.DataFrame:
    """``n`` single SYN packets from attacker hosts to the given (host, port) targets,
    spread uniformly over the trace."""
    t0, t1 = pk["ts"].min(), pk["ts"].max()
    tg = [targets[i] for i in rng.integers(0, len(targets), n)]
    extra = pd.DataFrame({
        "ts": rng.uniform(t0, t1, n), "src": rng.choice(attackers, n),
        "dst": [h for h, _ in tg], "sport": rng.integers(1024, 65536, n).astype(np.int32),
        "dport": np.array([p for _, p in tg], dtype=np.int32),
        "proto": np.full(n, 6, dtype=np.int16), "size": np.full(n, 20, dtype=np.int64),
        "flags": np.full(n, SYN, dtype=np.int16)})
    return pd.concat([pk, extra], ignore_index=True).sort_values("ts", kind="stable")
