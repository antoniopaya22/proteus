"""Kitsune's feature extractor on packets (Mirsky et al., NDSS 2018), for running the
published detector as published: per packet, damped incremental statistics of the
streams it belongs to, at five decay rates, fed to KitNET (``baselines.kitnet``).

For every packet and every decay rate λ (a statistic decays by 2^(-λ Δt)):

* ``MI``: the source host, packet sizes: weight, mean, variance. (The original keys
  this stream by source MAC and IP; the packet tables here carry no MAC, so it is the
  source IP, like ``H``.)
* ``H``: the source host, packet sizes: weight, mean, variance.
* ``HH``: the channel between source and destination hosts, packet sizes, as a 2D
  statistic of both directions: weight, mean, std, magnitude, radius, covariance and
  correlation coefficient.
* ``HH_jit``: the channel, inter-arrival times: weight, mean, variance.
* ``HpHp``: the socket (hosts and ports), packet sizes, as ``HH``.

23 statistics per λ, 115 in all (grouped by λ here).
"""

from __future__ import annotations

import math

import numpy as np

LAMBDAS = (5.0, 3.0, 1.0, 0.1, 0.01)
N_FEATURES = 23 * len(LAMBDAS)


class _Stat:
    """Damped weight, linear sum and squared sum of one stream at one decay rate."""

    __slots__ = ("lam", "last_res", "ls", "ss", "t", "w")

    def __init__(self, lam: float, t: float) -> None:
        self.lam, self.w, self.ls, self.ss, self.t, self.last_res = lam, 0.0, 0.0, 0.0, t, 0.0

    def decay(self, t: float) -> float:
        d = 2.0 ** (-self.lam * (t - self.t)) if t > self.t else 1.0
        if d != 1.0:
            self.w *= d
            self.ls *= d
            self.ss *= d
        self.t = max(self.t, t)
        return d

    def insert(self, x: float, t: float) -> None:
        self.decay(t)
        self.w += 1.0
        self.ls += x
        self.ss += x * x
        self.last_res = x - self.ls / self.w

    def mean(self) -> float:
        return self.ls / self.w if self.w > 0 else 0.0

    def var(self) -> float:
        if self.w <= 0:
            return 0.0
        m = self.ls / self.w
        return abs(self.ss / self.w - m * m)

    def stats(self) -> tuple[float, float, float]:
        return self.w, self.mean(), self.var()


class _Pair:
    """A 2D damped statistic of the two directions of a stream (``HH``, ``HpHp``): each
    direction its own ``_Stat``, plus the damped sum of products of their residuals."""

    __slots__ = ("a", "b", "lam", "sr", "t", "w3")

    def __init__(self, lam: float, t: float) -> None:
        self.lam, self.a, self.b = lam, _Stat(lam, t), _Stat(lam, t)
        self.sr, self.w3, self.t = 0.0, 0.0, t

    def insert(self, forward: bool, x: float, t: float) -> None:
        d = 2.0 ** (-self.lam * (t - self.t)) if t > self.t else 1.0
        self.sr *= d
        self.w3 *= d
        self.t = max(self.t, t)
        mine, other = (self.a, self.b) if forward else (self.b, self.a)
        other.decay(t)
        mine.insert(x, t)
        self.sr += mine.last_res * other.last_res
        self.w3 += 1.0

    def stats(self, forward: bool) -> tuple[float, ...]:
        mine, other = (self.a, self.b) if forward else (self.b, self.a)
        m1, m2 = mine.mean(), other.mean()
        v1, v2 = mine.var(), other.var()
        cov = self.sr / self.w3 if self.w3 > 0 else 0.0
        s1, s2 = math.sqrt(v1), math.sqrt(v2)
        pcc = cov / (s1 * s2) if s1 > 0 and s2 > 0 else 0.0
        return (mine.w, m1, s1, math.sqrt(m1 * m1 + m2 * m2), math.sqrt(v1 + v2), cov, pcc)


class AfterImage:
    """Kitsune's incremental feature extractor. ``update`` takes one packet and returns
    its 115 features; packets must come in time order."""

    def __init__(self, lambdas: tuple[float, ...] = LAMBDAS) -> None:
        self.lambdas = lambdas
        self.host: dict = {}
        self.chan: dict = {}
        self.jit: dict = {}
        self.sock: dict = {}
        self.jit_last: dict = {}

    def _get(self, table: dict, key, t: float, kind):
        s = table.get(key)
        if s is None:
            s = table[key] = [kind(lam, t) for lam in self.lambdas]
        return s

    def update(self, t: float, src: str, dst: str, sport: int, dport: int, size: float) -> list[float]:
        host = self._get(self.host, src, t, _Stat)
        ckey = (src, dst) if src <= dst else (dst, src)
        chan = self._get(self.chan, ckey, t, _Pair)
        fwd_chan = src <= dst
        a, b = (src, sport), (dst, dport)
        skey = (a, b) if a <= b else (b, a)
        sock = self._get(self.sock, skey, t, _Pair)
        fwd_sock = a <= b
        jit = self._get(self.jit, (src, dst), t, _Stat)
        gap = t - self.jit_last.get((src, dst), t)
        self.jit_last[(src, dst)] = t
        out: list[float] = []
        for i in range(len(self.lambdas)):
            host[i].insert(size, t)
            w, m, v = host[i].stats()
            out += [w, m, v, w, m, v]  # MI (keyed by source IP here) and H
            chan[i].insert(fwd_chan, size, t)
            out += chan[i].stats(fwd_chan)
            jit[i].insert(gap, t)
            out += jit[i].stats()
            sock[i].insert(fwd_sock, size, t)
            out += sock[i].stats(fwd_sock)
        return out

    def features(self, pk) -> np.ndarray:
        """Features of every packet of a packet table (``proteus.packets``), in order."""
        X = np.empty((len(pk), N_FEATURES), dtype=np.float32)
        cols = zip(pk["ts"].to_numpy(np.float64), pk["src"].astype(str), pk["dst"].astype(str),
                   pk["sport"].to_numpy(), pk["dport"].to_numpy(), pk["size"].to_numpy(np.float64))
        for i, (t, s, d, sp, dp, z) in enumerate(cols):
            X[i] = self.update(float(t), s, d, int(sp), int(dp), float(z))
        return X
