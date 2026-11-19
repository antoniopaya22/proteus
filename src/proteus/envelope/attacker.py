"""The attacker's worst case against threshold tests on witnesses, in closed form.

Each kind of harm leaves a least amount of every witness per unit of harm, whatever
the attacker does (``Harm.cost``: witness added in one window per unit). Against a
detector that alerts when a witness passes its threshold, the most harm that stays
quiet in a window is therefore ``min over witnesses of headroom / cost``, where the
headroom is the threshold minus what the victim's own traffic already puts there. No
search is involved, and no plan of the attacker can do better.

The costs assume the cheapest attack the protocol allows: connections reused up to
the server's limit, requests of minimal size, slots held with one packet per idle
timeout. They are lower bounds on evidence, so the harm computed is an upper bound.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd


@dataclass(frozen=True)
class Harm:
    unit: str
    cost: dict[str, float]  # least witness added in one window per unit of harm
    own: str  # witness that measures the harm of a recorded campaign
    per: float  # divide the campaign's witness by this to get harm units


def harms(window_s: float = 600.0, reuse: int = 100, min_request: float = 18.0,
          idle_timeout_s: float = 300.0) -> dict[str, Harm]:
    w = float(window_s)
    return {
        # connections held open at once: each needs a packet per idle timeout
        "slots": Harm("connections held", {"conc": 1.0, "pkts": w / idle_timeout_s}, "conc", 1.0),
        # requests per second: a packet and a minimal request each, a connection per `reuse`
        "requests": Harm("requests/s", {"pkts": w, "bytes": w * min_request, "conn": w / reuse},
                         "conn", w),
        # packets per second of a volumetric flood
        "packets": Harm("packets/s", {"pkts": w, "bytes": w * 28.0}, "pkts", w),
        # password attempts per second: the server allows a few per connection
        "guesses_ssh": Harm("attempts/s", {"conn": w / 6.0, "pkts": w}, "conn", w),
        "guesses_ftp": Harm("attempts/s", {"conn": w / 3.0, "pkts": w}, "conn", w),
        # ports probed on a host per window
        "probes": Harm("ports/window", {"ports": 1.0}, "ports", 1.0),
    }


KIND = {"dos_slowloris": "slots", "dos_slowhttptest": "slots", "dos_hulk": "requests",
        "dos_goldeneye": "requests", "ddos_loic_http": "requests", "ddos_hoic": "requests",
        "ddos_loic_udp": "packets", "bf_ssh": "guesses_ssh", "bf_ftp": "guesses_ftp",
        "portscan": "probes"}


def quiet_harm(background: pd.DataFrame, thresholds: dict[str, float], harm: Harm) -> np.ndarray:
    """Most harm per window that raises no alert, given the victim's own witnesses
    (one row per window). NaN where the victim's own traffic already alerts: such a
    window says nothing about the attack."""
    out = np.full(len(background), np.inf)
    noisy = np.zeros(len(background), bool)
    for w, c in harm.cost.items():
        b = background[w].to_numpy(np.float64)
        noisy |= b > thresholds[w]
        out = np.minimum(out, np.maximum(thresholds[w] - b, 0.0) / c)
    return np.where(noisy, np.nan, out)


def sustained(per_window: np.ndarray, n: int, start: int | None = None) -> float:
    """Harm an attack of ``n`` windows keeps: its lowest quiet window, from ``start``
    or, without it, from the start that suits the attacker best. NaN if it never finds
    ``n`` windows in a row that the victim's own traffic leaves quiet."""
    if len(per_window) < n:
        return float("nan")
    if start is not None:
        seg = per_window[start:start + n]
        return float(np.min(seg)) if len(seg) == n and not np.isnan(seg).any() else float("nan")
    m = pd.Series(per_window).rolling(n).min().to_numpy()  # NaN wherever a window is noisy
    return float(np.nanmax(m)) if not np.isnan(m).all() else float("nan")


def campaign_harm(windows: pd.DataFrame, harm: Harm) -> float:
    """Harm of a recorded campaign in the same units: the median of its active windows
    (one request or attempt per connection, a lower bound)."""
    v = windows[harm.own].to_numpy(np.float64)
    v = v[v > 0]
    return float(np.median(v) / harm.per) if len(v) else float("nan")
