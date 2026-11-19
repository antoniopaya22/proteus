"""The attacker's worst case against threshold tests on witnesses, in closed form.

Each kind of harm leaves a least amount of every witness per unit of harm, whatever
the attacker does (``Harm.cost``: witness added in one window per unit). Against a
detector that alerts when a witness passes its threshold, the most harm that stays
quiet in a window is therefore ``min over witnesses of headroom / cost``, where the
headroom is the threshold minus what the victim's own traffic already puts there. No
search is involved, and no plan of the attacker can do better.

The costs assume the cheapest attack the protocol allows: connections reused up to
the server's limit, requests of minimal size packed into full segments, slots held
with one packet per idle timeout, as many password attempts per connection as the
server grants. They are lower bounds on evidence, so the harm computed is an upper
bound. Distinct ports are not additive: a probe of a port the host's own traffic
already uses adds nothing, so for that witness the headroom is the whole threshold.
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
    cumulative: bool = False  # the harm is the total (guesses, probes), not a held rate


OVERLAP = ("ports",)  # witnesses that count distinct things the victim may already have


def harms(window_s: float = 600.0, reuse: int = 100, min_request: float = 18.0,
          idle_timeout_s: float = 300.0, mss: float = 1460.0, tries_ssh: int = 6,
          tries_ftp: int = 3, conn_pkts: float = 3.0) -> dict[str, Harm]:
    """Kinds of harm and the least each leaves in every witness. The parameters are
    limits of the protected servers, which their operator knows: requests served per
    connection, smallest request, idle timeout, password attempts per connection; and
    of the protocol: segment size and packets a client sends to open a connection."""
    w = float(window_s)
    return {
        # connections held open at once: each needs a packet per idle timeout
        "slots": Harm("connections held", {"conc": 1.0, "pkts": w / idle_timeout_s}, "conc", 1.0),
        # requests per second: a minimal request each, as many as fit in a segment, and
        # a connection per `reuse`
        "requests": Harm("requests/s", {"bytes": w * min_request, "pkts": w * min_request / mss,
                                        "conn": w / reuse}, "conn", w),
        # packets per second of a volumetric flood
        "packets": Harm("packets/s", {"pkts": w, "bytes": w * 28.0}, "pkts", w),
        # password attempts per second: the server allows a few per connection
        "guesses_ssh": Harm("attempts/s", {"conn": w / tries_ssh,
                                           "pkts": conn_pkts * w / tries_ssh}, "conn", w, True),
        "guesses_ftp": Harm("attempts/s", {"conn": w / tries_ftp,
                                           "pkts": conn_pkts * w / tries_ftp}, "conn", w, True),
        # ports probed on a host per window
        "probes": Harm("ports/window", {"ports": 1.0}, "ports", 1.0, True),
    }


KIND = {"dos_slowloris": "slots", "dos_slowhttptest": "slots", "dos_hulk": "requests",
        "dos_goldeneye": "requests", "ddos_loic_http": "requests", "ddos_hoic": "requests",
        "ddos_loic_udp": "packets", "bf_ssh": "guesses_ssh", "bf_ftp": "guesses_ftp",
        "portscan": "probes"}


def quiet_harm(background: pd.DataFrame, thresholds: dict[str, float], harm: Harm) -> np.ndarray:
    """Most harm per window that raises no alert, given the victim's own witnesses
    (one row per window). NaN where the victim's own traffic already alerts: such a
    window says nothing about the attack. Only the witnesses in ``thresholds`` count;
    on a table of totals over several windows the result is harm times windows."""
    out = np.full(len(background), np.inf)
    noisy = np.zeros(len(background), bool)
    for w, c in harm.cost.items():
        if w not in thresholds:
            continue
        b = background[w].to_numpy(np.float64)
        noisy |= b > thresholds[w]
        room = thresholds[w] - (0.0 if w in OVERLAP else b)
        out = np.minimum(out, np.maximum(room, 0.0) / c)
    return np.where(noisy, np.nan, out)


def hidden_rate(harm: Harm, floors: dict[str, float]) -> float:
    """Harm per window that keeps an otherwise idle window under every floor, so that
    the window is not written and adds nothing to the totals over several windows."""
    return min(floors[w] / c for w, c in harm.cost.items())


def kept(quiet: np.ndarray, written: np.ndarray, span: np.ndarray, room: dict[int, float],
         hidden: float, cumulative: bool) -> float:
    """Harm per window an attack keeps over the windows given, against the tests on
    single windows (``quiet``, from ``quiet_harm``) and on totals over spans of windows
    (``room[s]``: harm times windows left in span ``s``; no entry, no test). A window
    the victim's traffic did not write (``written`` false) adds to its span only if the
    attack lifts it over a floor, that is above ``hidden``.

    A held rate (denial of service) is the highest constant rate that passes every
    test. A cumulative harm (guesses, probes) is the largest total, with the rate free
    to change from window to window, divided by the number of windows. Both are exact:
    per span the attacker either hides in the unwritten windows or spends the room.
    NaN if the victim's own traffic alerts in any of the windows or spans."""
    if np.isnan(quiet).any() or any(np.isnan(room.get(int(s), np.inf)) for s in np.unique(span)):
        return float("nan")
    n = len(quiet)
    spans = [(room[int(s)], quiet[span == s], written[span == s])
             for s in np.unique(span) if int(s) in room]
    if not cumulative:
        top = float(quiet.min())
        # above `hidden` every window counts; at or below it only the written ones
        loud = min([top] + [r / len(q) for r, q, _ in spans])
        if loud > hidden:
            return loud
        return min([top, hidden] + [r / wr.sum() for r, _, wr in spans if wr.any()])
    total = float(quiet[~np.isin(span, [int(s) for s in room])].sum())
    for r, q, wr in spans:
        free = np.sort(q[~wr])[::-1]  # unwritten windows, the roomiest first
        low = np.minimum(free, hidden)
        base = float(q[wr].sum())
        # count the j roomiest unwritten windows against the room, hide in the rest
        counted = np.concatenate([[0.0], np.cumsum(free)])
        hid = low.sum() - np.concatenate([[0.0], np.cumsum(low)])
        total += float(np.max(hid + np.minimum(r, base + counted)))
    return total / n


def best_start(n_total: int, n: int, value) -> float:
    """Largest ``value(start)`` over the starts of an attack of ``n`` windows."""
    v = [value(s) for s in range(max(n_total - n + 1, 0))]
    v = [x for x in v if not np.isnan(x)]
    return max(v) if v else float("nan")


def campaign_harm(windows: pd.DataFrame, harm: Harm) -> float:
    """Harm of a recorded campaign in the same units: the median of its active windows
    (one request or attempt per connection, a lower bound)."""
    v = windows[harm.own].to_numpy(np.float64)
    v = v[v > 0]
    return float(np.median(v) / harm.per) if len(v) else float("nan")
