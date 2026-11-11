"""Evidence features for captures too large to process at once (UGR'16, CIC-DDoS-2019).

The capture is cut in time windows. Each window is computed together with a warm-up
of the preceding ``warmup_s`` seconds, and only the window's own flows are kept.
Events older than the warm-up are dropped, so each decayed counter can be lower than
the exact value by at most exp(-warmup/τ) times the counter's value at the start of
the warm-up. With warmup = 3·τ_max that is ≤ e⁻³ ≈ 5 % at the longest scale and
negligible at shorter ones. Dropping old events can only *lower* counters: the
approximation may cost a little recall, but never raises a spurious alert, and an
alert certified on approximated features stays certified (the true evidence is at
least as high).

``sample`` lets the caller keep only some flows of each window (all attack flows and a
sample of the rest), while counters are still computed from every flow.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator

import numpy as np
import pandas as pd

from .features import DEFAULT_TAUS, build


def windows(t_end: pd.Series, window_s: float) -> Iterator[tuple[pd.Timestamp, pd.Timestamp]]:
    start, end = t_end.min().floor("s"), t_end.max()
    step = pd.Timedelta(seconds=window_s)
    while start <= end:
        yield start, start + step
        start = start + step


def build_chunked(df: pd.DataFrame, window_s: float = 3600.0, warmup_s: float | None = None,
                  taus=DEFAULT_TAUS,
                  sample: Callable[[pd.DataFrame], np.ndarray] | None = None
                  ) -> tuple[pd.DataFrame, list]:
    """Features for ``df`` (sorted by ``t_end``) computed window by window.

    Returns the features of the kept flows (index of ``df``) and the feature specs.
    """
    warmup = pd.Timedelta(seconds=warmup_s if warmup_s is not None else 3 * max(taus))
    t = df["t_end"]
    parts, specs = [], None
    for lo, hi in windows(t, window_s):
        lo_i = t.searchsorted(lo - warmup, side="left")
        a_i = t.searchsorted(lo, side="left")
        hi_i = t.searchsorted(hi, side="left")
        if hi_i <= a_i:
            continue
        chunk = df.iloc[lo_i:hi_i]
        feats, specs = build(chunk, taus)
        own = feats.iloc[a_i - lo_i:]
        if sample is not None:
            own = own[sample(df.iloc[a_i:hi_i])]
        parts.append(own)
    return pd.concat(parts), specs
