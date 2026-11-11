"""Per-flow classifier (the shell).

Covers attacks with little aggregate footprint (web attacks, exploits, single-flow
infiltration) and makes Proteus comparable with per-flow detectors on their own
protocol. Features are the CICFlowMeter statistics; identifiers that encode the
dataset rather than the behaviour (IPs, ports, timestamps) are excluded, following
Arp et al. (USENIX Security 2022).
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier

BASE = ["duration_us", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes"]


def feature_columns(columns, with_port: bool = False) -> list[str]:
    cols = [c for c in columns if c.startswith("f_")] + [c for c in BASE if c in columns]
    if with_port:
        cols.append("dst_port")
    return cols


def model(random_state: int = 0) -> HistGradientBoostingClassifier:
    return HistGradientBoostingClassifier(
        max_iter=400, learning_rate=0.1, max_leaf_nodes=63, l2_regularization=1.0,
        class_weight="balanced", random_state=random_state)


def features(df: pd.DataFrame, cols: list[str]) -> np.ndarray:
    return df[cols].to_numpy(np.float32)
