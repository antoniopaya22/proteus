"""Flow records from an exporter that is not ours: NFStream.

``exporter.export`` was written to the accounting that assumption (A1) of the
certificate describes. NFStream is an independent flow meter with its own expiry
logic; reading the same packets through it tests the assumption on an implementation
we did not write. Records come back in the schema of ``exporter.export``.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd


def export_nfstream(pcap: Path, active_s: float = 120.0, idle_s: float = 60.0) -> pd.DataFrame:
    """Bidirectional flow records of ``pcap`` by NFStream, with its active and idle
    timeouts set to ``active_s`` and ``idle_s`` and bytes counted from the transport
    header on (the ``size`` of our packet table). The initiator of a record is the
    sender of its first packet, as NFStream reports it."""
    from nfstream import NFStreamer

    f = NFStreamer(source=str(pcap), decode_tunnels=False, idle_timeout=int(idle_s),
                   active_timeout=int(active_s), accounting_mode=2, n_dissections=0,
                   statistical_analysis=True, snapshot_length=65535, n_meters=1).to_pandas()
    df = pd.DataFrame({
        "src_ip": f["src_ip"].astype("string"), "src_port": f["src_port"].astype(np.int32),
        "dst_ip": f["dst_ip"].astype("string"), "dst_port": f["dst_port"].astype(np.int32),
        "proto": f["protocol"].astype(np.int16),
        "fwd_pkts": f["src2dst_packets"].astype(np.int64),
        "bwd_pkts": f["dst2src_packets"].astype(np.int64),
        "fwd_bytes": f["src2dst_bytes"].astype(np.int64),
        "bwd_bytes": f["dst2src_bytes"].astype(np.int64),
        "t_start": pd.to_datetime(f["bidirectional_first_seen_ms"], unit="ms").astype("datetime64[us]"),
        "t_end": pd.to_datetime(f["bidirectional_last_seen_ms"], unit="ms").astype("datetime64[us]"),
        "f_bwd_rst_flags": f["dst2src_rst_packets"].astype(np.float32),
    })
    df["duration_us"] = (df["t_end"] - df["t_start"]).dt.total_seconds().mul(1e6).astype(np.int64)
    return df.sort_values("t_end", kind="stable").reset_index(drop=True)
