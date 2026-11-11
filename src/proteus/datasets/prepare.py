"""Convert raw datasets to Parquet.

    python -m proteus.datasets.prepare --dataset cicids2017 \
        --raw data/raw/cicids2017 --out data/processed/cicids2017
"""

from __future__ import annotations

import argparse
from pathlib import Path

from .cic import convert


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", required=True, choices=["cicids2017", "csecicids2018"])
    ap.add_argument("--raw", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    summary = convert(args.raw, args.out, args.dataset)
    summary.to_csv(args.out / "summary.csv", index=False)
    print(summary.to_string())


if __name__ == "__main__":
    main()
