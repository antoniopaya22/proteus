"""Convert raw datasets to Parquet.

    python -m proteus.datasets.prepare --dataset cicids2017 \
        --raw data/raw/cicids2017 --out data/processed/cicids2017
"""

from __future__ import annotations

import argparse
from pathlib import Path

from . import ctu13, unsw
from .cic import convert


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", required=True, choices=["cicids2017", "csecicids2018", "ctu13", "unsw_nb15"])
    ap.add_argument("--raw", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    if args.dataset == "ctu13":
        summary = ctu13.convert(args.raw, args.out)
    elif args.dataset == "unsw_nb15":
        summary = unsw.convert(args.raw, args.out)
    else:
        summary = convert(args.raw, args.out, args.dataset)
    summary.to_csv(args.out / "summary.csv", index=False)
    print(summary.to_string())


if __name__ == "__main__":
    main()
