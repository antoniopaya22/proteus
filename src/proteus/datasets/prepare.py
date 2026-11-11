"""Convert raw datasets to Parquet.

    python -m proteus.datasets.prepare --dataset cicids2017 \
        --raw data/raw/cicids2017 --out data/processed/cicids2017
"""

from __future__ import annotations

import argparse
from pathlib import Path

from . import ctu13, ugr16, unsw
from .cic import convert


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", required=True, choices=["cicids2017", "csecicids2018", "ctu13", "unsw_nb15", "ugr16"])
    ap.add_argument("--raw", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--sample-rate", type=float, default=0.01, help="ugr16: background kept")
    ap.add_argument("--max-hours", type=float, default=None, help="ugr16: smoke tests")
    args = ap.parse_args()
    if args.dataset == "ctu13":
        summary = ctu13.convert(args.raw, args.out)
    elif args.dataset == "unsw_nb15":
        summary = unsw.convert(args.raw, args.out)
    elif args.dataset == "ugr16":
        import pandas as pd

        rows = []
        for week in sorted(args.raw.glob("*.parquet")):
            print(f"ugr16 {week.name}", flush=True)
            rows += ugr16.convert_week(week, args.out, args.sample_rate,
                                       max_hours=args.max_hours)
        summary = pd.DataFrame(rows)
    else:
        summary = convert(args.raw, args.out, args.dataset)
    summary.to_csv(args.out / "summary.csv", index=False)
    print(summary.to_string())


if __name__ == "__main__":
    main()
