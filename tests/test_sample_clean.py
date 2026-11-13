"""sample_clean reads row group by row group but returns the rows of the old path."""

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from proteus.evaluation import h1


def test_sample_clean_matches_full_read(tmp_path, monkeypatch):
    rng = np.random.default_rng(1)
    n = 5_000
    df = pd.DataFrame({"a": rng.random(n), "b": rng.random(n), "c": rng.random(n),
                       "clean": rng.random(n) < 0.7})
    path = tmp_path / "day.parquet"
    pq.write_table(pa.Table.from_pandas(df, preserve_index=False), path, row_group_size=700)
    monkeypatch.setattr(h1, "cache_parts", lambda ds, day: [path])
    cols = ["c", "a"]
    for k in (100, 10_000):
        old = df.loc[df["clean"], cols].to_numpy(np.float32)
        old = old[np.random.default_rng(7).choice(len(old), min(len(old), k), replace=False)]
        new = h1.sample_clean("x", path, cols, k, np.random.default_rng(7))
        assert np.array_equal(old, new)
