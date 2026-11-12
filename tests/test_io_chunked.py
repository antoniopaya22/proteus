import numpy as np
import pandas as pd

from proteus.evaluation import h1


def frame(n):
    return pd.DataFrame({"a": np.arange(n, dtype=np.int64),
                         "s": pd.array([f"h{i % 7}" for i in range(n)], dtype="string"),
                         "c": pd.Categorical([["x", "y"][i % 2] for i in range(n)]),
                         "f": np.linspace(0, 1, n, dtype=np.float32)})


def test_write_chunked_equals_concat(tmp_path):
    ev = frame(2_345)
    extra = {"b": np.arange(2_345, dtype=np.float32) * 2}
    h1._write_chunked(tmp_path / "x.parquet", ev, extra, chunk=1_000)
    got = pd.read_parquet(tmp_path / "x.parquet")
    want = pd.concat([ev, pd.DataFrame(extra)], axis=1)
    assert list(got.columns) == list(want.columns)
    np.testing.assert_array_equal(got["a"], want["a"])
    np.testing.assert_array_equal(got["b"], want["b"])
    assert (got["s"].astype(str) == want["s"].astype(str)).all()
    assert (got["c"].astype(str) == want["c"].astype(str)).all()


def test_read_rows_across_batches(tmp_path):
    ev = frame(5_000)
    ev.to_parquet(tmp_path / "y.parquet", index=False, row_group_size=700)
    idx = np.array([0, 1, 699, 700, 701, 2_500, 4_999])
    got = h1.read_rows(tmp_path / "y.parquet", idx, ["a", "f"], batch=600)
    np.testing.assert_array_equal(got["a"], idx)
    assert list(got.columns) == ["a", "f"]
