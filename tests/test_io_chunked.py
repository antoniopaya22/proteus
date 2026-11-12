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


def test_parts_with_disjoint_columns_are_stitched(tmp_path):
    n = 2_500
    main = pd.DataFrame({"a": np.arange(n, dtype=np.float32), "b": np.ones(n, np.float32)})
    side = pd.DataFrame({"x": -np.arange(n, dtype=np.float32)})
    main.to_parquet(tmp_path / "m.parquet", index=False)
    side.to_parquet(tmp_path / "s.parquet", index=False)
    parts = [tmp_path / "m.parquet", tmp_path / "s.parquet"]
    X = np.concatenate(list(h1.score_batches(parts, ["x", "a"], batch=1_000)))
    np.testing.assert_array_equal(X[:, 0], -X[:, 1])
    rows = h1.read_rows(parts, np.array([3, 1_999, 2_400]), ["a", "x"], batch=700)
    assert list(rows.columns) == ["a", "x"]
    np.testing.assert_array_equal(rows["x"], [-3, -1_999, -2_400])
