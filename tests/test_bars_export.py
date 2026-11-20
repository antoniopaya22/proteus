import numpy as np

from proteus.evaluation.bars_export import variant_rows


def test_variant_rows_follow_each_flow_and_skip_decoys():
    # Variant: flow 0, decoys (-1), flow 2 split in two pieces, flow 1 moved to the end.
    orig = np.array([0, -1, 2, 2, -1, 1])
    assert variant_rows(orig, np.array([0, 1, 2])).tolist() == [0, 5, 2]
    assert variant_rows(orig, np.array([3])).tolist() == [-1]  # no counterpart
