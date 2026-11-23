import numpy as np
import pandas as pd

from proteus.datasets.reexport import best_offset, cic_day, transfer_labels

T0 = pd.Timestamp("2017-07-05 14:00:00")


def flows(rows):
    """rows: (src, sport, dst, dport, start_s, end_s)."""
    return pd.DataFrame({
        "src_ip": [r[0] for r in rows], "src_port": np.array([r[1] for r in rows], np.int32),
        "dst_ip": [r[2] for r in rows], "dst_port": np.array([r[3] for r in rows], np.int32),
        "proto": np.full(len(rows), 6, np.int16),
        "t_start": [T0 + pd.Timedelta(seconds=r[4]) for r in rows],
        "t_end": [T0 + pd.Timedelta(seconds=r[5]) for r in rows],
    })


def cic(rows, labels):
    df = flows(rows)
    df["attack"] = pd.Categorical([lab[0] for lab in labels])
    df["family"] = pd.Categorical([lab[1] for lab in labels])
    df["attempted"] = [lab[2] for lab in labels]
    df["is_attack"] = [lab[1] != "benign" and not lab[2] for lab in labels]
    df["label_raw"] = pd.Categorical([lab[3] for lab in labels])
    return df


HULK = ("dos_hulk", "dos", False, "DoS Hulk")
HULK_ATT = ("dos_hulk", "dos", True, "DoS Hulk - Attempted")
BEN = ("benign", "benign", False, "BENIGN")


def test_labels_follow_the_5tuple_in_either_direction_and_overlap():
    c = cic([("1.1.1.1", 4000, "2.2.2.2", 80, 0, 10),       # attack
             ("3.3.3.3", 5000, "2.2.2.2", 80, 0, 10),       # benign
             ("1.1.1.1", 4001, "2.2.2.2", 80, 100, 110)],   # attack, later
            [HULK, BEN, HULK])
    n = flows([("2.2.2.2", 80, "1.1.1.1", 4000, 2, 8),        # reversed direction
               ("3.3.3.3", 5000, "2.2.2.2", 80, 1, 9),
               ("1.1.1.1", 4001, "2.2.2.2", 80, 0, 10),       # no overlap: benign
               ("9.9.9.9", 1, "2.2.2.2", 80, 0, 1)])          # unmatched
    lab, matched = transfer_labels(n, c)
    assert list(lab["attack"].astype(str)) == ["dos_hulk", "benign", "benign", "benign"]
    assert list(lab["is_attack"]) == [True, False, False, False]
    assert list(matched) == [True, True, False, False]


def test_attack_wins_over_attempted_and_benign_on_a_split_record():
    # one NFStream record spans three CIC records of the same 5-tuple
    c = cic([("1.1.1.1", 4000, "2.2.2.2", 80, 0, 5),
             ("1.1.1.1", 4000, "2.2.2.2", 80, 6, 10),
             ("1.1.1.1", 4000, "2.2.2.2", 80, 11, 15)], [BEN, HULK_ATT, HULK])
    n = flows([("1.1.1.1", 4000, "2.2.2.2", 80, 0, 15),
               ("1.1.1.1", 4000, "2.2.2.2", 80, 6, 9)])
    lab, _ = transfer_labels(n, c)
    assert list(lab["label_raw"].astype(str)) == ["DoS Hulk", "DoS Hulk - Attempted"]
    assert list(lab["attempted"]) == [False, True]
    assert list(lab["is_attack"]) == [True, False]


def test_best_offset_finds_the_clock_shift():
    rows = [("1.1.1.%d" % i, 4000 + i, "2.2.2.2", 80, 20 * i, 20 * i + 5) for i in range(40)]
    c = cic(rows, [HULK] * 40)
    shifted = flows([(r[0], r[1], r[2], r[3], r[4] + 3 * 3600, r[5] + 3 * 3600) for r in rows])
    off, share = best_offset(shifted, c, candidates_h=range(-5, 6), sample=40)
    assert off == 3 * 3600 and share == 1.0
    lab, matched = transfer_labels(shifted, c, offset_s=off)
    assert matched.all() and lab["is_attack"].all()


def test_cic_day_matches_weekday(tmp_path):
    for d in ("monday", "tuesday"):
        (tmp_path / f"{d}.parquet").write_bytes(b"")
    assert cic_day(tmp_path, "Monday-WorkingHours").name == "monday.parquet"
    assert cic_day(tmp_path, "Friday-WorkingHours") is None
