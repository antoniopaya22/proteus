import numpy as np

from proteus.datasets import ctusme11

HEADER = """#separator \\x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\tconn
#fields\t""" + "\t".join(ctusme11.FIELDS) + """
#types\t""" + "\t".join(["x"] * len(ctusme11.FIELDS)) + "\n"


def row(ts, src, sp, dst, dp, proto, dur, ob, rb, hist, op, rp, label, detail):
    return "\t".join(map(str, [ts, "C1", src, sp, dst, dp, proto, "-", dur, ob, rb, "S0", "-",
                               "-", 0, hist, op, 0, rp, 0, "-", label, detail])) + "\n"


def write(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(HEADER + "".join(rows) + "#close\t2023-03-23-20-34-41\n")


def test_read_conn_maps_fields(tmp_path):
    p = tmp_path / "conn.log.labeled"
    write(p, [
        row(1677024017.5, "1.2.3.4", 5555, "192.168.1.50", 23, "tcp", "-", "-", "-", "S", 1, 0,
            "Malicious", "From_malicious-To_benign-Discovery"),
        row(1677024018.0, "192.168.1.50", 4000, "8.8.8.8", 53, "udp", 0.5, 40, 120, "Dd", 1, 1,
            "Benign", "From_benign-To_benign-DNS"),
        row(1677024019.0, "1.2.3.4", 5556, "192.168.1.50", 80, "tcp", 0.1, 0, 0, "Sr", 1, 1,
            "Malicious", "From_malicious-To_benign-Discovery"),
    ])
    df = ctusme11.read_conn(p, "dev")
    assert len(df) == 3
    assert df["is_attack"].tolist() == [True, False, True]
    assert df["family"].tolist() == ["portscan", "benign", "portscan"]
    assert df["f_bwd_rst_flags"].tolist() == [0.0, 0.0, 1.0]
    assert df["fwd_bytes"].tolist() == [0, 40, 0] and df["bwd_bytes"].tolist() == [0, 120, 0]
    assert df["proto"].tolist() == [6, 17, 6]
    assert (df["t_end"] - df["t_start"]).dt.total_seconds().tolist() == [0.0, 0.5, 0.1]


def test_convert_merges_devices_and_drops_shared_flows(tmp_path):
    shared = row(1677024020.1234, "192.168.1.50", 4000, "192.168.1.60", 80, "tcp", 1, 10, 10,
                 "ShAD", 3, 3, "Benign", "From_benign-To_benign-HTTP")
    for dev, extra in (("A", "192.168.1.50"), ("B", "192.168.1.60")):
        write(tmp_path / "raw" / "CTU-SME-11" / dev / "2023-02-21" / "zeek" / "conn.log.labeled",
              [shared, row(1677024030, extra, 1, "9.9.9.9", 443, "tcp", 1, 1, 1, "S", 1, 1,
                           "Benign", "From_benign-To_benign-HTTPS")])
    s = ctusme11.convert(tmp_path / "raw", tmp_path / "out")
    assert int(s["flows"].sum()) == 3 and int(s["duplicates"].iloc[0]) == 1
    import pandas as pd
    d = pd.read_parquet(tmp_path / "out" / "2023-02-22.parquet")
    assert np.all(np.diff(d["t_end"].to_numpy()) >= np.timedelta64(0, "us"))
