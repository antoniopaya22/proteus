"""End-to-end run of the cross-network experiment on a tiny synthetic dataset.

Two networks with three days each (one of them benign only), a flood and a scan on the
others. Runs ``proteus.evaluation.h1`` as a user would (a subprocess with
``PROTEUS_EVIDENCE=v3``) and checks what silently went wrong in the past: every
requested model is in the results for every day, benign-only days report their alarms,
unknown models fail, and ``--reuse`` reproduces the detections.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

SRC = str(Path(__file__).resolve().parents[1] / "src")


def _day(net: int, day: int, attack: bool, rng) -> pd.DataFrame:
    t0 = pd.Timestamp("2021-03-01 09:00") + pd.Timedelta(days=day)
    n = 2500
    hosts = [f"10.{net}.0.{i}" for i in range(2, 40)]
    servers = [f"10.{net}.1.{i}" for i in range(1, 6)]
    t = np.sort(rng.uniform(0, 7200, n))
    df = pd.DataFrame({
        "t_start": t, "src_ip": rng.choice(hosts, n), "dst_ip": rng.choice(servers, n),
        "dst_port": rng.choice([80, 443, 53], n), "fwd_pkts": rng.integers(3, 20, n),
        "bwd_pkts": rng.integers(2, 20, n), "fwd_bytes": rng.integers(200, 4000, n),
        "bwd_bytes": rng.integers(200, 9000, n), "attack": "benign", "family": "benign",
    })
    if attack:
        m = 1500  # a flood on one server and a scan of the servers' ports
        flood = pd.DataFrame({
            "t_start": np.sort(rng.uniform(3000, 3900, m)), "src_ip": "172.16.9.9",
            "dst_ip": servers[0], "dst_port": 80, "fwd_pkts": 6, "bwd_pkts": 4,
            "fwd_bytes": 500, "bwd_bytes": 300, "attack": "dos_hulk", "family": "dos"})
        k = 800
        scan = pd.DataFrame({
            "t_start": np.sort(rng.uniform(5000, 5600, k)), "src_ip": "172.16.9.8",
            "dst_ip": rng.choice(servers, k), "dst_port": rng.integers(1, 20000, k),
            "fwd_pkts": 1, "bwd_pkts": 0, "fwd_bytes": 60, "bwd_bytes": 0,
            "attack": "portscan", "family": "portscan"})
        df = pd.concat([df, flood, scan], ignore_index=True)
    df = df.sort_values("t_start").reset_index(drop=True)
    dur = rng.integers(10_000, 2_000_000, len(df))
    df["t_start"] = (t0 + pd.to_timedelta(df["t_start"], unit="s")).astype("datetime64[us]")
    df["duration_us"] = dur.astype(np.int64)
    df["t_end"] = df["t_start"] + pd.to_timedelta(dur, unit="us")
    df["src_port"] = rng.integers(1024, 65000, len(df)).astype(np.int32)
    df["dst_port"] = df["dst_port"].astype(np.int32)
    df["proto"] = np.int16(6)
    df["f_bwd_rst_flags"] = np.float32(0)
    df["is_attack"] = df["family"] != "benign"
    df["attempted"] = False
    df["dataset"], df["day"] = f"net{net}", f"day{day}"
    for c in ("fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes"):
        df[c] = df[c].astype(np.int64)
    for c in ("src_ip", "dst_ip"):
        df[c] = df[c].astype("string")
    return df.sort_values("t_end", kind="stable").reset_index(drop=True)


def _run(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "PROTEUS_EVIDENCE": "v3", "PYTHONPATH": SRC}
    return subprocess.run([sys.executable, "-m", "proteus.evaluation.h1", *args],
                          cwd=cwd, env=env, capture_output=True, text=True, check=False)


@pytest.fixture(scope="module")
def world(tmp_path_factory) -> Path:
    root = tmp_path_factory.mktemp("e2e")
    rng = np.random.default_rng(0)
    for net in (1, 2):
        d = root / "data" / "processed" / f"net{net}"
        d.mkdir(parents=True)
        for day in range(3):
            _day(net, day, attack=day > 0, rng=rng).to_parquet(d / f"day{day}.parquet", index=False)
    return root


def test_cross_network_run_end_to_end(world):
    models = ["proteus", "proteus_cert", "proteus2", "proteus_cert_r", "rate_rules_local",
              "rate_rules_sel"]
    r = _run(world, "--train", "net1", "--test", "net2", "--models", *models,
             "--entity-budgets", "1", "--alert-variants", "--tag", "e2e")
    assert r.returncode == 0, r.stderr[-2000:]
    out = world / "experiments/outputs/h1/net1__net2__loo_labels__e2e"
    c = pd.read_csv(out / "campaigns.csv")
    local = c[(c["threshold"] == "local") & (c["target_fpr"] == 1e-3)]
    for m in [*models, "proteus_cert@cert", "proteus_sys", "proteus2_sys", "proteus2@cert"]:
        assert set(local.loc[local["model"] == m, "day"]) == {"day0", "day1", "day2"}, m
    benign_day = local[local["day"] == "day0"]
    assert (benign_day["attack"] == "(none)").all() and benign_day["alarms_per_hour"].notna().all()
    flood = local[(local["attack"] == "dos_hulk") & (local["model"] == "proteus")]
    assert len(flood) == 2 and flood["detected_strict"].all()
    assert {"entity", "local+ent", "local+k2n5"} <= set(c["threshold"])
    s = pd.read_csv(out / "summary.csv")
    assert "(none)" not in set(s["attack"])
    info = json.loads((out / "run.json").read_text())
    assert info["env"] == {"PROTEUS_EVIDENCE": "v3"} and "--alert-variants" in info["argv"]

    again = _run(world, "--train", "net1", "--test", "net2", "--reuse", str(out),
                 "--models", "proteus", "--tag", "e2e_reuse")
    assert again.returncode == 0, again.stderr[-2000:]
    c2 = pd.read_csv(world / "experiments/outputs/h1/net1__net2__loo_labels__e2e_reuse/campaigns.csv")
    a = local[local["model"] == "proteus"].sort_values(["day", "attack"])["detected"].tolist()
    b = c2[(c2["model"] == "proteus") & (c2["threshold"] == "local") & (c2["target_fpr"] == 1e-3)]
    assert b.sort_values(["day", "attack"])["detected"].tolist() == a


def test_unknown_models_and_bad_flags_fail(world):
    r = _run(world, "--train", "net1", "--test", "net2", "--models", "proteus", "typo", "--tag", "bad")
    assert r.returncode != 0 and "unknown models" in r.stderr
    r = _run(world, "--train", "net1", "--test", "net2", "--models", "proteus",
             "--alert-variants", "--tag", "bad")
    assert r.returncode != 0 and "--entity-budgets" in r.stderr
