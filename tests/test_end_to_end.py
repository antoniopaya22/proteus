"""End-to-end run of the cross-network experiment on a tiny synthetic dataset.

Two networks with three days each (one of them benign only), a flood and a scan on the
others. Runs ``proteus.evaluation.h1`` as a user would (a subprocess with
``PROTEUS_EVIDENCE=v3``) and checks what silently went wrong in the past: every
requested model is in the results for every day, benign-only days report their alarms,
unknown models fail, and ``--reuse`` reproduces the detections.
"""

import json
import os
import re
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
    models = ["proteus", "proteus_cert", "proteus2", "proteus_cert_r", "proteus_cert_p", "proteus_lin", "rate_rules_cr", "rate_rules_local",
              "rate_rules_sel", "flow_clf", "apollon", "rate_rules_r"]
    r = _run(world, "--train", "net1", "--test", "net2", "--models", *models,
             "--entity-budgets", "1", "--alert-variants", "--export-alerts", "--tag", "e2e")
    assert r.returncode == 0, r.stderr[-2000:]
    out = world / "experiments/outputs/h1/net1__net2__loo_labels__e2e"
    c = pd.read_csv(out / "campaigns.csv")
    local = c[(c["threshold"] == "local") & (c["target_fpr"] == 1e-3)]
    for m in [*models, "proteus_cert@cert", "proteus_sys", "proteus_pcr", "proteus2_sys", "proteus2@cert",
              "rules_pcr"]:
        assert set(local.loc[local["model"] == m, "day"]) == {"day0", "day1", "day2"}, m
    benign_day = local[local["day"] == "day0"]
    assert (benign_day["attack"] == "(none)").all() and benign_day["alarms_per_hour"].notna().all()
    flood = local[(local["attack"] == "dos_hulk") & (local["model"] == "proteus")]
    assert len(flood) == 2 and flood["detected_strict"].all()
    assert {"entity", "local+ent", "local+k2n5"} <= set(c["threshold"])
    s = pd.read_csv(out / "summary.csv")
    assert "(none)" not in set(s["attack"])
    from proteus.evaluation.h1 import load_alerts
    al = load_alerts(out / "alerts" / "day1.npz")
    n_rows = len(pd.read_parquet(world / "data/processed/net2/day1.parquet"))
    assert al["proteus__local0.001"].shape == (n_rows,) and al["proteus__local0.001"].any()
    assert "proteus_sys_r__local0.001" in al and "proteus__side" in al
    info = json.loads((out / "run.json").read_text())
    assert info["env"] == {"PROTEUS_EVIDENCE": "v3"} and "--alert-variants" in info["argv"]

    # The window-fidelity complement, with the metrics of h1 and in union with Proteus.
    wf = world / "experiments/outputs/h1/net1__net2__loo_labels__e2e_wf"
    env = {**os.environ, "PROTEUS_EVIDENCE": "v3", "PYTHONPATH": SRC}
    r = subprocess.run([sys.executable, "-m", "proteus.evaluation.window_fidelity", "--test", "net2",
                        "--with-alerts", str(out), "--out", str(wf), "--window", "300"],
                       cwd=world, env=env, capture_output=True, text=True, check=False)
    assert r.returncode == 0, r.stderr[-2000:]
    cw = pd.read_csv(wf / "campaigns.csv")
    lw = cw[(cw["threshold"] == "local") & (cw["target_fpr"] == 1e-3)]
    for m in ["window_fidelity", "proteus", "proteus_w", "proteus_sys_rw"]:
        assert set(lw.loc[lw["model"] == m, "day"]) == {"day0", "day1", "day2"}, m
    same = lw[lw["model"] == "proteus"].sort_values(["day", "attack"])["detected_strict"].tolist()
    assert same == local[local["model"] == "proteus"].sort_values(["day", "attack"])["detected_strict"].tolist()
    both = lw[(lw["model"] == "proteus_w") & (lw["attack"] == "dos_hulk")]
    assert both["detected_strict"].all()  # the union detects at least what Proteus does

    # One calibrated maximum over the sub-cores of two fitted detectors (needs --reuse).
    uni = _run(world, "--train", "net1", "--test", "net2", "--reuse", str(out), "--models",
               "proteus&proteus_cert_r", "--entity-budgets", "1", "--export-alerts", "--tag", "e2e_uni")
    assert uni.returncode == 0, uni.stderr[-2000:]
    uni_dir = world / "experiments/outputs/h1/net1__net2__loo_labels__e2e_uni"
    # Candidate systems from the per-flow alerts of the three runs.
    un = world / "experiments/outputs/h1/net1__net2__loo_labels__e2e_unions"
    r = subprocess.run([sys.executable, "-m", "proteus.evaluation.unions", "--test", "net2",
                        "--alerts", str(out), str(wf), str(uni_dir),
                        "--union", "cand=proteus,rate_rules_r,window_fidelity",
                        "--out", str(un)], cwd=world, env=env, capture_output=True, text=True, check=False)
    assert r.returncode == 0, r.stderr[-2000:]
    cu = pd.read_csv(un / "campaigns.csv")
    assert {"local", "entity"} <= set(cu["threshold"])
    for m in ["cand", "proteus", "proteus&proteus_cert_r", "rate_rules_r", "window_fidelity"]:
        got = cu[(cu["model"] == m) & (cu["threshold"] == "local") & (cu["target_fpr"] == 1e-3)]
        assert set(got["day"]) == {"day0", "day1", "day2"}, m
    pu = cu[(cu["model"] == "proteus") & (cu["threshold"] == "local") & (cu["target_fpr"] == 1e-3)]
    assert pu.sort_values(["day", "attack"])["detected_strict"].tolist() == same
    ca = cu[(cu["model"] == "cand") & (cu["threshold"] == "entity")]
    assert len(ca) and ca.loc[ca["attack"] == "dos_hulk", "detected"].all()

    # The query attacker: two detectors and their union, which nothing passes more
    # easily than a member (the shapes of each search are replayed against the others).
    r = subprocess.run([sys.executable, "-m", "proteus.evaluation.query_attack", "--run", str(out),
                        "--test", "net2", "--targets", "proteus", "rate_rules_local",
                        "--union", "both=proteus,rate_rules_local", "--local", "rate_rules_local",
                        "--attacks", "dos_hulk", "--days", "day1", "--budget", "12", "--grid", "10",
                        "--rmax", "2", "--costly", "--shrink", "--alarm-budget", "1", "--tag", "e2e"],
                       cwd=world, env=env, capture_output=True, text=True, check=False)
    assert r.returncode == 0, r.stderr[-2000:]
    # Thresholds at an alarm budget (the operating point), and three searches per target:
    # free operations, those with minimal requests, those with more sources.
    q = pd.read_csv(out / "query_attack_b1_e2e.csv")
    assert len(q) == 9 and (q["query_flows_per_h"] >= q["search_flows_per_h"]).all()
    mode = np.where(q["costly"], "costly", np.where(q["shrink"], "shrink", "free"))
    for m in ("free", "shrink", "costly"):
        d = q[mode == m].set_index("target")["query_flows_per_h"]
        assert d["both"] <= min(d["proteus"], d["rate_rules_local"]), m
    free = q[mode == "free"].set_index("target")["query_flows_per_h"]
    # At its alarm budget Proteus still alerts on a flood: the threshold is on the scale
    # the attacker's oracle compares with, so the highest rate tried does not pass.
    assert free["proteus"] < q["rmax_flows_per_h"].iloc[0]
    for m in ("shrink", "costly"):
        assert (q[mode == m].set_index("target")["query_flows_per_h"] >= free).all(), m

    # The adaptive attacker at an alarm budget saves after every scenario and resumes.
    adapt = [sys.executable, "-m", "proteus.evaluation.adaptive", "--run", str(out), "--test", "net2",
             "--models", "proteus", "proteus_cert_r", "--local", "rate_rules_local",
             "--certify", "proteus_cert_r", "--alarm-budget", "1", "--grid", "6", "--rmax", "2",
             "--variants", "1", "--days", "day1", "--tag", "e2e"]
    r = subprocess.run(adapt + ["--attacks", "dos_hulk"], cwd=world, env=env, capture_output=True,
                       text=True, check=False)
    assert r.returncode == 0, r.stderr[-2000:]
    a1 = pd.read_csv(out / "adaptive_b1_e2e.csv")
    assert set(a1["attack"]) == {"dos_hulk"} and len(a1) == 3
    assert {"shrink_flows_per_h", "spread_flows_per_h"} <= set(a1.columns)
    assert (out / "adaptive_ladder_b1_e2e.csv").exists()
    r = subprocess.run(adapt + ["--attacks", "dos_hulk", "portscan", "--resume"], cwd=world, env=env,
                       capture_output=True, text=True, check=False)
    assert r.returncode == 0 and "resuming: 1 scenarios" in r.stdout, r.stderr[-2000:]
    a2 = pd.read_csv(out / "adaptive_b1_e2e.csv")
    assert sorted(a2["attack"].unique()) == ["dos_hulk", "portscan"] and len(a2) == 6
    assert a2[a2["attack"] == "dos_hulk"].reset_index(drop=True).equals(a1)

    # Poisoning at the operating point: thresholds at an alarm budget, named b<budget>.
    r = subprocess.run([sys.executable, "-m", "proteus.evaluation.poisoning", "--run", str(out),
                        "--test", "net2", "--model", "proteus_cert_r", "--alarm-budget", "1",
                        "--rounds", "1", "--caps", "none", "--rmax", "2", "--attacks", "dos_hulk"],
                       cwd=world, env=env, capture_output=True, text=True, check=False)
    assert r.returncode == 0, r.stderr[-2000:]
    p = pd.read_csv(out / "poisoning_proteus_cert_r_b1.csv")
    assert len(p) and (p["attack"] == "dos_hulk").all() and np.isfinite(p["threshold"]).all()

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
    # The message lists what h1 offers: every detector of scripts/reproduce.sh is there.
    from test_scripts import script_models
    available = set(re.findall(r"'([^']+)'", r.stderr.split("available:")[1]))
    assert script_models() <= available | {"kitnet_local"}, script_models() - available
    r = _run(world, "--train", "net1", "--test", "net2", "--models", "proteus",
             "--alert-variants", "--tag", "bad")
    assert r.returncode != 0 and "--entity-budgets" in r.stderr
