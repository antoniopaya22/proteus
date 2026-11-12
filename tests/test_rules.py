import numpy as np
import pandas as pd

from proteus.core.rules import Rule, fire, report


def frame():
    return pd.DataFrame({
        "shost__n_dhost_nr__t3600": np.log1p([5, 50, 500, 2000]),
        "dsvc__flows__t600": np.log1p([10, 10, 10, 10]),
        "dst_ip": ["a", "b", "honeypot", "c"],
    })


def test_rules_fire_in_counts_and_respect_scope():
    ev = frame()
    rules = [Rule("scan", "shost__n_dhost_nr__t3600", 100),
             Rule("honeypot", "dsvc__flows__t600", 1, where={"dst_ip": "honeypot"})]
    f = fire(rules, ev)
    assert f["scan"].tolist() == [False, False, True, True]
    assert f["honeypot"].tolist() == [False, False, True, False]


def test_certified_rules_need_margin():
    ev = frame()
    specs = {"shost__n_dhost_nr__t3600": "conserved"}
    r = [Rule("scan", "shost__n_dhost_nr__t3600", 480)]
    plain = fire(r, ev)["scan"].tolist()
    cert = fire(r, ev, specs, delta_s=120.0)["scan"].tolist()
    assert plain == [False, False, True, True]
    # Slack 2*120/3600 = 0.067 in log1p: 500 drops below 480 (log 500/480 = 0.04), 2000 stays.
    assert cert == [False, False, False, True]


def test_report_flags_rules_the_benign_traffic_breaks():
    ev = frame()
    benign = np.array([True, True, False, True])
    rep = report([Rule("scan", "shost__n_dhost_nr__t3600", 100)], ev, benign)
    row = rep.iloc[0]
    assert row["benign_violation"] == 1 / 3 and row["attack_flows_caught"] == 1
    assert row["benign_lo"] < 1 / 3 < row["benign_hi"]
