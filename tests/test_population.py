import numpy as np
import pandas as pd

from proteus.evidence import baseline as bl


def test_population_is_robust_to_poisoning_one_peer():
    keys = [f"10.0.0.{i}:22/6" for i in range(200)] + ["10.0.1.1:80/6"]
    base = pd.DataFrame({"c": np.r_[np.linspace(0, 2, 200), 5.0]}, index=keys)
    q = keys.index("10.0.0.7:22/6")
    pop0 = bl.population_for("dsvc", base, pd.Series(keys))
    poisoned = base.copy()
    poisoned.iloc[q, 0] = 50.0  # the attacker raised its victim's own baseline
    pop1 = bl.population_for("dsvc", poisoned, pd.Series(keys))
    # One poisoned service among 200 peers moves the 0.99 quantile very little.
    assert pop1.iloc[q, 0] - pop0.iloc[q, 0] < 0.5
    # Groups are per port: the web server is its own group.
    assert pop0.iloc[-1, 0] == 5.0
    # Unseen keys get their group's population baseline; unseen groups get 0.
    new = bl.population_for("dsvc", base, pd.Series(["10.9.9.9:22/6", "10.9.9.9:443/6"]))
    assert new.iloc[0, 0] == pop0.iloc[0, 0] and new.iloc[1, 0] == 0.0


def test_peer_group_of_hosts_is_one_group():
    g = bl.peer_group("dhost", pd.Index(["10.0.0.1", "10.0.0.2"]))
    assert (g == "all").all()
