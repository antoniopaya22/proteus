"""Certify alerts of a monotone core on synthetic evidence (no dataset needed).

    python examples/certificate.py

Evidence features are log1p of decayed per-destination counters at three time scales
(10 s, 10 min, 1 h). A gradient-boosting core is trained with monotonicity
constraints, so more evidence never lowers its score. An alert is certified when the
score of the evidence minus the slack 2Δ/τ still exceeds the threshold: then every
variant of the trace built with free operations (padding, splitting, decoys, new
source ports) alerts too. The longer the time scale, the smaller the slack.
"""

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier

from proteus.core.certify import slack, worst_case_features

rng = np.random.default_rng(0)
names = ["dst__flows__t10", "dst__flows__t600", "dst__flows__t3600",
         "dst__fbytes__t10", "dst__fbytes__t600", "dst__fbytes__t3600"]
conservation = dict.fromkeys(names, "conserved")


def evidence(n, rate):
    """log1p of decayed counters for traffic at ``rate`` (arbitrary units)."""
    base = rng.lognormal(np.log(rate), 0.5, size=(n, 1))
    scales = np.array([0.2, 1.0, 1.5, 3.0, 5.0, 6.0])
    return np.log1p(base * scales * rng.uniform(0.8, 1.2, size=(n, len(names))))


X = np.vstack([evidence(4000, 1.0), evidence(600, 25.0)])
y = np.r_[np.zeros(4000), np.ones(600)]
cst = np.ones(len(names), dtype=int)  # every feature is conserved: score can only grow
core = HistGradientBoostingClassifier(monotonic_cst=cst.tolist(), random_state=0).fit(X, y)

benign = core.predict_proba(evidence(5000, 1.0))[:, 1]
threshold = float(np.quantile(benign, 1 - 1e-3))        # local threshold, FPR 1e-3
attacks = evidence(1000, 25.0)
alerts = core.predict_proba(attacks)[:, 1] >= threshold
print(f"threshold {threshold:.3f}, alerts on {alerts.mean():.1%} of the attack flows")

delta = 120.0  # active timeout of the flow exporter (s)
for keep in (["__t10", "__t600", "__t3600"], ["__t600", "__t3600"]):
    cols = [j for j, n in enumerate(names) if any(n.endswith(k) for k in keep)]
    sub = HistGradientBoostingClassifier(monotonic_cst=cst[cols].tolist(),
                                         random_state=0).fit(X[:, cols], y)
    thr = float(np.quantile(sub.predict_proba(evidence(5000, 1.0)[:, cols])[:, 1], 1 - 1e-3))
    s = slack([names[j] for j in cols], conservation, delta)
    worst = worst_case_features(attacks[:, cols], cst[cols], s)
    alert = sub.predict_proba(attacks[:, cols])[:, 1] >= thr
    certified = alert & (sub.predict_proba(worst)[:, 1] >= thr)
    print(f"scales {' '.join(k[3:] + ' s' for k in keep):<20} slack {np.round(s[:len(keep)], 3)}  "
          f"alerts {alert.mean():6.1%}  certified {certified.mean():6.1%}")
