# Monotone core

The core is the part of Proteus that turns conserved evidence into alerts. It is built
so that adding evidence can never lower its score. That property, together with
[conserved evidence](conserved-evidence.md), is what makes alerts certifiable.

## Monotone gradient boosting

Each model in the core is a gradient-boosted tree ensemble
(`HistGradientBoostingClassifier` from scikit-learn) trained with **monotone increasing
constraints** on every evidence feature: raw counters and excess over baseline. The
learner enforces the constraint during training, so for any two inputs $x \le x'$
(coordinate-wise) the model satisfies $f(x) \le f(x')$.

Monotonicity is enforced by the learner, but a wiring mistake (a wrong column order, a
wrong sign, a feature left unconstrained) would silently void it without changing
accuracy. `proteus.core.verify` therefore checks every trained model empirically on
held-out data by increasing each feature and looking for a score that drops.

## Sub-cores

The core is made of four **sub-cores**. Each one is a monotone model trained on one
kind of evidence only:

| Sub-core | Evidence | Why it is separate |
|---|---|---|
| Destination | destination service and host counters, and their excess over baselines | Volume, attempts and scans against a target; does not depend on how many sources the attacker uses |
| Source | source host counters and their excess | Horizontal scans that touch thousands of hosts once each |
| Pair | raw source–service pair counters | Brute force: one source insisting on one service, diluted in the service's total traffic |
| Raw destination | raw destination counters, without baselines | Bounds what poisoning a baseline can hide |

Keeping the sides apart prevents shortcuts. A model that sees destination and source
evidence together can learn that a denial of service comes from one heavy source, a
pattern that spreading the attack over bots defeats. A destination-only model cannot
learn that shortcut. Since no sub-core depends on another, defeating one leaves the
others in place.

## Calibrated maximum

The sub-cores are combined by a **calibrated maximum** (`CalibratedMax`). Each sub-core
score $f_i(x)$ is mapped through $F_i$, the empirical distribution function of that
sub-core's scores on local benign traffic, and the core outputs

$$
f(x) = \max_i F_i\big(f_i(x)\big).
$$

A plain maximum with one threshold is dominated by the sub-core with the highest benign
scores; lowering the false-alarm rate then raises the threshold above everything the
other sub-cores produce, and silences them. After calibration, every sub-core speaks in
the same unit (a benign percentile), and one threshold treats them evenly.

Each $F_i$ is non-decreasing and the maximum of non-decreasing functions is
non-decreasing, so the calibrated maximum is monotone and the certificate applies to
the combination as a whole. The $F_i$ are fitted on benign traffic only; the sub-cores
are not refitted.

A sub-core whose benign scores tie at its maximum for more than the target
false-positive rate cannot separate anything at that rate. This happens when a model
saturates on a network unlike its training network. Such a sub-core can be left out of
the maximum (`--exclude-saturated` in the H1 experiment); the result is still monotone.

## Local thresholds

Thresholds are calibrated where the detector runs, from benign traffic of the test
network only, at a target false-positive rate, and **without attack labels**. In the
experiments, the threshold for a test day is set on clean benign flows of the other
days of the same network.

A threshold learned on the training network does not transfer to another network: the
score distributions of benign traffic differ too much. The training network is used to
learn the *shape* of the sub-cores; the test network decides where to cut. The same
calibration data fits the $F_i$ of the calibrated maximum.

## Proteus and Proteus-cert

The same four sub-cores are trained twice, with different time scales:

| Detector | Time scales | Behaviour |
|---|---|---|
| `proteus` | 10 s, 60 s, 600 s, 1 h, 6 h | Reacts quickly to bursts. Short-scale features carry a large certification slack, so many of its alerts are not certified. |
| `proteus_cert` | 600 s, 1 h, 6 h | Slower to react, but its slack is small, so its alerts are usually certifiable. |

A deployment runs both: Proteus for timeliness, Proteus-cert as the certified floor.
The [Certificate](certificate.md) page explains why the time scale decides the slack.

## Why monotonicity

Monotonicity serves two purposes.

**It is the right inductive bias for conserved evidence.** More attempts against a
service, more unanswered destinations from a source, more bytes towards a victim should
never make traffic look *less* suspicious. An unconstrained model is free to learn
non-monotone patterns that hold in its training data, for instance a dip at a typical
attack rate, and an attacker can exploit them by adding traffic. The constraint removes
that freedom.

**It makes the worst case computable.** If the attacker can only raise evidence, and
the model can only raise its score with evidence, the worst case over every
free-operation variant is the original input. When some operations re-time flows,
evidence can drop by a known amount per feature, and the worst case is the input shifted
down by that amount. In both cases it is one model evaluation, with no search over
variants and no randomisation.

!!! note "Comparison detectors"
    The experiments also train unconstrained models on the same evidence
    (`core_free_dst_b`, `proteus_free`) to measure the price of the constraint, fixed
    per-feature rate thresholds (`rate_rules_local`), which are monotone too, and
    KitNET on the same decayed statistics (`kitnet_local`). See
    [Experiment modules](../guide/experiments.md).

## Explaining alerts and declared rules

An alert can be explained by walking down the calibrated maximum
(`proteus.core.explain`): first the sub-core that gave the maximum, then, within it,
the evidence that is most unusual on local benign traffic and how many times the
entity's normal it is. Because the model is monotone, these features can only push the
score up, so they are the evidence an analyst should look at first.

Operators can also declare rules as thresholds on conserved counters
(`proteus.core.rules`), such as "no source reaches 100 unanswered destinations per
hour" or "the honeypot receives no flows". A rule is an indicator $x \ge \theta$ on a
conserved feature, so it is monotone and certified in the same way as the core. Rules
are reported apart from the learned core.
