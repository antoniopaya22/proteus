# Harm frontier

The [certificate](certificate.md) removes the free operations from the attacker's
options. What remains is to do less: send at a lower rate, probe fewer ports per hour,
try fewer passwords per hour. Any detector can be evaded this way at some rate, so the
useful question is *at which rate*. The **harm frontier** answers it.

## Definition

For an attack with a given flow shape, against a given victim with its real background
traffic, the harm frontier is the **highest attack rate that raises no attributable
alert**.

It is reported in the attack's own units: flows per hour, which for the attacks studied
approximates requests, probes or authentication attempts (one per connection), and
forward packets per hour. These are quantities an operator can reason about: "a brute
force below this many attempts per hour against this SSH server goes unnoticed".

There are two frontiers:

| Frontier | Scores | Meaning |
|---|---|---|
| **Plain** | the core on the attack's features, $f(x)$ | Highest rate that raises no alert, for the attack as observed. |
| **Certified** | the worst case over free operations, $f(x - s)$ | Highest rate that the attacker can reach by combining a lower rate with *any* free operation. |

The certified frontier is the one that bounds an informed attacker. It is also what
covers an attacker limited by its own bandwidth, who pays for padding with rate: the
combination of a lower rate and free operations is exactly what it measures.
Both frontiers hold for the attack as replayed: one trace of the campaign, thinned to
the rate, over ten minutes at that point of the day. Another attack at the same rate is
another trace, with a frontier of its own. The paper reports the certified frontier of
Proteus-cert, whose evidence connection reuse with unchanged requests cannot lower, next to
the damage an adaptive attacker does to it. Bursts that move flows by more than the
exporter's active timeout fall outside the certificate and can exceed it.

Comparing defences by their frontier compares them by the damage they let through,
rather than by an evasion rate on a fixed set of adversarial examples.

## Attributable alerts

On a busy victim, the background traffic alone sometimes crosses the threshold: these
are the benign false positives the threshold allows. If those alerts counted against
the attacker, any rate, however small, would look detected, and the frontier would be
zero without saying anything about the attack.

Proteus therefore counts only **attributable alerts**: an alert, on an attack flow or on
a background flow whose evidence the attack raised, in a minute where the background
alone raises none. The minutes in which the background alone alerts (`noisy_minutes`)
are computed once per scenario and excluded.

## Scenarios

Each scenario reuses real data from the test network:

- **target**: the real victim of a campaign;
- **background**: its real traffic that day;
- **flow shapes**: sampled from the real campaign (packets, bytes, flags, answers).

Two shapes of scenario are supported:

- **Destination side** (denial of service, brute force, vertical scan): every attack
  flow goes to one target, over the real traffic towards that target.
- **Source side** (horizontal scan): one fresh source replays the real probes of the
  busiest scanning source, keeping their destinations and ports, over the real traffic
  towards those destinations (`proteus.evaluation.frontier_scan`).

The features of an attack flow depend only on flows that share its service, its
destination host or its source, so this background is exact for the attack flows.

## Nested attacks and bisection

The attack is drawn once at the highest rate $r_{\max}$, and each attack event gets a
uniform mark $u \in [0, 1)$. The attack at rate $r$ keeps the events with
$u < r / r_{\max}$. Attacks at different rates are therefore **nested**: a higher rate
is a superset of a lower one.

Adding events never lowers evidence, and the core is monotone, so "the attack raises an
attributable alert" is monotone in $r$. A binary search between $r_{\min}$ and
$r_{\max}$ then finds the frontier exactly, up to the chosen resolution. If even
$r_{\min}$ alerts, the frontier is reported as below $r_{\min}$; if $r_{\max}$ stays
silent, as above $r_{\max}$. For the system, which alerts when either of its two
detectors does, the paper reads the frontier on the grid of rates of the adaptive
attacker, at the operating point of 0.5 alarms per hour: the highest rate at which the
attack, sent as it ran, leaves both detectors quiet.

## How to read a frontier

- **Lower is better for the defender.** The frontier is the most an attacker can do
  without being noticed.
- **Compare it with the real campaign's rate.** If the real attack ran far above the
  frontier, the attacker would have to slow down by that factor to stay silent; if it
  ran below, the detector misses it as it is.
- **It is specific to a victim and its background.** A busy server with a high baseline
  hides more than an idle one. Frontiers are reported per attack type and victim.
- **Long time scales lower the frontier of slow attacks.** A counter with $\tau = 6$ h
  accumulates a sustained trickle that never shows at the scale of minutes.
- **An infinite frontier** means that no rate up to $r_{\max}$ alerted: the detector
  does not see that attack shape at all on that victim.

## The adaptive attacker

The frontier fixes the attack shape and varies only the rate. The adaptive experiment
(`proteus.evaluation.adaptive`) lets the attacker also change the shape. For every
scenario, its damage is the highest rate at which no attacker flow raises an
attributable alert, maximised over:

- the plain attack;
- random combinations of free operations (padding, inserted packets, split flows,
  decoys, new source ports);
- **mimicry**: padding and inserted packets until each attack flow reaches the median
  forward packets and bytes per packet of the victim's benign traffic, only adding,
  never removing;
- **connection reuse**: up to 20 requests per connection, one after another, within each
  service's limit (SSH 6 attempts, FTP 3); connections open at the same time cannot be
  merged, so a slow denial of service gains nothing from it;
- **bursts**: each minute's flows sent in its first six seconds;
- reuse and bursts together;
- the same plans with **minimal requests**: every TCP request carries the fewest
  payload bytes its service allows (18 for HTTP, 24 for FTP, 500 for SSH). No
  certificate covers this (assumption A5); it is reported apart.

The system is quiet only when both of its detectors are, at the same rate and with the
same plan, and every detector is at its operating point (0.5 alarms per hour).

Rates are scanned on a geometric grid, without assuming monotonicity in the rate: the
attacker needs only one quiet rate, and detectors without monotone structure need not
be monotone in it. For monotone detectors, free operations only raise evidence, so the
best variant is the plain attack, and for certified detectors the certified frontier is
reported as well. The same procedure is applied to the comparison detectors
(an unconstrained core, rate thresholds, KitNET), which makes the comparison one of
damage under the same attacker.

## The query attacker

The adaptive attacker tries a list of plans that the defender wrote. A real attacker is
not limited to that list, so Proteus is also evaluated against one that *searches*
(`proteus.evaluation.query_attack`).

- **What it knows.** Nothing about the detector: no model, no thresholds, no features.
- **What it controls.** The shape of its own traffic (padding, inserted packets, split
  flows, decoys, source ports, requests per connection, bursts, minimal requests and,
  as a costly option, the number of sources) and its rate.
- **What it observes.** One bit per attempt: whether any of its flows was alerted.

It wants the highest rate that passes, because rate is damage. It first probes the rate
of the plain attack by bisection. Then it changes one or two parameters of its best
shape and tries the result one step above its best rate. If the attempt is alerted,
the change is dropped at the cost of one query. If it passes, the new shape is better,
and its rate is pushed up until it is alerted again. The search goes on from the best
shape found until the query budget is spent.

<div class="qa"></div>

Every rate it reports is backed by an attempt that really passed, so it is a lower
bound on the damage a detector lets through: with more queries, or a smarter search,
it could be higher. The target can be one detector or a union of detectors, which is
quiet only when every member is. The search does not break the certificate. What it
finds, when it finds something, is what the certificate does not cover: carrying many
requests in one connection, which is why the deployed system includes sub-cores fitted
only on evidence that connection reuse cannot lower.

## Baseline poisoning

Free operations cannot lower the evidence of the day being scored, but an attacker who
sends traffic on *earlier* days can raise an entity's baseline, and so lower the excess
features the next day. This is the other adaptive attack, modelled in
`proteus.core.poisoning` and run by `proteus.evaluation.poisoning`.

The strongest such attacker is modelled as follows. In deployment, minutes that raised
an alert are left out of the baseline, so poisoning traffic must itself stay below the
frontier. On every reference minute, the attacker sends the attack just below the
current frontier; the baseline of each entity the attack touches is recomputed under
that traffic (never below the old one). Iterating gives the frontier after $k$ baseline
refreshes (days).

Two mechanisms bound it:

- **Ceiling.** The core uses raw conserved counters as well as excess, and the raw
  destination and pair sub-cores have no baseline at all. Even with an infinite
  baseline, the raw evidence remains. The frontier with the baseline set to infinity on
  every touched entity is a hard limit on what poisoning can achieve.
- **Growth cap.** An optional cap limits how much a baseline may rise per refresh, in
  the log units of the counters, which bounds the rate of poisoning per day. A cap also
  limits legitimate growth, and the experiment measures how often benign baselines grow
  by more than a given cap (`--growth-only`).

Long time scales help here too: poisoning traffic sustained over days is itself
visible on the 1 h and 6 h counters.
