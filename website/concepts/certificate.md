# Certificate

A Proteus alert is **certified** when no combination of the attacker's free operations
could have avoided it: every variant of the attack trace obtained with free operations
is also alerted, at most $\Delta$ later. Checking this costs one extra evaluation of the
core per alert. This page explains why.

## Step 1: free operations only add, or re-time by at most Δ

Free operations act on flow records in two ways.

- **Pure additions.** Padding, inserting packets into a flow, sending decoy flows and
  changing source ports only add weight to existing events or add new events. Every
  decayed counter of every variant is at least the original one, at every instant.
- **Re-timing.** Splitting a flow, or keeping it open by appending packets, also changes
  *when* the exporter accounts its packets. The pieces of a split flow are exported
  earlier; an extended flow is exported later.

Re-timing is bounded by the exporter. A NetFlow/IPFIX exporter emits a record when a
flow ends, after an idle timeout, or after the **active timeout** $\Delta$ for long
flows. Every packet is therefore accounted in a record whose event time lies between
the packet's send time and $\Delta$ after it, in the original trace and in every
variant.

## Step 2: a bound on every counter

Take a decayed counter with time constant $\tau$. In the original trace $X$, a packet
sent at time $p$ is accounted at some $t_r \in [p, p + \Delta]$. In a variant $X'$, the
same packet is accounted at some $t'_r \in [p, p + \Delta]$, so
$t_r - \Delta \le t'_r \le t_r + \Delta$. Compare the counter of $X'$ at $t + \Delta$
with that of $X$ at $t$. Every packet counted in $X$ by time $t$ is already counted in
$X'$ by time $t + \Delta$, and its contribution has decayed for at most $2\Delta$ longer.
The variant may have more contributions, never fewer. Hence, for every entity $e$, weight $w$ and time $t$:

$$
C^{w}_{e,\tau}[X'](t + \Delta) \;\ge\; e^{-2\Delta/\tau}\; C^{w}_{e,\tau}[X](t).
$$

The same bound holds for decayed distinct counts, because the last-seen time of each
item also moves by at most $\Delta$. When no operation re-times a flow, the bound holds
with $\Delta = 0$: evidence never decreases.

Features are on a $\log(1 + \cdot)$ scale, and $\log(1 + a c) \ge \log(1 + c) + \log a$
for $0 < a \le 1$. So every evidence feature of any variant, read $\Delta$ later, is at
least the original feature minus a **slack**

$$
s_\tau = \frac{2\Delta}{\tau}.
$$

Baselines are fixed while a day is scored, so baseline features need no slack. The
excess $x - b$ inherits the slack of $x$.

## Step 3: one extra evaluation

Let $s$ be the vector of slacks, one per feature, and $f$ the monotone core. Every
free-operation variant has features at least $x - s$ at the corresponding time, and $f$
is monotone, so

$$
f(x') \;\ge\; f(x - s) \quad \text{for every variant } x'.
$$

The worst case over the infinite set of variants is a single evaluation. An alert is
certified when

$$
f(x - s) \;\ge\; \theta,
$$

where $\theta$ is the local threshold. Then the same entity is alerted in every variant,
at most $\Delta$ later. This is the computation in `proteus.core.certify`: `slack`
builds $s$ from the time constant encoded in each feature name, and
`worst_case_features` returns $x - s$.

No randomisation, secret or perturbation budget on the features is involved. The
guarantee holds against an attacker who knows the model, its weights, the baselines and
the thresholds.

## Slack per time scale

The slack depends only on the exporter's active timeout and the counter's time
constant. For $\Delta = 120$ s, the active timeout of the exporter used in the CIC
datasets:

| τ | Slack $2\Delta/\tau$ (log units) | Share of evidence guaranteed, $e^{-2\Delta/\tau}$ |
|---|---|---|
| 10 s | 24 | ≈ 4 × 10⁻¹¹ |
| 60 s | 4 | ≈ 0.018 |
| 600 s | 0.4 | ≈ 0.67 |
| 1 h | 0.067 | ≈ 0.94 |
| 6 h | 0.011 | ≈ 0.99 |

At ten seconds the slack wipes out any evidence, so short scales cannot support a
certificate. From ten minutes on, the slack is a modest shift. This is why
**Proteus-cert** keeps only the scales of 600 s and more, while **Proteus** keeps all of
them for speed (see [Monotone core](monotone-core.md#proteus-and-proteus-cert)).

The defender controls $\Delta$: lowering the exporter's active timeout shrinks the slack
at every scale.

## Re-scoring timer δ

"Every variant alerts at most $\Delta$ later" presumes that the detector looks at the
entity at that moment. A detector that scores an entity only when one of its records
arrives might not. A deployment therefore also re-scores active entities on a timer of
period $\delta$. The alert of a variant then comes by $t + \Delta + \delta$, and the
slack becomes

$$
s_\tau = \frac{2\Delta + \delta}{\tau}.
$$

In the code, `slack(..., timer_s=δ)` implements this, and the experiments set $\delta$
with the environment variable `PROTEUS_TIMER_S` (0 by default).

## Connection reuse

Carrying many requests in one connection (HTTP keep-alive, several login attempts per
SSH session) is free for many attacks, and it lowers per-connection counts. The bound
above does not cover it, because it merges records instead of adding or re-timing them.

Proteus treats connection reuse as a second worst case of the same model
(`reuse_worst_case`). Starting from $x - s$:

- per-connection counters (`flows`, `rst`, `noreply`) go to their minimum;
- forward packet counters drop by a factor of at most $c = 5$, that is, by $\log 5$ on
  the log scale (handshake and teardown packets saved per request);
- forward bytes and distinct counts do not change.

The factor $c$ is an assumption about the protocol: a connection adds about four forward
packets of handshake and teardown, so $c = 5$ holds when every request carries at least
one forward packet of its own. An alert that survives this second worst case is
certified against free operations combined with any connection reuse, under that
assumption.

## Assumptions

The certificate holds when:

1. **Bounded accounting delay.** Every packet is accounted in a flow record whose event
   time is at most $\Delta$ after the packet was sent. This holds for NetFlow/IPFIX
   exporters with an active timeout; it does not hold for loggers that emit a long
   connection only when it ends, such as Zeek's `conn.log`.
2. **Free operations keep the attack.** They keep every packet of the trace with its
   send time, addresses, destination port and protocol, and only add weight or packets.
3. **No merging.** They do not merge the records of different connections. Merging is
   connection reuse, treated as a separate worst case.
4. **Target-side answers.** The victim resets, or leaves unanswered, the attacker's
   flows in the variant whenever it did in the original. This holds when the missing
   answer comes from the target (an absent host, a closed or filtered port), as in
   scans. An attacker who can draw answers by choosing its requests can lower reset and
   unanswered counts, and an alert that rests only on them is not certified against
   that choice.

## What the certificate does not cover

| Not covered | Where it is handled |
|---|---|
| Sending at a lower rate, or doing less | The [harm frontier](harm-frontier.md) measures the highest rate that stays silent, plain and certified. |
| Poisoning the baselines by acting on earlier days | Evaluated as an adaptive attack; bounded by the raw sub-cores and by an optional growth cap. See [Harm frontier](harm-frontier.md#baseline-poisoning). |
| Requesting small responses | Response counters are excluded from the core. |
| Attacks without aggregate footprint | Covered only by the uncertified per-flow shell. |
| Exporters without an active timeout | The bound needs a finite $\Delta$. |

The certificate is about evidence and the model. It says nothing about whether the
threshold is well chosen; that is a matter of the false-alarm budget of the network.

!!! note "Checking it empirically"
    The bound is proved, but its premises are easy to get wrong in code (a feature
    misclassified as conserved, an exporter detail). The repository checks it on flow
    records (`proteus.evaluation.free_ops`) and on real packets re-exported as flows
    (`proteus.evaluation.packet_check`, see
    [Checking the certificate on packets](../guide/packets.md)).
