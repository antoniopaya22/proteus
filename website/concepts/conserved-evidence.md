# Conserved evidence

Most flow-based detectors classify each flow from its statistics: packet sizes,
inter-arrival times, flag counts, ratios between directions. An attacker controls
almost all of these for its own traffic, and can move them in either direction at no
cost to the attack. Proteus uses a different kind of input: per-entity counters that
the attacker's free operations can only increase.

## What is conserved

A piece of evidence is **conserved** if no free attacker operation can lower it. Free
operations are those that do not reduce what the attack achieves: padding packets,
inserting extra packets, splitting a flow into several, sending decoy flows, changing
source ports (see [Threat model](threat-model.md)). They all have one thing in common:
they *add* bytes, packets or flows, or they regroup the same packets into different
records. They never remove a packet the attack needs.

Counts of events per entity therefore only grow under these operations, as long as
two rules are respected:

- **Counts, never ratios.** A ratio such as failed attempts over all attempts can be
  diluted by adding benign-looking traffic. The count of failed attempts cannot.
- **Only what the attacker sends, or what it cannot influence.** Forward packets and
  bytes are sent by the attacker. Resets and missing answers come from the target, and
  the attacker cannot turn an unanswered flow into an answered one for a host or port
  that does not answer. The *volume* of the victim's responses, on the other hand, can
  be lowered by requesting small resources, so it is not conserved.

## Entities and counters

Every flow record is an event at the time of its last packet, when an exporter would
emit it. The record contributes to four entities:

| Entity | Key | Purpose |
|---|---|---|
| Destination service (`dsvc`) | destination IP, destination port, protocol | Volume and attempts against one service |
| Destination host (`dhost`) | destination IP | Activity against a host across its ports |
| Source host (`shost`) | source IP | What one source does across destinations (horizontal scans) |
| Source–service pair (`spair`) | source IP, destination IP, port, protocol | One source insisting on one service (brute force), which is otherwise diluted in the service's total traffic |

For each entity Proteus keeps exponentially decayed sums of event weights,

$$
C^{w}_{e,\tau}(t) = \sum_{r \in e,\ t_r \le t} w(r)\, e^{-(t - t_r)/\tau},
$$

and decayed distinct counts,

$$
D_{e,\tau}(t) = \sum_{j} e^{-(t - \ell_j(t))/\tau},
$$

where $\ell_j(t)$ is the last time item $j$ (a port, a peer, a service) was seen.
Repeating an item does not inflate $D$, and inserting events only moves $\ell_j$ later
or adds items, so both quantities are non-decreasing under event insertion. Features are
$\log(1 + C)$ and $\log(1 + D)$.

| Weight | Meaning | Class |
|---|---|---|
| `flows` | one per flow record | conserved (except under connection reuse) |
| `fpkts` | forward packets | conserved |
| `fbytes` | forward bytes | conserved |
| `rst` | flows reset by the responder | conserved |
| `noreply` | flows with no packet back (evidence version 2 and later) | conserved |
| `bpkts`, `bbytes` | backward packets and bytes | response: excluded from the monotone core |
| `conn_s` | connection-seconds (flow durations) | not conserved: excluded from the monotone core |

| Entity | Distinct counts |
|---|---|
| `dsvc` | sources |
| `dhost` | sources, destination ports |
| `shost` | destination hosts, destination services, unanswered destination hosts (version 2 and later) |
| `spair` | none; only `flows`, `fbytes`, `rst` and `noreply` |

Feature names follow the pattern `<entity>__<counter>__t<τ>`, for example
`dsvc__flows__t600` or `shost__n_dhost_nr__t3600`.

## Time scales

Each counter is kept at several time constants:

| τ | Captures |
|---|---|
| 10 s, 60 s | Bursts: floods, fast scans |
| 600 s | Sustained activity over minutes |
| 1 h, 6 h | Slow attacks that accumulate over hours (evidence version 3) |

Decayed counters have no window edges that an attacker could time its traffic around.
The two long scales are kept only for counters that a slow attack cannot avoid
accumulating: flows, forward bytes, resets, unanswered flows and distinct counts.
Long scales also matter for the [certificate](certificate.md): the slack it has to
allow for shrinks as $2\Delta/\tau$.

## Baselines and excess

A busy DNS server and an idle web server should not share a threshold. For every
entity and feature, Proteus computes a **baseline** from other days of the same
network, without labels: the 95th percentile, over every minute of the reference
period, of the per-minute maximum of the feature (0 for minutes in which the entity was
inactive). Rarely used services thus have a baseline of 0.

- Reference days are either every other day of the capture (`loo`, leave one day out,
  the setting used with the 5–10 day datasets) or only the previous days (`prior`, the
  causal setting). In deployment the reference is past traffic.
- Minutes in which the entity was under attack, and the following ten minutes, are
  left out of the baseline (in deployment: minutes that raised alerts).
- The core receives the raw feature $x$ and the **excess** $x - b_e$, but not the
  baseline $b_e$ alone. A model given the baseline learns that rarely used entities are
  suspicious and then flags any traffic to a new destination.
- Pair counters have no baseline: almost every pair is new. An optional pair baseline
  (`PROTEUS_PAIRBASE=1`) compares a pair with the busiest normal pair of the same
  service, and an optional population baseline (`PROTEUS_PEER=1`) compares a service
  with the other services on the same port and protocol. Both are experimental.

The baseline is fixed while a day is scored, and the excess $x - b_e$ is increasing in
$x$, so baselines do not weaken the guarantee against free operations. An attacker can
only influence a baseline by sending traffic on earlier days: that is **baseline
poisoning**, a costly adaptive attack evaluated separately (see
[Harm frontier](harm-frontier.md#baseline-poisoning)).

## Free operations and their effect

The table shows how each free operation affects each conserved counter of the
attacker's entities. "≥" means the counter can only stay equal or grow; "re-timed"
means that the moment the exporter accounts some packets moves, by at most the active
timeout $\Delta$.

| Free operation | `flows` | `fpkts` | `fbytes` | `rst`, `noreply` | distinct counts | Timing |
|---|---|---|---|---|---|---|
| Pad packets | = | = | ≥ | = | = | unchanged |
| Insert packets into a flow | = | ≥ | ≥ | = | = | unchanged, or re-timed if appended at the end |
| Send decoy or benign-looking flows | ≥ | ≥ | ≥ | ≥ | ≥ | unchanged |
| Change source ports of new connections | = | = | = | = | = | unchanged |
| Split a flow (e.g. hop source ports mid-connection) | ≥ | ≥ | = | ≥ | = | re-timed (pieces exported earlier) |
| Keep a flow open longer | = | ≥ | ≥ | = | = | re-timed (exported later) |

Operations that do not re-time flows give an exact guarantee: the evidence of every
variant is at least the evidence of the original at every instant. Operations that
re-time flows need a slack, which the [certificate](certificate.md) accounts for.

Three free operations are *not* in this table because they lower specific counters:

- **Connection reuse** (several requests in one connection, e.g. HTTP keep-alive)
  lowers per-connection counts (`flows`, `rst`, `noreply`) and saves handshake packets.
  Proteus treats it as a second worst case with an explicit protocol budget (see
  [Certificate](certificate.md#connection-reuse)).
- **Requesting small responses** lowers the victim's response volume, which is why
  `bpkts` and `bbytes` are excluded from the monotone core.
- **Abandoning a connection for a new one** lowers the durations in flow records.

## Why per-flow features are not conserved

Per-flow statistics (mean packet size, inter-arrival times, flag ratios, bytes per
packet, flow duration) describe *how* the attacker sends, not *how much* it does. The
attacker can move each of them in either direction with padding, extra packets or
timing, at no cost to the attack. A detector built on them can be evaded by shaping
traffic, and no monotone constraint can fix that, because there is no direction in
which the attacker is constrained. These features are still useful for attacks without
aggregate footprint, and Proteus uses them in its uncertified per-flow shell.

## Durations are not conserved

Connection-seconds look like natural evidence of slow denial-of-service attacks, which
hold many connections open. They are not conserved. An attacker that moves a connection
to a new source port splits its flow record, and the gaps between the pieces are lost
from the records, while the server may keep the abandoned connection open.

This was not evident from flow records alone. The
[packet-level check of the certificate](../guide/packets.md), which applies free
operations to real attack packets and re-exports them as flows, exposed it. Since then
`conn_s` is classified as non-conserved and only unconstrained comparison models use
it.
