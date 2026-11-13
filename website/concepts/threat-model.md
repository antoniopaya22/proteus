# Threat model

This page states what Proteus assumes about the network, the attacker and the
deployment, and what lies outside its scope.

## Setting

Proteus monitors a network from a vantage point that sees the traffic of the protected
hosts and summarises it as **flow records** (NetFlow/IPFIX). The detector uses only
fields that any flow exporter provides:

- endpoints, ports and protocol;
- start and end times;
- packet and byte counts per direction;
- TCP flags (in particular, resets sent by the responder).

The flow exporter emits a record when a flow ends or, for long flows, after an
**active timeout** $\Delta$ chosen by the defender. Every packet is therefore accounted
at most $\Delta$ after it was sent. In the CIC datasets $\Delta = 120$ s.

Two deployments are considered:

- **Passive.** The detector raises alerts; the attacker sees nothing.
- **Inline.** An alert also blocks the offending source, which gives the attacker a
  pass/block signal it can query.

## Attacker goal

The attacker wants to complete an attack (exhaust a service, find open ports, guess
credentials) without being alerted. Attacks are measured by what they achieve per unit
of time: requests per second against the victim, ports probed per hour, authentication
attempts per hour. An attack that is never alerted but achieves nothing is not a
success. This is why the [harm frontier](harm-frontier.md) is expressed as a rate.

## Capabilities

The attacker controls the packets its own hosts send, and nothing else. It cannot:

- modify the traffic of other hosts;
- change the victim's responses beyond what its own requests cause;
- tamper with the sensor, the exporter or the detector;
- inject training data.

It may control several sources, at a cost proportional to their number. It may also act
on earlier days to shift the per-entity baselines (baseline poisoning), which is
evaluated as an adaptive attack.

## Knowledge

| Tier | Knows | Used to evaluate |
|---|---|---|
| Transfer | Nothing of the deployed detector; crafts traffic against surrogate models | Per-flow shell and comparison detectors |
| Query | The inline pass/block signal | Per-flow shell, feedback counter |
| Full knowledge | The design, the features, the trained model, the thresholds and the baselines | The certificate and the harm frontier |

The certificate does not rely on any secret. It holds against the full-knowledge
attacker.

## Free and costly operations

Operations on an attack trace are split by their cost to the attacker.

**Free** operations do not reduce the attack's effect:

| Operation | Effect on evidence | Covered by |
|---|---|---|
| Pad packets, insert packets into a flow | Bytes and packets only grow | Certificate (exact) |
| Decoy flows, benign-looking traffic (dilution) | Events are only added | Certificate (exact) |
| Change source ports | None; counters ignore source ports | Certificate (exact) |
| Split a flow, keep a flow open | Accounting time moves by at most $\Delta$ | Certificate (slack $2\Delta/\tau$) |
| Change flags, options, packet order, inter-arrival times | Not used by the core | — |
| Reuse a connection for many requests | Per-connection counts drop | Reuse worst case |
| Request small responses | Response volume drops | Response counters are not in the core |
| Abandon a connection for a new one | Record durations drop | Durations are not in the core |

**Costly** operations reduce the attack's effect or require resources:

| Operation | Effect on evidence | Covered by |
|---|---|---|
| Send at a lower rate, do less | Evidence drops with the attack | Harm frontier |
| Spread over more sources | Source-side evidence is divided | Destination evidence; harm frontier |
| Raise baselines over days (poisoning) | Excess over the baseline drops | Raw and pair sub-cores; growth cap |
| Probe the inline shell | Blocked probes accumulate against the source | Feedback counter |

Padding and inserted packets are free as long as the attacker is not limited by its own
bandwidth. A flood that already saturates the attacker's uplink pays for padding with
rate; the certified frontier covers that combination.

## Assumptions

- **Bounded export delay.** The exporter has a finite active timeout $\Delta$. Zeek's
  `conn.log` emits long connections only when they end, so the guarantee is not bounded
  for datasets built from it (CTU-SME-11).
- **Honest flow export.** Records reflect the packets on the wire; the exporter is not
  compromised and does not drop records selectively.
- **Target-side answers.** Resets and missing answers are produced by the target. An
  attacker who can make a closed port answer is outside the model for those counters.
- **Benign calibration data.** Thresholds and calibrated maxima are fitted on benign
  traffic of the deployment network. Minutes that raised alerts are kept out of the
  baselines.

## Out of scope

- **Attacks without an aggregate footprint**, such as a single exploit request or an SQL
  injection in one connection. A benign request can look identical at the flow level,
  so no flow-based detector can detect them with a guarantee. Proteus covers them with
  the uncertified per-flow shell and reports this limit.
- **Compromise of the sensor, the exporter or the training pipeline.**
- **Alert flooding.** The number of entity alerts is bounded by the number of entities
  and time scales, which limits its effect, but it is not part of the guarantee.
- **Source spoofing for attribution.** With spoofed UDP sources, the alert on the
  destination is correct, but the source it names may not be the attacker.
- **Content inspection.** Proteus does not look at payloads; it works the same on
  encrypted traffic.
