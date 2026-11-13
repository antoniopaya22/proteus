# Checking the certificate on packets

The [certificate](../concepts/certificate.md) is proved on flow records, under
assumptions about how an exporter turns packets into records. Experiments that apply
free operations directly to flow records (`free_ops`) inherit those assumptions. The
packet-level check removes that shortcut: it applies the free operations to real attack
*packets*, exports both the original and the modified traces to flow records with the
same exporter, computes the evidence of both, and checks the bound.

## What is checked

For a window of a real capture $X$ and a packet-level variant $X'$, the certificate
predicts, for every decayed counter $E$ with time constant $\tau$ and every time $t$,

$$
E_{X'}(t + \Delta) \;\ge\; e^{-2\Delta/\tau}\, E_X(t).
$$

`proteus.evaluation.packet_check` checks this inequality at every flow end of $X$ for:

- the victim's **destination-service** and **destination-host** counters, and
- each attacker's **source-host** and **source–service-pair** counters,

at every conserved counter and time scale (by default
$\tau \in \{10, 60, 600, 3600, 21600\}$ s). It reports the number of violations
(expected: none) and the tightest observed ratio $E_{X'}(t + \Delta) / E_X(t)$ next to
the bound $e^{-2\Delta/\tau}$. The first variant is the identity, as a sanity check.

## Components

| Module | Role |
|---|---|
| `proteus.packets.pcap` | Reads IPv4 TCP/UDP packets from a pcap or pcapng file (with `dpkt`), keeping packets to or from given hosts in a time window |
| `proteus.packets.exporter` | Turns packets into bidirectional flow records, as a NetFlow/IPFIX exporter would |
| `proteus.packets.ops` | Free operations on the attacker's own packets |
| `proteus.evidence.features` | The same evidence computation used everywhere else |

The exporter keys a flow by its 5-tuple, takes the sender of the first packet as the
initiator, and exports a record when:

- the flow has been active for `active_s` (the active timeout $\Delta$);
- no packet was seen for `idle_s` (idle timeout);
- a RST is seen, or both sides have sent a FIN.

Every packet is thus accounted in a record whose end time lies between the packet's
time and $\Delta$ after it, which is the premise of the certificate.

## Free operations on packets

None of these operations removes or delays an attacker packet. They add bytes, add
packets or change header fields the attacker controls, which may change how packets are
grouped into flows.

| Operation | Function | What it does | Effect on records |
|---|---|---|---|
| Padding | `ops.pad` | Adds a fixed number of bytes to every attacker packet | More bytes |
| Inserted packets | `ops.insert` | After a random share of attacker packets, sends one more small packet of the same connection (e.g. a duplicate ACK) | More packets; may extend flows |
| Source-port hopping | `ops.hop_ports` | Moves each attacker connection to a fresh source port every *n* of its packets; replies follow the new port | Splits records; pieces are exported earlier |
| Decoys | `ops.decoys` | Sends single SYN packets from attacker hosts to given targets, spread over the trace | New flows, many unanswered |

Each variant draws a random combination: padding of 0, 40 or 400 bytes; inserted packets
after 0 %, 20 % or 100 % of attacker packets; port hopping every 3 or 20 packets, or
none; and 0, 500 or 5000 decoys towards the attacked service and another port of the
victim.

## Running it

The check needs the `packets` extra (`dpkt`) and `Friday-WorkingHours.pcap` from the
original CIC-IDS2017 capture (see [Datasets](datasets.md)). The window used in the
manuscript covers the LOIC DDoS against the web server:

```bash
PROTEUS_EVIDENCE=v3 python -m proteus.evaluation.packet_check \
    --pcap data/raw/cicids2017_pcap/Friday-WorkingHours.pcap \
    --packets experiments/outputs/packet_check/loic_packets.parquet \
    --victim 192.168.10.50 --attackers 172.16.0.1 --port 80 \
    --start 1499453400 --minutes 25 \
    --out experiments/outputs/packet_check_v3
```

or simply `bash scripts/reproduce.sh packets`.

| Option | Meaning |
|---|---|
| `--pcap` | Capture file |
| `--packets` | Parquet cache of the filtered packets; read from it if it exists |
| `--victim`, `--attackers`, `--port` | Victim address, attacker addresses and attacked port |
| `--start`, `--minutes` | Window start (epoch seconds) and length |
| `--delta` | Exporter active timeout $\Delta$ (default 120 s) |
| `--variants` | Number of variants, the first being the identity (default 12) |
| `--taus` | Time constants checked |
| `--seed`, `--out` | Seed and output directory |

Reading the pcap is the slow part; the `--packets` cache makes later runs fast. The
results are written to `packet_check_<victim>_<port>.csv` in the output directory, with
one row per variant, counter and entity: points checked, violations, the tightest ratio
and the bound.

## What it found

Beyond confirming the bound for the conserved counters, the packet-level check is how
**connection durations** were found not to be conserved. Source-port hopping splits a
connection into several records, and the gaps between the pieces disappear from the
records, while the server may keep the abandoned connection open. Flow-level
experiments could not show this, because they modify records directly. Since then,
connection-seconds are classified as non-conserved and excluded from the monotone core
(see [Conserved evidence](../concepts/conserved-evidence.md#durations-are-not-conserved)).
