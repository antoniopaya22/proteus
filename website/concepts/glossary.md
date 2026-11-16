# Glossary

Plain definitions of the terms used across this documentation.

| Term | Meaning |
|---|---|
| **Flow record** | A summary of one connection as a router or sensor exports it: who talked to whom, when, and how many packets and bytes went each way. Proteus works on these, not on packet contents. |
| **Entity** | What an alert is about: a destination service (address and port), a destination host, a source host or a source–service pair. |
| **Counter (tally)** | A running total kept per entity, such as connections received or distinct sources seen. It fades with time; the *time scale* says how fast (from ten seconds to six hours). |
| **Baseline** | The normal level of a counter for one entity, learned from ordinary days of the same network. |
| **Free operation** | Something an attacker can do to its own traffic without weakening the attack: pad packets, insert packets, split a connection, add decoy connections, change source ports. |
| **Costly operation** | Something that does weaken the attack or needs resources: sending less, going slower, using many machines. |
| **Conserved evidence** | Counters that free operations can only keep or raise, never lower. |
| **Monotone model** | A model whose score cannot go down when any of its inputs goes up. |
| **Alert** | Proteus saying that an entity is under attack now, with the counters that triggered it. |
| **Certified alert** | An alert with a proof that no combination of free operations could have avoided it. |
| **Slack** | The small amount a counter can drop because of *when* the sensor accounts packets. The certificate subtracts it before checking the alert again. |
| **Connection reuse** | Carrying many requests in one connection. It lowers per-connection counters, so it has its own certificate, on evidence it cannot lower. |
| **Harm frontier** | The highest attack rate that raises no alert: what the attacker keeps by going slower. |
| **Campaign** | One episode of one attack type, separated from the next by more than ten minutes. Detection is counted per campaign. |
| **False alarm (per entity)** | An entity alerted on benign traffic, counted once per ten minutes. |
| **Local calibration** | Setting thresholds from benign traffic of the network being protected, with no attack labels of that network. |
| **Per-flow shell** | An ordinary detector that judges each connection, placed next to the core for attacks that fit in a few connections. It carries no guarantee. |
| **Adaptive attacker** | An attacker that picks its rate and its disguise from a list of plans, knowing the detector. |
| **Query attacker** | An attacker that knows nothing about the detector and searches for a disguise, learning after each attempt only whether it was alerted. |
