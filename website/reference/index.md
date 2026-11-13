# API reference

Proteus is organised as a single Python package, `proteus`, under `src/proteus/`. The
pages in this section document the modules that implement the guarantee. The rest of
the package is described in the table below and in the docstrings of each module.

| Package | Contents |
|---|---|
| `proteus.datasets` | Readers and conversion to Parquet for CIC-IDS2017, CSE-CIC-IDS2018, CTU-13, UNSW-NB15, UGR'16, CIC-DDoS2019 and CTU-SME-11; canonical labels; staged processing of captures too large for memory |
| `proteus.evidence` | Decayed per-entity counters and distinct counts (`counters`), evidence features and their conservation class (`features`), per-entity baselines (`baseline`), window-by-window evidence for very large captures (`chunked`) |
| `proteus.core` | Certificate (`certify`), combination of sub-cores (`combine`), harm frontier (`frontier`), baseline poisoning (`poisoning`), explanations (`explain`), declared rules (`rules`), empirical monotonicity check (`verify`) |
| `proteus.packets` | pcap reading, a NetFlow/IPFIX-style flow exporter and free operations on packets |
| `proteus.shell` | Per-flow classifier (the shell) |
| `proteus.attacks` | Attacker operations on flow records: free operations and slowing down |
| `proteus.baselines` | Apollon (published code and corrected implementation), fixed rate thresholds, KitNET, randomised smoothing |
| `proteus.evaluation` | Experiments and tables; see [Experiment modules](../guide/experiments.md) |

## Documented modules

| Page | Module | What it contains |
|---|---|---|
| [Certificate](certify.md) | `proteus.core.certify` | Slack per feature, worst-case features, worst case under connection reuse |
| [Combination of sub-cores](combine.md) | `proteus.core.combine` | `MaxCore` and `CalibratedMax` |
| [Harm frontier](frontier.md) | `proteus.core.frontier` | Scenarios, nested attacks, attributable alerts, bisection of the frontier |
| [Evidence counters](counters.md) | `proteus.evidence.counters` | Exponentially decayed sums and distinct counts per entity |
| [Baselines](baselines.md) | `proteus.evidence.baseline` | Per-entity baselines, excess features, population baselines |

The API is research code and may change between versions. Feature names, entity keys
and output file names are the most stable parts.
