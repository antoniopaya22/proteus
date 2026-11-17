# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Query attacker in the traffic space (`proteus query-attack`): a black-box search over
  the shape and the rate of the attacker's traffic that only observes whether it was
  alerted. The shapes found against one target are replayed against the others, so a
  union of detectors is never reported easier to evade than one of its members.
- Structured plans for the adaptive attacker: connection reuse, bursts and spreading over
  sources; damage of a union of detectors from the per-rate ladder.
- Proteus-cert-R, fitted only on evidence that connection reuse cannot lower, and the
  certificate against connection reuse in the evaluation.
- Comparison detectors: threshold random walk and CUSUM on flow records
  (`proteus classic`), rate thresholds with selected features and on reuse-safe evidence,
  and Apollon as a per-flow detector across networks.
- `--export-alerts` in the cross-network evaluation, `proteus.evaluation.unions` to
  compare candidate systems from per-flow alerts, and one calibrated maximum over several
  detectors (`a&b`).
- Pilot of a window-fidelity detector as an uncertified complement of the core
  (`proteus window-fidelity`).
- Evidence computed window by window with its state carried over, for traces that do
  not fit in memory.
- Website: animated step-by-step walkthroughs, a demo of the query attacker and a
  glossary.

### Changed

- The system is the union of two detectors: Proteus-fast (`proteus`, every time scale)
  and Proteus-cert (`proteus_cert_r`, long scales on the evidence that connection reuse
  cannot lower), evaluated as `proteus_pcr`. Documentation, tables and scripts follow;
  the earlier certified detector on every conserved counter stays as a comparison.
- `scripts/reproduce.sh` and `scripts/paper_tables.sh` rewritten for the current
  experiments: new stages (`baselines`, `systems`, `cert`, `query`, `robustness`), a dry
  run (`DRY=1`) that prints every command, and tables generated from any copy of the
  results (`O=... T=...`).
- Splitting flows (`attacks.operators.split_flows`) no longer loops over flows: same
  output, about a thousand times faster.
- Detection of a campaign also reported under a strict criterion (at least five alerted
  flows and 1% of the campaign); false alarms reported per alerted entity as well as
  per destination and minute.
- The adaptive attacker no longer scores a monotone detector above two consecutive
  alerting rates (same results, less time).

### Fixed

- Per-entity baselines: the minutes left out of a day (attacks and the minutes that
  follow) were not discounted when counting the minutes of that day.

## [0.1.0] - 2026-11-13

First public release, accompanying the manuscript in preparation.

### Added

- Command line interface: `proteus <command>` runs every experiment (`prepare`, `detect`,
  `frontier`, `adaptive`, `poisoning`, `packets`, `tables`, …).
- `examples/certificate.py`: certification of alerts on synthetic evidence, no dataset
  needed.
- Apache License 2.0.
- `proteus` Python package (Python ≥ 3.11) for network intrusion detection on conserved
  traffic evidence.
- Conserved evidence: exponentially decayed counters and distinct counts per destination
  service, destination host, source host and source–service pair, at time scales from
  10 s to 6 h, with per-entity baselines learned from benign traffic.
- Monotone core: gradient-boosted sub-cores with monotonicity constraints, combined by a
  calibrated maximum and thresholded on local benign traffic (Proteus and Proteus-cert).
- Certificate of alerts against free attacker operations, with slack 2Δ/τ (or
  (2Δ+δ)/τ with a re-scoring timer), and a second worst case for connection reuse.
- Harm frontier with attributable alerts, adaptive attacker and baseline poisoning
  analysis.
- Per-flow shell with feedback of blocked probes into the core.
- Packet-level tools: pcap reader, flow exporter and free operations on packets.
- Dataset converters for corrected CIC-IDS2017 and CSE-CIC-IDS2018, CTU-13, UNSW-NB15,
  UGR'16, CIC-DDoS2019 and CTU-SME-11, to a common Parquet flow schema.
- Baselines: Apollon (published code and a reimplementation), fixed rate
  thresholds, KitNET and randomised smoothing.
- Evaluation framework: cross-network detection, free-operation and packet-level checks,
  harm frontiers, adaptive attacks, poisoning, attacks on per-flow detectors, cost,
  multidimensional comparison of defences and table generation.
- `scripts/reproduce.sh` and `scripts/paper_tables.sh` to reproduce the experiments
  stage by stage.
- Documentation website built with MkDocs Material, in English and Spanish.
