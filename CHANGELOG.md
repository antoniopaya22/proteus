# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
