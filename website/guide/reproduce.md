# Reproducing the experiments

`scripts/reproduce.sh` runs every experiment of the manuscript with its exact
parameters, grouped in stages. `scripts/paper_tables.sh` then regenerates the tables
and the data of the figures. Both scripts run from the repository root and expect the
virtual environment in `.venv`.

```bash
bash scripts/reproduce.sh data          # convert the datasets (once)
bash scripts/reproduce.sh h1 tables     # cross-network detection, then the tables
bash scripts/reproduce.sh all           # every stage, in order
```

Stages run sequentially, in the order given. Each command writes its standard output
and errors to a `.log` file next to its results, and the log line printed to the
terminal shows the exact command.

## Stages

| Stage | Produces | Notes |
|---|---|---|
| `data` | Parquet files of CIC-IDS2017, CSE-CIC-IDS2018, CTU-13, UGR'16 and CIC-DDoS2019 | Raw files must be in `data/raw/<dataset>`; see [Datasets](datasets.md) |
| `h1` | Cross-network detection in both directions: every Proteus detector fitted, then evaluated together at the same thresholds and alarm budgets | The 2017 → 2018 run takes about 1.5 h and peaks at about 16 GB |
| `baselines` | The detectors Proteus is compared with: KitNET, rate thresholds with selected features, Apollon and the per-flow classifier, TRW and CUSUM | Reuses the `h1` models where it can |
| `systems` | Per-flow alerts of every detector, the window-fidelity complement and the candidate systems (unions) built from them | See [Experiments](experiments.md) |
| `cert` | Free operations on the real campaigns, each campaign without the other attacks of its day, the certificate slack with a re-scoring timer, saturated sub-cores | Reuses the `h1` models |
| `frontier` | Harm frontier per attack type, plain and certified, on the real victim and on the busiest service | |
| `adaptive` | Damage under the adaptive attacker with fixed plans (minimal requests apart), at the operating point (alarm budget 0.5) | Peaks at about 12 GB |
| `query` | Damage under the query attacker (black-box search with hard labels), at the operating point | About 3 h per direction |
| `injection` | Every attack of a test day against many real victims of varying load: hundreds of cases instead of one victim per attack | Several hours |
| `ablation` | Sub-core ablation (`proteus-K` drops sub-core K) | Reuses the `h1` models |
| `poisoning` | Baseline poisoning frontiers | |
| `budget` | Budget certificate (randomised smoothing, the mechanism of BARS) against free operations | |
| `real` | CTU-13 and UGR'16 (two folds each) and CIC-DDoS2019; source-side frontiers on CTU-13 | |
| `shell` | Decision- and score-based attacks on per-flow detectors; calibration of the feedback counter | Needs the `attacks` extra (ART); takes hours |
| `robustness` | Four more seeds, baselines computed without labels, class balance of the training set | Refits the detectors |
| `packets` | Packet-level check of the certificate on the CIC-IDS2017 Friday pcap | Needs the pcap and the `packets` extra (`dpkt`) |
| `kitsune` | Kitsune as published, on the packets of the Friday capture of CIC-IDS2017, against packet-level free operations | Needs the pcap and the `packets` extra |
| `cost` | Evidence throughput, scoring throughput and state per entity | Measured on one CPU core |
| `tables` | Runs `scripts/paper_tables.sh` | Uses only finished runs |

## Commands per stage

The script is the reference: every stage is a short function with the exact commands.
To read them without running anything, ask for a dry run, which prints each command
and the log file it would write:

```bash
DRY=1 bash scripts/reproduce.sh adaptive query
```

The variables used by the commands are defined at the top of the script:

```bash
export PROTEUS_EVIDENCE=v3
PY=".venv/bin/python -m"
O=experiments/outputs/h1
A=$O/csecicids2018__cicids2017__loo_labels__r2   # trained on 2018, tested on 2017
B=$O/cicids2017__csecicids2018__loo_labels__r2   # trained on 2017, tested on 2018
BUD="--entity-budgets 0.5 1 3 10"                # alarm budgets per entity and hour
```

A run directory is named `<train>__<test>__loo_labels__<tag>`; later stages find the
fitted models of `h1` through `--reuse` and `--extra-runs`.

`scripts/paper_tables.sh` writes the tables and the figure data to
`experiments/outputs/paper_tables/`. It takes the directory of the runs and the output
directory from the environment, so it can also run on a copy of the results:

```bash
O=/path/to/runs T=/path/to/tables bash scripts/paper_tables.sh
```

## Determinism

- Seeds are fixed: `--seed 0` in every experiment and variant generator, and
  `random_state=0` in every model.
- Thresholds are calibrated only on benign traffic of the test network (other days),
  with no attack labels.
- Apollon, which is evaluated as a baseline, answers at random by design, so its
  answers vary between runs; each adversarial example against it is evaluated with ten
  draws.

## Environment variables

| Variable | Default | Effect |
|---|---|---|
| `PROTEUS_EVIDENCE` | `v1` | Evidence version. `v2` adds unanswered flows and unanswered destinations; `v3` adds the 1 h and 6 h scales and the source–service pair entity. `proteus` and `proteus_cert` need `v3`. |
| `PROTEUS_TIMER_S` | `0` | Re-scoring timer $\delta$ in seconds; the certificate slack becomes $(2\Delta + \delta)/\tau$. |
| `PROTEUS_PEER` | `0` | `1` adds population baselines: excess over the 99th percentile of services with the same port and protocol (`__xp` features). Experimental; it roughly doubles the evidence cache. |
| `PROTEUS_PAIRBASE` | `0` | `1` adds a pair baseline relative to the busiest normal pair of the same service (evidence v3). Experimental. |

Evidence caches live in separate directories per evidence version, baseline setting and
option (`data/processed/<dataset>/evidence_b_*`), so switching variables does not
overwrite earlier caches.

## Memory

!!! warning
    Runs that test on CSE-CIC-IDS2018 peak at about 16–18 GB of RAM. On a 32 GB machine,
    never run two of them at once. The script runs stages sequentially; if you start
    stages by hand in parallel, check which test dataset each one uses.

The `shell` stage runs its attacks in 8 worker processes (`--workers 8`); reduce it on
smaller machines.
