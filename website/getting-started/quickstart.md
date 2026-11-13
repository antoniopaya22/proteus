# Quickstart

This page takes you from a fresh clone to the cross-network detection tables. It
assumes you have followed [Installation](installation.md) and that the virtual
environment lives in `.venv` at the repository root.

!!! note "What to expect"
    Proteus is research code. The commands below are the ones used for the manuscript,
    with the same parameters. They are batch experiments on full capture days, not a
    streaming service, and some of them take hours.

## 1. Run the tests

```bash
uv run pytest
```

If the tests pass, the package, numba and the monotone gradient boosting of
scikit-learn work on your machine.

## 2. Convert a dataset

The detection experiments train on one network and test on another. The main pair is
the corrected CIC-IDS2017 and CSE-CIC-IDS2018 (Liu et al., CNS 2022), distributed by
the DistriNet group at
[intrusion-detection.distrinet-research.be/CNS2022/Datasets](https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/).

Download `CICIDS2017_improved.zip` (328 MB) and `CSECICIDS2018_improved.zip` (9.7 GB),
unzip the per-day CSV files and convert them:

```bash
mkdir -p data/raw/cicids2017 data/raw/csecicids2018
# unzip the CSV files of each dataset into its folder, then:
.venv/bin/python -m proteus.datasets.prepare --dataset cicids2017 \
    --raw data/raw/cicids2017 --out data/processed/cicids2017
.venv/bin/python -m proteus.datasets.prepare --dataset csecicids2018 \
    --raw data/raw/csecicids2018 --out data/processed/csecicids2018
```

Each capture day becomes `data/processed/<dataset>/<day>.parquet` in the common flow
schema, and `summary.csv` lists flows per day and attack. See
[Datasets](../guide/datasets.md) for the schema, the labels and the other datasets.

To convert every dataset used by the detection stages at once (the raw files must be
in `data/raw/<dataset>`), run the `data` stage:

```bash
bash scripts/reproduce.sh data
```

## 3. Run the cross-network detection stage

`scripts/reproduce.sh` runs each experiment of the manuscript with its exact parameters.
The `h1` stage trains Proteus, Proteus-cert and the comparison detectors on one dataset
and tests them on the other, in both directions:

```bash
bash scripts/reproduce.sh h1
```

Internally, the stage selects evidence version 3 and calls the H1 experiment. The first
of its runs is:

```bash
export PROTEUS_EVIDENCE=v3
.venv/bin/python -m proteus.evaluation.h1 --train csecicids2018 --test cicids2017 \
    --models proteus proteus_cert core_pair core_mono_dst_x core_cert core_free_dst_b rate_rules_local \
    --tag v3
```

`PROTEUS_EVIDENCE=v3` matters: the default evidence version (`v1`) has neither the
long time scales (1 h and 6 h) nor the source–service pair entity, and the `proteus`
and `proteus_cert` detectors are only defined on version 3.

!!! warning "Time and memory"
    The 2017 → 2018 direction takes about an hour and a half and peaks at about 16 GB
    of RAM. Do not start a second run that tests on CSE-CIC-IDS2018 while it is running.

The first run of each direction computes the evidence features and caches them under
`data/processed/<dataset>/` (`evidence_b_*` directories); later stages reuse that cache and the trained
models (`--reuse`).

## 4. Regenerate the tables

```bash
bash scripts/paper_tables.sh
# or, equivalently, as the last stage:
bash scripts/reproduce.sh tables
```

The script only uses runs that finished (those with a `summary.csv`) and skips the
tables whose inputs are missing, so you can run it after any subset of stages.

## Where the outputs go

| Path | Content |
|---|---|
| `experiments/outputs/h1/<train>__<test>__loo_labels__<tag>/` | One directory per run: `campaigns.csv` (detection per attack campaign), `summary.csv`, `false_alarms.csv`, the fitted models (`models.pkl`) and, after later stages, frontier and adaptive CSVs. |
| `experiments/outputs/h1/*.log` | Log of every command run by `reproduce.sh`. |
| `experiments/outputs/paper_tables/` | LaTeX tables and the CSV data of the figures, written by `paper_tables.sh`. |
| `experiments/outputs/packet_check*/`, `experiments/outputs/aml_feature/` | Outputs of the packet-level check and of the attacks on per-flow detectors. |

The run directory name encodes the direction: `csecicids2018__cicids2017__loo_labels__v3`
was trained on CSE-CIC-IDS2018 and tested on CIC-IDS2017, with leave-one-day-out
baselines (`loo`) and attack minutes masked out of the baselines (`labels`).

To print the detection results of a run in the terminal:

```bash
.venv/bin/python -m proteus.evaluation.report_h1 \
    experiments/outputs/h1/csecicids2018__cicids2017__loo_labels__v3
```

## Next steps

- [Reproducing the experiments](../guide/reproduce.md) lists every stage.
- [Experiment modules](../guide/experiments.md) documents each command and its options.
- [How Proteus works](../concepts/index.md) explains what the numbers mean.
