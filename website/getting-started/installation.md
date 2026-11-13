# Installation

## Requirements

- Python 3.11 or newer. The experiments of the manuscript were run with Python 3.12.3.
- A C toolchain is not needed: every dependency ships binary wheels for Linux and macOS.
- [uv](https://docs.astral.sh/uv/) is recommended, but plain `pip` works too.

The core package depends on `numpy`, `pandas`, `pyarrow`, `scipy`, `scikit-learn` and
`numba` (the decayed counters are compiled with numba).

## Install the package

Clone the repository and install it in editable mode with the development extras
(`pytest` and `ruff`):

=== "uv"

    ```bash
    git clone https://github.com/antoniopaya22/proteus.git
    cd proteus
    uv venv
    uv pip install -e ".[dev]"
    ```

=== "pip"

    ```bash
    git clone https://github.com/antoniopaya22/proteus.git
    cd proteus
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -e ".[dev]"
    ```

`scripts/reproduce.sh` and `scripts/paper_tables.sh` call `.venv/bin/python`, so keep
the virtual environment in `.venv` at the repository root.

## Optional extras

Two experiments need extra dependencies:

| Extra | Installs | Needed by |
|---|---|---|
| `attacks` | `adversarial-robustness-toolbox>=1.20` (ART) | `proteus.evaluation.aml_feature`: decision- and score-based attacks on per-flow detectors (`shell` stage) |
| `packets` | `dpkt>=1.9` | `proteus.packets.pcap` and `proteus.evaluation.packet_check`: reading pcap files (`packets` stage) |

=== "uv"

    ```bash
    uv pip install -e ".[attacks,packets]"
    ```

=== "pip"

    ```bash
    pip install -e ".[attacks,packets]"
    ```

## Run the tests

```bash
uv run pytest
```

The suite runs in under a minute and needs no dataset. Besides the usual unit tests,
it checks the properties the guarantee depends on: that decayed counters never
decrease when events are inserted, that the certificate's slack is computed per time
scale (with and without a re-scoring timer), that free operations on packets respect
the bound after flow export, that trained cores respect their monotonicity
constraints and that a maximum of monotone cores stays monotone.

## Versions used in the manuscript

| Package | Version |
|---|---|
| Python | 3.12.3 |
| numpy | 2.5.4 |
| pandas | 3.1.1 |
| scikit-learn | 1.9.1 |
| scipy | 1.18.1 |
| numba | 0.68.1 |
| pyarrow | 26.0.1 |
| adversarial-robustness-toolbox | 1.20.1 |
| dpkt | 1.9.8 |

Newer versions are expected to work. If you need byte-for-byte reproduction of the
tables, pin these versions.

## Hardware

The experiments were run on an AWS `c6a.4xlarge` instance: 16 vCPU, 32 GB of RAM and
no GPU. Nothing in Proteus uses a GPU.

!!! warning "Memory"
    Runs that evaluate on CSE-CIC-IDS2018 peak at about 16–18 GB of RAM. On a 32 GB
    machine, do not run two of them at the same time. `scripts/reproduce.sh` runs its
    stages one after another for this reason.

Disk space is dominated by the datasets: the corrected CSE-CIC-IDS2018 archive alone is
about 9.7 GB compressed, and each converted dataset keeps a cache of evidence features
next to its Parquet files (`data/processed/<dataset>/evidence*/`).

Next: [Quickstart](quickstart.md).
