# Getting started

Proteus is a research codebase. It contains the detector, the evidence pipeline, the
dataset converters and every experiment of the accompanying manuscript. There is no
packaged service to deploy: you install the Python package, convert the datasets you
need and run the experiments from the command line.

Getting a first result takes three steps.

| Step | What you do | Page |
|---|---|---|
| 1. Install | Create a virtual environment, install the package with its development extras and run the tests. | [Installation](installation.md) |
| 2. Prepare data | Download one corrected CIC dataset and convert it to the common Parquet flow schema. | [Quickstart](quickstart.md#2-convert-a-dataset) |
| 3. Run a stage | Run the cross-network detection stage and regenerate the tables. | [Quickstart](quickstart.md#3-run-the-cross-network-detection-stage) |

Before running the larger experiments, it helps to read
[How Proteus works](../concepts/index.md): the outputs refer to conserved evidence,
sub-cores, certified alerts and harm frontiers, and those terms are defined there.

!!! note "Hardware"
    The unit tests run on a laptop. The full experiments were run on a 16 vCPU machine
    with 32 GB of RAM, and the runs that evaluate on CSE-CIC-IDS2018 need 16–18 GB each.
    See [Installation](installation.md#hardware).
