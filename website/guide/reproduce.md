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
| `data` | Parquet files of CIC-IDS2017, CSE-CIC-IDS2018, CTU-13 and UNSW-NB15 | Raw files must be in `data/raw/<dataset>`; see [Datasets](datasets.md) |
| `h1` | Cross-network detection in both directions for Proteus, Proteus-cert and the comparison detectors; KitNET and rate thresholds on the same evidence | Evidence v3. The 2017 → 2018 run takes about 1.5 h and peaks at about 16 GB |
| `single` | Single-model cores on evidence v1 (appendix tables); free operations on the real campaigns | Default evidence (v1) |
| `review` | Unconstrained calibrated maximum, thresholds at equal alarm budgets, certificate slack with a re-scoring timer | Reuses the `h1` models |
| `ablation` | Sub-core ablation (`proteus-K` drops sub-core K) | Reuses the `h1` models |
| `packets` | Packet-level check of the certificate on the CIC-IDS2017 Friday pcap | Needs the pcap and the `packets` extra (`dpkt`) |
| `budget` | Budget certificate (randomised smoothing, the mechanism of BARS) against free operations | |
| `frontier` | Harm frontier per attack type, plain and certified, with attributable alerts | |
| `adaptive` | Damage under the adaptive attacker; robustness dimension of the defence comparison | |
| `poisoning` | Baseline poisoning frontiers and growth of benign baselines | |
| `real` | CTU-13 (two folds of scenarios) and UNSW-NB15; source-side frontiers and alarms on CTU-13 | |
| `shell` | Decision- and score-based attacks on per-flow detectors; calibration of the feedback counter | Needs the `attacks` extra (ART); takes hours |
| `cost` | Evidence throughput, scoring throughput and state per entity | Measured on one CPU core |
| `tables` | Runs `scripts/paper_tables.sh` | Uses only finished runs |

## Commands per stage

The variables used below are defined at the top of the script:

```bash
PY=".venv/bin/python -m"
O=experiments/outputs/h1
P=data/processed
R=data/raw
A=$O/csecicids2018__cicids2017__loo_labels   # trained on 2018, tested on 2017
B=$O/cicids2017__csecicids2018__loo_labels   # trained on 2017, tested on 2018
V3="proteus proteus_cert core_pair core_mono_dst_x core_cert core_free_dst_b rate_rules_local"
```

### `data`

```bash
for d in cicids2017 csecicids2018 ctu13 unsw_nb15; do
  $PY proteus.datasets.prepare --dataset $d --raw $R/$d --out $P/$d
done
```

### `h1`

```bash
export PROTEUS_EVIDENCE=v3
$PY proteus.evaluation.h1 --train csecicids2018 --test cicids2017 --models $V3 --tag v3
$PY proteus.evaluation.h1 --train cicids2017 --test csecicids2018 --models $V3 --tag v3
# KitNET and rate thresholds on the same evidence, fitted on local benign traffic
$PY proteus.evaluation.h1 --train csecicids2018 --test cicids2017 --reuse ${A}__v3 \
  --models kitnet_local rate_rules_local proteus proteus_cert --tag v3_kitnet
$PY proteus.evaluation.h1 --train cicids2017 --test csecicids2018 --reuse ${B}__v3 \
  --models kitnet_local rate_rules_local proteus proteus_cert --tag v3_kitnet
```

### `single`

```bash
$PY proteus.evaluation.h1 --train csecicids2018 --test cicids2017
$PY proteus.evaluation.h1 --train cicids2017 --test csecicids2018
$PY proteus.evaluation.h1 --train csecicids2018 --test cicids2017 --models core_cert --tag cert
$PY proteus.evaluation.h1 --train cicids2017 --test csecicids2018 --models core_cert --tag cert
$PY proteus.evaluation.free_ops --run ${A}__cert --test cicids2017 \
  --models core_cert core_mono_dst_x --variants 20
```

### `review`

```bash
export PROTEUS_EVIDENCE=v3
# for each direction (shown for 2018 -> 2017)
$PY proteus.evaluation.h1 --train csecicids2018 --test cicids2017 --models proteus_free \
  --entity-budgets 0.5 1 3 10 --tag v3_free
$PY proteus.evaluation.h1 --train csecicids2018 --test cicids2017 --reuse ${A}__v3 \
  --models proteus proteus_cert rate_rules_local core_free_dst_b \
  --entity-budgets 0.5 1 3 10 --tag v3_budget
# certificate slack with a re-scoring timer of 10 s and 60 s
PROTEUS_TIMER_S=10 $PY proteus.evaluation.h1 --train csecicids2018 --test cicids2017 \
  --reuse ${A}__v3 --models proteus proteus_cert --tag v3_timer10
PROTEUS_TIMER_S=60 $PY proteus.evaluation.h1 --train csecicids2018 --test cicids2017 \
  --reuse ${A}__v3 --models proteus proteus_cert --tag v3_timer60
```

### `ablation`

```bash
export PROTEUS_EVIDENCE=v3
p="proteus proteus-0 proteus-1 proteus-2 proteus-3"
c="proteus_cert proteus_cert-0 proteus_cert-1 proteus_cert-2 proteus_cert-3"
$PY proteus.evaluation.h1 --train csecicids2018 --test cicids2017 --reuse ${A}__v3 --models $p $c --tag v3_ablation
$PY proteus.evaluation.h1 --train cicids2017 --test csecicids2018 --reuse ${B}__v3 --models $p --tag v3_ablation
$PY proteus.evaluation.h1 --train cicids2017 --test csecicids2018 --reuse ${B}__v3 --models $c --tag v3_ablation_cert
```

### `packets`

```bash
PROTEUS_EVIDENCE=v3 $PY proteus.evaluation.packet_check \
  --pcap $R/cicids2017_pcap/Friday-WorkingHours.pcap \
  --packets experiments/outputs/packet_check/loic_packets.parquet \
  --victim 192.168.10.50 --attackers 172.16.0.1 --port 80 --start 1499453400 --minutes 25 \
  --out experiments/outputs/packet_check_v3
```

### `budget`

```bash
PROTEUS_EVIDENCE=v3 $PY proteus.evaluation.smoothing \
  --run ${A}__v3 --test cicids2017 --base core_free_dst_b --certified proteus_cert
```

### `frontier`

```bash
export PROTEUS_EVIDENCE=v3
for m in proteus_cert proteus; do
  $PY proteus.evaluation.frontier_exp --run ${A}__v3 --test cicids2017 --model $m --rmax 200
  $PY proteus.evaluation.frontier_exp --run ${B}__v3 --test csecicids2018 --model $m --rmax 200
done
```

### `adaptive`

```bash
export PROTEUS_EVIDENCE=v3
m="proteus proteus_cert core_mono_dst_x core_free_dst_b core_pair"
$PY proteus.evaluation.adaptive --run ${A}__v3 --test cicids2017 \
  --models $m --local rate_rules_local kitnet_local --certify proteus_cert --grid 20
$PY proteus.evaluation.adaptive --run ${B}__v3 --test csecicids2018 \
  --models $m --local rate_rules_local kitnet_local --certify proteus_cert --variants 8 --grid 20
```

### `poisoning`

```bash
$PY proteus.evaluation.poisoning --run $A --test cicids2017 --model core_mono_dst_x --rounds 8 --caps none 0.25 0.1
$PY proteus.evaluation.poisoning --run $A --test cicids2017 --growth-only --caps 0.1 0.25 0.5 1
$PY proteus.evaluation.poisoning --run $B --test csecicids2018 --growth-only --caps 0.1 0.25 0.5 1
export PROTEUS_EVIDENCE=v3
$PY proteus.evaluation.poisoning --run ${A}__v3 --test cicids2017 --model proteus_cert --rounds 8 --caps none 0.25 0.1
$PY proteus.evaluation.poisoning --run ${A}__v3 --test cicids2017 --model proteus --rounds 8 --caps none 0.1
```

### `real`

```bash
fa="s01 s02 s03 s04 s06 s10"; fb="s05 s07 s08 s09 s11 s12 s13"
m="proteus proteus_cert core_both_x core_both_cert core_pair rate_rules_local"
export PROTEUS_EVIDENCE=v3
$PY proteus.evaluation.h1 --train ctu13 --test ctu13 --train-days $fb --test-days $fa \
  --tag foldB_v3 --entity-budgets 1 0.1 --models $m
$PY proteus.evaluation.h1 --train ctu13 --test ctu13 --train-days $fa --test-days $fb \
  --tag foldA_v3 --entity-budgets 1 0.1 --models $m
for h in 1 6; do
  $PY proteus.evaluation.frontier_scan --run $O/ctu13__ctu13__loo_labels__foldB_v3 \
    --test ctu13 --model proteus --fpr 1e-3 --hours $h
done
$PY proteus.evaluation.alarms --run $O/ctu13__ctu13__loo_labels__foldB_v3 --test ctu13 \
  --models proteus proteus_cert --days $fa --top 30
unset PROTEUS_EVIDENCE
$PY proteus.evaluation.h1 --train cicids2017 --test unsw_nb15 \
  --models core_both_x core_both_cert core_src_x rate_rules_local --tag src
```

### `shell`

```bash
$PY proteus.evaluation.aml_feature --dataset cicids2017 --n 100 --workers 8
for f in 1e-3 1e-4; do
  $PY proteus.evaluation.feedback --run $A --test cicids2017 --block-fpr $f
  $PY proteus.evaluation.feedback --run $B --test csecicids2018 --block-fpr $f
done
```

### `cost`

```bash
PROTEUS_EVIDENCE=v3 $PY proteus.evaluation.cost --run ${A}__v3 --test cicids2017 \
  --day wednesday --models proteus proteus_cert core_mono_dst_x
```

### `tables`

```bash
bash scripts/paper_tables.sh
```

It writes LaTeX tables and figure data to `experiments/outputs/paper_tables/`:
detection across networks at two false-positive rates, confidence intervals (Wilson
intervals for campaigns, bootstrap over days for alarms), the comparison of defences,
the adaptive-attacker table, the sub-core ablations and the harm frontiers.

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
