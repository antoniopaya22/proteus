# Experiment modules

Every experiment is a module of `proteus.evaluation` with a command-line interface.
Run any of them with `--help` to see all options:

```bash
python -m proteus.evaluation.h1 --help
```

Most modules take a **run directory** (`--run`) produced by `h1`, which holds the fitted
models (`models.pkl`) and the evidence settings, and the name of the **test dataset**
(`--test`). Thresholds are always calibrated on benign traffic of the test network at a
target false-positive rate (`--fpr`, default `0.001`). Set `PROTEUS_EVIDENCE=v3` when a
run was trained on evidence version 3. Seeds default to `0`.

The table summarises the modules; each one is described below.

| Module | Purpose |
|---|---|
| [`h1`](#h1) | Train and test detectors across networks; detection per campaign and false alarms |
| [`report_h1`](#report_h1) | Print detection and false-alarm tables of `h1` runs |
| [`clean`](#clean) | In-dataset per-flow evaluation with the protocol of the literature |
| [`free_ops`](#free_ops) | Free operations on real campaigns: empirical check of the guarantee on flow records |
| [`frontier_exp`](#frontier_exp) | Harm frontier per attack type (destination side) |
| [`frontier_scan`](#frontier_scan) | Harm frontier of horizontal scans (source side) |
| [`adaptive`](#adaptive) | Damage under an adaptive attacker (rate, free operations, mimicry) |
| [`poisoning`](#poisoning) | Baseline poisoning and growth of benign baselines |
| [`packet_check`](#packet_check) | Check of the certificate on real packets |
| [`smoothing`](#smoothing) | Whether a budget certificate (randomised smoothing) covers free operations |
| [`aml_feature`](#aml_feature) | Feature-space evasion attacks on per-flow detectors |
| [`feedback`](#feedback) | Calibration of the shell-feedback counter |
| [`alarms`](#alarms) | Alarms per entity on real traffic, attributed to a side |
| [`cost`](#cost) | Throughput and state per entity |
| [`bench`](#bench) | Multidimensional comparison of defences |
| [`tables`](#tables) | LaTeX tables and figure data |

## `h1`

The main experiment. It asks whether a monotone core over conserved evidence detects
volumetric, scanning and brute-force campaigns across networks at a low false-alarm
rate. Detectors are trained on one dataset and tested on another, with thresholds
calibrated on benign traffic of the test network.

```bash
PROTEUS_EVIDENCE=v3 python -m proteus.evaluation.h1 \
    --train csecicids2018 --test cicids2017 \
    --models proteus proteus_cert rate_rules_local --tag v3
```

| Option | Meaning |
|---|---|
| `--train`, `--test` | Training and test datasets (required) |
| `--models` | Detectors to train and evaluate (default: all) |
| `--reuse RUN` | Evaluate the fitted models of an earlier run instead of training; `--models` may then name maxima such as `a+b` |
| `--tag` | Suffix of the output directory |
| `--baseline {loo,prior}` | Reference days of the baselines: leave one day out, or previous days only |
| `--mask {labels,none}` | Leave attack minutes out of the baselines, or not |
| `--entity-budgets` | Also calibrate thresholds to at most this many alarms per hour |
| `--train-days`, `--test-days` | Restrict training or testing to some capture days |
| `--balance {cap,type,type_entity,none}` | Class balance of the training set |
| `--exclude-saturated FPR` | Drop sub-cores that cannot reach this FPR on local benign traffic from calibrated maxima |
| `--train-thresholds` | Also evaluate thresholds calibrated on the training network |

Main detector names:

| Name | Detector |
|---|---|
| `proteus`, `proteus_cert` | Calibrated maximum of the four sub-cores, all scales / scales ≥ 600 s (evidence v3) |
| `proteus-K`, `proteus_cert-K` | The same without sub-core K (ablation) |
| `proteus_free` | The same four sub-cores without monotonicity constraints |
| `core_pair` | Pair sub-core alone |
| `core_mono_dst`, `core_mono_dst_x`, `core_cert` | Single monotone destination cores: raw, raw plus excess, longest scale only |
| `core_src_x`, `core_both_x`, `core_both_cert` | Source core, and maxima of destination and source cores |
| `core_free_dst_b` | Unconstrained destination core with baselines |
| `rate_rules_local` | Fixed per-feature thresholds fitted on local benign traffic |
| `kitnet_local` | KitNET on the same decayed statistics, fitted on local benign traffic |
| `flow_clf` | Per-flow classifier (the shell) |

Outputs, in `experiments/outputs/h1/<train>__<test>__<baseline>_<mask>[__<tag>]/`:
`campaigns.csv`, `summary.csv`, `false_alarms.csv` and `models.pkl`.

## `report_h1`

Prints campaign detection per attack and detector, and false alarms, for one or more
`h1` runs.

```bash
python -m proteus.evaluation.report_h1 experiments/outputs/h1 --by-family
```

Options: run directories or a parent directory, `--threshold` (default `local`),
`--by-family`, `--models`.

## `clean`

Per-flow evaluation inside one dataset, with the protocol common in the literature:
random 80/20 split per capture day, binary labels with "Attempted" flows counted as
benign, training on a subsample and evaluation on the whole test split. It places the
per-flow shell next to published per-flow results.

```bash
python -m proteus.evaluation.clean --dataset cicids2017 --seeds 0 1 2 3 4
```

Options: `--dataset`, `--seeds`, `--with-port`, `--cap-attack`, `--cap-benign`,
`--out`.

## `free_ops`

Empirical check of the guarantee on flow records. For every attack type, it takes a
window of the real campaign against its victim plus the real traffic towards the victim,
and applies random combinations of free operations (`proteus.attacks.operators`) to the
attack flows. It checks that:

- with operations that do not re-time flows, no original flow's score decreases;
- if the original campaign has a certified alert, every variant alerts on the victim no
  later than $\Delta$ after it;

and it reports what the attacker gains against uncertified detection.

```bash
python -m proteus.evaluation.free_ops \
    --run experiments/outputs/h1/csecicids2018__cicids2017__loo_labels__cert \
    --test cicids2017 --models core_cert core_mono_dst_x --variants 20
```

Options: `--run`, `--test`, `--models`, `--fpr`, `--variants`, `--seed`.

## `frontier_exp`

Harm frontier per attack type on the test network: real victim, its real background,
flow shapes from the real campaign, model and local threshold as in `h1`. Reports the
plain frontier (flows/s, flows/h, forward packets/h), the certified frontier and the
rate the real campaign used. Only attributable alerts count (see
[Harm frontier](../concepts/harm-frontier.md)).

```bash
PROTEUS_EVIDENCE=v3 python -m proteus.evaluation.frontier_exp \
    --run experiments/outputs/h1/csecicids2018__cicids2017__loo_labels__v3 \
    --test cicids2017 --model proteus_cert --rmax 200
```

| Option | Meaning |
|---|---|
| `--model` | Detector of the run |
| `--delta` | Exporter active timeout used for the certified frontier (default 120 s) |
| `--rmax` | Highest rate tried, flows/s |
| `--fpr`, `--seed` | Target false-positive rate and seed |

Output: `frontier_<model>_<fpr>_attr.csv` in the run directory.

## `frontier_scan`

Harm frontier of horizontal scans, on the source side (for example, the botnet scans of
CTU-13). For every day with a scan campaign, the probes of the busiest scanning source
are replayed from one fresh source at rate $r$, keeping destinations and ports, over the
real traffic towards the same destinations. Reports the frontier in probes and distinct
destinations per minute, and the rate the real bot used.

```bash
PROTEUS_EVIDENCE=v3 python -m proteus.evaluation.frontier_scan \
    --run experiments/outputs/h1/ctu13__ctu13__loo_labels__foldB_v3 \
    --test ctu13 --model proteus --fpr 1e-3 --hours 6
```

Options: `--model`, `--family` (default `portscan`), `--fpr`, `--delta`, `--rmax`
(probes/s), `--hours` (duration of the replayed scan; long time scales need hours),
`--seed`.

## `adaptive`

Damage under an adaptive attacker. For every scenario of `frontier_exp`, the attacker
chooses a rate and a combination of free operations, including mimicry of the victim's
benign traffic. Its damage is the highest rate at which no attacker flow raises an
attributable alert. Rates are scanned on a geometric grid, without assuming monotonicity
in the rate, so detectors without guarantees are evaluated fairly.

```bash
PROTEUS_EVIDENCE=v3 python -m proteus.evaluation.adaptive \
    --run experiments/outputs/h1/csecicids2018__cicids2017__loo_labels__v3 \
    --test cicids2017 --models proteus proteus_cert core_free_dst_b \
    --local rate_rules_local kitnet_local --certify proteus_cert --grid 20
```

| Option | Meaning |
|---|---|
| `--models` | Fitted models of the run, or maxima of them written `a+b` |
| `--extra-runs` | More runs of the same direction to take models from |
| `--local` | Unsupervised detectors fitted per day on local benign traffic |
| `--certify` | Detectors for which the certified frontier is also reported |
| `--variants` | Random free-operation variants per rate |
| `--grid`, `--rmin`, `--rmax` | Geometric grid of rates |
| `--attacks` | Restrict to some attack types |

Outputs: `adaptive_<fpr>.csv` and `adaptive_ladder_<fpr>.csv` in the run directory.

## `poisoning`

Baseline poisoning (see `proteus.core.poisoning`). For every attack scenario, the
frontier after $k = 0, \dots, \text{rounds}$ baseline refreshes in which the attacker
poisons the whole reference period just below the current frontier, with and without a
cap on baseline growth per refresh, and the ceiling with an infinite baseline.

```bash
PROTEUS_EVIDENCE=v3 python -m proteus.evaluation.poisoning \
    --run experiments/outputs/h1/csecicids2018__cicids2017__loo_labels__v3 \
    --test cicids2017 --model proteus_cert --rounds 8 --caps none 0.25 0.1
```

| Option | Meaning |
|---|---|
| `--model` | A model of the run, or `a+b` for the maximum of several |
| `--rounds` | Number of baseline refreshes (days) |
| `--caps` | Growth caps per refresh, in log1p units; `none` means uncapped |
| `--growth-only` | Only measure the day-to-day growth of benign baselines |
| `--rmax`, `--attacks`, `--fpr`, `--seed` | As in `adaptive` |

## `packet_check`

Checks the certificate on packets: free operations applied to real attack packets,
re-exported as flow records, never lower the victim's or the attackers' evidence beyond
the slack. See [Checking the certificate on packets](packets.md).

```bash
PROTEUS_EVIDENCE=v3 python -m proteus.evaluation.packet_check \
    --pcap data/raw/cicids2017_pcap/Friday-WorkingHours.pcap \
    --packets experiments/outputs/packet_check/loic_packets.parquet \
    --victim 192.168.10.50 --attackers 172.16.0.1 --port 80 \
    --start 1499453400 --minutes 25 --out experiments/outputs/packet_check_v3
```

## `smoothing`

Does a certificate stated as a perturbation budget cover the attacker's free operations?
An unconstrained core is smoothed with feature-wise Gaussian noise
(`proteus.baselines.smoothing`, a reimplementation of the mechanism behind BARS), and
each alerted attack flow gets a certified radius. Random free-operation variants are
then applied, and the experiment measures whether each variant stays inside the radius.
The share of flows whose alert Proteus-cert certifies is reported next to it.

```bash
PROTEUS_EVIDENCE=v3 python -m proteus.evaluation.smoothing \
    --run experiments/outputs/h1/csecicids2018__cicids2017__loo_labels__v3 \
    --test cicids2017 --base core_free_dst_b --certified proteus_cert
```

Options: `--base`, `--certified`, `--fpr`, `--scales` (noise scales), `--variants`,
`--flows` (attack flows per campaign), `--n` (noise samples), `--seed`.

## `aml_feature`

Feature-space evasion attacks against per-flow detectors, with the protocol of the
literature made explicit: in-dataset 80/20 split, CICFlowMeter features scaled to
$[0, 1]$, HopSkipJump (decision-based) and ZOO (score-based) attacks through ART
targeted to the benign class, functional features restored after the attack, and
success rates reported per $L_\infty$ budget. It needs the `attacks` extra.

```bash
python -m proteus.evaluation.aml_feature --dataset cicids2017 --n 100 --workers 8
```

Options: `--dataset`, `--n` (attack flows per model), `--cap-attack`, `--cap-benign`,
`--workers`, `--n-adv` (examples added by adversarial training), `--out`, `--resume`,
`--seed`.

## `feedback`

Calibrates the feedback of shell alerts into the core. In inline mode, the core keeps
per source host the decayed count of flows the shell blocked,
$Q_s(t) = \sum_i e^{-(t - t_i)/\tau}$, and alerts the source when $Q_s \ge K$. The script
prints, for each $K$, the alarms per hour that the shell's false positives would cause
on benign traffic of the test network.

```bash
python -m proteus.evaluation.feedback \
    --run experiments/outputs/h1/csecicids2018__cicids2017__loo_labels \
    --test cicids2017 --block-fpr 1e-3
```

Options: `--model` (default `flow_clf`), `--block` (shell score that blocks a flow) or
`--block-fpr` (block at this FPR on local benign traffic).

## `alarms`

Alarms per entity on real traffic: who is alerted, how often and why. Every alert is
attributed to the side whose sub-core gives the maximum score and to that side's entity;
an alarm is a (day, entity, time bucket) group. Writes `alarms_<model>_<fpr>.csv` with a
description of each alerted entity.

```bash
PROTEUS_EVIDENCE=v3 python -m proteus.evaluation.alarms \
    --run experiments/outputs/h1/ctu13__ctu13__loo_labels__foldB_v3 --test ctu13 \
    --models proteus proteus_cert --days s01 s02 s03 s04 s06 s10 --top 30
```

Options: `--models`, `--days`, `--fpr`, `--bucket-min` (default 10), `--top`.

## `cost`

Cost of Proteus on one capture day: flows per second to compute the evidence (batch
implementation, single process), flows per second to score each detector and its
certified worst case, and the state a streaming deployment keeps per entity.

```bash
PROTEUS_EVIDENCE=v3 python -m proteus.evaluation.cost \
    --run experiments/outputs/h1/csecicids2018__cicids2017__loo_labels__v3 \
    --test cicids2017 --day wednesday --models proteus proteus_cert
```

Options: `--day`, `--models`, `--rows` (rows used for the measurement).

## `bench`

Multidimensional comparison of defences, following the METIS methodology. Each defence
gets a score in $[0, 1]$ per dimension (detection, false alarms, robustness under the
adaptive attacker), anchored to declared or empirical references. Dimensions are
combined so that a dimension at zero is barely offset by the others, and the Pareto
front over the dimensions is reported as the first reading.

```bash
python -m proteus.evaluation.bench \
    --h1 experiments/outputs/h1/csecicids2018__cicids2017__loo_labels__v3 \
         experiments/outputs/h1/csecicids2018__cicids2017__loo_labels__v3_kitnet \
    --adaptive experiments/outputs/h1/csecicids2018__cicids2017__loo_labels__v3/adaptive_0.001.csv \
    --out experiments/outputs/bench/18_17.csv
```

Options: `--h1` (run directories; the first wins for a repeated model), `--adaptive`,
`--fpr`, `--detectors`, `--out`.

## `tables`

Writes the LaTeX tables of the manuscript, and CSV data for the figures, from the
outputs above. The first argument selects the table: `h1`, `summary`, `ablation`,
`frontier`, `frontier_system` or `adaptive`.

```bash
python -m proteus.evaluation.tables h1 --set v3 --fpr 1e-3 \
    --runs experiments/outputs/h1/csecicids2018__cicids2017__loo_labels__v3 \
           experiments/outputs/h1/cicids2017__csecicids2018__loo_labels__v3 \
    --out experiments/outputs/paper_tables/h1_v3_1e-3.tex
```

| Option | Meaning |
|---|---|
| `--runs`, `--extra` | Run directories; `--extra` adds detectors for the same direction |
| `--csv` | Frontier or adaptive CSV files |
| `--data-out` | CSV with the data of the corresponding figure |
| `--detectors`, `--set` | Detector columns |
| `--base` | Full model of an ablation table |
| `--fpr`, `--out` | Target false-positive rate and output file |

`scripts/paper_tables.sh` calls this module for every table of the manuscript.
