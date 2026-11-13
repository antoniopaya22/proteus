# Datasets

Datasets are not distributed with the repository. They live on the machine that runs
the experiments, under `data/`:

```text
data/
  raw/
    cns2022/            original zips (Liu et al., CNS 2022)
    cicids2017/         per-day CSV (corrected CIC-IDS2017)
    csecicids2018/      per-day CSV (corrected CSE-CIC-IDS2018)
    cicids2017_pcap/    per-day pcap of CIC-IDS2017 (only Friday is needed)
    ctu13/              .binetflow files of the 13 scenarios
    unsw_nb15/          official UNSW-NB15 CSV files
    ugr16_hf/           UGR'16 weeks as Parquet (mirror)
    cicddos2019/        CIC-DDoS2019 CSV files
    ctusme11_zeek/      Zeek conn.log files of CTU-SME-11
  processed/
    <dataset>/<day>.parquet     common flow schema
    <dataset>/summary.csv       flows per day, attack and "Attempted"
    <dataset>/evidence*/        caches of evidence features and baselines
```

## Overview

| Dataset | Use | Source | Notes |
|---|---|---|---|
| CIC-IDS2017 and CSE-CIC-IDS2018, corrected (Liu et al., CNS 2022) | Cross-network detection, harm frontiers, adaptive attacks | [DistriNet](https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/): `CICIDS2017_improved.zip` (328 MB), `CSECICIDS2018_improved.zip` (9.7 GB) | Use the corrected versions, which fix CICFlowMeter bugs and relabel flows; they mark ineffective attack flows as "Attempted". |
| CIC-IDS2017 pcap | Packet-level check of the certificate | [CIC](https://www.unb.ca/cic/datasets/ids-2017.html) (download form) | Only `Friday-WorkingHours.pcap` is needed. Verify it against the official MD5 checksums. |
| CTU-13 | Real traffic with unlabelled background | [Stratosphere Lab](https://www.stratosphereips.org/datasets-ctu13) | Extract only the `.binetflow` files and READMEs: the archive also contains the malware binaries. The unlabelled background is not treated as benign. |
| UNSW-NB15 | Attackers from a traffic generator | [UNSW Canberra](https://research.unsw.edu.au/projects/unsw-nb15-dataset) | Use the official CSV files. The `rdpahalavan/UNSW-NB15` mirror is deduplicated and must not be used. |
| UGR'16 | Real ISP NetFlow over long periods (in progress) | [NESG, UGR](https://nesg.ugr.es/nesg-ugr16/) | The official site returned HTTP 403; the unofficial Hugging Face mirror `Lystea/UGR16-PARQUET` was used (`july_week5`, `august_week1`). |
| CIC-DDoS2019 | Reflection and exploitation DDoS (in progress) | [CIC](https://www.unb.ca/cic/datasets/ddos-2019.html) (download form) | CSV files of both days. Too large for memory; evidence is computed hour by hour. |
| CTU-SME-11 | Small-enterprise network with IoT devices (in progress) | Zenodo, record 7958259 (CC BY 4.0, about 103 GB) | Zeek `conn.log`. Zeek exports long connections only when they end, so the export delay $\Delta$ of the certificate is not bounded for this dataset. |

## Conversion

Every converter is reached through `proteus.datasets.prepare`:

```bash
python -m proteus.datasets.prepare --dataset <name> --raw <raw dir> --out <processed dir>
```

where `<name>` is one of `cicids2017`, `csecicids2018`, `ctu13`, `unsw_nb15`, `ugr16`,
`cicddos2019`, `ctusme11`.

The corrected CIC datasets:

```bash
python -m proteus.datasets.prepare --dataset cicids2017 \
    --raw data/raw/cicids2017 --out data/processed/cicids2017
python -m proteus.datasets.prepare --dataset csecicids2018 \
    --raw data/raw/csecicids2018 --out data/processed/csecicids2018
```

The other datasets:

```bash
for d in ctu13 unsw_nb15 cicddos2019; do
  python -m proteus.datasets.prepare --dataset $d --raw data/raw/$d --out data/processed/$d
done
python -m proteus.datasets.prepare --dataset ugr16 --raw data/raw/ugr16_hf \
    --out data/processed/ugr16 --weeks july_week5 august_week1
python -m proteus.datasets.prepare --dataset ctusme11 --raw data/raw/ctusme11_zeek \
    --out data/processed/ctusme11
```

`bash scripts/reproduce.sh data` converts the four datasets used by the main experiments
(the two CIC datasets, CTU-13 and UNSW-NB15).

!!! note "Very large captures"
    UGR'16 and CIC-DDoS2019 do not fit in memory. Their converters stream the input,
    compute evidence window by window with a warm-up from the preceding window
    (`proteus.evidence.chunked`, `proteus.datasets.staged`), and store all attack flows
    plus a deterministic sample of the rest. Counters always use every flow. Dropping
    events older than the warm-up can only lower counters: the approximation may cost
    some recall, but it never raises a spurious alert, and a certified alert stays
    certified.

## Common flow schema

Every converter writes one Parquet file per capture day with the same columns:

| Column | Type | Meaning |
|---|---|---|
| `dataset`, `day` | category | Dataset name and capture day (file stem) |
| `t_start`, `t_end` | datetime (µs, UTC) | Flow start and end; `t_end` is the event time of the record |
| `src_ip`, `dst_ip` | string | Initiator and responder addresses |
| `src_port`, `dst_port` | int32 | Ports |
| `proto` | int16 | IP protocol number |
| `duration_us` | int64 | Flow duration in microseconds |
| `fwd_pkts`, `bwd_pkts` | int64 | Packets from initiator and from responder |
| `fwd_bytes`, `bwd_bytes` | int64 | Bytes from initiator and from responder |
| `f_*` | float32 | Remaining per-flow statistics of the source format (CICFlowMeter, Argus), used only by the per-flow shell; e.g. `f_bwd_rst_flags` |
| `label_raw` | category | Original label |
| `attack`, `family`, `attempted`, `is_attack` | see below | Canonical labels |

Rows are sorted by `t_end`. Dataset-specific approximations (for example, forward
packets estimated from Argus totals in CTU-13, or responder resets inferred from the
connection state in UNSW-NB15) are documented in the docstring of each converter under
`proteus.datasets`.

## Labels

| Column | Meaning |
|---|---|
| `attack` | Canonical attack subtype, shared across CIC-IDS2017 and CSE-CIC-IDS2018 (e.g. `dos_hulk`, `bf_ssh`, `web_sqli`) |
| `family` | Attack family: `benign`, `dos`, `ddos`, `portscan`, `bruteforce`, `web`, `botnet`, `infiltration`, … (`background` for the unlabelled traffic of CTU-13) |
| `attempted` | The flow belongs to an attack but had no malicious effect ("Attempted" in the corrected datasets) |
| `is_attack` | `family != "benign"` and not `attempted` |

"Attempted" flows are kept as traffic events, since they exist on the wire and feed the
evidence counters, but they are not used as training labels or in detection metrics,
following the dataset authors' guidance.

In CTU-13, background flows get `family = "background"` and are not treated as
benign: the background of a real network may contain unlabelled attacks.
