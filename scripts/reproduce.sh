#!/usr/bin/env bash
# Reproduce the experiments of the paper, stage by stage, from the repository root.
#
#   bash scripts/reproduce.sh <stage> [<stage> ...]     e.g.  bash scripts/reproduce.sh data h1
#   bash scripts/reproduce.sh all
#
# Stages run sequentially. Runs that test on CSE-CIC-IDS-2018 peak at about 16-18 GB of
# RAM; do not run two of them at once on a 32 GB machine. Every output goes to
# experiments/outputs/; logs next to it. The paper's tables are then regenerated with
# scripts/paper_tables.sh. Seeds are fixed (--seed 0, random_state=0 in every model).
set -euo pipefail
PY=".venv/bin/python -m"
O=experiments/outputs/h1
P=data/processed
R=data/raw
A=$O/csecicids2018__cicids2017__loo_labels   # trained on 2018, tested on 2017
B=$O/cicids2017__csecicids2018__loo_labels   # trained on 2017, tested on 2018
mkdir -p "$O"
log() { echo "[$(date -u +%H:%M:%S)] $*" >&2; }
run() { local out=$1; shift; log "$* > $out"; "$@" > "$out" 2>&1; }

# Detectors of the paper (evidence v3) and the single-model cores (evidence v1).
V3="proteus proteus_cert core_pair core_mono_dst_x core_cert core_free_dst_b rate_rules_local"

stage_data() {  # Raw files: see data/README.md.
  for d in cicids2017 csecicids2018 ctu13 unsw_nb15; do
    run $P/prepare_$d.log $PY proteus.datasets.prepare --dataset $d --raw $R/$d --out $P/$d
  done
}

stage_h1() {  # tab:h1, tab:h1-1e-4 (Proteus, Proteus-cert, unconstrained core, rules).
  export PROTEUS_EVIDENCE=v3
  run $O/run_18_17_v3.log $PY proteus.evaluation.h1 --train csecicids2018 --test cicids2017 --models $V3 --tag v3
  run $O/run_17_18_v3.log $PY proteus.evaluation.h1 --train cicids2017 --test csecicids2018 --models $V3 --tag v3
  # KitNET and rate thresholds on the same evidence, fitted on local benign traffic.
  for pair in "csecicids2018 cicids2017 $A" "cicids2017 csecicids2018 $B"; do
    set -- $pair
    run $O/run_${1}_${2}_v3_kitnet.log $PY proteus.evaluation.h1 --train $1 --test $2 \
      --reuse $3__v3 --models kitnet_local rate_rules_local proteus proteus_cert --tag v3_kitnet
  done
  unset PROTEUS_EVIDENCE
}

stage_single() {  # tab:h1-v1, tab:h1-v1-1e-4, sec:evaluation:cert (single-model cores, evidence v1).
  run $O/run_18_17.log $PY proteus.evaluation.h1 --train csecicids2018 --test cicids2017
  run $O/run_17_18.log $PY proteus.evaluation.h1 --train cicids2017 --test csecicids2018
  run $O/run_18_17_cert.log $PY proteus.evaluation.h1 --train csecicids2018 --test cicids2017 --models core_cert --tag cert
  run $O/run_17_18_cert.log $PY proteus.evaluation.h1 --train cicids2017 --test csecicids2018 --models core_cert --tag cert
  # Free operations on the real campaigns (sec:evaluation:cert).
  run $O/free_ops_18_17.log $PY proteus.evaluation.free_ops --run ${A}__cert --test cicids2017 \
    --models core_cert core_mono_dst_x --variants 20
}

stage_review() {  # Reviewer checks: unconstrained maximum, equal alarm budgets, timer slack.
  export PROTEUS_EVIDENCE=v3
  local budgets="--entity-budgets 0.5 1 3 10"
  for pair in "csecicids2018 cicids2017 $A 18_17" "cicids2017 csecicids2018 $B 17_18"; do
    set -- $pair
    run $O/run_$4_v3_free.log $PY proteus.evaluation.h1 --train $1 --test $2 --models proteus_free $budgets --tag v3_free
    run $O/run_$4_v3_budget.log $PY proteus.evaluation.h1 --train $1 --test $2 --reuse $3__v3 \
      --models proteus proteus_cert rate_rules_local core_free_dst_b $budgets --tag v3_budget
  done
  for d in 10 60; do
    PROTEUS_TIMER_S=$d run $O/run_18_17_v3_timer$d.log $PY proteus.evaluation.h1 --train csecicids2018 \
      --test cicids2017 --reuse ${A}__v3 --models proteus proteus_cert --tag v3_timer$d
  done
  unset PROTEUS_EVIDENCE
}

stage_ablation() {  # tab:ablation (sub-core ablation; proteus-K drops sub-core K).
  export PROTEUS_EVIDENCE=v3
  local p="proteus proteus-0 proteus-1 proteus-2 proteus-3"
  local c="proteus_cert proteus_cert-0 proteus_cert-1 proteus_cert-2 proteus_cert-3"
  run $O/run_18_17_v3_ablation.log $PY proteus.evaluation.h1 --train csecicids2018 --test cicids2017 --reuse ${A}__v3 --models $p $c --tag v3_ablation
  run $O/run_17_18_v3_ablation.log $PY proteus.evaluation.h1 --train cicids2017 --test csecicids2018 --reuse ${B}__v3 --models $p --tag v3_ablation
  run $O/run_17_18_v3_ablation_cert.log $PY proteus.evaluation.h1 --train cicids2017 --test csecicids2018 --reuse ${B}__v3 --models $c --tag v3_ablation_cert
  unset PROTEUS_EVIDENCE
}

stage_packets() {  # sec:evaluation:packets. Needs the CIC-IDS-2017 Friday pcap and dpkt (.[packets]).
  PROTEUS_EVIDENCE=v3 run experiments/outputs/packet_check_v3.log $PY proteus.evaluation.packet_check \
    --pcap $R/cicids2017_pcap/Friday-WorkingHours.pcap --packets experiments/outputs/packet_check/loic_packets.parquet \
    --victim 192.168.10.50 --attackers 172.16.0.1 --port 80 --start 1499453400 --minutes 25 \
    --out experiments/outputs/packet_check_v3
}

stage_budget() {  # tab:budget (randomised smoothing, the mechanism of BARS).
  PROTEUS_EVIDENCE=v3 run $O/smoothing_18_17.log $PY proteus.evaluation.smoothing \
    --run ${A}__v3 --test cicids2017 --base core_free_dst_b --certified proteus_cert
}

stage_frontier() {  # tab:frontier, fig:frontier (harm frontier, attributable alerts).
  export PROTEUS_EVIDENCE=v3
  for m in proteus_cert proteus; do
    run $O/frontier_v3_${m}_18_17.log $PY proteus.evaluation.frontier_exp --run ${A}__v3 --test cicids2017 --model $m --rmax 200
    run $O/frontier_v3_${m}_17_18.log $PY proteus.evaluation.frontier_exp --run ${B}__v3 --test csecicids2018 --model $m --rmax 200
  done
  unset PROTEUS_EVIDENCE
}

stage_adaptive() {  # sec:evaluation:adaptive and the robustness dimension of tab:bench.
  export PROTEUS_EVIDENCE=v3
  local m="proteus proteus_cert core_mono_dst_x core_free_dst_b core_pair"
  run $O/adaptive_18_17_v3.log $PY proteus.evaluation.adaptive --run ${A}__v3 --test cicids2017 \
    --models $m --local rate_rules_local kitnet_local --certify proteus_cert --grid 20
  run $O/adaptive_17_18_v3.log $PY proteus.evaluation.adaptive --run ${B}__v3 --test csecicids2018 \
    --models $m --local rate_rules_local kitnet_local --certify proteus_cert --variants 8 --grid 20
  unset PROTEUS_EVIDENCE
}

stage_poisoning() {  # fig:poisoning and the discussion of baseline poisoning.
  run $O/poisoning_18_17.log $PY proteus.evaluation.poisoning --run $A --test cicids2017 --model core_mono_dst_x --rounds 8 --caps none 0.25 0.1
  run $O/growth_17.log $PY proteus.evaluation.poisoning --run $A --test cicids2017 --growth-only --caps 0.1 0.25 0.5 1
  run $O/growth_18.log $PY proteus.evaluation.poisoning --run $B --test csecicids2018 --growth-only --caps 0.1 0.25 0.5 1
  export PROTEUS_EVIDENCE=v3
  run $O/poisoning_v3_cert_18_17.log $PY proteus.evaluation.poisoning --run ${A}__v3 --test cicids2017 --model proteus_cert --rounds 8 --caps none 0.25 0.1
  run $O/poisoning_v3_18_17.log $PY proteus.evaluation.poisoning --run ${A}__v3 --test cicids2017 --model proteus --rounds 8 --caps none 0.1
  unset PROTEUS_EVIDENCE
}

stage_real() {  # sec:evaluation:real (CTU-13 folds, UNSW-NB15).
  local fa="s01 s02 s03 s04 s06 s10" fb="s05 s07 s08 s09 s11 s12 s13"
  local m="proteus proteus_cert core_both_x core_both_cert core_pair rate_rules_local"
  export PROTEUS_EVIDENCE=v3
  run $O/run_ctu_foldB_v3.log $PY proteus.evaluation.h1 --train ctu13 --test ctu13 --train-days $fb --test-days $fa --tag foldB_v3 --entity-budgets 1 0.1 --models $m
  run $O/run_ctu_foldA_v3.log $PY proteus.evaluation.h1 --train ctu13 --test ctu13 --train-days $fa --test-days $fb --tag foldA_v3 --entity-budgets 1 0.1 --models $m
  for h in 1 6; do
    run $O/frontier_scan_ctuB_v3_${h}h.log $PY proteus.evaluation.frontier_scan --run $O/ctu13__ctu13__loo_labels__foldB_v3 --test ctu13 --model proteus --fpr 1e-3 --hours $h
  done
  run $O/alarms_ctuB_v3.log $PY proteus.evaluation.alarms --run $O/ctu13__ctu13__loo_labels__foldB_v3 --test ctu13 --models proteus proteus_cert --days $fa --top 30
  unset PROTEUS_EVIDENCE
  run $O/run_17_unsw.log $PY proteus.evaluation.h1 --train cicids2017 --test unsw_nb15 --models core_both_x core_both_cert core_src_x rate_rules_local --tag src
}

stage_shell() {  # tab:aml (decision-based attacks on per-flow detectors) and tab:feedback.
  run experiments/outputs/aml_feature/cicids2017_s0.log $PY proteus.evaluation.aml_feature --dataset cicids2017 --n 100 --workers 8
  for f in 1e-3 1e-4; do
    run $O/feedback_18_17_fpr$f.log $PY proteus.evaluation.feedback --run $A --test cicids2017 --block-fpr $f
    run $O/feedback_17_18_fpr$f.log $PY proteus.evaluation.feedback --run $B --test csecicids2018 --block-fpr $f
  done
}

stage_cost() {  # Deployment and cost (sec:discussion).
  PROTEUS_EVIDENCE=v3 run $O/cost_v3.log $PY proteus.evaluation.cost --run ${A}__v3 --test cicids2017 \
    --day wednesday --models proteus proteus_cert core_mono_dst_x
}

stage_tables() { bash scripts/paper_tables.sh; }

STAGES="data h1 single review ablation packets budget frontier adaptive poisoning real shell cost tables"
[ $# -eq 0 ] && { echo "usage: $0 all | <stage>...   stages: $STAGES"; exit 1; }
[ "$1" = all ] && set -- $STAGES
for s in "$@"; do "stage_$s"; done
