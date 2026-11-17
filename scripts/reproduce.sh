#!/usr/bin/env bash
# Reproduce the experiments of the paper, stage by stage, from the repository root.
#
#   bash scripts/reproduce.sh <stage> [<stage> ...]     e.g.  bash scripts/reproduce.sh data h1
#   bash scripts/reproduce.sh all
#   DRY=1 bash scripts/reproduce.sh all                 print the commands without running them
#
# Stages run sequentially and every later stage reuses the models that `h1` fits. Runs
# that test on CSE-CIC-IDS-2018 peak at about 16-18 GB of RAM, and the adaptive attacker
# with every detector at about 12 GB: do not run two of them at once on a 32 GB machine.
# Every output goes to experiments/outputs/; logs next to it. The paper's tables are then
# regenerated with scripts/paper_tables.sh. Seeds are fixed (--seed 0, random_state=0 in
# every model). All runs use evidence version v3.
set -euo pipefail
export PROTEUS_EVIDENCE=v3
PY=".venv/bin/python -m"
O=experiments/outputs/h1
P=data/processed
R=data/raw
A=$O/csecicids2018__cicids2017__loo_labels__r2   # trained on 2018, tested on 2017
B=$O/cicids2017__csecicids2018__loo_labels__r2   # trained on 2017, tested on 2018
BUD="--entity-budgets 0.5 1 3 10"                # alarm budgets per entity and hour
mkdir -p "$O"
log() { echo "[$(date -u +%H:%M:%S)] $*" >&2; }
run() {  # run <log file> <command...>
  local out=$1; shift
  log "$* > $out"
  [ -n "${DRY:-}" ] || "$@" > "$out" 2>&1
}
pairs() {  # "<train> <test> <run directory> <short name>" for both directions
  echo "csecicids2018 cicids2017 $A 18_17"
  echo "cicids2017 csecicids2018 $B 17_18"
}

# Detectors fitted on the training network.
FIT="proteus proteus_cert proteus_cert_r proteus_free core_mono_dst_x core_free_dst_b core_pair rate_rules_local flow_clf"
# Detectors evaluated together (same thresholds, unions formed by h1).
SYS="proteus proteus_cert proteus_cert_r proteus2 proteus_free core_mono_dst_x core_free_dst_b rate_rules_local"

stage_data() {  # Raw files: see data/README.md.
  for d in cicids2017 csecicids2018 ctu13 ugr16 cicddos2019 unsw_nb15; do
    run $P/prepare_$d.log $PY proteus.datasets.prepare --dataset $d --raw $R/$d --out $P/$d
  done
}

stage_h1() {  # tab:h1, tab:h1-1e-4, fig:curves: detection across networks, both directions.
  while read -r train test dir tag; do
    run $O/run_${tag}_r2.log $PY proteus.evaluation.h1 --train $train --test $test --models $FIT $BUD --tag r2
    # The detector on evidence that connection reuse cannot lower, at every time scale.
    run $O/run_${tag}_r2_p2.log $PY proteus.evaluation.h1 --train $train --test $test --models proteus2 $BUD --tag r2_p2
    run $O/run_${tag}_r2c.log $PY proteus.evaluation.h1 --train $train --test $test --reuse $dir \
      --extra-runs ${dir}_p2 --models $SYS $BUD --tag r2c
  done < <(pairs)
}

stage_baselines() {  # The detectors Proteus is compared with (tab:detectors).
  while read -r train test dir tag; do
    run $O/run_${tag}_r2_kitnet.log $PY proteus.evaluation.h1 --train $train --test $test --reuse $dir \
      --models kitnet_local --tag r2_kitnet
    run $O/run_${tag}_r2_sel.log $PY proteus.evaluation.h1 --train $train --test $test \
      --models rate_rules_sel $BUD --tag r2_sel
    run $O/run_${tag}_r2_apollon.log $PY proteus.evaluation.h1 --train $train --test $test \
      --models apollon flow_clf $BUD --tag r2_apollon
    run $O/run_classic_${test}_r2.log $PY proteus.evaluation.classic --test $test $BUD --tag r2
  done < <(pairs)
}

stage_systems() {  # Candidate systems from per-flow alerts; the window-fidelity complement.
  while read -r train test dir tag; do
    run $O/run_${tag}_r2_alerts.log $PY proteus.evaluation.h1 --train $train --test $test --reuse $dir \
      --models proteus proteus_cert proteus_cert_r flow_clf --export-alerts --tag r2_alerts
    run $O/run_${tag}_r2_wf300.log $PY proteus.evaluation.window_fidelity --test $test --window 300 \
      --with-alerts ${dir}_alerts --out ${dir}_wf300
  done < <(pairs)
  run $O/run_18_17_r2_opt.log $PY proteus.evaluation.h1 --train csecicids2018 --test cicids2017 --reuse $A \
    --extra-runs ${A}_p2 ${A}_sel --models proteus proteus_cert proteus_cert_r proteus2 \
    "proteus&proteus_cert&proteus_cert_r" "proteus&proteus_cert_r" rate_rules_local rate_rules_r \
    rate_rules_sel $BUD --export-alerts --tag r2_opt
  run $O/run_18_17_r2_unions.log $PY proteus.evaluation.unions --test cicids2017 \
    --alerts ${A}_opt ${A}_wf300 --out ${A}_unions \
    --union sys3=proteus,proteus_cert,proteus_cert_r --union pcr=proteus,proteus_cert_r \
    --union pcrw=proteus,proteus_cert_r,window_fidelity --union p2w=proteus2,window_fidelity \
    --union pw=proteus,window_fidelity --union pr=proteus,rate_rules_r
}

stage_cert() {  # sec:evaluation:cert and the appendix checks of the certificate.
  run $O/free_ops_r2_18_17.log $PY proteus.evaluation.free_ops --run $A --test cicids2017 \
    --models proteus proteus_cert proteus_cert_r --variants 20
  while read -r train test dir tag; do
    # Each campaign without the other attacks of its day.
    run $O/isolated_r2_$tag.log $PY proteus.evaluation.isolated --run $dir --test $test \
      --models proteus proteus_cert proteus_cert_r
    # Saturated sub-cores left out of the calibrated maximum (diagnostic).
    run $O/run_${tag}_r2_sat.log $PY proteus.evaluation.h1 --train $train --test $test --reuse $dir \
      --models proteus proteus_cert proteus_cert_r --exclude-saturated 1e-3 $BUD --tag r2_sat
  done < <(pairs)
  for d in 10 60; do  # slack of a re-scoring timer
    run $O/run_18_17_r2_timer$d.log env PROTEUS_TIMER_S=$d $PY proteus.evaluation.h1 --train csecicids2018 \
      --test cicids2017 --reuse $A --models proteus proteus_cert proteus_cert_r --tag r2_timer$d
  done
}

stage_frontier() {  # tab:frontier, fig:frontier: real victim, then the busiest service.
  while read -r train test dir tag; do
    for m in proteus proteus_cert proteus_cert_r proteus2; do
      run $O/frontier_r2_${m}_$tag.log $PY proteus.evaluation.frontier_exp --run $dir \
        --extra-runs ${dir}_p2 --test $test --model $m --rmax 200
      run $O/frontier_r2_busy_${m}_$tag.log $PY proteus.evaluation.frontier_exp --run $dir \
        --extra-runs ${dir}_p2 --test $test --model $m --busy
    done
  done < <(pairs)
}

stage_adaptive() {  # tab:adaptive: fixed plans on a grid of rates, at the operating point.
  local m="proteus proteus_cert_r proteus_free rate_rules_sel"
  local c="--certify proteus_cert_r --alarm-budget 0.5"
  run $O/adaptive_r2g_18_17_b0.5.log $PY proteus.evaluation.adaptive --run $A --extra-runs ${A}_p2 ${A}_sel \
    --test cicids2017 --models $m --local rate_rules_local kitnet_local $c --grid 30 --tag g30
  run $O/adaptive_r2g_17_18_b0.5.log $PY proteus.evaluation.adaptive --run $B --extra-runs ${B}_p2 \
    --test csecicids2018 --models proteus proteus_cert_r proteus_free rate_rules_sel --local rate_rules_local \
    $c --variants 2 --grid 16 --tag g16
}

stage_query() {  # tab:query: black-box search with hard labels, at the operating point.
  local q="--local rate_rules_local --alarm-budget 0.5 --costly --shrink --max-flows 300000 --tag all"
  run $O/query_attack_18_17_b0.5.log $PY proteus.evaluation.query_attack --run $A \
    --extra-runs ${A}_p2 ${A}_sel --test cicids2017 \
    --targets proteus proteus_cert_r rate_rules_local rate_rules_sel \
    --union pcr=proteus,proteus_cert_r --budget 150 $q
  run $O/query_attack_17_18_b0.5.log $PY proteus.evaluation.query_attack --run $B \
    --extra-runs ${B}_p2 --test csecicids2018 \
    --targets proteus proteus_cert_r rate_rules_local rate_rules_sel \
    --union pcr=proteus,proteus_cert_r --budget 100 $q
}

stage_injection() {  # Every attack against many real victims of varying load (2018 -> 2017).
  run $O/injection_18_17_b0.5.log $PY proteus.evaluation.injection --run $A --extra-runs ${A}_sel \
    --test cicids2017 --models proteus proteus_cert_r proteus_free rate_rules_sel \
    --local rate_rules_local kitnet_local --certify proteus_cert_r --alarm-budget 0.5 \
    --victims 16 --grid 14 --window 1800 --tag v16
}

stage_ablation() {  # tab:ablation (proteus-K drops sub-core K).
  local p="proteus proteus-0 proteus-1 proteus-2 proteus-3"
  local c="proteus_cert_r proteus_cert_r-0 proteus_cert_r-1 proteus_cert_r-2 proteus_cert_r-3"
  while read -r train test dir tag; do
    run $O/run_${tag}_r2_ablation.log $PY proteus.evaluation.h1 --train $train --test $test \
      --reuse $dir --models $p --tag r2_ablation
    run $O/run_${tag}_r2_ablation_r.log $PY proteus.evaluation.h1 --train $train --test $test \
      --reuse $dir --models $c --tag r2_ablation_r
  done < <(pairs)
}

stage_poisoning() {  # fig:poisoning: baselines raised over days.
  run $O/poisoning_r2_certr_18_17.log $PY proteus.evaluation.poisoning --run $A --test cicids2017 \
    --model proteus_cert_r --rounds 8 --caps none 0.25 0.1
  run $O/poisoning_r2_18_17.log $PY proteus.evaluation.poisoning --run $A --test cicids2017 \
    --model proteus --rounds 8 --caps none 0.1
}

stage_budget() {  # tab:budget (randomised smoothing, the mechanism of BARS).
  run $O/smoothing_r2_18_17.log $PY proteus.evaluation.smoothing --run $A --test cicids2017 \
    --base core_free_dst_b --certified proteus_cert_r
}

stage_real() {  # sec:evaluation:real and the appendix: CTU-13, UGR'16, CIC-DDoS-2019, UNSW-NB15.
  local fa="s01 s02 s03 s04 s06 s10" fb="s05 s07 s08 s09 s11 s12 s13"
  local jul="2016-07-27 2016-07-28 2016-07-29 2016-07-30 2016-07-31"
  local aug="2016-08-01 2016-08-02 2016-08-03 2016-08-04 2016-08-05 2016-08-06 2016-08-07"
  local m="proteus proteus_cert proteus_cert_r proteus2 core_both_x rate_rules_local"
  local r="proteus proteus_cert proteus_cert_r proteus2 rate_rules_local"
  local b="--entity-budgets 0.5 1 0.1" xs=""
  run $O/run_ctu_foldB_r2.log $PY proteus.evaluation.h1 --train ctu13 --test ctu13 --train-days $fb --test-days $fa --tag foldB_r2 $b --models $m $xs
  run $O/run_ctu_foldA_r2.log $PY proteus.evaluation.h1 --train ctu13 --test ctu13 --train-days $fa --test-days $fb --tag foldA_r2 $b --models $m $xs
  for h in 1 6; do
    run $O/frontier_scan_ctuB_r2_${h}h.log $PY proteus.evaluation.frontier_scan \
      --run $O/ctu13__ctu13__loo_labels__foldB_r2 --test ctu13 --model proteus --fpr 1e-3 --hours $h --rmax 20 $xs
  done
  run $O/run_classic_ctu_r2.log $PY proteus.evaluation.classic --test ctu13 $b --tag r2
  run $O/run_ugr_julaug_r2.log $PY proteus.evaluation.h1 --train ugr16 --test ugr16 --train-days $jul --test-days $aug --tag julaug_r2 $b --models $m $xs
  run $O/run_ugr_augjul_r2.log $PY proteus.evaluation.h1 --train ugr16 --test ugr16 --train-days $aug --test-days $jul --tag augjul_r2 $b --models $m $xs
  run $O/run_17_ugr_r2.log $PY proteus.evaluation.h1 --train cicids2017 --test ugr16 --reuse $B --extra-runs ${B}_p2 --test-days $jul $aug --tag r2 $b --models $r $xs
  run $O/run_17_ddos19_r2.log $PY proteus.evaluation.h1 --train cicids2017 --test cicddos2019 --reuse $B --extra-runs ${B}_p2 --tag r2 --models $r
  run $O/run_18_ddos19_r2.log $PY proteus.evaluation.h1 --train csecicids2018 --test cicddos2019 --reuse $A --extra-runs ${A}_p2 --tag r2 --models $r
  # UNSW-NB15: source-side detectors on the default evidence (v1).
  run $O/run_17_unsw.log env PROTEUS_EVIDENCE=v1 $PY proteus.evaluation.h1 --train cicids2017 --test unsw_nb15 \
    --models core_both_x core_both_cert core_src_x rate_rules_local --tag src
}

stage_shell() {  # tab:aml (decision-based attacks on per-flow detectors) and tab:feedback.
  run experiments/outputs/aml_feature/cicids2017_s0.log $PY proteus.evaluation.aml_feature --dataset cicids2017 --n 100 --workers 8
  for f in 1e-3 1e-4; do
    run $O/feedback_r2_18_17_fpr$f.log $PY proteus.evaluation.feedback --run $A --test cicids2017 --block-fpr $f
    run $O/feedback_r2_17_18_fpr$f.log $PY proteus.evaluation.feedback --run $B --test csecicids2018 --block-fpr $f
  done
}

stage_robustness() {  # Seeds, baselines without labels, class balance of the training set.
  local ms="proteus proteus_cert_r proteus_free rate_rules_local"
  while read -r train test dir tag; do
    for s in 1 2; do
      run $O/run_${tag}_r2_s$s.log $PY proteus.evaluation.h1 --train $train --test $test --models $ms $BUD --seed $s --tag r2_s$s
    done
    for b in type type_entity none; do
      run $O/run_${tag}_r2_bal_$b.log $PY proteus.evaluation.h1 --train $train --test $test --balance $b \
        --models proteus proteus_cert_r $BUD --tag r2_bal_$b
    done
  done < <(pairs)
  run $O/run_18_17_r2_prior_none.log $PY proteus.evaluation.h1 --train csecicids2018 --test cicids2017 \
    --baseline prior --mask none --models proteus proteus_cert_r rate_rules_local $BUD --tag r2
}

stage_kitsune() {  # Kitsune as published on the Friday packets (needs the pcap and dpkt).
  for n in 100000 1000000; do
    run experiments/outputs/kitsune_friday_$n.log $PY proteus.evaluation.kitsune_pcap \
      --pcap $R/cicids2017_pcap/Friday-WorkingHours.pcap --flows $P/cicids2017/friday.parquet \
      --attacker 172.16.0.1 --train-packets $n --out experiments/outputs/kitsune_$n
  done
}

stage_packets() {  # sec:evaluation:packets. Needs the CIC-IDS-2017 Friday pcap and dpkt (.[packets]).
  run experiments/outputs/packet_check_v3.log $PY proteus.evaluation.packet_check \
    --pcap $R/cicids2017_pcap/Friday-WorkingHours.pcap --packets experiments/outputs/packet_check/loic_packets.parquet \
    --victim 192.168.10.50 --attackers 172.16.0.1 --port 80 --start 1499453400 --minutes 25 \
    --out experiments/outputs/packet_check_v3
}

stage_cost() {  # Deployment and cost (sec:evaluation:cost): one thread, pinned to one core.
  run $O/cost_r2.log env OMP_NUM_THREADS=1 taskset -c 0 $PY proteus.evaluation.cost --run $A --test cicids2017 \
    --day wednesday --models proteus proteus_cert_r core_mono_dst_x
}

stage_tables() {
  log "bash scripts/paper_tables.sh"
  [ -n "${DRY:-}" ] || bash scripts/paper_tables.sh
}

STAGES="data h1 baselines systems cert frontier adaptive query injection ablation poisoning budget real shell robustness packets kitsune cost tables"
[ $# -eq 0 ] && { echo "usage: $0 all | <stage>...   stages: $STAGES"; exit 1; }
[ "$1" = all ] && set -- $STAGES
for s in "$@"; do "stage_$s"; done
