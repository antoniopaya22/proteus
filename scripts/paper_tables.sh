#!/usr/bin/env bash
# Regenerate the paper's result tables from the experiment outputs (run on the VM,
# from the repository root). Writes to experiments/outputs/paper_tables/.
set -euo pipefail
O=experiments/outputs/h1
T=experiments/outputs/paper_tables
mkdir -p "$T"
PY=".venv/bin/python -m"
A=$O/csecicids2018__cicids2017__loo_labels   # 2018 -> 2017
B=$O/cicids2017__csecicids2018__loo_labels   # 2017 -> 2018
exists() { for d in "$@"; do [ -f "$d/summary.csv" ] && echo "$d"; done; }  # finished runs only

# Detection across networks (v3 detectors; flow classifier from the first runs).
for f in 1e-3 1e-4; do
  $PY proteus.evaluation.tables h1 --set v3 --fpr $f \
    --runs $(exists ${A}__v3 ${B}__v3) \
    --extra $(exists ${A}__v3_kitnet ${B}__v3_kitnet $A $B) \
    --out $T/h1_v3_$f.tex > /dev/null
done

# Confidence intervals (campaigns: Wilson; alarms: bootstrap over days).
$PY proteus.evaluation.tables summary --runs $(exists ${A}__v3 ${B}__v3) \
  --extra $(exists ${A}__v3_kitnet ${B}__v3_kitnet $A $B) \
  --detectors proteus proteus_cert@cert core_free_dst_b rate_rules_local kitnet_local flow_clf \
  --out $T/summary_ci.csv > /dev/null

# Comparison of defences (METIS-style), one table per direction.
DEF="proteus proteus_cert@cert core_free_dst_b rate_rules_local kitnet_local flow_clf"
for pair in "A:18_17" "B:17_18"; do
  run=${pair%%:*}; tag=${pair##*:}; R=${!run}
  adaptive=$(ls ${R}__v3/adaptive_0.001.csv 2>/dev/null || true)
  $PY proteus.evaluation.bench --h1 $(exists ${R}__v3 ${R}__v3_kitnet $R) \
    ${adaptive:+--adaptive $adaptive} --detectors $DEF --out $T/bench_$tag.csv > /dev/null
done

# Damage under the adaptive attacker, both directions.
csvs=$(for d in ${A}__v3 ${B}__v3; do [ -f $d/adaptive_0.001.csv ] && echo $d/adaptive_0.001.csv; done || true)
[ -n "$csvs" ] && $PY proteus.evaluation.tables adaptive --csv $csvs --out $T/adaptive.tex > /dev/null

# Sub-core ablations.
$PY proteus.evaluation.tables ablation --runs $(exists ${A}__v3_ablation ${B}__v3_ablation) \
  --out $T/ablation.tex > /dev/null || true
$PY proteus.evaluation.tables ablation --base proteus_cert \
  --runs $(exists ${A}__v3_ablation ${B}__v3_ablation_cert) --out $T/ablation_cert.tex > /dev/null || true

# Harm frontiers (v3, attributable alerts): table and data of the dumbbell figure.
for m in proteus_cert proteus; do
  csvs=$(for d in ${A}__v3 ${B}__v3; do f=$d/frontier_${m}_0.001_attr.csv; [ -f $f ] && echo $f; done || true)
  [ -n "$csvs" ] && $PY proteus.evaluation.tables frontier --csv $csvs \
    --data-out $T/frontier_${m}.csv --out $T/frontier_${m}.tex > /dev/null
done
ls -la "$T"

# Frontier of the deployed system (proteus or proteus_cert alerts): plain and certified.
$PY proteus.evaluation.tables frontier_system --runs $(for d in ${A}__v3 ${B}__v3; do [ -d $d ] && echo $d; done) \
  --data-out $T/frontier_system.csv --out $T/frontier_system.tex > /dev/null
ls -la "$T"
