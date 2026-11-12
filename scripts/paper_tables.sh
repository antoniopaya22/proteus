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
exists() { for d in "$@"; do [ -d "$d" ] && echo "$d"; done; }

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

# Sub-core ablations.
$PY proteus.evaluation.tables ablation --runs $(exists ${A}__v3_ablation ${B}__v3_ablation) \
  --out $T/ablation.tex > /dev/null || true
$PY proteus.evaluation.tables ablation --runs $(exists ${B}__v3_ablation_cert) \
  --out $T/ablation_cert.tex > /dev/null || true
ls -la "$T"
