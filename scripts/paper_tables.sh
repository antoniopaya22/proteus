#!/usr/bin/env bash
# Regenerate the paper's result tables and figure data from the experiment outputs of
# scripts/reproduce.sh (run from the repository root). Writes to
# experiments/outputs/paper_tables/ (or to $T); only finished runs are used.
#
#   bash scripts/paper_tables.sh
#   O=<directory with the runs> T=<output directory> bash scripts/paper_tables.sh
set -euo pipefail
O=${O:-experiments/outputs/h1}
T=${T:-experiments/outputs/paper_tables}
PY=${PY:-.venv/bin/python -m}
mkdir -p "$T"
A=$O/csecicids2018__cicids2017__loo_labels__r2   # 2018 -> 2017
B=$O/cicids2017__csecicids2018__loo_labels__r2   # 2017 -> 2018
C17=$O/classic__cicids2017__r2
C18=$O/classic__csecicids2018__r2
exists() { for d in "$@"; do [ -f "$d/summary.csv" ] && echo "$d"; done; true; }  # finished runs only
files() { for f in "$@"; do [ -f "$f" ] && echo "$f"; done; true; }
# Every detector at the same thresholds: the r2c runs (r2b where r2c is not there yet).
both() { local a b; a=$(exists ${A}c); b=$(exists ${B}c); echo ${a:-$(exists ${A}b)} ${b:-$(exists ${B}b)}; }

# Detection across networks (tab:h1, tab:h1-1e-4).
for f in 1e-3 1e-4; do
  $PY proteus.evaluation.tables h1 --set r2 --fpr $f --runs $(both) \
    --extra $(exists $A $B ${A}_kitnet ${B}_kitnet ${A}_apollon ${B}_apollon) \
    --out $T/h1_r2_$f.tex > /dev/null
done

# Detection against alarms per alerted entity (fig:curves).
$PY proteus.evaluation.tables curves \
  --runs $(both) $(exists ${A}_sel ${B}_sel ${A}_kitnet ${B}_kitnet $C17 $C18) \
  --detectors proteus_sys_r proteus rate_rules_local rate_rules_sel proteus_free kitnet_local syn_cusum trw_svc \
  --data-out $T/curves.csv --out $T/curves.tex > /dev/null

# Confidence intervals (campaigns: Wilson; alarms: bootstrap over days).
$PY proteus.evaluation.tables summary --runs $(both) \
  --extra $(exists $A $B ${A}_kitnet ${B}_kitnet ${A}_apollon ${B}_apollon) \
  --detectors proteus proteus_sys_r proteus_cert@cert proteus_cert_r@certr proteus_free rate_rules_local kitnet_local flow_clf apollon \
  --out $T/summary_ci.csv > /dev/null

# Harm frontiers (tab:frontier and the data of fig:frontier).
for m in proteus proteus_cert proteus_cert_r proteus2; do
  csvs=$(files $A/frontier_${m}_0.001_attr.csv $B/frontier_${m}_0.001_attr.csv)
  [ -n "$csvs" ] && $PY proteus.evaluation.tables frontier --csv $csvs \
    --data-out $T/frontier_${m}.csv --out $T/frontier_${m}.tex > /dev/null
done

# Damage under the adaptive attacker (tab:adaptive) and under the query attacker (tab:query).
csvs=$(files $A/adaptive_0.001_g30.csv $B/adaptive_0.001_g20.csv)
[ -n "$csvs" ] && $PY proteus.evaluation.tables adaptive --csv $csvs --out $T/adaptive.tex > /dev/null
csvs=$(files $A/query_attack_0.001_all.csv $B/query_attack_0.001_all.csv)
[ -n "$csvs" ] && $PY proteus.evaluation.tables query --csv $csvs --out $T/query.tex > /dev/null

# Sub-core ablations (tab:ablation).
runs=$(exists ${A}_ablation ${B}_ablation)
[ -n "$runs" ] && $PY proteus.evaluation.tables ablation --runs $runs --out $T/ablation.tex > /dev/null
runs=$(exists ${A}_ablation ${B}_ablation_cert)
[ -n "$runs" ] && $PY proteus.evaluation.tables ablation --base proteus_cert --runs $runs \
  --out $T/ablation_cert.tex > /dev/null

# Comparison of defences (tab:bench), one file per direction.
DEF="proteus proteus_sys_r proteus_cert@cert proteus_free rate_rules_local kitnet_local flow_clf apollon"
for pair in "A:18_17:g30" "B:17_18:g20"; do
  IFS=: read -r run tag grid <<< "$pair"; R=${!run}
  h1=$(exists ${R}c ${R}b | head -1)
  [ -n "$h1" ] || continue
  $PY proteus.evaluation.bench --h1 $h1 $(exists $R ${R}_kitnet ${R}_apollon) \
    $(f=$(files $R/adaptive_0.001_$grid.csv); [ -n "$f" ] && echo --adaptive $f) \
    --detectors $DEF --out $T/bench_$tag.csv > /dev/null
done
ls "$T"
