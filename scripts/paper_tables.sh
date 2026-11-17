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

# More detectors for the same directions: the system of two on 2018 -> 2017, the first
# runs (per-flow classifier), selected rate thresholds, KitNET and Apollon.
MORE="${A}_pcr $A $B ${A}_sel ${B}_p2 ${A}_kitnet ${B}_kitnet ${A}_apollon ${B}_apollon"

# Detection across networks (tab:h1, tab:h1-1e-4).
for f in 1e-3 1e-4; do
  $PY proteus.evaluation.tables h1 --set paper --fpr $f --runs $(both) \
    --extra $(exists $MORE) --out $T/h1_$f.tex > /dev/null
done

# Every threshold evaluated (tab:budgets): the system first where a run has it.
$PY proteus.evaluation.tables budgets --runs $(exists ${A}_pcr | head -1) $(exists ${B}c ${B}b | head -1) \
  --extra $(both) $(exists ${A}_sel ${B}_p2) --out $T/budgets.tex > /dev/null

# Detection against alarms per alerted entity (fig:curves).
$PY proteus.evaluation.tables curves \
  --runs $(exists ${A}_pcr) $(both) $(exists ${A}_sel ${B}_p2 ${A}_kitnet ${B}_kitnet $C17 $C18) \
  --detectors proteus_pcr proteus proteus_cert_r rate_rules_local rate_rules_sel proteus_free kitnet_local syn_cusum trw_svc \
  --data-out $T/curves.csv --out $T/curves.tex > /dev/null

# Intervals at the operating point (tab:intervals): Wilson for campaigns, bootstrap over
# test days for alarms.
$PY proteus.evaluation.tables intervals --alarm-budget 0.5 \
  --runs $(exists ${A}_pcr | head -1) $(exists ${B}c ${B}b | head -1) \
  --extra $(both) $(exists ${A}_sel ${B}_p2) --data-out $T/intervals.csv --out $T/intervals.tex > /dev/null

# Confidence intervals (campaigns: Wilson; alarms: bootstrap over days).
$PY proteus.evaluation.tables summary --runs $(both) --extra $(exists $MORE) \
  --detectors proteus_pcr proteus proteus_cert_r@certr proteus_free rate_rules_local rate_rules_sel kitnet_local flow_clf apollon \
  --out $T/summary_ci.csv > /dev/null

# Harm frontier of the system (tab:frontier) and of each detector.
runs=$(for d in $A $B; do [ -f $d/frontier_proteus_0.001_attr.csv ] && echo $d; done; true)
[ -n "$runs" ] && $PY proteus.evaluation.tables frontier_system --set paper --runs $runs \
  --data-out $T/frontier.csv --out $T/frontier.tex > /dev/null
for m in proteus proteus_cert_r; do
  csvs=$(files $A/frontier_${m}_0.001_attr.csv $B/frontier_${m}_0.001_attr.csv)
  [ -n "$csvs" ] && $PY proteus.evaluation.tables frontier --csv $csvs --out $T/frontier_${m}.tex > /dev/null
done

# Damage under the adaptive attacker (tab:adaptive) and under the query attacker (tab:query).
csvs=$(files $A/adaptive_b0.5_g30.csv $B/adaptive_b0.5_g16.csv)
[ -n "$csvs" ] && $PY proteus.evaluation.tables adaptive --set paper --csv $csvs --out $T/adaptive.tex > /dev/null
csvs=$(files $A/query_attack_b0.5_all.csv $B/query_attack_b0.5_all.csv)
[ -n "$csvs" ] && $PY proteus.evaluation.tables query --set paper --csv $csvs --out $T/query.tex > /dev/null

# Sub-core ablations (tab:ablation).
runs=$(exists ${A}_ablation ${B}_ablation)
[ -n "$runs" ] && $PY proteus.evaluation.tables ablation --runs $runs --out $T/ablation.tex > /dev/null
runs=$(exists ${A}_ablation_r ${B}_ablation_r)
[ -n "$runs" ] && $PY proteus.evaluation.tables ablation --base proteus_cert_r --runs $runs \
  --out $T/ablation_cert.tex > /dev/null

# Comparison of defences (tab:bench), one file per direction: the defences the adaptive
# attacker was run against (Apollon and the per-flow classifier are compared in tab:h1
# and against the attacks on per-flow detection).
DEF="proteus_pcr proteus proteus_cert_r@certr proteus_free rate_rules_local rate_rules_sel kitnet_local"
for pair in "A:18_17:g30" "B:17_18:g16"; do
  IFS=: read -r run tag grid <<< "$pair"; R=${!run}
  h1=$(exists ${R}_pcr ${R}c ${R}b $R ${R}_sel ${R}_p2 ${R}_kitnet ${R}_apollon)
  [ -n "$h1" ] || continue
  $PY proteus.evaluation.bench --h1 $h1 \
    $(f=$(files $R/adaptive_b0.5_$grid.csv); [ -n "$f" ] && echo --adaptive $f) \
    --alarm-budget 0.5 --detectors $DEF --out $T/bench_$tag.csv > /dev/null
done
ls "$T"
