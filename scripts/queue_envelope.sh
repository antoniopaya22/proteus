#!/usr/bin/env bash
# Queue of the envelope check on a shared machine: every step waits for the lock of the
# heavy jobs, leaves a mark when done and is skipped on a rerun.
# Deciding check of docs/13: label-free envelope on harm witnesses. Under the lock, in series.
cd ~/proteus
PY=".venv/bin/python -m"
O=experiments/outputs/envelope
mkdir -p $O ~/tools/m
RAW=$(find ~/proteus/data -type f -name "*.parquet" -size +2G -ipath "*ugr*" | sort | tr "\n" " ")
step() {
  local name=$1 log=$2; shift 2
  [ -f ~/tools/m/$name ] && return 0
  echo "[$(date -u +%d-%H:%M)] start $name" >> ~/tools/master.log
  if flock /home/ubuntu/tools/heavy.lock "$@" > $O/$log 2>&1; then
    touch ~/tools/m/$name; echo "[$(date -u +%d-%H:%M)] done  $name" >> ~/tools/master.log
  else
    echo "[$(date -u +%d-%H:%M)] FAIL  $name" >> ~/tools/master.log
  fi
}
echo "raw: $RAW" > $O/raw.txt
# Tables first, alone: the log ends with rows per day and their size in memory. Check it
# against free memory before the rest (the calibration holds every day at once).
step env_ugr_build env_ugr_build.log $PY proteus.evaluation.envelope_exp --test ugr16 --raw $RAW --build-only
[ -f ~/tools/m/env_ugr_build ] || exit 1
[ -n "$ENV_GO" ] || { echo "tables built; rerun with ENV_GO=1 after reading $O/env_ugr_build.log"; exit 0; }
step env_ugr env_ugr.log $PY proteus.evaluation.envelope_exp --test ugr16 --templates csecicids2018 --alarm-budget 0.5 --victims 25 --span 36 --attack-windows 3 36 144
step env_ugr_causal env_ugr_causal.log $PY proteus.evaluation.envelope_exp --test ugr16 --templates csecicids2018 --alarm-budget 0.5 --victims 25 --span 36 --attack-windows 3 36 144 --protocol causal
for ds in cicids2017 csecicids2018; do
  step env_${ds}_causal env_${ds}_causal.log $PY proteus.evaluation.envelope_exp --test $ds --alarm-budget 0.5 --victims 25 --span 36 --attack-windows 3 36 144 --protocol causal --min-days 1
  step env_${ds}_loo env_${ds}_loo.log $PY proteus.evaluation.envelope_exp --test $ds --alarm-budget 0.5 --victims 25 --span 36 --attack-windows 3 36 144 --min-days 1
done
