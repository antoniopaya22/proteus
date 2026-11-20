#!/bin/bash
# CertTA (released code) on LOIC-HTTP flows and their free-operation variants.
set -u
R=/home/ubuntu/tools/ext/CertTA-run
PY=/home/ubuntu/tools/ext/certta-env/bin/python
D=/home/ubuntu/proteus/experiments/outputs/certta
MN=DF_CertTA_beta_length_100_beta_time_ms_40_pr_sel_0.15
NV=${NV:-12}
log() { echo "[$(date -u +%d-%H:%M)] $*" >> /home/ubuntu/tools/master.log; }
log "start certta_run (capped, no lock)"
cd $R
for d in $D/datasets/LOIC*; do
  n=$(basename $d)
  rm -rf dataset/$n && cp -r $d dataset/$n
  cp evaluation/config/DF_CICDOH20_config.json evaluation/config/DF_${n}_config.json
done
if [ ! -f model/DF/save/LOIC/$MN/best_model.bin ]; then
  echo "== train"; $PY evaluation/train.py --dataset LOIC --model DF --augment CertTA || exit 1
fi
echo "== test clean"
rm -rf model/DF/save/LOIC/$MN/CertTA/clean
$PY evaluation/test.py --dataset LOIC --model DF --augment CertTA --smoothed CertTA
$PY evaluation/collect_classification_results.py --dataset LOIC --model DF --augment CertTA --smoothed CertTA
cat model/DF/save/LOIC/$MN/CertTA/clean/empirical_acc.txt
for k in $(seq -f %02g 0 $((NV-1))); do
  echo "== test variant $k"
  m=model/DF/save/LOIC_v$k/$MN
  rm -rf $m && mkdir -p $m && ln -s $R/model/DF/save/LOIC/$MN/best_model.bin $m/best_model.bin
  $PY evaluation/test.py --dataset LOIC_v$k --model DF --augment CertTA --smoothed CertTA
done
echo "== region"
cd /home/ubuntu/proteus
$PY -I scripts/external/certta_region.py --certta $R --data $D/datasets --out $D
echo "exit $?"
log "done  certta_run"
