# data

Los datasets no se versionan y viven solo en la máquina de experimentos.

```
data/
  raw/
    cns2022/            zips originales (Liu et al., CNS 2022)
    cicids2017/         CSV por día (CIC-IDS-2017 corregido)
    csecicids2018/      CSV por día (CSE-CIC-IDS-2018 corregido)
  processed/
    <dataset>/<día>.parquet     esquema común de flujo (proteus.datasets.cic)
    <dataset>/summary.csv       flujos por día, ataque y "Attempted"
    <dataset>/evidence/         caché de características de evidencia
```

Origen: https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/
(`CICIDS2017_improved.zip`, 328 MB; `CSECICIDS2018_improved.zip`, 9,7 GB).

Regenerar:

```
python -m proteus.datasets.prepare --dataset cicids2017 \
    --raw data/raw/cicids2017 --out data/processed/cicids2017
python -m proteus.datasets.prepare --dataset csecicids2018 \
    --raw data/raw/csecicids2018 --out data/processed/csecicids2018
```

Etiquetas: `attack` (subtipo canónico), `family`, `attempted` y `is_attack`
(`family != benign` y no "Attempted"). Los flujos "Attempted" se mantienen como
eventos de tráfico pero no se usan como etiqueta ni en las métricas, siguiendo a
los autores del dataset.
