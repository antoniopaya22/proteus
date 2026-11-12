# data

Los datasets no se versionan y viven solo en la máquina de experimentos.

```
data/
  raw/
    cns2022/            zips originales (Liu et al., CNS 2022)
    cicids2017/         CSV por día (CIC-IDS-2017 corregido)
    csecicids2018/      CSV por día (CSE-CIC-IDS-2018 corregido)
    cicids2017_pcap/    pcap por día de CIC-IDS-2017 (solo el viernes hace falta)
    ctu13/              .binetflow de los 13 escenarios
    unsw_nb15/          CSV oficiales de UNSW-NB15
    ugr16_hf/           semanas de UGR'16 en Parquet (espejo)
    cicddos2019/        CSV de CIC-DDoS-2019
    ctusme11_zeek/      conn.log de Zeek de CTU-SME-11
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

## Otros datasets

| Dataset | Origen | Notas |
|---|---|---|
| pcap de CIC-IDS-2017 | https://www.unb.ca/cic/datasets/ids-2017.html (formulario) | Solo `Friday-WorkingHours.pcap` (comprobación con paquetes). Verificar con los md5 oficiales |
| CTU-13 | https://www.stratosphereips.org/datasets-ctu13 | Extraer solo `.binetflow` y README: el archivo incluye los binarios del malware. El fondo no etiquetado no se trata como benigno |
| UNSW-NB15 | https://research.unsw.edu.au/projects/unsw-nb15-dataset | CSV oficiales (el espejo `rdpahalavan/UNSW-NB15` está deduplicado: no usarlo) |
| UGR'16 | https://nesg.ugr.es/nesg-ugr16/ | La web oficial daba 403; se usó el espejo no oficial de Hugging Face `Lystea/UGR16-PARQUET` (`july_week5`, `august_week1`) |
| CIC-DDoS-2019 | https://www.unb.ca/cic/datasets/ddos-2019.html (formulario) | CSV de los dos días |
| CTU-SME-11 | Zenodo (CC BY 4.0, ~103 GB) | `conn.log` de Zeek; Zeek exporta las conexiones largas al terminar, así que su Δ no está acotado |

```
for d in ctu13 unsw_nb15 cicddos2019; do
  python -m proteus.datasets.prepare --dataset $d --raw data/raw/$d --out data/processed/$d
done
python -m proteus.datasets.prepare --dataset ugr16 --raw data/raw/ugr16_hf \
    --out data/processed/ugr16 --weeks july_week5 august_week1
python -m proteus.datasets.prepare --dataset ctusme11 --raw data/raw/ctusme11_zeek \
    --out data/processed/ctusme11
```
