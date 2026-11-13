# Datasets

Los datasets no se distribuyen con el repositorio. Residen en la máquina que ejecuta los
experimentos, bajo `data/`:

```text
data/
  raw/
    cns2022/            original zips (Liu et al., CNS 2022)
    cicids2017/         per-day CSV (corrected CIC-IDS2017)
    csecicids2018/      per-day CSV (corrected CSE-CIC-IDS2018)
    cicids2017_pcap/    per-day pcap of CIC-IDS2017 (only Friday is needed)
    ctu13/              .binetflow files of the 13 scenarios
    unsw_nb15/          official UNSW-NB15 CSV files
    ugr16_hf/           UGR'16 weeks as Parquet (mirror)
    cicddos2019/        CIC-DDoS2019 CSV files
    ctusme11_zeek/      Zeek conn.log files of CTU-SME-11
  processed/
    <dataset>/<day>.parquet     common flow schema
    <dataset>/summary.csv       flows per day, attack and "Attempted"
    <dataset>/evidence*/        caches of evidence features and baselines
```

## Visión general

| Dataset | Uso | Fuente | Notas |
|---|---|---|---|
| CIC-IDS2017 y CSE-CIC-IDS2018, corregidos (Liu et al., CNS 2022) | Detección entre redes, fronteras de daño, ataques adaptativos | [DistriNet](https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/): `CICIDS2017_improved.zip` (328 MB), `CSECICIDS2018_improved.zip` (9.7 GB) | Usa las versiones corregidas, que arreglan fallos de CICFlowMeter y reetiquetan flujos; marcan como "Attempted" los flujos de ataque sin efecto. |
| CIC-IDS2017 pcap | Comprobación del certificado a nivel de paquete | [CIC](https://www.unb.ca/cic/datasets/ids-2017.html) (formulario de descarga) | Solo se necesita `Friday-WorkingHours.pcap`. Verifícalo con las sumas MD5 oficiales. |
| CTU-13 | Tráfico real con fondo sin etiquetar | [Stratosphere Lab](https://www.stratosphereips.org/datasets-ctu13) | Extrae solo los ficheros `.binetflow` y los README: el archivo también contiene los binarios del malware. El fondo sin etiquetar no se trata como benigno. |
| UNSW-NB15 | Atacantes procedentes de un generador de tráfico | [UNSW Canberra](https://research.unsw.edu.au/projects/unsw-nb15-dataset) | Usa los ficheros CSV oficiales. La réplica `rdpahalavan/UNSW-NB15` está deduplicada y no debe usarse. |
| UGR'16 | NetFlow real de un ISP durante periodos largos (en curso) | [NESG, UGR](https://nesg.ugr.es/nesg-ugr16/) | El sitio oficial devolvió HTTP 403; se usó la réplica no oficial de Hugging Face `Lystea/UGR16-PARQUET` (`july_week5`, `august_week1`). |
| CIC-DDoS2019 | DDoS por reflexión y por explotación (en curso) | [CIC](https://www.unb.ca/cic/datasets/ddos-2019.html) (formulario de descarga) | Ficheros CSV de ambos días. Demasiado grande para la memoria; la evidencia se calcula hora a hora. |
| CTU-SME-11 | Red de pequeña empresa con dispositivos IoT (en curso) | Zenodo, registro 7958259 (CC BY 4.0, unos 103 GB) | `conn.log` de Zeek. Zeek exporta las conexiones largas solo cuando terminan, así que el retardo de exportación $\Delta$ del certificado no está acotado en este dataset. |

## Conversión

Todos los conversores se invocan a través de `proteus.datasets.prepare`:

```bash
python -m proteus.datasets.prepare --dataset <name> --raw <raw dir> --out <processed dir>
```

donde `<name>` es uno de `cicids2017`, `csecicids2018`, `ctu13`, `unsw_nb15`, `ugr16`,
`cicddos2019`, `ctusme11`.

Los datasets CIC corregidos:

```bash
python -m proteus.datasets.prepare --dataset cicids2017 \
    --raw data/raw/cicids2017 --out data/processed/cicids2017
python -m proteus.datasets.prepare --dataset csecicids2018 \
    --raw data/raw/csecicids2018 --out data/processed/csecicids2018
```

Los demás datasets:

```bash
for d in ctu13 unsw_nb15 cicddos2019; do
  python -m proteus.datasets.prepare --dataset $d --raw data/raw/$d --out data/processed/$d
done
python -m proteus.datasets.prepare --dataset ugr16 --raw data/raw/ugr16_hf \
    --out data/processed/ugr16 --weeks july_week5 august_week1
python -m proteus.datasets.prepare --dataset ctusme11 --raw data/raw/ctusme11_zeek \
    --out data/processed/ctusme11
```

`bash scripts/reproduce.sh data` convierte los cuatro datasets que usan los experimentos
principales (los dos datasets CIC, CTU-13 y UNSW-NB15).

!!! note "Capturas muy grandes"
    UGR'16 y CIC-DDoS2019 no caben en memoria. Sus conversores leen la entrada en
    streaming, calculan la evidencia ventana a ventana con un calentamiento a partir de
    la ventana anterior (`proteus.evidence.chunked`, `proteus.datasets.staged`) y
    guardan todos los flujos de ataque más una muestra determinista del resto. Los
    contadores siempre usan todos los flujos. Descartar eventos anteriores al
    calentamiento solo puede reducir los contadores: la aproximación puede costar algo
    de exhaustividad (recall), pero nunca lanza una alerta espuria, y una alerta
    certificada sigue estando certificada.

## Esquema común de flujos

Todos los conversores escriben un fichero Parquet por día de captura con las mismas
columnas:

| Columna | Tipo | Significado |
|---|---|---|
| `dataset`, `day` | category | Nombre del dataset y día de captura (nombre del fichero sin extensión) |
| `t_start`, `t_end` | datetime (µs, UTC) | Inicio y fin del flujo; `t_end` es el instante de evento del registro |
| `src_ip`, `dst_ip` | string | Direcciones del iniciador y del que responde |
| `src_port`, `dst_port` | int32 | Puertos |
| `proto` | int16 | Número de protocolo IP |
| `duration_us` | int64 | Duración del flujo en microsegundos |
| `fwd_pkts`, `bwd_pkts` | int64 | Paquetes del iniciador y del que responde |
| `fwd_bytes`, `bwd_bytes` | int64 | Bytes del iniciador y del que responde |
| `f_*` | float32 | Resto de estadísticas por flujo del formato de origen (CICFlowMeter, Argus), usadas solo por la capa por flujo; p. ej., `f_bwd_rst_flags` |
| `label_raw` | category | Etiqueta original |
| `attack`, `family`, `attempted`, `is_attack` | ver abajo | Etiquetas canónicas |

Las filas están ordenadas por `t_end`. Las aproximaciones propias de cada dataset (por
ejemplo, los paquetes en sentido directo estimados a partir de los totales de Argus en
CTU-13, o los resets del que responde inferidos del estado de la conexión en UNSW-NB15)
se documentan en el docstring de cada conversor dentro de `proteus.datasets`.

## Etiquetas

| Columna | Significado |
|---|---|
| `attack` | Subtipo de ataque canónico, común a CIC-IDS2017 y CSE-CIC-IDS2018 (p. ej., `dos_hulk`, `bf_ssh`, `web_sqli`) |
| `family` | Familia de ataque: `benign`, `dos`, `ddos`, `portscan`, `bruteforce`, `web`, `botnet`, `infiltration`, … (`background` para el tráfico sin etiquetar de CTU-13) |
| `attempted` | El flujo pertenece a un ataque pero no tuvo efecto malicioso ("Attempted" en los datasets corregidos) |
| `is_attack` | `family != "benign"` y no `attempted` |

Los flujos "Attempted" se conservan como eventos de tráfico, porque existen en la red y
alimentan los contadores de evidencia, pero no se usan como etiquetas de entrenamiento
ni en las métricas de detección, siguiendo las indicaciones de los autores del dataset.

En CTU-13, los flujos de fondo reciben `family = "background"` y no se tratan como
benignos: el fondo de una red real puede contener ataques sin etiquetar.
