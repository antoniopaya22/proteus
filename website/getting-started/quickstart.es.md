# Inicio rápido

Esta página te lleva desde un clon recién hecho hasta las tablas de detección entre
redes. Supone que has seguido [Instalación](installation.md) y que el entorno virtual
está en `.venv`, en la raíz del repositorio.

!!! note "Qué esperar"
    Proteus es código de investigación. Los comandos siguientes son los que se usaron
    para el manuscrito, con los mismos parámetros. Son experimentos por lotes sobre días
    de captura completos, no un servicio en streaming, y algunos tardan horas.

## 1. Ejecutar los tests

```bash
uv run pytest
```

Si los tests pasan, el paquete, numba y el gradient boosting monótono de scikit-learn
funcionan en tu máquina.

## 2. Convertir un dataset

Los experimentos de detección entrenan en una red y prueban en otra. El par principal
son CIC-IDS2017 y CSE-CIC-IDS2018 corregidos (Liu et al., CNS 2022), que distribuye el
grupo DistriNet en
[intrusion-detection.distrinet-research.be/CNS2022/Datasets](https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/).

Descarga `CICIDS2017_improved.zip` (328 MB) y `CSECICIDS2018_improved.zip` (9.7 GB),
descomprime los ficheros CSV de cada día y conviértelos:

```bash
mkdir -p data/raw/cicids2017 data/raw/csecicids2018
# unzip the CSV files of each dataset into its folder, then:
.venv/bin/python -m proteus.datasets.prepare --dataset cicids2017 \
    --raw data/raw/cicids2017 --out data/processed/cicids2017
.venv/bin/python -m proteus.datasets.prepare --dataset csecicids2018 \
    --raw data/raw/csecicids2018 --out data/processed/csecicids2018
```

Cada día de captura se convierte en `data/processed/<dataset>/<day>.parquet` con el
esquema común de flujos, y `summary.csv` enumera los flujos por día y ataque. Consulta
[Datasets](../guide/datasets.md) para el esquema, las etiquetas y los demás datasets.

Para convertir de una vez todos los datasets que usan las etapas de detección (los
ficheros originales deben estar en `data/raw/<dataset>`), ejecuta la etapa `data`:

```bash
bash scripts/reproduce.sh data
```

## 3. Ejecutar la etapa de detección entre redes

`scripts/reproduce.sh` ejecuta cada experimento del manuscrito con sus parámetros
exactos. La etapa `h1` entrena Proteus, Proteus-cert y los detectores de comparación en
un dataset y los prueba en el otro, en ambas direcciones:

```bash
bash scripts/reproduce.sh h1
```

Internamente, la etapa selecciona la versión 3 de la evidencia y llama al experimento
H1. La primera de sus ejecuciones es:

```bash
export PROTEUS_EVIDENCE=v3
.venv/bin/python -m proteus.evaluation.h1 --train csecicids2018 --test cicids2017 \
    --models proteus proteus_cert core_pair core_mono_dst_x core_cert core_free_dst_b rate_rules_local \
    --tag v3
```

`PROTEUS_EVIDENCE=v3` es importante: la versión de evidencia por defecto (`v1`) no
tiene ni las escalas de tiempo largas (1 h y 6 h) ni la entidad par origen–servicio, y
los detectores `proteus` y `proteus_cert` solo están definidos sobre la versión 3.

!!! warning "Tiempo y memoria"
    La dirección 2017 → 2018 tarda alrededor de hora y media y alcanza un pico de unos
    16 GB de RAM. No lances una segunda ejecución que pruebe sobre CSE-CIC-IDS2018
    mientras esta esté en marcha.

La primera ejecución de cada dirección calcula las características de evidencia y las
guarda en caché en `data/processed/<dataset>/` (directorios `evidence_b_*`); las etapas
posteriores reutilizan esa caché y los modelos entrenados (`--reuse`).

## 4. Regenerar las tablas

```bash
bash scripts/paper_tables.sh
# or, equivalently, as the last stage:
bash scripts/reproduce.sh tables
```

El script solo usa las ejecuciones que terminaron (las que tienen un `summary.csv`) y se
salta las tablas a las que les faltan datos de entrada, así que puedes ejecutarlo tras
cualquier subconjunto de etapas.

## Dónde van los resultados

| Ruta | Contenido |
|---|---|
| `experiments/outputs/h1/<train>__<test>__loo_labels__<tag>/` | Un directorio por ejecución: `campaigns.csv` (detección por campaña de ataque), `summary.csv`, `false_alarms.csv`, los modelos ajustados (`models.pkl`) y, tras etapas posteriores, los CSV de frontera y del atacante adaptativo. |
| `experiments/outputs/h1/*.log` | Registro de cada comando que ejecuta `reproduce.sh`. |
| `experiments/outputs/paper_tables/` | Tablas LaTeX y datos CSV de las figuras, escritos por `paper_tables.sh`. |
| `experiments/outputs/packet_check*/`, `experiments/outputs/aml_feature/` | Resultados de la comprobación a nivel de paquete y de los ataques contra detectores por flujo. |

El nombre del directorio de una ejecución codifica la dirección:
`csecicids2018__cicids2017__loo_labels__v3` se entrenó en CSE-CIC-IDS2018 y se probó en
CIC-IDS2017, con líneas base que dejan fuera un día (`loo`) y con los minutos de ataque
excluidos de las líneas base (`labels`).

Para mostrar en el terminal los resultados de detección de una ejecución:

```bash
.venv/bin/python -m proteus.evaluation.report_h1 \
    experiments/outputs/h1/csecicids2018__cicids2017__loo_labels__v3
```

## Siguientes pasos

- [Reproducir los experimentos](../guide/reproduce.md) enumera todas las etapas.
- [Módulos de experimentos](../guide/experiments.md) documenta cada comando y sus opciones.
- [Cómo funciona Proteus](../concepts/index.md) explica qué significan los números.
