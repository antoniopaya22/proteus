# Instalación

## Requisitos

- Python 3.11 o posterior. Los experimentos del manuscrito se ejecutaron con Python 3.12.3.
- No hace falta un compilador de C: todas las dependencias se distribuyen como wheels
  binarios para Linux y macOS.
- Se recomienda [uv](https://docs.astral.sh/uv/), aunque `pip` también sirve.

El paquete principal depende de `numpy`, `pandas`, `pyarrow`, `scipy`, `scikit-learn` y
`numba` (los contadores con decaimiento se compilan con numba).

## Instalar el paquete

Clona el repositorio e instálalo en modo editable con los extras de desarrollo
(`pytest` y `ruff`):

=== "uv"

    ```bash
    git clone https://github.com/antoniopaya22/proteus.git
    cd proteus
    uv venv
    uv pip install -e ".[dev]"
    ```

=== "pip"

    ```bash
    git clone https://github.com/antoniopaya22/proteus.git
    cd proteus
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -e ".[dev]"
    ```

`scripts/reproduce.sh` y `scripts/paper_tables.sh` llaman a `.venv/bin/python`, así que
mantén el entorno virtual en `.venv`, en la raíz del repositorio.

## Extras opcionales

Dos experimentos necesitan dependencias adicionales:

| Extra | Instala | Lo necesita |
|---|---|---|
| `attacks` | `adversarial-robustness-toolbox>=1.20` (ART) | `proteus.evaluation.aml_feature`: ataques basados en decisión y en puntuación contra detectores por flujo (etapa `shell`) |
| `packets` | `dpkt>=1.9` | `proteus.packets.pcap` y `proteus.evaluation.packet_check`: lectura de ficheros pcap (etapa `packets`) |

=== "uv"

    ```bash
    uv pip install -e ".[attacks,packets]"
    ```

=== "pip"

    ```bash
    pip install -e ".[attacks,packets]"
    ```

## Ejecutar los tests

```bash
uv run pytest
```

La batería de tests tarda menos de un minuto y no necesita ningún dataset. Además de los
tests unitarios habituales, comprueba las propiedades de las que depende la garantía:
que los contadores con decaimiento nunca disminuyen al insertar eventos, que la holgura
del certificado se calcula por escala de tiempo (con y sin temporizador de
re-puntuación), que las operaciones gratuitas sobre paquetes respetan la cota tras la
exportación de flujos, que los núcleos entrenados respetan sus restricciones de
monotonía y que un máximo de núcleos monótonos sigue siendo monótono.

## Versiones usadas en el manuscrito

| Paquete | Versión |
|---|---|
| Python | 3.12.3 |
| numpy | 2.5.4 |
| pandas | 3.1.1 |
| scikit-learn | 1.9.1 |
| scipy | 1.18.1 |
| numba | 0.68.1 |
| pyarrow | 26.0.1 |
| adversarial-robustness-toolbox | 1.20.1 |
| dpkt | 1.9.8 |

Se espera que las versiones más recientes funcionen. Si necesitas reproducir las tablas
byte a byte, fija estas versiones.

## Hardware

Los experimentos se ejecutaron en una instancia `c6a.4xlarge` de AWS: 16 vCPU, 32 GB de
RAM y sin GPU. Nada en Proteus usa GPU.

!!! warning "Memoria"
    Las ejecuciones que evalúan sobre CSE-CIC-IDS2018 alcanzan picos de unos 16–18 GB de
    RAM. En una máquina de 32 GB, no ejecutes dos a la vez. Por este motivo,
    `scripts/reproduce.sh` ejecuta sus etapas una tras otra.

El espacio en disco lo ocupan sobre todo los datasets: solo el archivo corregido de
CSE-CIC-IDS2018 ocupa unos 9.7 GB comprimido, y cada dataset convertido guarda una
caché de características de evidencia junto a sus ficheros Parquet
(`data/processed/<dataset>/evidence*/`).

Siguiente: [Inicio rápido](quickstart.md).
