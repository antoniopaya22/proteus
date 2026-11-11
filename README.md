# Proteus

Sucesor de [Apollon](https://doi.org/10.1016/j.cose.2023.103546): detección de intrusiones
en red robusta frente a evasión adversaria. En lugar de ocultar qué modelo responde,
Proteus detecta sobre **evidencia conservada** (contadores por entidad que las operaciones
gratuitas del atacante solo pueden aumentar) con un **núcleo monótono**, de modo que la
evasión mediante esas operaciones queda descartada por construcción y la que queda
(ir más despacio) se mide como **frontera de daño**.

El paper está en un repositorio aparte (`proteus-paper`).

## Estructura

| Carpeta | Contenido |
|---|---|
| `docs/` | Análisis de Apollon v1, estado del arte, diseño, plan de trabajo y resultados |
| `src/proteus/datasets` | Lectura de CIC-IDS-2017/CSE-CIC-IDS-2018 (versiones corregidas) y etiquetas |
| `src/proteus/evidence` | Contadores con decaimiento por entidad y líneas base por entidad |
| `src/proteus/core` | Verificación de monotonía, certificación y frontera de daño |
| `src/proteus/attacks` | Operadores del atacante sobre registros de flujo |
| `src/proteus/baselines` | Apollon v1 (variantes "código" y corregida) y umbrales fijos |
| `src/proteus/evaluation` | Experimento H1 cruzado entre datasets, tablas y frontera |
| `tests/` | Tests, incluidos los de las propiedades que sostienen la garantía |
| `experiments/outputs/` | Tablas de resultados (CSV/JSON) |
| `data/` | Datasets (no versionados; ver `data/README.md`) |

## Uso

```sh
uv venv && uv pip install -e ".[dev]"
uv run pytest

# Datos (ver data/README.md) y experimentos
python -m proteus.datasets.prepare --dataset cicids2017 --raw data/raw/cicids2017 --out data/processed/cicids2017
python -m proteus.evaluation.h1 --train csecicids2018 --test cicids2017
python -m proteus.evaluation.report_h1 experiments/outputs/h1
python -m proteus.evaluation.frontier_exp --run experiments/outputs/h1/<run> --test cicids2017
```

Estado: fase 1 (prototipo del núcleo). Resultados en `docs/06-resultados-fase1.md`.
