# Referencia de la API

Proteus está organizado como un único paquete de Python, `proteus`, bajo `src/proteus/`.
Las páginas de esta sección documentan los módulos que implementan la garantía. El resto
del paquete se describe en la tabla siguiente y en los docstrings de cada módulo.

| Paquete | Contenido |
|---|---|
| `proteus.datasets` | Lectores y conversión a Parquet de CIC-IDS2017, CSE-CIC-IDS2018, CTU-13, UNSW-NB15, UGR'16, CIC-DDoS2019 y CTU-SME-11; etiquetas canónicas; procesamiento por etapas de capturas demasiado grandes para la memoria |
| `proteus.evidence` | Contadores con decaimiento por entidad y recuentos de elementos distintos (`counters`), características de evidencia y su clase de conservación (`features`), líneas base por entidad (`baseline`), evidencia ventana a ventana para capturas muy grandes (`chunked`) |
| `proteus.core` | Certificado (`certify`), combinación de subnúcleos (`combine`), frontera de daño (`frontier`), envenenamiento de la línea base (`poisoning`), explicaciones (`explain`), reglas declaradas (`rules`), comprobación empírica de la monotonía (`verify`) |
| `proteus.packets` | Lectura de pcap, un exportador de flujos al estilo NetFlow/IPFIX y operaciones gratuitas sobre paquetes |
| `proteus.shell` | Clasificador por flujo (la capa) |
| `proteus.attacks` | Operaciones del atacante sobre registros de flujo: operaciones gratuitas y ralentización |
| `proteus.baselines` | Apollon (código publicado e implementación corregida), umbrales de tasa fijos, KitNET, suavizado aleatorizado |
| `proteus.evaluation` | Experimentos y tablas; consulta [Módulos de experimentos](../guide/experiments.md) |

## Módulos documentados

| Página | Módulo | Qué contiene |
|---|---|---|
| [Certificado](certify.md) | `proteus.core.certify` | Holgura por característica, características del peor caso, peor caso con reutilización de conexiones |
| [Combinación de subnúcleos](combine.md) | `proteus.core.combine` | `MaxCore` y `CalibratedMax` |
| [Frontera de daño](frontier.md) | `proteus.core.frontier` | Escenarios, ataques anidados, alertas atribuibles, bisección de la frontera |
| [Contadores de evidencia](counters.md) | `proteus.evidence.counters` | Sumas con decaimiento exponencial y recuentos de elementos distintos por entidad |
| [Líneas base](baselines.md) | `proteus.evidence.baseline` | Líneas base por entidad, características de exceso, líneas base de población |

La API es código de investigación y puede cambiar entre versiones. Los nombres de las
características, las claves de las entidades y los nombres de los ficheros de salida son
las partes más estables.
