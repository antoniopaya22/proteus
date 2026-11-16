# Reproducir los experimentos

`scripts/reproduce.sh` ejecuta cada experimento del manuscrito con sus parámetros
exactos, agrupados en etapas. A continuación, `scripts/paper_tables.sh` regenera las
tablas y los datos de las figuras. Ambos scripts se ejecutan desde la raíz del
repositorio y esperan el entorno virtual en `.venv`.

```bash
bash scripts/reproduce.sh data          # convert the datasets (once)
bash scripts/reproduce.sh h1 tables     # cross-network detection, then the tables
bash scripts/reproduce.sh all           # every stage, in order
```

Las etapas se ejecutan de forma secuencial, en el orden indicado. Cada comando escribe
su salida estándar y sus errores en un fichero `.log` junto a sus resultados, y la línea
de registro que se muestra en el terminal indica el comando exacto.

## Etapas

| Etapa | Produce | Notas |
|---|---|---|
| `data` | Ficheros Parquet de CIC-IDS2017, CSE-CIC-IDS2018, CTU-13, UGR'16, CIC-DDoS2019 y UNSW-NB15 | Los ficheros originales deben estar en `data/raw/<dataset>`; consulta [Datasets](datasets.md) |
| `h1` | Detección entre redes en ambos sentidos: se ajustan todos los detectores de Proteus y después se evalúan juntos, con los mismos umbrales y presupuestos de alarmas | La ejecución 2017 → 2018 tarda alrededor de 1,5 h y alcanza un pico de unos 16 GB |
| `baselines` | Los detectores con los que se compara Proteus: KitNET, umbrales de tasa con rasgos seleccionados, Apollon y el clasificador por flujo, TRW y CUSUM | Reutiliza los modelos de `h1` donde puede |
| `systems` | Alertas por flujo de cada detector, el complemento de fidelidad por ventana y los sistemas candidatos (uniones) que se forman con ellas | Consulta [Experimentos](experiments.md) |
| `cert` | Operaciones gratuitas sobre las campañas reales, cada campaña sin los demás ataques de su día, holgura del certificado con temporizador de recálculo, subnúcleos saturados | Reutiliza los modelos de `h1` |
| `frontier` | Frontera de daño por tipo de ataque, simple y certificada, sobre la víctima real y sobre el servicio con más tráfico | |
| `adaptive` | Daño bajo el atacante adaptativo con planes fijos, todos los detectores | Pico de unos 12 GB |
| `query` | Daño bajo el atacante por consultas (búsqueda de caja negra con etiqueta dura), todos los candidatos en una ejecución | Unas 3 h |
| `ablation` | Ablación de subnúcleos (`proteus-K` elimina el subnúcleo K) | Reutiliza los modelos de `h1` |
| `poisoning` | Fronteras bajo envenenamiento de la línea base | |
| `budget` | Certificado de presupuesto (suavizado aleatorizado, el mecanismo de BARS) frente a operaciones gratuitas | |
| `real` | CTU-13 y UGR'16 (dos particiones cada uno), CIC-DDoS2019 y UNSW-NB15; fronteras del lado del origen en CTU-13 | |
| `shell` | Ataques basados en decisión y en puntuación contra detectores por flujo; calibración del contador de realimentación | Necesita el extra `attacks` (ART); tarda horas |
| `robustness` | Cuatro semillas más, líneas base calculadas sin etiquetas, balance de clases del conjunto de entrenamiento | Vuelve a ajustar los detectores |
| `packets` | Comprobación del certificado a nivel de paquete sobre el pcap del viernes de CIC-IDS2017 | Necesita el pcap y el extra `packets` (`dpkt`) |
| `cost` | Rendimiento del cálculo de evidencia, rendimiento de la puntuación y estado por entidad | Medido en un núcleo de CPU |
| `tables` | Ejecuta `scripts/paper_tables.sh` | Usa solo las ejecuciones terminadas |

## Comandos por etapa

El script es la referencia: cada etapa es una función corta con los comandos exactos.
Para leerlos sin ejecutar nada, pide una pasada en seco, que imprime cada comando y el
fichero de registro que escribiría:

```bash
DRY=1 bash scripts/reproduce.sh adaptive query
```

Las variables que usan los comandos se definen al principio del script:

```bash
export PROTEUS_EVIDENCE=v3
PY=".venv/bin/python -m"
O=experiments/outputs/h1
A=$O/csecicids2018__cicids2017__loo_labels__r2   # entrenado en 2018, probado en 2017
B=$O/cicids2017__csecicids2018__loo_labels__r2   # entrenado en 2017, probado en 2018
BUD="--entity-budgets 0.5 1 3 10"                # presupuestos de alarmas por entidad y hora
```

El directorio de una ejecución se llama `<train>__<test>__loo_labels__<tag>`; las etapas
posteriores encuentran los modelos ajustados por `h1` con `--reuse` y `--extra-runs`.

`scripts/paper_tables.sh` escribe las tablas y los datos de las figuras en
`experiments/outputs/paper_tables/`. Toma del entorno el directorio de las ejecuciones y
el de salida, así que también funciona sobre una copia de los resultados:

```bash
O=/ruta/a/ejecuciones T=/ruta/a/tablas bash scripts/paper_tables.sh
```

## Determinismo

- Las semillas están fijadas: `--seed 0` en todos los experimentos y generadores de
  variantes, y `random_state=0` en todos los modelos.
- Los umbrales se calibran solo con tráfico benigno de la red de prueba (otros días),
  sin etiquetas de ataque.
- Apollon, que se evalúa como línea base, responde al azar por diseño, así que sus
  respuestas varían entre ejecuciones; cada ejemplo adversario contra él se evalúa con
  diez extracciones.

## Variables de entorno

| Variable | Valor por defecto | Efecto |
|---|---|---|
| `PROTEUS_EVIDENCE` | `v1` | Versión de la evidencia. `v2` añade los flujos sin respuesta y los destinos sin respuesta; `v3` añade las escalas de 1 h y 6 h y la entidad par origen–servicio. `proteus` y `proteus_cert` necesitan `v3`. |
| `PROTEUS_TIMER_S` | `0` | Temporizador de re-puntuación $\delta$ en segundos; la holgura del certificado pasa a ser $(2\Delta + \delta)/\tau$. |
| `PROTEUS_PEER` | `0` | `1` añade líneas base de población: exceso sobre el percentil 99 de los servicios con el mismo puerto y protocolo (características `__xp`). Experimental; aproximadamente duplica la caché de evidencia. |
| `PROTEUS_PAIRBASE` | `0` | `1` añade una línea base de pares relativa al par normal más activo del mismo servicio (evidencia v3). Experimental. |

Las cachés de evidencia residen en directorios separados por versión de evidencia,
configuración de la línea base y opción (`data/processed/<dataset>/evidence_b_*`), así
que cambiar las variables no sobrescribe las cachés anteriores.

## Memoria

!!! warning
    Las ejecuciones que prueban sobre CSE-CIC-IDS2018 alcanzan picos de unos 16–18 GB de
    RAM. En una máquina de 32 GB, no ejecutes nunca dos a la vez. El script ejecuta las
    etapas de forma secuencial; si lanzas etapas a mano en paralelo, comprueba qué
    dataset de prueba usa cada una.

La etapa `shell` ejecuta sus ataques en 8 procesos de trabajo (`--workers 8`); redúcelo
en máquinas más pequeñas.
