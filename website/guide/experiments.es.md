# Módulos de experimentos

Cada experimento es un módulo de `proteus.evaluation` con interfaz de línea de comandos.
Ejecuta cualquiera de ellos con `--help` para ver todas sus opciones:

```bash
python -m proteus.evaluation.h1 --help
```

La mayoría de los módulos reciben un **directorio de ejecución** (`--run`) generado por
`h1`, que contiene los modelos ajustados (`models.pkl`) y la configuración de la
evidencia, y el nombre del **dataset de prueba** (`--test`). Los umbrales siempre se
calibran sobre el tráfico benigno de la red de prueba con una tasa de falsos positivos
objetivo (`--fpr`, por defecto `0.001`). Fija `PROTEUS_EVIDENCE=v3` cuando una ejecución
se entrenó con la versión 3 de la evidencia. Las semillas valen `0` por defecto.

La tabla resume los módulos; cada uno se describe más abajo.

| Módulo | Propósito |
|---|---|
| [`h1`](#h1) | Entrenar y probar detectores entre redes; detección por campaña y falsas alarmas |
| [`report_h1`](#report_h1) | Mostrar las tablas de detección y de falsas alarmas de las ejecuciones de `h1` |
| [`clean`](#clean) | Evaluación por flujo dentro del dataset con el protocolo de la literatura |
| [`free_ops`](#free_ops) | Operaciones gratuitas sobre campañas reales: comprobación empírica de la garantía sobre registros de flujo |
| [`frontier_exp`](#frontier_exp) | Frontera de daño por tipo de ataque (lado del destino) |
| [`frontier_scan`](#frontier_scan) | Frontera de daño de los escaneos horizontales (lado del origen) |
| [`adaptive`](#adaptive) | Daño bajo un atacante adaptativo (tasa, operaciones gratuitas, mimetismo) |
| [`poisoning`](#poisoning) | Envenenamiento de la línea base y crecimiento de las líneas base benignas |
| [`packet_check`](#packet_check) | Comprobación del certificado sobre paquetes reales |
| [`smoothing`](#smoothing) | Si un certificado de presupuesto (suavizado aleatorizado) cubre las operaciones gratuitas |
| [`aml_feature`](#aml_feature) | Ataques de evasión en el espacio de características contra detectores por flujo |
| [`feedback`](#feedback) | Calibración del contador de realimentación de la capa |
| [`alarms`](#alarms) | Alarmas por entidad sobre tráfico real, atribuidas a un lado |
| [`cost`](#cost) | Rendimiento y estado por entidad |
| [`bench`](#bench) | Comparación multidimensional de defensas |
| [`tables`](#tables) | Tablas LaTeX y datos de las figuras |

## `h1`

El experimento principal. Estudia si un núcleo monótono sobre evidencia conservada
detecta campañas volumétricas, de escaneo y de fuerza bruta entre redes con una tasa de
falsas alarmas baja. Los detectores se entrenan en un dataset y se prueban en otro, con
umbrales calibrados sobre el tráfico benigno de la red de prueba.

```bash
PROTEUS_EVIDENCE=v3 python -m proteus.evaluation.h1 \
    --train csecicids2018 --test cicids2017 \
    --models proteus proteus_cert rate_rules_local --tag v3
```

| Opción | Significado |
|---|---|
| `--train`, `--test` | Datasets de entrenamiento y de prueba (obligatorios) |
| `--models` | Detectores que se entrenan y evalúan (por defecto: todos) |
| `--reuse RUN` | Evaluar los modelos ajustados de una ejecución anterior en lugar de entrenar; `--models` puede entonces nombrar máximos como `a+b` |
| `--tag` | Sufijo del directorio de salida |
| `--baseline {loo,prior}` | Días de referencia de las líneas base: dejar un día fuera, o solo los días anteriores |
| `--mask {labels,none}` | Excluir o no los minutos de ataque de las líneas base |
| `--entity-budgets` | Calibrar además los umbrales para no superar este número de alarmas por hora |
| `--train-days`, `--test-days` | Restringir el entrenamiento o la prueba a algunos días de captura |
| `--balance {cap,type,type_entity,none}` | Equilibrio de clases del conjunto de entrenamiento |
| `--exclude-saturated FPR` | Quitar de los máximos calibrados los subnúcleos que no pueden alcanzar esta FPR sobre el tráfico benigno local |
| `--train-thresholds` | Evaluar además los umbrales calibrados en la red de entrenamiento |

Nombres de los detectores principales:

| Nombre | Detector |
|---|---|
| `proteus`, `proteus_cert` | Máximo calibrado de los cuatro subnúcleos, todas las escalas / escalas ≥ 600 s (evidencia v3) |
| `proteus-K`, `proteus_cert-K` | Lo mismo sin el subnúcleo K (ablación) |
| `proteus_free` | Los mismos cuatro subnúcleos sin restricciones de monotonía |
| `core_pair` | Subnúcleo de par por sí solo |
| `core_mono_dst`, `core_mono_dst_x`, `core_cert` | Núcleos monótonos de destino individuales: en bruto, en bruto más exceso, solo la escala más larga |
| `core_src_x`, `core_both_x`, `core_both_cert` | Núcleo de origen, y máximos de los núcleos de destino y de origen |
| `core_free_dst_b` | Núcleo de destino sin restricciones con líneas base |
| `rate_rules_local` | Umbrales fijos por característica ajustados sobre el tráfico benigno local |
| `kitnet_local` | KitNET sobre las mismas estadísticas con decaimiento, ajustado sobre el tráfico benigno local |
| `flow_clf` | Clasificador por flujo (la capa) |

Resultados, en `experiments/outputs/h1/<train>__<test>__<baseline>_<mask>[__<tag>]/`:
`campaigns.csv`, `summary.csv`, `false_alarms.csv` y `models.pkl`.

## `report_h1`

Muestra la detección de campañas por ataque y detector, y las falsas alarmas, de una o
varias ejecuciones de `h1`.

```bash
python -m proteus.evaluation.report_h1 experiments/outputs/h1 --by-family
```

Opciones: directorios de ejecución o un directorio padre, `--threshold` (por defecto
`local`), `--by-family`, `--models`.

## `clean`

Evaluación por flujo dentro de un mismo dataset, con el protocolo habitual en la
literatura: partición aleatoria 80/20 por día de captura, etiquetas binarias con los
flujos "Attempted" contados como benignos, entrenamiento sobre una submuestra y
evaluación sobre toda la partición de prueba. Sitúa la capa por flujo junto a los
resultados por flujo publicados.

```bash
python -m proteus.evaluation.clean --dataset cicids2017 --seeds 0 1 2 3 4
```

Opciones: `--dataset`, `--seeds`, `--with-port`, `--cap-attack`, `--cap-benign`,
`--out`.

## `free_ops`

Comprobación empírica de la garantía sobre registros de flujo. Para cada tipo de ataque,
toma una ventana de la campaña real contra su víctima más el tráfico real hacia la
víctima, y aplica combinaciones aleatorias de operaciones gratuitas
(`proteus.attacks.operators`) a los flujos de ataque. Comprueba que:

- con operaciones que no retemporizan flujos, la puntuación de ningún flujo original
  disminuye;
- si la campaña original tiene una alerta certificada, cada variante genera una alerta
  sobre la víctima no más de $\Delta$ después;

e informa de lo que gana el atacante frente a la detección no certificada.

```bash
python -m proteus.evaluation.free_ops \
    --run experiments/outputs/h1/csecicids2018__cicids2017__loo_labels__cert \
    --test cicids2017 --models core_cert core_mono_dst_x --variants 20
```

Opciones: `--run`, `--test`, `--models`, `--fpr`, `--variants`, `--seed`.

## `frontier_exp`

Frontera de daño por tipo de ataque en la red de prueba: víctima real, su fondo real,
formas de flujo de la campaña real, modelo y umbral local como en `h1`. Informa de la
frontera simple (flujos/s, flujos/h, paquetes en sentido directo/h), de la frontera
certificada y de la tasa que usó la campaña real. Solo cuentan las alertas atribuibles
(consulta [Frontera de daño](../concepts/harm-frontier.md)).

```bash
PROTEUS_EVIDENCE=v3 python -m proteus.evaluation.frontier_exp \
    --run experiments/outputs/h1/csecicids2018__cicids2017__loo_labels__v3 \
    --test cicids2017 --model proteus_cert --rmax 200
```

| Opción | Significado |
|---|---|
| `--model` | Detector de la ejecución |
| `--delta` | Tiempo de espera activo del exportador usado para la frontera certificada (por defecto 120 s) |
| `--rmax` | Tasa máxima probada, en flujos/s |
| `--fpr`, `--seed` | Tasa de falsos positivos objetivo y semilla |

Resultado: `frontier_<model>_<fpr>_attr.csv` en el directorio de la ejecución.

## `frontier_scan`

Frontera de daño de los escaneos horizontales, en el lado del origen (por ejemplo, los
escaneos de las botnets de CTU-13). Para cada día con una campaña de escaneo, las sondas
del origen de escaneo más activo se reproducen desde un origen nuevo a tasa $r$,
manteniendo destinos y puertos, sobre el tráfico real hacia esos mismos destinos.
Informa de la frontera en sondas y en destinos distintos por minuto, y de la tasa que
usó el bot real.

```bash
PROTEUS_EVIDENCE=v3 python -m proteus.evaluation.frontier_scan \
    --run experiments/outputs/h1/ctu13__ctu13__loo_labels__foldB_v3 \
    --test ctu13 --model proteus --fpr 1e-3 --hours 6
```

Opciones: `--model`, `--family` (por defecto `portscan`), `--fpr`, `--delta`, `--rmax`
(sondas/s), `--hours` (duración del escaneo reproducido; las escalas de tiempo largas
necesitan horas), `--seed`.

## `adaptive`

Daño bajo un atacante adaptativo. Para cada escenario de `frontier_exp`, el atacante
elige una tasa y una combinación de operaciones gratuitas, incluido el mimetismo del
tráfico benigno de la víctima. Su daño es la mayor tasa a la que ningún flujo del
atacante lanza una alerta atribuible. Las tasas se recorren en una rejilla geométrica,
sin suponer monotonía en la tasa, de modo que los detectores sin garantías se evalúan
de forma justa.

```bash
PROTEUS_EVIDENCE=v3 python -m proteus.evaluation.adaptive \
    --run experiments/outputs/h1/csecicids2018__cicids2017__loo_labels__v3 \
    --test cicids2017 --models proteus proteus_cert core_free_dst_b \
    --local rate_rules_local kitnet_local --certify proteus_cert --grid 20
```

| Opción | Significado |
|---|---|
| `--models` | Modelos ajustados de la ejecución, o máximos de ellos escritos como `a+b` |
| `--extra-runs` | Otras ejecuciones de la misma dirección de las que tomar modelos |
| `--local` | Detectores no supervisados ajustados por día sobre el tráfico benigno local |
| `--certify` | Detectores para los que se informa también de la frontera certificada |
| `--variants` | Variantes aleatorias con operaciones gratuitas por tasa |
| `--grid`, `--rmin`, `--rmax` | Rejilla geométrica de tasas |
| `--attacks` | Restringir a algunos tipos de ataque |

Resultados: `adaptive_<fpr>.csv` y `adaptive_ladder_<fpr>.csv` en el directorio de la
ejecución.

## `poisoning`

Envenenamiento de la línea base (consulta `proteus.core.poisoning`). Para cada escenario
de ataque, calcula la frontera tras $k = 0, \dots, \text{rounds}$ actualizaciones de la
línea base en las que el atacante envenena todo el periodo de referencia justo por
debajo de la frontera actual, con y sin límite al crecimiento de la línea base por
actualización, y el techo con una línea base infinita.

```bash
PROTEUS_EVIDENCE=v3 python -m proteus.evaluation.poisoning \
    --run experiments/outputs/h1/csecicids2018__cicids2017__loo_labels__v3 \
    --test cicids2017 --model proteus_cert --rounds 8 --caps none 0.25 0.1
```

| Opción | Significado |
|---|---|
| `--model` | Un modelo de la ejecución, o `a+b` para el máximo de varios |
| `--rounds` | Número de actualizaciones de la línea base (días) |
| `--caps` | Límites de crecimiento por actualización, en unidades log1p; `none` significa sin límite |
| `--growth-only` | Medir solo el crecimiento diario de las líneas base benignas |
| `--rmax`, `--attacks`, `--fpr`, `--seed` | Como en `adaptive` |

## `packet_check`

Comprueba el certificado sobre paquetes: las operaciones gratuitas aplicadas a paquetes
de ataque reales, reexportados como registros de flujo, nunca reducen la evidencia de la
víctima ni la de los atacantes más allá de la holgura. Consulta
[Comprobar el certificado con paquetes](packets.md).

```bash
PROTEUS_EVIDENCE=v3 python -m proteus.evaluation.packet_check \
    --pcap data/raw/cicids2017_pcap/Friday-WorkingHours.pcap \
    --packets experiments/outputs/packet_check/loic_packets.parquet \
    --victim 192.168.10.50 --attackers 172.16.0.1 --port 80 \
    --start 1499453400 --minutes 25 --out experiments/outputs/packet_check_v3
```

## `smoothing`

¿Cubre un certificado expresado como presupuesto de perturbación las operaciones
gratuitas del atacante? Un núcleo sin restricciones se suaviza con ruido gaussiano por
característica (`proteus.baselines.smoothing`, una reimplementación del mecanismo en el
que se basa BARS), y cada flujo de ataque con alerta recibe un radio certificado. A
continuación se aplican variantes aleatorias con operaciones gratuitas, y el experimento
mide si cada variante se mantiene dentro del radio. Junto a ello se presenta la
fracción de flujos cuya alerta certifica Proteus-cert.

```bash
PROTEUS_EVIDENCE=v3 python -m proteus.evaluation.smoothing \
    --run experiments/outputs/h1/csecicids2018__cicids2017__loo_labels__v3 \
    --test cicids2017 --base core_free_dst_b --certified proteus_cert
```

Opciones: `--base`, `--certified`, `--fpr`, `--scales` (escalas del ruido),
`--variants`, `--flows` (flujos de ataque por campaña), `--n` (muestras de ruido),
`--seed`.

## `aml_feature`

Ataques de evasión en el espacio de características contra detectores por flujo, con el
protocolo de la literatura hecho explícito: partición 80/20 dentro del dataset,
características de CICFlowMeter escaladas a $[0, 1]$, ataques HopSkipJump (basado en
decisión) y ZOO (basado en puntuación) mediante ART dirigidos a la clase benigna,
características funcionales restauradas tras el ataque y tasas de éxito presentadas por
presupuesto $L_\infty$. Necesita el extra `attacks`.

```bash
python -m proteus.evaluation.aml_feature --dataset cicids2017 --n 100 --workers 8
```

Opciones: `--dataset`, `--n` (flujos de ataque por modelo), `--cap-attack`,
`--cap-benign`, `--workers`, `--n-adv` (ejemplos añadidos por el entrenamiento
adversario), `--out`, `--resume`, `--seed`.

## `feedback`

Calibra la realimentación de las alertas de la capa hacia el núcleo. En modo en línea,
el núcleo mantiene por host de origen el recuento con decaimiento de los flujos que
bloqueó la capa, $Q_s(t) = \sum_i e^{-(t - t_i)/\tau}$, y lanza una alerta sobre el
origen cuando $Q_s \ge K$. El script muestra, para cada $K$, las alarmas por hora que
causarían los falsos positivos de la capa sobre el tráfico benigno de la red de prueba.

```bash
python -m proteus.evaluation.feedback \
    --run experiments/outputs/h1/csecicids2018__cicids2017__loo_labels \
    --test cicids2017 --block-fpr 1e-3
```

Opciones: `--model` (por defecto `flow_clf`), `--block` (puntuación de la capa que
bloquea un flujo) o `--block-fpr` (bloquear con esta FPR sobre el tráfico benigno
local).

## `alarms`

Alarmas por entidad sobre tráfico real: a quién se señala, con qué frecuencia y por qué.
Cada alerta se atribuye al lado cuyo subnúcleo da la puntuación máxima y a la entidad de
ese lado; una alarma es un grupo (día, entidad, intervalo de tiempo). Escribe
`alarms_<model>_<fpr>.csv` con una descripción de cada entidad señalada.

```bash
PROTEUS_EVIDENCE=v3 python -m proteus.evaluation.alarms \
    --run experiments/outputs/h1/ctu13__ctu13__loo_labels__foldB_v3 --test ctu13 \
    --models proteus proteus_cert --days s01 s02 s03 s04 s06 s10 --top 30
```

Opciones: `--models`, `--days`, `--fpr`, `--bucket-min` (por defecto 10), `--top`.

## `cost`

Coste de Proteus en un día de captura: flujos por segundo al calcular la evidencia
(implementación por lotes, un solo proceso), flujos por segundo al puntuar cada detector
y su peor caso certificado, y el estado que mantiene por entidad un despliegue en
streaming.

```bash
PROTEUS_EVIDENCE=v3 python -m proteus.evaluation.cost \
    --run experiments/outputs/h1/csecicids2018__cicids2017__loo_labels__v3 \
    --test cicids2017 --day wednesday --models proteus proteus_cert
```

Opciones: `--day`, `--models`, `--rows` (filas usadas para la medición).

## `bench`

Comparación multidimensional de defensas, siguiendo la metodología METIS. Cada defensa
recibe una puntuación en $[0, 1]$ por dimensión (detección, falsas alarmas, robustez
frente al atacante adaptativo), anclada a referencias declaradas o empíricas. Las
dimensiones se combinan de modo que una dimensión a cero apenas la compensan las demás,
y el frente de Pareto sobre las dimensiones se presenta como primera lectura.

```bash
python -m proteus.evaluation.bench \
    --h1 experiments/outputs/h1/csecicids2018__cicids2017__loo_labels__v3 \
         experiments/outputs/h1/csecicids2018__cicids2017__loo_labels__v3_kitnet \
    --adaptive experiments/outputs/h1/csecicids2018__cicids2017__loo_labels__v3/adaptive_0.001.csv \
    --out experiments/outputs/bench/18_17.csv
```

Opciones: `--h1` (directorios de ejecución; si un modelo se repite, prevalece el
primero), `--adaptive`, `--fpr`, `--detectors`, `--out`.

## `tables`

Escribe las tablas LaTeX del manuscrito, y los datos CSV de las figuras, a partir de los
resultados anteriores. El primer argumento selecciona la tabla: `h1`, `summary`,
`ablation`, `frontier`, `frontier_system` o `adaptive`.

```bash
python -m proteus.evaluation.tables h1 --set v3 --fpr 1e-3 \
    --runs experiments/outputs/h1/csecicids2018__cicids2017__loo_labels__v3 \
           experiments/outputs/h1/cicids2017__csecicids2018__loo_labels__v3 \
    --out experiments/outputs/paper_tables/h1_v3_1e-3.tex
```

| Opción | Significado |
|---|---|
| `--runs`, `--extra` | Directorios de ejecución; `--extra` añade detectores de la misma dirección |
| `--csv` | Ficheros CSV de frontera o del atacante adaptativo |
| `--data-out` | CSV con los datos de la figura correspondiente |
| `--detectors`, `--set` | Columnas de detectores |
| `--base` | Modelo completo de una tabla de ablación |
| `--fpr`, `--out` | Tasa de falsos positivos objetivo y fichero de salida |

`scripts/paper_tables.sh` llama a este módulo para cada tabla del manuscrito.
