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
| `data` | Ficheros Parquet de CIC-IDS2017, CSE-CIC-IDS2018, CTU-13 y UNSW-NB15 | Los ficheros originales deben estar en `data/raw/<dataset>`; consulta [Datasets](datasets.md) |
| `h1` | Detección entre redes en ambas direcciones para Proteus, Proteus-cert y los detectores de comparación; KitNET y umbrales de tasa sobre la misma evidencia | Evidencia v3. La ejecución 2017 → 2018 tarda alrededor de 1.5 h y alcanza un pico de unos 16 GB |
| `single` | Núcleos de un solo modelo sobre la evidencia v1 (tablas del apéndice); operaciones gratuitas sobre las campañas reales | Evidencia por defecto (v1) |
| `review` | Máximo calibrado sin restricciones, umbrales con igual presupuesto de alarmas, holgura del certificado con temporizador de re-puntuación | Reutiliza los modelos de `h1` |
| `ablation` | Ablación de subnúcleos (`proteus-K` elimina el subnúcleo K) | Reutiliza los modelos de `h1` |
| `packets` | Comprobación del certificado a nivel de paquete sobre el pcap del viernes de CIC-IDS2017 | Necesita el pcap y el extra `packets` (`dpkt`) |
| `budget` | Certificado de presupuesto (suavizado aleatorizado, el mecanismo de BARS) frente a operaciones gratuitas | |
| `frontier` | Frontera de daño por tipo de ataque, simple y certificada, con alertas atribuibles | |
| `adaptive` | Daño bajo el atacante adaptativo; dimensión de robustez de la comparación de defensas | |
| `poisoning` | Fronteras bajo envenenamiento de la línea base y crecimiento de las líneas base benignas | |
| `real` | CTU-13 (dos particiones de escenarios) y UNSW-NB15; fronteras del lado del origen y alarmas en CTU-13 | |
| `shell` | Ataques basados en decisión y en puntuación contra detectores por flujo; calibración del contador de realimentación | Necesita el extra `attacks` (ART); tarda horas |
| `cost` | Rendimiento del cálculo de evidencia, rendimiento de la puntuación y estado por entidad | Medido en un núcleo de CPU |
| `tables` | Ejecuta `scripts/paper_tables.sh` | Solo usa ejecuciones terminadas |

## Comandos por etapa

Las variables que se usan a continuación se definen al principio del script:

```bash
PY=".venv/bin/python -m"
O=experiments/outputs/h1
P=data/processed
R=data/raw
A=$O/csecicids2018__cicids2017__loo_labels   # trained on 2018, tested on 2017
B=$O/cicids2017__csecicids2018__loo_labels   # trained on 2017, tested on 2018
V3="proteus proteus_cert core_pair core_mono_dst_x core_cert core_free_dst_b rate_rules_local"
```

### `data`

```bash
for d in cicids2017 csecicids2018 ctu13 unsw_nb15; do
  $PY proteus.datasets.prepare --dataset $d --raw $R/$d --out $P/$d
done
```

### `h1`

```bash
export PROTEUS_EVIDENCE=v3
$PY proteus.evaluation.h1 --train csecicids2018 --test cicids2017 --models $V3 --tag v3
$PY proteus.evaluation.h1 --train cicids2017 --test csecicids2018 --models $V3 --tag v3
# KitNET and rate thresholds on the same evidence, fitted on local benign traffic
$PY proteus.evaluation.h1 --train csecicids2018 --test cicids2017 --reuse ${A}__v3 \
  --models kitnet_local rate_rules_local proteus proteus_cert --tag v3_kitnet
$PY proteus.evaluation.h1 --train cicids2017 --test csecicids2018 --reuse ${B}__v3 \
  --models kitnet_local rate_rules_local proteus proteus_cert --tag v3_kitnet
```

### `single`

```bash
$PY proteus.evaluation.h1 --train csecicids2018 --test cicids2017
$PY proteus.evaluation.h1 --train cicids2017 --test csecicids2018
$PY proteus.evaluation.h1 --train csecicids2018 --test cicids2017 --models core_cert --tag cert
$PY proteus.evaluation.h1 --train cicids2017 --test csecicids2018 --models core_cert --tag cert
$PY proteus.evaluation.free_ops --run ${A}__cert --test cicids2017 \
  --models core_cert core_mono_dst_x --variants 20
```

### `review`

```bash
export PROTEUS_EVIDENCE=v3
# for each direction (shown for 2018 -> 2017)
$PY proteus.evaluation.h1 --train csecicids2018 --test cicids2017 --models proteus_free \
  --entity-budgets 0.5 1 3 10 --tag v3_free
$PY proteus.evaluation.h1 --train csecicids2018 --test cicids2017 --reuse ${A}__v3 \
  --models proteus proteus_cert rate_rules_local core_free_dst_b \
  --entity-budgets 0.5 1 3 10 --tag v3_budget
# certificate slack with a re-scoring timer of 10 s and 60 s
PROTEUS_TIMER_S=10 $PY proteus.evaluation.h1 --train csecicids2018 --test cicids2017 \
  --reuse ${A}__v3 --models proteus proteus_cert --tag v3_timer10
PROTEUS_TIMER_S=60 $PY proteus.evaluation.h1 --train csecicids2018 --test cicids2017 \
  --reuse ${A}__v3 --models proteus proteus_cert --tag v3_timer60
```

### `ablation`

```bash
export PROTEUS_EVIDENCE=v3
p="proteus proteus-0 proteus-1 proteus-2 proteus-3"
c="proteus_cert proteus_cert-0 proteus_cert-1 proteus_cert-2 proteus_cert-3"
$PY proteus.evaluation.h1 --train csecicids2018 --test cicids2017 --reuse ${A}__v3 --models $p $c --tag v3_ablation
$PY proteus.evaluation.h1 --train cicids2017 --test csecicids2018 --reuse ${B}__v3 --models $p --tag v3_ablation
$PY proteus.evaluation.h1 --train cicids2017 --test csecicids2018 --reuse ${B}__v3 --models $c --tag v3_ablation_cert
```

### `packets`

```bash
PROTEUS_EVIDENCE=v3 $PY proteus.evaluation.packet_check \
  --pcap $R/cicids2017_pcap/Friday-WorkingHours.pcap \
  --packets experiments/outputs/packet_check/loic_packets.parquet \
  --victim 192.168.10.50 --attackers 172.16.0.1 --port 80 --start 1499453400 --minutes 25 \
  --out experiments/outputs/packet_check_v3
```

### `budget`

```bash
PROTEUS_EVIDENCE=v3 $PY proteus.evaluation.smoothing \
  --run ${A}__v3 --test cicids2017 --base core_free_dst_b --certified proteus_cert
```

### `frontier`

```bash
export PROTEUS_EVIDENCE=v3
for m in proteus_cert proteus; do
  $PY proteus.evaluation.frontier_exp --run ${A}__v3 --test cicids2017 --model $m --rmax 200
  $PY proteus.evaluation.frontier_exp --run ${B}__v3 --test csecicids2018 --model $m --rmax 200
done
```

### `adaptive`

```bash
export PROTEUS_EVIDENCE=v3
m="proteus proteus_cert core_mono_dst_x core_free_dst_b core_pair"
$PY proteus.evaluation.adaptive --run ${A}__v3 --test cicids2017 \
  --models $m --local rate_rules_local kitnet_local --certify proteus_cert --grid 20
$PY proteus.evaluation.adaptive --run ${B}__v3 --test csecicids2018 \
  --models $m --local rate_rules_local kitnet_local --certify proteus_cert --variants 8 --grid 20
```

### `poisoning`

```bash
$PY proteus.evaluation.poisoning --run $A --test cicids2017 --model core_mono_dst_x --rounds 8 --caps none 0.25 0.1
$PY proteus.evaluation.poisoning --run $A --test cicids2017 --growth-only --caps 0.1 0.25 0.5 1
$PY proteus.evaluation.poisoning --run $B --test csecicids2018 --growth-only --caps 0.1 0.25 0.5 1
export PROTEUS_EVIDENCE=v3
$PY proteus.evaluation.poisoning --run ${A}__v3 --test cicids2017 --model proteus_cert --rounds 8 --caps none 0.25 0.1
$PY proteus.evaluation.poisoning --run ${A}__v3 --test cicids2017 --model proteus --rounds 8 --caps none 0.1
```

### `real`

```bash
fa="s01 s02 s03 s04 s06 s10"; fb="s05 s07 s08 s09 s11 s12 s13"
m="proteus proteus_cert core_both_x core_both_cert core_pair rate_rules_local"
export PROTEUS_EVIDENCE=v3
$PY proteus.evaluation.h1 --train ctu13 --test ctu13 --train-days $fb --test-days $fa \
  --tag foldB_v3 --entity-budgets 1 0.1 --models $m
$PY proteus.evaluation.h1 --train ctu13 --test ctu13 --train-days $fa --test-days $fb \
  --tag foldA_v3 --entity-budgets 1 0.1 --models $m
for h in 1 6; do
  $PY proteus.evaluation.frontier_scan --run $O/ctu13__ctu13__loo_labels__foldB_v3 \
    --test ctu13 --model proteus --fpr 1e-3 --hours $h
done
$PY proteus.evaluation.alarms --run $O/ctu13__ctu13__loo_labels__foldB_v3 --test ctu13 \
  --models proteus proteus_cert --days $fa --top 30
unset PROTEUS_EVIDENCE
$PY proteus.evaluation.h1 --train cicids2017 --test unsw_nb15 \
  --models core_both_x core_both_cert core_src_x rate_rules_local --tag src
```

### `shell`

```bash
$PY proteus.evaluation.aml_feature --dataset cicids2017 --n 100 --workers 8
for f in 1e-3 1e-4; do
  $PY proteus.evaluation.feedback --run $A --test cicids2017 --block-fpr $f
  $PY proteus.evaluation.feedback --run $B --test csecicids2018 --block-fpr $f
done
```

### `cost`

```bash
PROTEUS_EVIDENCE=v3 $PY proteus.evaluation.cost --run ${A}__v3 --test cicids2017 \
  --day wednesday --models proteus proteus_cert core_mono_dst_x
```

### `tables`

```bash
bash scripts/paper_tables.sh
```

Escribe tablas LaTeX y datos de figuras en `experiments/outputs/paper_tables/`:
detección entre redes a dos tasas de falsos positivos, intervalos de confianza
(intervalos de Wilson para las campañas, bootstrap sobre días para las alarmas), la
comparación de defensas, la tabla del atacante adaptativo, las ablaciones de subnúcleos
y las fronteras de daño.

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
