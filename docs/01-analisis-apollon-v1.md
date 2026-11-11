# 1. Análisis de Apollon v1

Fecha: 2026-11-10. Basado en la lectura del paper (Computers & Security 136, 2024,
DOI 10.1016/j.cose.2023.103546) y del repositorio público
(`github.com/antonioalfa22/apollon`). No se ha ejecutado ningún experimento: todo lo
que sigue sale de leer código, paper y resultados guardados en el repo.

## 1.1 Qué propone el paper

- Un pool de clasificadores (RF, DT, NB, LR, MLP) para detectar intrusiones.
- Un Multi-Armed Bandit con Thompson Sampling que elige el clasificador (o un
  ensemble por bagging en caso de empate) para cada petición.
- Clustering K-Means (k=2) de las peticiones, con una versión de cada clasificador
  por cluster.
- Idea central: el atacante no puede predecir qué modelo responde, así que no puede
  aprender el comportamiento del IDS en tiempos realistas.

Evaluación publicada:

- Tráfico tradicional en CIC-IDS-2017, CSE-CIC-IDS-2018 y CIC-DDoS-2019.
- Ataques ZOO, HopSkipJump y W-GAN, solo sobre CIC-IDS-2017.
- Apollon mantiene detección 0.88 (ZOO), 0.53 (HSJA) y 0.43 (W-GAN) mientras los
  clasificadores individuales caen a ~0–0.58.

## 1.2 Qué hace realmente el código

| Hallazgo | Dónde | Consecuencia |
|---|---|---|
| El bandit no aprende en inferencia | `select_arm`: muestrea `Beta(1+r, 2−r)`; `alpha` y `beta` nunca se actualizan | La selección es una distribución fija, no Thompson Sampling adaptativo |
| La recompensa se indexa por `label == arm` | `train`: `arm_mask = cluster_y_test == arm` | El brazo 0 se puntúa solo con benignos, el brazo 1 solo con ataques, y los brazos ≥2 reciben recompensa 0 |
| El entrenamiento por cluster no ocurre | Misma máscara; al quedar una sola clase, la rama de reserva hace `fit(X_train, y_train)` | Todos los brazos se entrenan con el conjunto completo; el clustering no aporta diversidad |
| El ataque no consulta a Apollon | `attacks/zoo.ipynb`, `attacks/hotskipjump.ipynb`: se ataca a `SklearnClassifier(model=model)` y se evalúa en `mab.predict` | Las tablas 5–7 miden transferencia desde un modelo suelto, no resistencia a un atacante que consulta el sistema |
| HSJA ataca siempre a LR | Bucle final: `model=lr` fijo dentro del `for` | Se promedian cinco repeticiones del mismo ataque, contra un modelo que no está en el pool (RF, DT, NB) |
| Las restricciones de tráfico están desactivadas | El wrapper `Classifier` está comentado; a la lista `FUNCTIONAL_FEATURES` le faltan comas (19 elementos en vez de 27) | ZOO y HSJA perturban todas las características; el GAN preserva solo parte de las funcionales |
| Los parámetros no coinciden con el paper | ZOO y HSJA se llaman sin `max_iter`; HSJA con `targeted=False` | El paper dice 100 iteraciones; el código usa los valores por defecto de ART (10 y 50, pendiente de comprobar) |
| Las métricas mezclan promedios | `results/MAB.txt` | El F1 0.77 es macro; en la clase ataque la precisión es 0.40 y el F1 0.55. La "detection rate" 0.942 es recall macro |

## 1.3 Discrepancias por aclarar

- **Frecuencias de selección.** El paper habla de "RF+DT 40%, RF 28%" con bagging en
  empates. Esa lógica no aparece en el repo público.
- **Dos logs distintos.** `ARMS.txt` muestra 5 brazos seleccionados al 20% cada uno
  (271,464 peticiones). Las métricas publicadas cuadran mejor con 3 brazos y un
  reparto fijo de ~47/47/7 entre RF, DT y NB: con esas proporciones la accuracy
  esperada es ≈0.977, frente al 0.974 publicado (cálculo propio, analítico).
- **Pregunta abierta:** ¿el repo público es el código exacto del paper o existe otra
  versión con la lógica de empates?

## 1.4 Debilidades de diseño (independientes del código)

- **Selector estocástico, no adversarial.** Thompson Sampling está pensado para
  encontrar el mejor brazo en un entorno estacionario. Frente a un adversario tiende
  a concentrarse en pocos modelos, lo que reduce la incertidumbre.
- **Recompensa con etiqueta.** En producción no hay etiquetas, así que la
  distribución queda congelada tras el entrenamiento.
- **Aleatoriedad por consulta.** La misma sonda puede recibir respuestas distintas,
  y el atacante puede promediar repitiendo consultas.
- **Pool poco diverso.** RF y DT son árboles muy correlacionados; un ejemplo que
  engaña a uno probablemente engaña al otro.
- **Coste en limpio.** La pérdida de precisión viene de elegir NB una fracción de las
  veces. Es un problema de pool, no de selector.
- **Sin baselines de defensa.** No hay comparación con adversarial training ni con
  otras defensas.
- **Un solo dataset para los ataques.** CIC-IDS-2017, que además tiene errores de
  etiquetado documentados (ver documento 2).

## 1.5 Implicaciones para el nuevo trabajo

- La fase "romper v1" tiene éxito casi asegurado: un atacante que consulte
  directamente se enfrenta a una mezcla fija de dos árboles correlacionados.
- v1 debe reimplementarse de forma fiel y limpia como baseline, no extenderse.
- El nuevo paper debe decir abiertamente qué medía la evaluación original
  (transferencia) y qué mide la nueva (ataque directo y adaptativo).

## 1.6 Hallazgos adicionales y corrección (2026-11-11)

Al preparar la corrección del repo público aparecieron más fallos:

- **Solo tres brazos.** Los notebooks crean el bandit con `n_arms=3`: solo RF, DT y
  NB pueden elegirse; LR y MLP nunca responden. Con las recompensas indexadas por
  etiqueta, RF y DT reciben ~1 y NB 0, lo que explica el reparto ~47/47/7 estimado
  en 1.3.
- **`mlp` sin definir** en `mab.ipynb`: el notebook falla si se ejecuta desde cero.
- **HSJA sin intención de evadir.** Se llamaba con `targeted=False` y etiqueta 0
  (benigno) para muestras de ataque: ART busca "cualquier cosa menos benigno", que
  un ataque ya detectado cumple sin cambios.
- **Métricas de sorteos distintos.** Accuracy, detection rate, F1 y AUC se calculan
  con llamadas separadas a `mab.predict`, cada una con un sorteo de brazos nuevo.
- **Índices funcionales.** Además de las comas, los índices se calculaban sobre las
  columnas del CSV crudo (antes de eliminar columnas) y con los nombres cruzados:
  `FUNCTIONAL_FEATURES_IDEXES` contenía las columnas *no* funcionales. La salida
  guardada muestra 19 elementos y solo 11 coincidencias.

**Corrección publicada:** PR #1 en `antoniopaya22/apollon` (desde el fork
`antoniopaya/apollon`, rama `fix/mab-thompson-and-direct-attacks`):

- módulo `MAB/apollon_mab.py` con entrenamiento por cluster, recompensas sobre todas
  las muestras, Thompson sampling con actualización;
- `attacks/attack_utils.py` con ataques directos contra Apollon completo además de
  los de transferencia;
- 12 tests con datos sintéticos (versiones fijadas del repo).

No se han vuelto a ejecutar los notebooks con los datasets originales, así que los
resultados guardados y las tablas del paper no están regenerados.
