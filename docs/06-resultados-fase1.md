# 6. Resultados de la fase 1 (primer prototipo del núcleo)

Estado a 2026-11-10. Primera iteración de la fase 1: núcleo monótono sobre
contadores sin línea base por entidad. Todas las cifras salen de
`python -m proteus.evaluation.h1` y `python -m proteus.evaluation.report_h1`
(salidas en `experiments/outputs/h1/`, solo en la VM y copiadas al portátil).

## 6.1 Montaje

- **Datos:** CIC-IDS-2017 (2,1 M flujos, 5 días) y CSE-CIC-IDS-2018 (63 M flujos,
  10 días), versiones corregidas de Liu et al. (CNS 2022). Los flujos "Attempted"
  cuentan como tráfico pero no como etiqueta ni en las métricas.
- **Protocolo cruzado:** se entrena con un dataset y se prueba con el otro, en las
  dos direcciones. En cada dataset cada ataque aparece en un solo día, así que una
  partición por días dentro del mismo dataset no tiene ataques comunes.
- **Evidencia:** entidades servicio de destino, host de destino y host de origen.
  Contadores con decaimiento a 10 s, 60 s y 600 s: flujos, paquetes y bytes de ida,
  RST de la víctima, segundos de conexión, paquetes y bytes de vuelta, y distintos
  (orígenes, puertos, destinos, servicios). 72 características: 54 conservadas y
  18 de respuesta.
- **Detectores:**
  - `core_mono_strict`: gradient boosting monótono sobre las conservadas.
  - `core_mono_dst`: lo mismo, solo entidades de destino.
  - `core_mono_full`: monótono con conservadas y de respuesta.
  - `core_free`: mismo modelo sin restricción.
  - `rate_rules`: umbrales fijos por característica (OR).
  - `flow_clf`: clasificador por flujo con las 83 características de CICFlowMeter.
- **Umbral:**
  - `train`: calibrado con benigno del dataset de entrenamiento.
  - `local`: calibrado con benigno de los *otros* días de la red de prueba. No hace
    falta ninguna etiqueta de ataque, solo tráfico normal de la red donde se despliega.
- **Métricas:**
  - Campañas detectadas: episodios de un ataque separados por más de 10 minutos;
    cuenta como detectada si al menos un flujo de ataque alerta.
  - Recall medio por flujo.
  - FPR sobre benigno "limpio": se excluye el benigno que toca hosts implicados en
    un ataque en ±1 minuto.
  - Falsas alarmas por hora, agrupadas por (host de destino, minuto).

## 6.2 Resultados principales (umbral local)

**Entrenado con 2018, probado con 2017** (FPR objetivo 10⁻³):

| Ataque | core_mono_dst | core_free | flow_clf |
|---|---|---|---|
| DDoS LOIC-HTTP | 1/1 · 0,96 | 1/1 · 0,99 | 0/1 · 0 |
| DoS GoldenEye | 1/1 · 1,00 | 1/1 · 0,99 | 1/1 · 0,01 |
| DoS Hulk | 1/1 · 0,98 | 1/1 · 1,00 | 1/1 · 0,16 |
| DoS Slowhttptest | 1/1 · 1,00 | 1/1 · 0,91 | 1/1 · 0,02 |
| DoS Slowloris | 1/1 · 0,54 | 1/1 · 0,92 | 1/1 · 0,47 |
| Portscan | 5/6 · 0,63 | 2/6 · 0,17 | 6/6 · 0,49 |
| FTP/SSH-Patator | 0/3 | 0/3 | 0/3 |
| Botnet, web, infiltración, Heartbleed | 0 | 0 | casi 0 |
| **Falsas alarmas/hora** | **1,3** | 1,0 | 32,1 |

Con FPR 10⁻⁴ (0,3 alarmas/hora), `core_mono_dst` mantiene todos los DoS/DDoS
(recall de 0,49 a 1,00) y 4/6 escaneos. `core_free` pierde recall (LOIC 0,38;
escaneo 2/6).

**Entrenado con 2017, probado con 2018** (FPR objetivo 10⁻³):

| Ataque | core_mono_dst | core_free | flow_clf |
|---|---|---|---|
| SSH-BruteForce | 1/1 · 0,87 | 1/1 · 0,81 | 0/1 · 0 |
| DDoS HOIC | 1/1 · 0,97 | 1/1 · 0,22 | 0/1 · 0 |
| DDoS LOIC-HTTP | 1/1 · 0,94 | 0/1 · 0 | 0/1 · 0 |
| DDoS LOIC-UDP | 1/2 · 0,17 | 0/2 · 0 | 0/2 · 0 |
| DoS GoldenEye | 1/1 · 0,92 | 1/1 · 0,84 | 1/1 · 0,10 |
| DoS Hulk | 1/1 · 0,99 | 1/1 · 1,00 | 0/1 · 0 |
| DoS Slowloris | 1/1 · 0,89 | 1/1 · 0,97 | 1/1 · 0,97 |
| Portscan | 6/6 · 0,82 | 6/6 · 0,65 | 6/6 · 0,81 |
| Botnet, web, infiltración | 0 | 0 | 0 |
| **Falsas alarmas/hora** | **9,6** | 20,2 | 314,2 |

Con FPR 10⁻⁴: `core_mono_dst` da 1,5 alarmas/hora en una red de unos 20.000 hosts y
mantiene DDoS, DoS y 6/6 escaneos; pierde SSH.

Tiempo mediano hasta la detección (`core_mono_dst`, 10⁻³):

| Ataque | 2018 → 2017 | 2017 → 2018 |
|---|---|---|
| Hulk | 2 s | 7 s |
| GoldenEye | 8 s | 50 s |
| LOIC | 62 s | 2–3 min |
| Escaneo | 2 s | 3,6 min |
| Slowloris | 5 min | 4 min |

## 6.3 Lectura

1. **H1 se cumple en parte.**
   - Sí para DoS, DDoS y escaneo: el núcleo monótono detecta todas las campañas
     de DoS/DDoS salvo una de LOIC-UDP, y casi todos los escaneos, entrenando en
     otra red.
   - El coste es de 0,3–1,5 alarmas/hora con FPR 10⁻⁴ y de 1–10 con FPR 10⁻³.
   - Falla en la fuerza bruta: 0 de 3 campañas entrenando con 2018 (en 2018 solo
     hay SSH, porque FTP es todo "Attempted"), 1 de 1 al revés.
2. **H2, el precio de la monotonía, es negativo en el escenario cruzado.**
   - `core_mono_dst` iguala o supera al modelo sin restricción en casi todo.
   - Las excepciones son Slowloris, donde el modelo libre le saca ventaja clara en
     2017→2018 (0,54 frente a 0,92), y SSH, por poco.
   - Interpretación: la restricción actúa como sesgo inductivo que evita patrones
     propios de una red concreta. Hay que confirmarlo con más campañas.
3. **Solo destino generaliza mejor que destino más origen.** En 2018, LOIC sale de
   10 bots y en 2017 de un origen. El modelo con conteos por origen aprende algo
   que repartir el ataque rompe. Encaja con el modelo de transformaciones: los
   agregados por destino no cambian al repartir.
4. **El clasificador por flujo no generaliza entre redes.** Detecta 0 de 1 DDoS y
   0 de 1 Hulk en 2018, y genera 10–30 veces más falsas alarmas. Es el resultado
   conocido y refuerza el argumento del paper.
5. **Los umbrales fijos de tasa** (`rate_rules`) no detectan ningún DoS en
   2018→2017 con el umbral local. Aprender el modelo aporta algo frente a la
   detección por tasa clásica. Matiz: este baseline usa la distribución de la red
   de entrenamiento; hay que probarlo también ajustado con benigno local.
6. **El umbral no se transfiere entre redes.** Con el umbral de entrenamiento, el
   FPR sube al 15–50 %. Los conteos dependen del tamaño y la actividad de la red.
   Calibrar con benigno local lo resuelve sin etiquetas, y la línea base por entidad
   debería resolverlo de raíz.
7. **Fuera del alcance del núcleo, como se esperaba:**
   - Ataques web, infiltración, Heartbleed y botnet, que dejan muy poco rastro
     agregado.
   - Para estos el clasificador por flujo tampoco sirve entre redes. La cáscara
     tendrá que entrenarse en la red de destino o asumir esa limitación.

## 6.4 Problemas conocidos de esta iteración

- **Pocas campañas por ataque** (1–6). No hay base estadística; los resultados son
  orientativos. Hacen falta UNSW-NB15 y otros datasets, o generar campañas.
- **"Detectada" con un solo flujo es una métrica laxa.** El recall por flujo y el
  tiempo hasta la detección la complementan. Falta medir por ventana de entidad.
- **El benigno "limpio" excluye** el que toca hosts implicados en ±1 min. Esto
  puede ocultar falsas alarmas cercanas a un ataque.
- **No se ha verificado** que el modelo entrenado sea monótono (lo impone
  scikit-learn, pero hay que comprobarlo con un test).
- **El conteo de flujos no es conservado** frente a la reutilización de conexiones
  (ver 4.3).

## 6.5 Siguiente iteración

1. **Línea base por entidad:** cada contador frente a la historia de su propia
   entidad (cuantil robusto en periodos sin alerta), como característica con
   restricción −1 o como exceso con restricción +1. Objetivos: fuerza bruta (un
   servicio SSH/FTP normalmente recibe muy pocas conexiones) y transferencia del
   umbral.
2. **Test de monotonía del modelo entrenado:** subir cualquier característica nunca
   baja la puntuación.
3. **Métrica por ventana de entidad,** además de por campaña.
4. **`rate_rules` con distribución local,** para que el baseline sea justo.
5. **Más datos:** UNSW-NB15 y, para las escalas largas y el benigno real, UGR'16.

---

## 6.6 Iteraciones 2–4 (2026-11-10/11): línea base, certificación y frontera

Salidas en `experiments/outputs/h1/*__loo_labels/` (VM). Umbral local,
FPR objetivo 10⁻³ salvo que se diga otra cosa.

### Línea base por entidad

Tres variantes de referencia, en este orden:

1. **Días anteriores, sin excluir ataques.** Envenenada por ataques pasados: los
   DoS del miércoles de 2017 entran en la historia del servidor web y el DDoS del
   viernes parece normal. Además, el primer día no tiene historia (en 2018 es el
   único día con fuerza bruta SSH).
2. **Resto de días de la red, excluyendo los minutos con ataque** sobre la entidad
   (y los 10 siguientes). La exclusión usa etiquetas: es la cota superior de una
   línea base que solo aprende de periodos sin alerta. La versión realista
   (excluir los minutos que el propio sistema alertó) queda pendiente.
3. Sobre (2), tres formas de dárselo al modelo:
   - `core_mono_dst_b`: la línea base como característica (restricción −1) y el
     exceso (+1). **Falla**: aprende el atajo "entidad poco usada = ataque" (en 2018
     las víctimas son servidores casi sin tráfico) y en 2017 hay mucho benigno hacia
     destinos de Internet poco vistos con la misma puntuación.
   - `core_mono_dst_x`: conteos brutos y exceso sobre la línea base, sin la línea
     base sola. La rareza por sí misma no puede subir la puntuación. **Es la mejor.**

| | 2018 → 2017 | 2017 → 2018 |
|---|---|---|
| DoS/DDoS (recall medio) | todas 1/1, recall 1,00 (Slowloris 1,00; antes 0,61) | todas, recall 0,99–1,00 |
| Escaneo | 6/6 · 0,84 | 6/6 · 0,90 |
| Fuerza bruta | FTP 1/1 · 0,20; SSH 1/2 · 0,05 | SSH 1/1 · 1,00 |
| Botnet | 0/1 | 1/1 · 0,98 |
| Falsas alarmas/hora | 1,9 (0,2 con FPR 10⁻⁴) | 37,9 (0,8 con FPR 10⁻⁴) |

Con FPR 10⁻⁴ se mantienen DoS/DDoS y escaneos en las dos direcciones; la fuerza
bruta y la botnet se pierden.

### Certificación

Con Δ = 120 s (ver doc 04 §4.4.2), el recall certificado de los núcleos con todas
las escalas es **prácticamente nulo**: dependen de las escalas de 10 s y 60 s,
cuyo margen (24 y 4 en escala log) las anula.

`core_cert` es un núcleo monótono solo con la escala de 600 s (margen 0,4), con
conteos brutos y exceso sobre la línea base. Salidas en `*__loo_labels__cert/`.
Columnas: alerta normal de `core_cert` y alerta certificada (`@cert`, misma
puntuación con todas las características rebajadas en su margen).

| | 2018 → 2017, 10⁻³ | 2018 → 2017, 10⁻⁴ | 2017 → 2018, 10⁻³ | 2017 → 2018, 10⁻⁴ |
|---|---|---|---|---|
| DoS/DDoS certificados | 5/5 · 0,88–1,00 | 5/5 · 0,60–1,00 | 6/6 tipos · 0,94–1,00 | HOIC, Hulk, GoldenEye, Slowloris, LOIC-HTTP (0,05) |
| Escaneos certificados | 4/6 · 0,60 | 4/6 · 0,36 | 6/6 · 0,38 | 0/6 |
| Otros certificados | — | — | SSH 0,18; Botnet 0,77 | — |
| Falsas alarmas/h (`core_cert`) | 7,1 | 3,8 | 54,6 | 4,4 |

Lectura:

- **La certificación funciona para lo volumétrico.** Con FPR 10⁻⁴ y 0,5–4 falsas
  alarmas/hora, casi todos los DoS/DDoS quedan detectados con una alerta que ninguna
  combinación de operaciones gratuitas puede evitar (como mucho la retrasa Δ).
- **Coste:** más falsas alarmas que el núcleo rápido y detección más lenta (escala
  de 10 min). En 2018 el FPR local de 10⁻³ da 54,6 alarmas/h: hay que operar en 10⁻⁴.
- **Arquitectura resultante:** dos núcleos. Uno rápido sin certificar (todas las
  escalas) y uno lento certificado (escala larga). El certificado es el suelo de
  garantía; el rápido aporta velocidad y cobertura (fuerza bruta, botnet).
- La escala de 600 s es la única larga que se calculó. Probar 3.600 s (margen 0,07).

### Frontera de daño (2018 → 2017, `core_mono_dst_x`, FPR 10⁻³)

`python -m proteus.evaluation.frontier_exp`. Ataque real reproducido a tasa
variable sobre el tráfico benigno real de su víctima (ventana de 1 h).

| Ataque | Víctima | Tasa real (flujos/h) | Frontera (flujos/h) | Factor |
|---|---|---|---|---|
| SSH-Patator | .50:22 | 1.541 | 1.246 | 1,2× |
| FTP-Patator | .50:21 | 3.910 | 507 | 7,7× |
| DoS Hulk | .50:80 | 518.525 | 21 | ~25.000× |
| DoS GoldenEye | .50:80 | 44.976 | 11 | ~4.000× |
| DoS Slowloris | .50:80 | 10.461 | 10 | ~1.000× |
| DoS Slowhttptest | .50:80 | 5.107 | < 3,6 | — |
| DDoS LOIC | .50:80 | 290.167 | 37 | ~8.000× |
| Escaneo (jueves) | .5 | 10.418 | 154 | ~70× |
| Escaneo (viernes) | .50 | 107.850 | 265 | ~400× |

Frontera certificada: no se alcanza ni a 360.000 flujos/h (coherente con el recall
certificado nulo).

Lectura:

- La fuerza bruta SSH real iba apenas por encima de la frontera; por eso su recall
  es bajo. Un atacante que la frenara un 20 % pasaría.
- Las fronteras de DoS están **infladas por el dataset**: el servidor víctima de
  2017 recibe ~1.000 flujos benignos en 2 horas y su línea base es casi 0. Con una
  víctima ocupada la frontera será mucho más alta. Hay que medirla en 2018 y con
  tráfico real (UGR'16).

## 6.7 Primer contacto con tráfico real: CTU-13 (2026-11-11)

CTU-13 (red universitaria real, 2011; 19,6 M flujos; 13 escenarios de botnet). Los
flujos "Background" son tráfico real **sin etiquetar**, no benigno.

1. **Núcleo entrenado en CIC-IDS-2017, probado en CTU-13:** DDoS detectado solo en
   parte (4/14 campañas) y **ningún escaneo** (0/64). El umbral local tampoco se
   cumple (FPR pedido 10⁻³, real 10⁻²): los escenarios son capturas de días y
   semanas distintos.
2. **Los escaneos de las botnets no dejan huella en el destino:** el bot del escenario
   3 toca 26.725 destinos con un flujo cada uno. La evidencia está en el origen. Se
   añade un **núcleo de origen** y se combina con el de destino por máximo
   (`proteus.core.combine.MaxCore`; el máximo de funciones monótonas es monótono, la
   garantía se conserva; test en `tests/test_combine.py`).
3. **Ni con el núcleo de origen, ni entrenando dentro de CTU-13, se detectan los
   escaneos.** Diagnóstico: el bot escanea despacio (~30 destinos/min) y en el
   "fondo" hay orígenes con más evidencia. Los 38.583 flujos de fondo por encima del
   bot vienen de **35 orígenes, 34 externos**, que barren 665–970 destinos de la
   universidad buscando MSSQL (1433), SSH (22), Radmin (4899)…, con 70–100 % de
   conexiones sin respuesta. **Son escáneres reales de Internet sin etiquetar.**
   - Inflan el FPR: Proteus "falla" al detectar ataques reales.
   - Inflan el umbral: se calibra con ese "benigno".
4. **Corrección declarada:** los orígenes de fondo con ≥ 100 destinos distintos y
   ≥ 50 % de conexiones sin respuesta se marcan como `suspect` (ataque probable sin
   etiquetar). Sus flujos quedan fuera de falsas alarmas y calibración, y se informa
   aparte cuántos detecta cada modelo (`suspect src det.` en las tablas).

Lección para el paper: evaluar en tráfico real exige tratar el fondo como no
etiquetado; cualquier detector sobre CTU-13 sufre este sesgo. Es un argumento a favor
de medir alarmas por entidad y describirlas, no solo FPR por flujo.

### CTU-13 con los escáneres reales marcados (núcleo de origen, FPR 10⁻³)

| Run | DDoS | Escaneos | Spam | Fast-flux | Alarmas/h | Sospechosos detectados |
|---|---|---|---|---|---|---|
| CIC-17 → CTU, `core_both_x` | 4/14 | 0/64 | 0/9 | 0/1 | 13,8 | — |
| CIC-17 → CTU, `core_both_cert` | 2/14 | 0/64 | 4/9 | 1/1 | 192,8 | — |
| CTU B → A, `core_both_x` | 2/13 | 0/60 | 1/2 | — | 12,8 | 28/181 |
| CTU A → B, `core_both_x` | 1/1 | 0/4 | 2/7 | 0/1 | 2,0 | 1/119 |
| CTU B → A, `rate_rules_local` | 4/13 | 1/60 | 0/2 | — | 38,1 | 12/181 |

- Los escaneos de las botnets siguen sin detectarse, también al quitar los escáneres
  reales de la calibración. No es un problema de umbral: el bot va por debajo de la
  frontera de la red (unos 30 destinos/min frente a escáneres reales de cientos).
  Esto es lo que mide la frontera de daño: Proteus no promete detectar escaneos lentos,
  sino acotar su velocidad. Queda pendiente medir esa frontera en CTU-13.
- Probando en la partición A (entrenado en B), el núcleo de origen detecta 28 de los 181 escáneres reales sin
  etiquetar, con unas 13 alarmas/h. Son detecciones correctas que las métricas
  habituales cuentan como falsos positivos.

## 6.8 UNSW-NB15 (2026-11-11)

CSV oficiales (2,54 M flujos, 321 k ataques, dos días de captura).

**Pieza por flujo, partición aleatoria 80/20 (3 semillas):** F1 0,959 ± 0,001,
FPR 1,2 %, TPR al 10⁻³ de FPR 0,94, AUROC 0,9997. Es peor que en CIC (0,9999): en UNSW
varias familias (Exploits, Fuzzers, DoS) se parecen mucho al tráfico normal flujo a
flujo.

**Núcleo entrenado en CIC-IDS-2017 y probado en UNSW (umbral local, FPR 10⁻³):**

| Modelo | Campañas | FPR real | Alarmas/h |
|---|---|---|---|
| `core_mono_dst_x` | 57/81 | 3,9·10⁻² | 33,7 |
| `core_src_x` | 81/81 | 1,9·10⁻³ | 8,8 |
| `core_both_cert@cert` | 81/81 | 2,8·10⁻⁴ | 7,8 |
| `rate_rules_local` | 81/81 | 0,56 | 528 |

**Lectura con cautela.** En UNSW **todos los ataques salen de 4 IPs**
(175.45.176.0–3) contra 10 víctimas, y las 9 familias se mezclan cada día. Una
"campaña" de una familia no se distingue a nivel de entidad de las demás: el núcleo de
origen detecta a los **hosts atacantes**, no cada familia. El 81/81 significa "los 4
orígenes generadores de IXIA son anómalos", no "Proteus detecta shellcode". Lo
relevante es que el núcleo **certificado** los detecta con FPR 2,8·10⁻⁴ sin haber visto
UNSW, y que las reglas de tasa con umbral local fallan (FPR 0,56: el benigno de UNSW es
muy desigual entre días). En el paper, UNSW sirve para la pieza por flujo y como
comprobación de transferencia, no como evidencia de detección por familia.

## 6.9 Frontera de los escaneos horizontales en CTU-13 (2026-11-11)

`python -m proteus.evaluation.frontier_scan` (escenario de origen: un origen nuevo
reproduce los sondeos reales del bot, con sus destinos y puertos, sobre el tráfico
real hacia esos destinos). Modelo `core_both_x` entrenado en B, FPR 10⁻³.

| Escenario | Sondeos | Destinos | Puertos | Bot real (sondeos/min) | Frontera (sondeos/min) |
|---|---|---|---|---|---|
| s03 (prueba) | 26.759 | 26.724 | 22 | 6,8 | 3.916 |
| s06 (prueba) | 4.630 | 1.579 | 25 | 36,1 | 3.980 |
| s08 (entrenamiento) | 6.127 | 497 | 135, 3389 | 5,2 | 3.936 |
| s12 (entrenamiento) | 807 | 644 | 80, 53 | 12,8 | 4.042 |

Frontera certificada: por encima del máximo probado (12.000/min).

Lectura:

- El bot escanea 100–750 veces por debajo de la frontera: por eso 0/64.
- La frontera es casi la misma en todos los escenarios porque el umbral local es el
  mismo (0,999946): está en la **saturación** del modelo. El 0,1 % más alto del
  fondo ya recibe la puntuación máxima, así que un escaneo solo alerta cuando llega
  a ese techo (~65 sondeos/s desde un origen nuevo).
- Dos causas probables, en prueba:
  1. **Evidencia:** el núcleo de origen no ve las conexiones sin respuesta, la huella
     propia de un escaneo. Se añade en la evidencia v2 (`noreply`, `n_dhost_nr`;
     doc 04), conservada dados los destinos.
  2. **Calibración por flujo:** un FPR por flujo da más peso a los hosts con más
     flujos. Hace falta ver qué entidades saturan (`alarms.py`) y, si son unas
     pocas, calibrar por alarmas de entidad por hora.

## 6.10 Alarmas por entidad en CTU-13 (2026-11-11)

`python -m proteus.evaluation.alarms`. Cada alerta se atribuye al lado (origen o
destino) cuyo subnúcleo da el máximo y a la entidad de ese lado; una alarma es un par
(entidad, ventana de 10 min). Fold B (entrenado en B, probado en A: 89 h), FPR 10⁻³,
solo tráfico limpio y no sospechoso.

| Modelo | Alarmas/h por entidad | Métrica de h1 (destino, minuto) | Entidades alertadas |
|---|---|---|---|
| `core_both_x` | 0,12 (origen 0,11) | 16,4 | 11 |
| `core_both_cert` | 0,08 | 8,0 | 2 |
| `core_mono_dst_x` | 0,04 | 0,09 | 3 |

Lectura:

- **La métrica de h1 sobrestimaba las alarmas del núcleo de origen en dos órdenes de
  magnitud**: un escáner alertado contaba una vez por cada destino y minuto. Las
  cifras de alarmas/h del núcleo de origen en §6.7 (≈ 13/h) deben leerse así. h1
  añade ahora la columna `entity_alarms_per_hour` con esta atribución.
- **Las entidades alertadas son casi todas atacantes reales sin etiquetar** que el
  criterio de sospechoso no captó: escáneres SSH externos (245 destinos en el
  puerto 22, varios orígenes), uno de RDP (3389), uno web (80), y flujos masivos de un
  origen a un destino en puertos altos (Microsoft, probablemente P2P/Skype). El
  único destino alertado legítimo es el DNS de la universidad.
- El FPR por flujo medido (hasta 2,9 % con objetivo 10⁻³) confirma la saturación:
  muchos flujos empatan en la puntuación máxima y el cuantil no los separa. El FPR por
  flujo no es una buena medida para un detector de entidades.

## 6.11 Realimentación de la cáscara al núcleo: calibración de K (H5, 2026-11-12)

`python -m proteus.evaluation.feedback`. En modo en línea, cada flujo que la cáscara
bloquea es evidencia que el emisor no puede retirar. El núcleo lleva, por origen, el
contador decaído de bloqueos `F_s(t) = Σ exp(-(t - t_i)/τ)` y alerta al origen cuando
`F_s ≥ K`. El contador es monótono en las sondas bloqueadas, así que un ataque por
consultas contra la cáscara acaba con el origen alertado tras unas K sondas
bloqueadas dentro de τ.

K se fija con los falsos positivos de la cáscara en el tráfico benigno de la red de
prueba: alarmas (origen, ventana de 10 min) por hora para cada K y τ.

**18 → 17** (cáscara entrenada en CSE-CIC-IDS-2018, bloqueo con puntuación ≥ 0,5):
FPR por flujo de la cáscara 1,2–2,2 % según el día (19.920 falsos positivos en
40,8 h), pero concentrados en **14 orígenes**.

| K \ τ | 60 s | 600 s | 3600 s |
|---|---|---|---|
| 1 | 54,5 | 54,5 | 54,5 |
| 10 | 7,0 | 18,4 | 39,4 |
| 20 | 1,1 | 10,3 | 33,1 |
| 50 | 0,025 | 1,8 | 16,6 |
| 100 | 0 | 0,12 | 9,1 |
| 200 | 0 | 0 | 0,61 |
| 500 | 0 | 0 | 0 |

Lectura:

- En régimen estable el contador vale tasa × τ, así que la realimentación **limita la
  tasa de sondas bloqueadas** de un origen a K/τ. Con K = 100 y τ = 600 s (0,12
  alarmas/h en benigno) un origen puede encajar como mucho ~0,17 bloqueos/s sin ser
  alertado.
- En CIC-IDS-2017, toda evasión exitosa de la cáscara con HSJA se llevó ≥ 805 sondas
  bloqueadas (mediana 863, doc 07 §7.5). A ese ritmo, una evasión cuesta ≥ 80 min por
  origen, o ⌈805/K⌉ = 9 orígenes quemados si el atacante no frena.
- La FPR de la cáscara entre redes (1–2 %) es alta para bloquear en línea; la
  realimentación solo es usable porque los falsos positivos se concentran en pocos
  orígenes y no se acumulan rápido. Un umbral de bloqueo más alto (o calibrado en la
  red de despliegue) es necesario en cualquier caso.

**17 → 18:** pendiente (se cortó con la caída de la VM; relanzado).

## 6.12 Comprobación empírica de la garantía con operaciones libres (H3, 2026-11-12)

`python -m proteus.evaluation.free_ops`, 18 → 17, 20 variantes aleatorias por ataque
(relleno de 0/40/400 bytes, 0/1/5 paquetes insertados con o sin extensión de hasta
120 s, puertos de origen nuevos, 0/100/1000 señuelos, partición de flujos en 2 o 5),
aplicadas sobre una ventana de 10 min de la campaña real contra su víctima real, con
el tráfico real hacia la víctima.

| Ataque | `core_cert`: alertas originales → mín. variantes | víctima alertada | `core_mono_dst_x`: originales → mín. |
|---|---|---|---|
| DoS Hulk | 90.625 → 90.625 | 100 % | 90.613 → 90.613 |
| DoS GoldenEye | 7.567 → 7.567 | 100 % | 7.560 → 7.560 |
| DoS Slowloris | 1.788 → 1.788 | 100 % | 1.788 → 1.788 |
| DoS Slowhttptest | 1.120 → 1.120 | 100 % | 1.119 → 1.119 |
| DDoS LOIC-HTTP | 47.266 → 47.266 | 100 % | 47.648 → 47.648 |
| PortScan (jueves) | 1.991 → 2.011 | 100 % | 2.015 → 2.016 |
| PortScan (viernes) | 0 → 0 | 50 % | 96 → 97 |
| FTP-Patator | 0 → 0 | 100 % | 141 → 117 |
| SSH-Patator | 0 → 0 | 45 % | 33 → 33 |

Lectura:

- **Ninguna violación**: en ninguna variante bajó la puntuación de un flujo original
  con operaciones exactas (sin re-temporizar), ni se perdió una alerta certificada
  del núcleo certificado. H3 se cumple en todas las campañas reales.
- Las operaciones libres solo **suben** la evidencia: con FTP y SSH, que el núcleo
  certificado no alertaba, las variantes acaban alertando a la víctima en el 100 % y
  el 45 % de los casos; con el escaneo del viernes, en el 50 %.
- El núcleo rápido no está certificado, pero tampoco pierde alertas en la práctica.
  La única bajada (FTP, 141 → 117 flujos alertados) aparece en una variante que
  re-temporiza: alarga flujos 120 s con un paquete insertado y parte el 5 % en dos.
  Es justo la operación que el certificado cubre con la holgura Δ, y la víctima sigue
  alertada en todas las variantes.
