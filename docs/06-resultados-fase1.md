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

## 6.13 Envenenamiento de la línea base (2026-11-12, parcial)

`python -m proteus.evaluation.poisoning` (`proteus.core.poisoning`). Atacante más
fuerte: en cada minuto del periodo de referencia envía el ataque al 95 % de la
frontera actual. No alerta, así que el despliegue no enmascara esos minutos. La nueva
línea base de cada entidad tocada es el cuantil 95 de su evidencia por minuto con ese
tráfico, y nunca baja. Se itera una vez por día (actualización de la línea base) y se
mide la frontera tras cada actualización. Variantes:

- sin tope;
- con tope de crecimiento por actualización (0,25 y 0,1 en unidades log1p);
- **techo**: línea base infinita en todas las entidades tocadas. Los contadores
  brutos siguen limitando a un núcleo monótono que los use.

**18 → 17, `core_mono_dst_x`, FPR 10⁻³** (flujos/h; campaña real SSH 1.541/h, FTP
3.910/h):

| Ataque | Tope | día 0 | 1 | 2 | 4 | 8 |
|---|---|---|---|---|---|---|
| SSH | ninguno | 1.193 | 3.882 | 9.994 | 36.102 | 317.831 |
| SSH | 0,25 | 1.193 | 1.712 | 2.889 | 6.392 | 16.683 |
| SSH | 0,1 | 1.193 | 1.304 | 1.542 | 2.310 | 4.610 |
| FTP | ninguno | 417 | 1.606 | 4.097 | 21.254 | 241.124 |

Lectura (parcial):

- **Sin tope, el envenenamiento funciona y es rápido**: la frontera de SSH se
  multiplica por ~3 al día, y en un día ya supera el ritmo de la campaña real.
- **`core_mono_dst_x` no tiene techo**: con línea base infinita no alerta ni a
  200 flujos/s. Las alertas de fuerza bruta dependen del exceso sobre la línea base,
  no de los contadores brutos. Falta ver `core_cert`.
- ~~En DoS la frontera es 0 desde el día 0: no hay margen para envenenar.~~
  **Corregido (§6.15):** era un artefacto. El tráfico benigno de la víctima ya
  alertaba solo en algunos minutos, y cualquier flujo de ataque en esos minutos
  "alertaba". Con la atribución corregida hay que repetirlo.
- **El tope solo retrasa**: con 0,1 la frontera crece ×1,2 al día (×3,9 en 8 días).

**Coste del tope** (`--growth-only`): crecimiento día a día de las líneas base
benignas en CIC-IDS-2017 con referencia causal (1–4 días previos). La mediana es ≈ 0,
pero:

| Entidad | > 0,1 | > 0,25 | > 0,5 | > 1 |
|---|---|---|---|---|
| servicio destino | 13–21 % | 8–17 % | 6–14 % | 3–8 % |
| host destino | 10–18 % | 7–15 % | 5–12 % | 2–5 % |
| host origen | 7–12 % | 0,4–2 % | 0–0,4 % | 0 % |

Con tan poca historia, las líneas base benignas no son estables: un tope de 0,1
recortaría una de cada cinco.

En CSE-CIC-IDS-2018 (referencia causal de 1 a 9 días) se ve lo mismo: entre el 3 % y el
20 % de los pares (entidad, contador) crecen más de 0,1 al día, y entre el 1 % y el 6 %
más de 1, sin que baje claramente con más días de historia. **Un tope de crecimiento
uniforme no sale barato en estos datos.** Hacen falta techos que no dependan de la
línea base de la víctima: contadores brutos o por par, o líneas base de población. Hace falta historia de semanas (UGR'16) para fijar un
tope con coste bajo. Alternativas: línea base con ventana larga, o limitar el
crecimiento solo en entidades sin cambios de carga explicables.

## 6.14 La garantía a nivel de paquetes (2026-11-12)

`python -m proteus.evaluation.packet_check` (`proteus.packets`). La certificación
depende de cómo un exportador contabiliza los paquetes, así que se comprueba por
debajo de los registros de flujo:

- **Traza:** 25 min del pcap de viernes de CIC-IDS-2017 alrededor del DDoS LOIC-HTTP.
  Son 1,2 M de paquetes con la víctima 192.168.10.50, de los que 716.000 son del
  atacante 172.16.0.1.
- **Exportador propio:** flujos bidireccionales con timeout activo Δ = 120 s, timeout
  de inactividad de 60 s y cierre por FIN de ambos lados o por RST.
- **Variantes (11)**, sobre los paquetes del atacante: relleno de 40 o 400 B; un
  paquete extra tras el 20 % o el 100 % de sus paquetes; salto de puerto origen cada 3
  o 20 paquetes (parte las conexiones en varios registros); 500 o 5.000 SYN señuelo; y
  combinaciones de todo ello. Las variantes tienen hasta 4,6 veces más registros
  (412.000 frente a 90.000).
- **Comprobación:** E'(t+Δ) ≥ e^{−2Δ/τ}·E(t) en cada fin de flujo original, para
  todos los contadores conservados del servicio y del host víctima, a 10 s, 60 s,
  600 s y 1 h.

**Resultado: 0 violaciones.** El cociente mínimo es e^{−Δ/τ} (solo el decaimiento
durante Δ), por encima de la cota en todas las escalas.

**Hallazgo:** los segundos de conexión (`conn_s`) **no se conservan**. Saltar de
puerto parte una conexión y se pierden los huecos entre los trozos, mientras el
servidor puede seguir reteniendo la conexión abandonada. El operador a nivel de
registro (`split_flows`) lo ocultaba porque reparte la duración por construcción.
`conn_s` pasa a ser una característica de respuesta, sin línea base y fuera de los
núcleos monótonos (commit 2ab77da). Los resultados anteriores de núcleos con `conn_s`
deben repetirse con la v3, que ya lo excluye.

## 6.15 Corrección: alertas atribuibles al ataque (2026-11-12)

La frontera y el atacante adaptativo contaban como alerta del ataque cualquier flujo
de ataque por encima del umbral. En víctimas con mucho tráfico, el fondo benigno solo
ya supera el umbral local en algunos minutos. En la víctima de Hulk y GoldenEye
(miércoles de CIC-IDS-2017, `core_cert`, 18 → 17) lo hace el 0,5 % de los flujos de
fondo, con un máximo de 0,97 frente a un umbral de 0,93. Un flujo de ataque en esos
minutos hereda la evidencia del fondo y "alerta" a cualquier ritmo. Consecuencias:

- las fronteras de DoS cercanas a 0 (14/h en Hulk, 0 en Slowloris y GoldenEye) no
  medían el ataque;
- en el envenenamiento, el primer día "saltaba" (Hulk de 14 a 3.351/h incluso con
  tope 0,1) porque la nueva línea base absorbía la carga benigna de ese día.

**Arreglo (commit 1edc682):** solo cuentan las alertas en minutos en que el fondo,
por sí solo, no alerta; los flujos benignos cuya evidencia sube el ataque también
cuentan. Sigue siendo monótono en el ritmo. Se aplica en `core.frontier` y en
`evaluation.adaptive`.

**Pendiente:** recalcular con la v3 las fronteras y el envenenamiento. La tabla de
fronteras certificadas del paper (Hulk 6.238/h, etc.) está menos expuesta, porque el
peor caso baja las puntuaciones del fondo, pero también se repite.

## 6.16 Evidencia v3 (2026-11-12, parcial)

Evidencia v3: escalas de 1 h y 6 h, entidad par origen→servicio con contadores
brutos, `conn_s` fuera del núcleo y máximo calibrado de cuatro subnúcleos (destino,
origen, par y bruto). Detectores `proteus` (todas las escalas) y `proteus_cert`
(τ ≥ 10 min).

**Detección 18 → 17, FPR 10⁻³:**

| Detector | Volumétricos y escaneos | Fuerza bruta | Alarmas/h (10⁻³ / 10⁻⁴) |
|---|---|---|---|
| `proteus` | 11/11 (escaneos 6/6, recall 0,82) | FTP 1/1, SSH 1/2 (recall ≤ 0,03) | 2,7 / 0,18 |
| `proteus_cert`, alertas certificadas | 8/11 (escaneos 3/6) | — | 1,5 / 0,09 |
| núcleo certificado v1, alertas certificadas | 9/11 | — | 3,2 / 0,77 |
| `core_pair` solo | 5/11 (todos los DoS y DDoS, ningún escaneo) | — | 0,27 |
| reglas de tasa locales (v3) | 9/11 | FTP, SSH, botnet, infiltración | 36 |

- `proteus` iguala al núcleo rápido v1 en volumétricos con alarmas parecidas (2,7
  frente a 1,9 por hora), y ve débilmente la fuerza bruta.
- Las alertas certificadas cuestan la mitad de alarmas que en la v1.
- **Los pares brutos solos no ven la fuerza bruta entre redes:** un cliente benigno
  muy activo (DNS, NTP) tiene tantos flujos por par como un Patator. Respuesta
  implementada sin ejecutar: la línea base del par por servicio (`PROTEUS_PAIRBASE=1`,
  commit cf10633).
- Con la v3, las reglas de tasa empeoran mucho en alarmas (36/h frente a 11): más
  características significan más formas de superar un percentil por separado.

**Envenenamiento con `proteus_cert` (18 → 17):**

| Ataque | Ritmo real | Frontera día 0 | Tras 8 días envenenando (sin tope) | Techo (línea base ∞) |
|---|---|---|---|---|
| SSH | 1.541/h | 3.469/h | 3.469/h | 3.469/h |
| FTP | 3.910/h | 17.165/h | 17.165/h | 17.165/h |

En la v1, el núcleo certificado pasaba en SSH de 16.001/h a infinito en 4 días.
**En la v3 el envenenamiento no da nada:** la frontera la fijan los contadores de
par y brutos, no el exceso sobre la línea base, y el techo coincide con la frontera
del día 0. El precio: esas fronteras siguen por encima del ritmo real de las campañas
(2,3× en SSH y 4,4× en FTP). El núcleo certificado no ve esas fuerzas brutas, pero
envenenar tampoco le sirve al atacante.

**Incidencias:** la v3 17 → 18 y la ablación 18 → 17 murieron por memoria (OOM)
mientras corrían 4–5 trabajos a la vez. Se corrigió h1 para puntuar por lotes y
compartir la muestra benigna entre detectores locales (commits 14fcc3a, ebf2d04), y se
relanzaron.

## 6.17 Certificado por presupuesto frente a operaciones libres (2026-11-12)

`python -m proteus.evaluation.smoothing` (`baselines/smoothing.py`). Reimplementación
del mecanismo de BARS (no su código: la VM no tiene PyTorch ni GPU): suavizado
aleatorio del núcleo sin restricciones con ruido gaussiano por característica
(σ_j = escala × desviación típica benigna), 200 muestras, cota de Clopper-Pearson
(α = 0,001) y radio certificado en la métrica L2 escalada por σ. Sobre las campañas
reales de 2018 → 2017 (300 flujos de ataque por campaña, 6 variantes aleatorias de
operaciones libres), se mide cuánto mueve cada variante cada flujo en esa métrica y si
el desplazamiento cabe en el radio.

| Ataque | Radio (mediana, σ = 0,25) | Desplazamiento (mediana) | Cubierto | Base sigue alertando | Proteus-cert |
|---|---|---|---|---|---|
| Hulk | 1,83 | 116 | 0 % | 100 % | 100 % |
| GoldenEye | 1,83 | 104 | 0 % | 99 % | 76 % |
| Slowloris | 0,84 | 16 | 0 % | 99 % | 52 % |
| Slowhttptest | 1,52 | 9,6 | 4 % | 97 % | 98 % |
| Escaneo (jueves) | 0,25 | 64 | 0 % | 93 % | 77 % |
| LOIC-HTTP | 1,60 | 251 | 0 % | 100 % | 86 % |

Lectura:

- **El certificado por presupuesto no cubre las operaciones libres:** los desplaza-
  mientos son de 5 a 626 unidades de ruido según la escala, y el radio no supera 1,83.
  Certificar un radio r exige p ≥ Φ(r): r = 5 pide p ≈ 1 − 3·10⁻⁷, del orden de 10⁷
  muestras de ruido por flujo.
- El modelo base sigue alertando en el 93–100 % de las variantes (las operaciones
  libres suben la evidencia), pero el suavizado no puede demostrarlo; Proteus lo
  demuestra por construcción en el 52–100 % de los flujos de los DoS y DDoS.
- Más ruido no ayuda: no cubre más y pierde detección (Slowloris 0,95 → 0,72; escaneo
  del jueves 0,49 → 0,32 con σ de 0,1 a 0,5).
- Fuerza bruta y escaneo del viernes: ni el base ni Proteus-cert alertan, no hay nada
  que certificar.

## 6.18 Ablación de subnúcleos (2026-11-12, solo 18 → 17)

`h1 --reuse ... --models proteus proteus-0..3 proteus_cert proteus_cert-0..3`
(Proteus sin el subnúcleo K: 0 destino, 1 origen, 2 par, 3 destino bruto). FPR 10⁻³.

| Variante | `proteus`: volumétricos / resto / alarmas/h | `proteus_cert`: ídem |
|---|---|---|
| Completo | 1,00 / 0,20 / 2,7 | 0,82 / 0,10 / 4,3 |
| Sin destino (con exceso) | 1,00 / 0,20 / **0,7** | 0,82 / 0,10 / 3,6 |
| Sin origen | 1,00 / 0,20 / 3,1 | 0,82 / 0,10 / 7,6 |
| Sin par | 1,00 / 0,20 / 3,1 | 0,82 / **0,00** / 7,1 |
| Sin destino bruto | **0,82 / 0,00** / 2,7 | 0,82 / 0,10 / 5,3 |

Lectura provisional:

- El **destino bruto** sostiene la detección de `proteus` (sin él se pierden dos
  campañas y la fuerza bruta) y es además el techo frente al envenenamiento.
- El **destino con exceso** no aporta detección en 18 → 17 y multiplica por cuatro
  las alarmas. Si 17 → 18 lo confirma, conviene quitarlo: menos alarmas y menos
  superficie de envenenamiento.
- Quitar origen o par sube las alarmas: el umbral se recalibra al mismo FPR y cambia
  el reparto entre subnúcleos. El par aporta el "resto" de `proteus_cert`
  (infiltración).
- Pendiente: 17 → 18 (en cola, partido en dos runs por memoria).

## 6.19 Coste (2026-11-12)

`python -m proteus.evaluation.cost`, v3, un núcleo de CPU, implementación por lotes,
miércoles de CIC-IDS-2017 (496.641 flujos):

| Etapa | Flujos/s |
|---|---|
| Evidencia (152 contadores) | 103.000 |
| Puntuar `proteus` (218 características) | 79.000 |
| Puntuar `proteus_cert` (126) | 68.000 |
| Certificar todos los flujos (`proteus`) | 60.000 |
| Puntuar el núcleo de un solo modelo (122) | 386.000 |

Estado del día: 11.744 servicios × 39 valores, 9.012 hosts × 44, 22.981 pares × 20
(unos 10 MB en total; solo 25 orígenes porque CIC-2017 pasa por NAT). La
certificación solo hace falta en las alertas. El máximo calibrado cuesta unas cinco
veces lo que un solo modelo (cuatro subnúcleos más las CDF).

## 6.20 Detección v3 de 2018 → 2017 y comparación de defensas (2026-11-12)

`tables h1 --set v3`, `tables summary`, `bench` sobre
`csecicids2018__cicids2017__loo_labels__v3`. FPR 10⁻³, umbrales locales.

| Detector | Volumétricos y escaneos | Resto | Alarmas/h (IC 95 %) |
|---|---|---|---|
| `proteus` | 11/11 [0,74–1,00] | 2/10 | 2,7 [0,4–6,2] |
| `proteus_cert@cert` | 8/11 [0,43–0,90] | 1/10 | 1,5 [0,2–3,2] |
| `core_pair` | 5/11 | 0/10 | 0,3 |
| `core_free_dst_b` (sin monotonía) | 9/11 | 0/10 | 5,6 [3,7–7,4] |
| `rate_rules_local` | 9/11 [0,52–0,95] | 5/10 | 36,1 [17,8–54,4] |
| `flow_clf` | 11/11 | 3/10 | 31,1 |

A 10⁻⁴, `proteus` mantiene los cinco DoS/DDoS y 4/6 escaneos con 0,2 alarmas/h; las
reglas dan 28,1. Detección: los intervalos de Wilson se solapan; alarmas: no.

Banco al estilo METIS (detección y alarmas, ssd λ = 3; falta robustez): `proteus`
0,64 (Pareto), `proteus_cert@cert` 0,55 (Pareto), sin monotonía 0,47, por flujo 0,32,
reglas 0,29.

## 6.21 Frontera v3 del sistema desplegado, 2018 → 2017 (2026-11-12)

`tables frontier_system`: el sistema alerta si `proteus` o `proteus_cert` alertan.
Frontera simple: el menor de los dos (ataque tal cual). Certificada: el menor de los
dos certificados (toda variante con operaciones libres alerta por encima). Flujos/h.

| Ataque | Real | Simple | × | Certificada | × |
|---|---|---|---|---|---|
| SSH | 1.541 | 969 | 1,6 | 4.602 | — |
| FTP | 3.910 | 432 | 9,0 | 19.786 | — |
| DoS Hulk | 518.525 | 1.407 | 369 | 11.291 | 46 |
| DoS GoldenEye | 44.976 | 1.497 | 30 | 8.139 | 5,5 |
| DoS Slowloris | 10.461 | 811 | 13 | 6.002 | 1,7 |
| DoS Slowhttptest | 5.107 | 629 | 8,1 | 5.476 | — |
| Escaneo (jue.) | 10.418 | 11 | 915 | 629 | 17 |
| Escaneo (vie.) | 107.850 | 352 | 306 | 3.692 | 29 |
| DDoS LOIC-HTTP | 290.167 | 2.174 | 134 | 28.728 | 10 |

Lectura: el margen certificado de la v3 es mucho menor que el del núcleo certificado
de un solo modelo (23–2.355×); el paper usa ya estas cifras. Envenenamiento de
`proteus` (todas las escalas): en FTP el techo con línea base infinita es 432, igual
que la frontera sin envenenar.

## 6.22 Revisión interna y experimentos pedidos (2026-11-12)

Revisión del borrador (agente con rol de revisor de Computers & Security). Aplicado en
el paper: supuestos A1–A4 y temporizador junto a la proposición; tiempo de evento =
último paquete; afirmaciones acotadas (operaciones libres, paquetes, envenenamiento
de fuerza bruta, unidades de la frontera, contador de sondas); cifras reconciliadas
(7,1/54,6 eran todas las alertas de `core_cert`; el núcleo envenenado era el rápido);
RQ en los encabezados; amenazas a la validez; trabajo clásico (verificado).

Experimentos nuevos:

- `proteus_free`: los cuatro subnúcleos sin monotonía (precio de la monotonía de la
  combinación). En cola tras el cerrojo de 2018.
- `--entity-budgets 0.5 1 3 10` con `proteus`, `proteus_cert`, reglas y núcleo libre:
  comparación a igual presupuesto de alarmas; las reglas de tasa son monótonas y ahora
  también dan alertas certificadas (`rate_rules_local@cert`).
- `PROTEUS_TIMER_S`: holgura (2Δ+δ)/τ con re-puntuación cada δ; 18 → 17 con δ = 10 y
  60 s.
- `packet_check` ampliado a los contadores de origen y de par del atacante y a 6 h.

## 6.23 Incidencia: OOM y cerrojo de trabajos de 2018 (2026-11-12)

La v3 17 → 18 (pico de ~16 GB evaluando 2018) murió por OOM a las 12:57 UTC al
coincidir con el entrenamiento de `proteus_free`, y la frontera certificada 17 → 18
(18 GB) a las 13:22. El script original creó `v3_1718.done` pese a la muerte. Ahora
todo trabajo que evalúa en 2018, o entrena en 2018 desde cero, pasa por
`flock ~/tools/heavy.lock`; la v3 17 → 18 se relanzó con `--reuse` sobre su
`models.pkl`.

## 6.24 Detección v3 de 2017 → 2018 (2026-11-12)

`cicids2017__csecicids2018__loo_labels__v3` (relanzado con `--reuse` tras el OOM).
FPR 10⁻³; entre corchetes, IC 95 % (Wilson para campañas, bootstrap sobre 10 días para
alarmas).

| Detector | Volumétricos y escaneos | Resto | Alarmas/h | A 10⁻⁴ |
|---|---|---|---|---|
| `proteus` | 13/13 | 1/12 (SSH) | 16,0 [1,5–37,9] | 13/13, 6,7/h |
| `proteus_cert@cert` | 6/13 | 1/12 (SSH) | 17,0 [12,3–22,4] | 6/13, 2,9/h |
| `core_free_dst_b` | 13/13 | 3/12 (SSH, botnet, infiltración) | 124,6 [94,3–157,6] | 13/13 + botnet, 5,3/h |
| `rate_rules_local` | 13/13 | 2/12 (SSH, botnet) | 45,5 [31,8–58,4] | 13,9/h |
| `flow_clf` | 9/13 | 0/12 | 273,8 | 77,7/h |

Lectura:

- `proteus` detecta todo lo volumétrico y los escaneos, pero con recall bajo en
  LOIC-HTTP (0,32) y escaneos (0,41), y pierde la botnet que sí ven las reglas y el
  núcleo libre.
- `proteus_cert` en la red grande certifica poco a 10⁻³ (nada de LOIC-HTTP ni de
  escaneos) y da tantas alarmas como `proteus`; a 10⁻⁴ mantiene sus 6 campañas con
  2,9/h. TTD mediano 165 s frente a 115 s.
- Precio de la monotonía en este sentido: a 10⁻⁴ el núcleo libre detecta lo mismo y la
  botnet con menos alarmas (5,3 frente a 6,7). A 10⁻³ da 7,8 veces más alarmas.
- El IC de alarmas de `proteus` (1,5–37,9) toca el de las reglas: la afirmación de que
  los intervalos de alarmas no se solapan solo vale en 18 → 17. Corregido en el paper.
- Banco (detección y alarmas): `proteus` 0,41 (Pareto), cert 0,28, reglas 0,23, libre
  0,18, por flujo 0,13.

## 6.25 Envenenamiento de `proteus` (todas las escalas), 18 → 17 (2026-11-12)

Frontera simple (flujos/h) tras 8 días de envenenamiento sin tope; entre paréntesis,
el techo con línea base infinita.

| Ataque | Real | Día 0 | Día 8 | Techo |
|---|---|---|---|---|
| SSH | 1.541 | 969 | 969 | 969 |
| FTP | 3.910 | 432 | 432 | 432 |
| DoS (Hulk, GoldenEye, Slowloris, Slowhttptest) | — | 629–1.497 | igual | igual |
| DDoS LOIC-HTTP | 290.167 | 2.174 | 2.174 | 2.174 |
| Escaneo (vie.) | 107.850 | 352 | 352 | 352 |
| Escaneo (jue.) | 10.418 | 11 | 956 | 1.978 |

Solo se mueve el escaneo del jueves (víctima casi sin tráfico); con tope 0,1 llega a
24. El SSH sigue alertando a su ritmo real aunque la línea base esté envenenada.

## 6.26 Ablación v3 de 2017 → 2018 (2026-11-13)

Todas las alertas, FPR 10⁻³ (volumétricos y escaneos / resto / alarmas por hora).

| Variante | `proteus` 18→17 | `proteus` 17→18 | `proteus_cert` 18→17 | `proteus_cert` 17→18 |
|---|---|---|---|---|
| Completo | 1,00 / 0,20 / 2,7 | 1,00 / 0,08 / 16,0 | 0,82 / 0,10 / 4,3 | 1,00 / 0,08 / 42,0 |
| Sin destino (exceso) | 1,00 / 0,20 / 0,7 | 0,92 / 0,08 / 15,3 | 0,82 / 0,10 / 3,6 | 0,92 / 0,08 / 41,3 |
| Sin origen | 1,00 / 0,20 / 3,1 | 1,00 / 0,08 / 11,8 | 0,82 / 0,10 / 7,6 | 1,00 / 0,08 / 35,0 |
| Sin par | 1,00 / 0,20 / 3,1 | 1,00 / 0,08 / 18,7 | 0,82 / 0,00 / 7,1 | 1,00 / 0,08 / 41,8 |
| Sin destino bruto | 0,82 / 0,00 / 2,7 | 1,00 / 0,08 / 21,0 | 0,82 / 0,10 / 5,3 | 1,00 / 0,17 / 37,2 |

- Ningún subnúcleo sobra en los dos sentidos.
- Destino con exceso: en 18 → 17 cuesta 2 alarmas/h y no aporta campañas; en 17 → 18
  es el que encuentra LOIC-HTTP y los flujos de escaneo (sin él, el recall de escaneos
  cae de 0,41 a 0,008 y el SSH tarda 126 s en vez de 47 s). **Decisión: se queda.**
  Elegir subnúcleos por sentido sería ajustar el detector a los ataques de prueba.
- Origen y par no cambian la detección de `proteus` en ningún sentido; las alarmas se
  mueven en ambos sentidos al recalibrar el umbral.
- En `proteus_cert`: sin par se pierde la Infiltration de 2017; sin destino, una
  campaña volumétrica de 2018. Quitar el destino bruto en 17 → 18 encuentra la botnet
  y baja las alarmas (42,0 → 37,2): único caso en que quitar ayuda en las dos cosas,
  pero en `proteus` 18 → 17 esa misma retirada pierde dos campañas y todo lo demás.

## 6.27 Incidencia: OOM de la frontera de `proteus` 17 → 18 (2026-11-13)

La frontera murió a las 00:43 UTC con 28,8 GB, sola en la máquina (2.º OOM tras el
reinicio). Causa: `local_threshold` y `local_benign` leían el día entero de la caché
con todas las columnas de `proteus` (218 × 7,4 M filas el viernes 16-02-2018, unos
26 GB en float64) antes de muestrear 300.000 filas. `proteus_cert` tiene menos columnas
y cabía. Arreglo (commit 15fe433): `h1.sample_clean` lee la columna `clean`, elige las
mismas filas con el mismo generador y luego lee solo los grupos de filas necesarios.
Mismas filas, mismo orden (test `test_sample_clean.py`); pico medido 4,5 GB. Afecta
también al adaptativo de 17 → 18, que usa `local_benign`. Frontera relanzada bajo el
cerrojo (`fix3.sh`).

## 6.28 Atacante adaptativo v3, 2018 → 2017 (2026-11-13)

Daño: el ritmo más alto de la rejilla (20 puntos de 10⁻³ a 200 flujos/s, factor 1,9
entre puntos) al que el ataque no da alerta propia, eligiendo además operaciones
libres (8 combinaciones aleatorias y mimetismo). Flujos/h, FPR 10⁻³. **Negrita** en el
paper: el ataque pasa a su ritmo real.

| Ataque | Real | proteus | cert | cert certificado | sin monotonía | reglas | KitNET |
|---|---|---|---|---|---|---|---|
| SSH | 1.541 | 614 | 2.220 | 4.220 | 55.122 | 2.220 | 28.995 |
| FTP | 3.910 | 323 | 15.252 | 15.252 | 28.995 | 614 | 1.168 |
| Hulk | 518.525 | 1.168 | 8.023 | 8.023 | 8.023 | 1.168 | 104.792 |
| GoldenEye | 44.976 | 1.168 | 8.023 | 8.023 | 8.023 | 1.168 | 28.995 |
| Slowloris | 10.461 | 614 | 2.220 | 4.220 | 8.023 | 1.168 | 4.220 |
| Slowhttptest | 5.107 | 614 | 2.220 | 4.220 | 8.023 | 1.168 | 15.252 |
| Escaneo (jue.) | 10.418 | 7 | 13 | 614 | 170 | 47 | 1.168 (mim.) |
| Escaneo (vie.) | 107.850 | 323 | 2.220 | 4.220 | 8.023 (mim.) | 1.168 | 2.220 (mim.) |
| LOIC-HTTP | 290.167 | 1.168 | 8.023 | 15.252 | 15.252 | 2.220 | 28.995 |

- `proteus` deja el menor daño en los 9 ataques (empata con las reglas en Hulk y
  GoldenEye): obliga a ir 2,5× (SSH) a ~1.500× (escaneo del jueves) más lento.
- Contra `proteus`, `proteus_cert` y las reglas, el mejor plan es siempre el ataque
  simple: las operaciones libres no ayudan (monotonía). Contra KitNET y el núcleo sin
  monotonía, el mimetismo sube el daño en los escaneos.
- Pasan a ritmo real: KitNET en SSH y Slowhttptest; sin monotonía en SSH, FTP y
  Slowhttptest; reglas y cert en SSH. El daño certificado de cert queda bajo el ritmo
  real salvo en las dos fuerzas brutas.
- Banco con robustez (solo 18 → 17, provisional hasta tener KitNET en h1 y 17 → 18):
  `proteus` 0,60 / 0,68 / 0,40 → compuesto 0,54 (Pareto); alertas certificadas
  0,41 / 0,78 / 0,15 → 0,36 (Pareto); reglas 0,66 / 0,12 / 0,30 → 0,30 (Pareto); sin
  monotonía 0,41 / 0,54 / 0,14 → 0,32.
- Código: `tables.py adaptive` (tabla del paper) y `bench` toma la robustez de las
  alertas certificadas del daño certificado (commit 65a8d03).

## 6.29 Atacante adaptativo v3, 2017 → 2018, y banco con robustez (2026-11-13)

Daño en flujos/h (FPR 10⁻³). «0»: alerta a todos los ritmos probados. (v): una
variante con operaciones libres subió el daño.

| Ataque | Real | proteus | cert | cert certificado | sin monotonía | reglas | KitNET |
|---|---|---|---|---|---|---|---|
| SSH | 62.340 | 8.023 | 8.023 | 8.023 | 0 | 55.122 | 55.122 |
| GoldenEye | 38.445 | 4.220 | 8.023 | 15.252 | 4 | 4.220 | 15.252 |
| Slowloris | 12.184 | 2.220 | 2.220 | 4.220 | 0 | 4.220 | 4.220 |
| Hulk | 8.383.527 | 8.023 | 15.252 | 15.252 | 13 | 4.220 | 55.122 |
| LOIC-HTTP | 275.992 | 1.168 | 55.122 | 104.792 | 7 | 170 (v) | 4.220 |
| LOIC-UDP (mar.) | 3.192 | 7 | 47 | 323 | 0 | 0 | 0 |
| HOIC | 1.185.992 | 104.792 | 55.122 | 104.792 | 4.220 (v) | 4.220 | 378.731 |
| LOIC-UDP (mié.) | 2.983 | 7 | 170 | 323 | 7 (v) | 0 | 0 |
| Escaneo (28-02) | 2.882 | **55.122** | **28.995** | **104.792** | 0 | 170 | **4.220** (v) |
| Escaneo (01-03) | 1.567 | **4.220** | **28.995** | **104.792** | 0 | 170 | **4.220** (v) |

- Resultado negativo en este sentido: `proteus` obliga a bajar de 5,5× (Slowloris) a
  ~1.000× (Hulk) en volumétricos y SSH, pero los dos escaneos de 2018 (1.600–2.900/h)
  pasan a su ritmo real (coherente con su recall 0,41).
- Las reglas dejan menos daño en 7 de 10 ataques y el núcleo sin monotonía no deja
  pasar nada salvo HOIC por encima de 13/h; ambos lo pagan en alarmas (45,5 y 124,6/h
  frente a 16,0).
- Contra `proteus` y `proteus_cert` el mejor plan es siempre el simple. Las reglas
  ganan un escalón con una variante en LOIC-HTTP (89 → 170): la monotonía solo
  descarta ganancias salvo el desfase de exportación que absorbe la holgura del
  certificado; los detectores no certificados no la tienen. Corregida en el paper la
  frase de 18 → 17 que decía «como predice la monotonía» para los tres.
- Daño certificado de cert: bajo el ritmo real salvo las fuerzas brutas de 2017 y los
  escaneos de 2018.

Banco (detección / alarmas / robustez → compuesto, Pareto):

| Defensa | 18 → 17 | 17 → 18 |
|---|---|---|
| `proteus` | 0,60 / 0,68 / 0,40 → **0,54** • | 0,54 / 0,31 / 0,25 → **0,35** • |
| alertas certificadas | 0,41 / 0,78 / 0,15 → 0,36 • | 0,27 / 0,30 / 0,15 → 0,24 |
| sin monotonía | 0,41 / 0,54 / 0,14 → 0,32 | 0,62 / 0,00 / 0,86 → 0,30 • |
| reglas | 0,66 / 0,12 / 0,30 → 0,30 • | 0,58 / 0,07 / 0,35 → 0,27 • |
| por flujo | 0,65 / 0,16 / — | 0,35 / 0,00 / — |

`proteus` sigue primero en los dos sentidos. KitNET entra cuando acabe su ejecución h1.
El paper pasa a 21 páginas (tabla adaptativa a doble columna).

## 6.30 Frontera v3 del sistema en 2017 → 2018 y temporizador (2026-11-13)

Frontera del sistema (alerta `proteus` o `proteus_cert`), flujos/h; factor = cuántas
veces más lento que la campaña real.

| Ataque | Real | Simple | Factor | Certificada | Factor |
|---|---|---|---|---|---|
| SSH | 62.340 | 11.963 | 5,2 | 12.105 | 5,2 |
| GoldenEye | 38.445 | 5.523 | 7,0 | 16.301 | 2,4 |
| Slowloris | 12.184 | 2.223 | 5,5 | 5.058 | 2,4 |
| Hulk | 8.383.527 | 14.114 | 594 | 28.011 | 299 |
| LOIC-HTTP | 275.992 | 1.317 | 210 | 188.314 | 1,5 |
| LOIC-UDP (mar.) | 3.192 | 8 | 407 | 348 | 9,2 |
| HOIC | 1.185.992 | 72.618 | 16 | 126.517 | 9,4 |
| LOIC-UDP (mié.) | 2.983 | 7 | 400 | 343 | 8,7 |
| Escaneo (28-02) | 2.882 | 7.480 | — | 126.995 | — |
| Escaneo (01-03) | 1.567 | 6.917 | — | 113.965 | — |

- Todo DoS/DDoS y SSH quedan por debajo de su ritmo real, también con la frontera
  certificada (Hulk 299×, LOIC-UDP y HOIC ~9×, SSH 5,2×, GoldenEye y Slowloris 2,4×,
  LOIC-HTTP 1,5×).
- Los dos escaneos de 2018 (1.600–2.900/h) van por debajo de ambas fronteras: pasan a
  su ritmo real. Coherente con el recall 0,41 y con el adaptativo (6.29).
- Ya no hay OOM: la ejecución alcanzó ~11 GB con el muestreo por grupos de filas (6.27).
- La figura del paper sigue solo con 18 → 17 (`data/frontier.csv`); los dos sentidos
  están en `data/frontier_both.csv`.

Temporizador de re-puntuación (18 → 17, `PROTEUS_TIMER_S`), alertas certificadas de
`proteus_cert`, FPR 10⁻³:

| δ | Campañas vol./escaneo | Recall de flujos | Alarmas/h |
|---|---|---|---|
| 0 | 8/11 | 0,613 | 1,48 |
| 10 s | 8/11 | 0,612 | 1,48 |
| 60 s | 8/11 | 0,604 | 1,48 |

La holgura (2Δ+δ)/τ apenas cambia nada; añadido a la sección de diseño del paper.

## 6.31 KitNET v3 y fallo de `proteus_free` (2026-11-13)

KitNET sobre los mismos contadores por entidad (no supervisado), FPR 10⁻³:

| Sentido | Volumétricos y escaneos | Otros | Alarmas/h | TTD mediano | Compuesto (Pareto) |
|---|---|---|---|---|---|
| 18 → 17 | 9/11 (LOIC-HTTP 0,84; escaneos 4/6) | FTP, 1 infiltración | 11,8 | 11 s | 0,30 (no) |
| 17 → 18 | 12/13 (falla LOIC-HTTP; GoldenEye 0,01, Slowloris 0,22) | SSH (0,20), 3/4 infiltraciones | 31,2 | 521 s | 0,26 (sí) |

`proteus` sigue con el mejor compuesto en los dos sentidos (0,54 y 0,35).

`proteus_free` 18 → 17 murió tras entrenar: la comprobación de monotonía indexaba
`monotonic_cst=None`. Arreglado (commit c5d000d, se salta la comprobación sin
restricciones) y relanzado bajo el cerrojo (`fix4.sh`); el de 17 → 18 aún no había
empezado y ya usa el código corregido.

## 6.32 Experimentos de la revisión: reglas certificadas, reutilización y máximo sin monotonía (2026-11-13)

Corridas `__v3_budget` (reutilizan los modelos de `__v3`) y `__v3_free`, FPR 10⁻³, umbrales
locales. Campañas detectadas sobre el total del sentido (21 en 18 → 17, 25 en 17 → 18):

| Detector | 18 → 17 | Alarmas/h | 17 → 18 | Alarmas/h |
|---|---|---|---|---|
| `proteus` | 13/21 | 2,7 | 14/25 | 16,0 |
| `proteus_cert@cert` | 9/21 | 1,5 | 7/25 | 17,0 |
| `proteus_cert@certr` (también frente a reutilización) | 2/21 | 0,0 | 0/25 | 0,0 |
| `rate_rules_local` | 14/21 | 36,3 | 15/25 | 45,5 |
| `rate_rules_local@cert` | 14/21 | 28,4 | 15/25 | 27,6 |
| `proteus_free` (los cuatro subnúcleos sin restricciones) | 15/21 | 5,7 | 18/25 | 62,9 |

A 10⁻⁴: `proteus_free` 11/21 a 0,2/h (TTD mediano 74 s) frente a `proteus` 9/21 a 0,2/h (1 s);
en 17 → 18, 17/25 a 9,1/h frente a 14/25 a 6,7/h. Reglas certificadas a 10⁻⁴: 13/21 a 25,5/h
y 12/25 a 10,2/h.

Lectura:
- **Reglas certificadas.** Las reglas de tasa son monótonas en la evidencia y su certificado
  conserva casi todo, a unas 28 alarmas/h. Lo que separa a Proteus de ellas son las falsas
  alarmas, no el certificado. Los subnúcleos aprendidos pagan las alarmas bajas con
  cobertura certificada, sobre todo de escaneos.
- **Reutilización de conexiones.** El certificado frente a reutilización deja a
  `proteus_cert` casi sin nada: GoldenEye y un poco de Hulk en 18 → 17, ninguna en 17 → 18.
  Los subnúcleos se apoyan en flujos, RST y flujos sin respuesta, justo lo que la
  reutilización baja. Haría falta un detector entrenado solo con bytes de carga y
  conteos distintos (trabajo futuro).
- **Máximo sin monotonía.** Detecta más campañas, sobre todo las que dejan poca evidencia
  conservada: SSH, web y botnet. En volumétricos y escaneos no gana (8/11 frente a 11/11 en
  18 → 17; 13/13 en ambos en 17 → 18). Cuesta más alarmas en 17 → 18 y no tiene certificado.
  La conclusión del paper pasa de "robustness does not cost detection" a "costs little
  detection on the attacks that leave conserved evidence".

**Fallo detectado:** los presupuestos por alarmas/h (`--entity-budgets`) solo se aplicaron a
`core_free_dst_b`. Los detectores locales (`proteus`, `proteus_cert`, reglas) se ajustan en la
pasada 2, y las puntuaciones altas limpias se recogían en la pasada 1. Arreglado con una
pasada 3 (commit c903249). El umbral de cada día sale de las puntuaciones altas limpias de los
otros días, cada uno puntuado por el detector ajustado sin ese día; solo usa tráfico
benigno. Relanzado bajo el cerrojo como `__v3_budget2` (`fix5.sh`) en los dos sentidos.

**Segundo fallo de los presupuestos (2026-11-13, 16:30).** El primer `__v3_budget2` de
18 → 17 dio 0 alarmas y 0 detecciones para Proteus en todos los presupuestos. Las
puntuaciones altas de cada día se hacían con el detector ajustado *sin* ese día. Un host
benigno del lunes, fuera de muestra, puntuaba 1,019 y subía el umbral de los demás días por
encima de cualquier ataque. Ahora la pasada 2 guarda los rasgos del 1 % de flujos limpios más
altos de cada día, y la pasada 3 los puntúa con el detector del día evaluado, igual que los
umbrales locales (commit 00263dd). Con las probabilidades discretas del boosting hay muchos
empates en 1,0, así que a presupuestos bajos (≤ 1/h) el umbral salta a "> 1". 18 → 17 se rehace
(`fix6.sh`); 17 → 18 aún no había empezado y ya usa el código corregido.

## 6.33 Dos OOM más y CTU-13 v3 sin excluir subnúcleos saturados (2026-11-13, 18:30)

- **OOM 17:12, presupuestos 17 → 18 (pasada 3, 28,6 GB).** Las puntuaciones de las reglas de
  tasa saturan, así que "en o por encima del percentil 99" se llevaba mucho más del 1 % de
  un día de 2018 como candidatos (17 GB en `_scores`). Ahora, si los empates pasan del
  doble del 1 %, se queda el 1 % más alto por puntuación (commit 2a6d075). Se rehacen los
  dos sentidos como `__v3_budget3` (`fix7.sh`); el `__v3_budget2` de 18 → 17 sirve de
  comprobación.
- **OOM 17:35, frontera de escaneo de CTU-13 a 6 h.** La búsqueda probaba hasta 200
  sondas/s: 4,3 M flujos inyectados en 6 h. Se relanza con `--rmax 20` (1.200
  sondas/min). Las fronteras sin certificar a 1 h quedan en 26–540 sondas/min.
- **CTU-13 v3 se ejecutó sin `--exclude-saturated`.** Proteus (máximo calibrado) da 120
  alarmas/h en el fold B y 784–1.211 en el A, con un FPR medido 3–5 veces por encima del
  objetivo. Los subnúcleos saturados empatan en su máximo con más del 10⁻³ del tráfico
  benigno (el caso para el que existe la opción, commit 0ca4b14). Sí sirve el núcleo de
  origen y destino `core_both_x`: 0,31 alarmas por entidad/h y 27/181 sospechosos en el
  fold B (v1: 0,12 y 28/181); 1,10/h y 19/119 en el A (v1: 1/119). Se rehace con
  `--reuse --exclude-saturated 1e-3` para `proteus` y `proteus_cert`, y la frontera de
  escaneo a 1 y 6 h con la misma exclusión (`fix8.sh`; `frontier_scan` admite ahora la
  opción, commit 186afcd).
- Frontera de escaneo v3 a 1 h, sin exclusión: Proteus alerta a un escáner nuevo que
  repite las sondas del bot a 26 (s03), 139 (s12), 273 (s08) y 539 (s06) sondas/min. En v1,
  con solo la escala de 10 min, eran ~3.900 en s03. Los bots reales van a 5–36 sondas/min.
  El certificado no acota ninguno por debajo de 200 sondas/s. Pendiente de repetir con
  exclusión.

## 6.34 Detección a igual presupuesto de alarmas (`__v3_budget3`, 2026-11-13)

Umbral por presupuesto B de grupos (destino, minuto)/h en los flujos limpios de los otros
días de prueba, puntuados por el detector del día evaluado. Comparamos a ritmo
**realizado** en el día de prueba, que no coincide con B. Volumétricos y escaneos (11 en
18 → 17, 13 en 17 → 18):

| Detector | 18 → 17 | 17 → 18 |
|---|---|---|
| `proteus` | 9/11 a 0,06/h; 11/11 a 0,67/h | 12/13 a 6,4/h (recall 0,61); 13/13 a 8,8/h |
| `proteus_cert` | 6/11 a 0,36/h; 9/11 a 7,0/h | 13/13 a 0,40/h (recall 0,80) |
| `proteus_cert@cert` | 5/11 a 0,09/h | 6/13 a 0,08/h |
| `rate_rules_local` | 9/11 a 27,5/h (no baja más) | 13/13 a 6,6/h (recall 0,95) |
| `core_free_dst_b` | 7/11 a 0,09/h; 9/11 a 0,68/h | 13/13 a 0,70/h |
| `proteus_cert@certr` | 2/11 | 0/13 |

- En 18 → 17 Proteus gana con claridad. Las reglas no bajan de 27,5 alarmas/h: cada día
  nuevo tiene flujos por encima de cualquier máximo benigno, así que el umbral
  más estricto (> 1) sigue alarmando.
- En 17 → 18 cambia el orden. Las reglas igualan al Proteus de todas las escalas
  (6,6 frente a 8,8 alarmas/h para los 13), y el detector de 10 min (`proteus_cert`) los
  detecta a 0,4/h. No hemos aislado por qué las escalas de 1 h y 6 h cuestan alarmas en
  esa red.
- Paper: párrafo nuevo en la evaluación. La introducción y la conclusión matizan que la
  ventaja en falsas alarmas es a igual FPR objetivo; a igual presupuesto, las reglas
  igualan a Proteus en 17 → 18.
- `__v3_budget2` de 18 → 17 (sin tope de candidatos) da exactamente los mismos resultados
  en todos los detectores: en ese sentido el tope no cambia nada (comprobado sobre
  `false_alarms.csv` y `summary.csv`).

## 6.35 CTU-13 v3 con `--exclude-saturated` (2026-11-13, 22:50)

- **Fold B** (entrena s05/07/08/09/11/12/13, prueba s01/02/03/04/06/10), FPR 10⁻³: Proteus da
  2,66 alarmas/h, 0,66 por entidad/h, FPR medido 1,16·10⁻³, y 9/181 sospechosos. Sin exclusión
  daba 120/h. Detecta 3/5 DDoS de ctu10, los dos spam y 3/59 escaneos de ctu3.
  `proteus_cert@certr` = 0.
- **Fold A** (prueba s05/07/08/09/11/12/13): Proteus sigue en 1.114 alarmas/h de media por
  escenario. Todo viene de **s11** (Rbot, DDoS ICMP; 16 min de captura): FPR 0,030 y 7.757
  alarmas/h. Los demás escenarios dan 0–25 alarmas/h (s08 14,0; s09 25,1). Ponderando por
  horas: 56,6/h con s11 y 9,4/h sin él. La exclusión de saturados no cambia s11.
- `alarms.py` sobre el mismo fold da 2,03 alarmas/h, 5 de ellas en s11. No es comparable:
  ajusta el máximo calibrado una vez con el benigno de **todos** los días, incluido el
  evaluado (en muestra), y excluye a los sospechosos. `h1` deja fuera el día evaluado, que
  es el protocolo del paper. El benigno de s11, fuera de distribución para un detector
  ajustado con capturas de otras semanas, es lo que dispara las alarmas.
- Frontera de escaneo a 1 h con exclusión: idéntica a la de sin exclusión (26/139/273/539
  sondas/min en s03/s12/s08/s06). El certificado no acota ninguna por debajo de 200 sondas/s.
- Pendiente antes de escribir CTU en el paper:
  1. decidir cómo informar de s11: por escenario, ponderado por horas, o con s11 aparte;
  2. explicar las alarmas de s11 con el protocolo de `h1` (hoy `alarms.py` solo calibra
     en muestra);
  3. la frontera a 6 h.

## 6.36 Frontera de escaneo de CTU-13 a 6 h y OOM del balanceo (2026-11-14, 00:15)

Frontera de escaneo de CTU-13 a 6 h (fold B, `--exclude-saturated 1e-3`, `--rmax 20`), en sondas/min:

| Escenario | Bot real | 1 h | 6 h |
|---|---|---|---|
| s03 | 6,8 | 26,3 | 14,3 |
| s12 | 12,8 | 139,1 | 132,7 |
| s08 | 5,2 | 273,4 | 235,0 |
| s06 | 36,1 | 539,3 | 430,0 |

El bot más lento sigue a la mitad de la frontera. El certificado no acota ninguna por debajo de
1.200 sondas/min (límite de la búsqueda). Añadido a la discusión del paper.

OOM n.º 5 (22:15): el balanceo `type_entity` de 17 → 18 murió puntuando (16,5 GB). A la misma hora
corría mi `alarms.py` de CTU fuera del cerrojo; desde ahora todo va bajo el cerrojo. Relanzado con
`--reuse` (`fix9.sh`).

## 6.37 Balanceo de clases (2026-11-14, 02:30)

FPR 10⁻³, umbrales locales. `cap` = por defecto (tope por tipo y día, `class_weight="balanced"`).

| Modo | 18 → 17 Proteus | 17 → 18 Proteus | 18 → 17 `core_mono_dst_x` | 17 → 18 `core_mono_dst_x` |
|---|---|---|---|---|
| `cap` (v3) | 13/21, vol. 11/11, 2,7/h | 14/25, vol. 13/13, 16,0/h | 9/21, 4,1/h | 17/25, 41,5/h |
| `type` | 15/21, 11/11, 5,2/h | 11/25, 9/13, 28,8/h | 15/21, 16,9/h | 18/25, 43,6/h |
| `type_entity` | 15/21, 11/11, 10,8/h | 9/25, 7/13, 31,1/h | 14/21, 17,5/h | 20/25, 43,5/h |
| `none` | 12/21, 10/11, 1,7/h | 14/25, 13/13, 14,8/h | 9/21, 3,3/h | 17/25, 41,2/h |

- Ningún modo domina. `type` gana dos campañas en 18 → 17 con el doble de alarmas, pero pierde 4
  volumétricos y escaneos en 17 → 18. `none` queda a una campaña de `cap`.
- Se mantiene `cap`, fijado antes de estas pruebas. La sensibilidad va al apéndice del paper.
- Las certificadas de `proteus_cert` se mueven poco (8/11 en todos los modos de 18 → 17; 6–7/13 en
  17 → 18), con 1,5–6,8 y 7,8–24,4 alarmas/h.

## 6.38 Línea base del par relativa a su servicio, realimentación en 17 → 18 y coste en un núcleo (2026-11-14, 03:30)

**pairbase** (`PROTEUS_PAIRBASE=1`, núcleos reentrenados), FPR 10⁻³:

| | 18 → 17 v3 | 18 → 17 pairbase | 17 → 18 v3 | 17 → 18 pairbase |
|---|---|---|---|---|
| `proteus` | 13/21, 2,7/h | 13/21, 2,4/h | 14/25, 16,0/h | 15/25, 16,5/h |
| `proteus_cert@cert` | 9/21 (vol. 8/11), 1,5/h | 4/21 (4/11), 0,4/h | 7/25, 17,0/h | 8/25, 17,1/h |
| `core_pair` | 5/21, 0,3/h | 5/21, 0,6/h | 6/25 (SSH no), 16,2/h | 15/25 (vol. 13/13 + SSH), 36,4/h |

La fuerza bruta de 18 → 17 sigue sin detectarse (0/3 en las certificadas). No es el remedio para la
fuerza bruta lenta; en 18 → 17 cuesta cobertura certificada. No se midieron fronteras con ella.

**Realimentación en 17 → 18** (bloqueo de la cáscara al FPR local). Alarmas de origen/h según K y τ:
- **FPR 10⁻³:** 60.903 falsos positivos de 18.296 orígenes en 166,8 h. Con K=100 y τ=600 s salen
  5,4/h, y ni con K=500 bajan de 5,2: unos pocos orígenes con mucho tráfico acumulan bloqueos.
- **FPR 10⁻⁴:** 17.866 falsos positivos de 8.491 orígenes. Desde K=10 salen 0,5/h.
- **18 → 17 a 10⁻⁴:** 507 falsos positivos de 13 orígenes. Con τ=600 s salen 0 desde K=5.
- Con K=10 y τ=600 s, las 805 sondas bloqueadas que necesita una evasión exigen más de 13 h.

**Coste: error propio.** `cost.py` no limitaba los hilos, y el boosting de scikit-learn predice con
OpenMP en todos los núcleos. Las cifras "en un núcleo" de 6.19 (103.000 / 79.000 / 60.000 flujos/s)
eran multihilo y con la VM cargada. Medido con `OMP_NUM_THREADS=1 taskset -c 15`
(`cost_v3_1core.log`):

| Etapa | Flujos/s (1 núcleo) |
|---|---|
| Evidencia (152 contadores) | 172.000 |
| Puntuar `proteus` (218 características) | 25.400 |
| Puntuar `proteus_cert` (126) | 26.900 |
| Certificar todos los flujos (`proteus`) | 30.600 |
| Puntuar el núcleo de un solo modelo (122) | 84.500 |

Paper corregido (discusión, "Deployment and cost").

## 6.39 OOM n.º 6: UGR'16, 7 de agosto de 2016 (2026-11-14, 05:20)

La conversión de `august_week1` murió a las 04:41 (28,6 GB) al cerrar el día 2016-08-07. Ese día
tiene ~1 M de flujos de ataque por hora (1.064.134 a las 21:00), y se guardaban todos en memoria
hasta escribir el día. Escritos: 08-01 a 08-06.

Arreglo (commit fe9432a): como mucho 100.000 flujos de ataque guardados por hora, por una muestra
determinista independiente de la del fondo, y rasgos en float32. La evidencia sigue contando todos
los flujos; solo el recall de esas horas se estima sobre la muestra. Ningún día anterior llegaba
al tope, así que no cambia. Se reanuda desde 2016-08-07 bajo el cerrojo (`fix10.sh`), tras
`july_week5`.

Además (06:15): `july_week5` corría con el código antiguo y llegó al 2016-07-31 con 612.148 flujos de
ataque por hora (06:00). Se paró antes de que acumulara el día y se reanuda desde el 31 con el tope
(`fix11.sh`). Escritos: 07-27 a 07-30.

## 6.40 UGR'16 convertido y OOM n.º 7 en CIC-DDoS-2019 (2026-11-14, 07:30)

- **UGR'16 convertido:** 2016-07-27 a 2016-08-08 (13 días; 07-31 y 08-07 con el tope de ataques).
- **OOM n.º 7 (06:38, 28,6 GB):** el procesado de CIC-DDoS-2019 calculaba la evidencia de cada hora
  de una vez, y la ventana 10 del 2018-11-03 tiene 14,5 M flujos (casi todos de ataque).
- **Arreglo** (commit bb1732f): las ventanas de más de 3 M flujos se cortan en subventanas de 10 min
  con 10 min de calentamiento, y solo se calculan donde hay flujos que guardar. Los contadores solo
  pueden quedar por debajo de los del calentamiento de 30 min. Tests: coincide con el cálculo exacto
  cuando una subventana lo cubre todo, y nunca lo supera.
- **Relanzado** bajo el cerrojo (`fix12.sh`, reutiliza `_stage`) tras CTU-SME-11, que está corriendo.

**OOM n.º 8 (07:48):** CIC-DDoS-2019 volvió a morir una hora después de la de 14,5 M. `process()`
guardaba en memoria todas las ventanas del calentamiento (30 min de esa hora), y el 2018-12-01
13:00 es aún mayor (845 MB en staging). Ahora cada ventana y su calentamiento se leen del disco
con filtro por tiempo, y las ventanas de más de 3 M flujos se calculan en tramos de unos 3 M flujos
(al menos 2 min), cada uno con un calentamiento tan largo como el tramo (commit 28170af; test nuevo
del camino denso en `process`). Relanzado (`fix13.sh`). CTU-SME-11 convertido sin errores.

**OOM n.º 9 (08:34):** la hora 2018-12-01 13:00 de CIC-DDoS-2019 tiene 23,5 M flujos. Los ataques
llegan en ráfagas, así que los tramos de igual duración tenían mucho más de 3 M flujos. Ahora los
tramos se cortan por número de filas (cuantiles de `t_end` de la ventana; como mucho 2 M flujos por
tramo, commit 69f69e0). Relanzado (`fix14.sh`). 2018-11-03 ya está escrito.

## 6.41 Evidencia con estado para UGR'16, CIC-DDoS-2019 y CTU-SME-11 (2026-11-14)

La conversión por ventanas con calentamiento de 30 min no llega a las escalas de 1 h y 6 h de la
v3. Las capturas convertidas solo tenían escalas de hasta 10 min, y ningún modelo v3 (ni siquiera
`proteus_cert`, que usa 44 rasgos de escala larga) podía evaluarse en ellas. Decisión (Antonio):
arrastrar el estado y reconvertir.

- `proteus.evidence.stream.StreamingEvidence` (commit 439edb1) guarda, por contador, el estado de
  cada entidad (valores con decaimiento y última vez) y, en los conteos distintos, la última vez de
  cada par (entidad, elemento). Usa identificadores por hash, estables entre ventanas. Procesar
  por ventanas reproduce `build` sobre la captura entera: test exacto en v1 y v3.
- Poda:
  - entidades inactivas más de 3·τ_max (18 h): bajan como mucho e⁻³;
  - pares olvidados: exceso ≤ e⁻³ por vuelta;
  - entidades ligeras (inactivas más de 1 h y con < 3 de evidencia a 6 h) se descartan con sus
    elementos, así que solo pueden bajar. Sin esto, 4 h de UGR'16 eran 153 M entradas y 16 GB.
- Prueba en la VM (3 h de UGR'16): ~80 s por hora de captura, 10 GB, 166 columnas con `t21600`.
- `reconv.sh`: reconvierte UGR'16 (las dos semanas como un solo flujo), CIC-DDoS-2019 y
  CTU-SME-11, y después lanza `real2.sh` (pliegues de UGR'16, CIC-IDS-2017 → UGR'16 y
  CIC → CIC-DDoS-2019). `h1` acepta la evidencia convertida si tiene las escalas largas.
- CTU-13 en el paper: alarmas ponderadas por horas; s11 aparte como captura fuera de distribución
  (decisión de Antonio).

**Reconversión (2026-11-15, 05:15).**
- **UGR'16:** 2016-07-27 a 2016-08-08, ~7 h, estado estable en 180–220 M entradas (14–17 GB).
- **CIC-DDoS-2019:** convertido, estado de ~1,3 M.
- **CTU-SME-11:** parado a mano. Ventanas de 10 min con 2,3 M flujos de ataque llevaban el estado a
  427 M entradas y subiendo (18,6 GB, 9 GB libres). Ningún `\todo` del paper depende de él; queda
  sin convertir.
- Han empezado los experimentos de `real2.sh` (pliegue julio → agosto de UGR'16).

## 6.42 UGR'16 dentro del dataset, dos pliegues (2026-11-15, provisional)

Evidencia v3 con estado, `--exclude-saturated 1e-3`, umbral local. Campañas por familia (UGR'16
etiqueta varias por día):

| Pliegue | Detector | FPR 10⁻³ | FPR 10⁻⁴ |
|---|---|---|---|
| jul → ago | `proteus` | 19,2/h (18,4 ent.); DoS 22/26, botnet 7/7, scan11 2/13, scan44 3/13 | 6,7/h; DoS 14/26 |
| jul → ago | `core_both_x` | 7,0/h (0,33 ent.); DoS 23/26, scans 2+3/13 | 0,2/h; DoS 21/26 |
| ago → jul | `proteus` | 20,3/h (17,5 ent.); DoS 19/20, botnet 4/4, scans 8/8 + 8/8 (recall 0,87/0,75) | 2,0/h; lo mismo (DoS 19/20, scans 16/16) |
| ago → jul | `core_both_x` | 11,1/h (1,5 ent.); DoS 17/20, scans 16/16, botnet 4/4 | 0,7/h; DoS 10/20, scans 14/16 |

- El spam, el sshscan y el udpscan apenas se detectan (≤ 3/22, 0/8, 1/4).
- `proteus@cert` y `core_both_x@cert` = 0 en UGR'16. Las certificadas de `proteus_cert` sí
  existen (ago → jul: DoS 14/20, botnet 4/4 a 7,0/h).
- **Fallo de la línea base:** las reglas de tasa alertaban en todos los flujos (FPR 1,0). UGR'16 es
  unidireccional, 20 contadores de RST y respuesta valen siempre 0 y la CDF benigna los ponía a 1.
  Ahora `RateRules` ignora los rasgos constantes en la referencia (commit 02c0aed). En CIC no hay
  ninguno (comprobado), así que sus resultados no cambian. Se repiten las reglas en los dos
  pliegues y en 2017 → UGR'16 (`fix15.sh`).
- Pendiente: 2017 → UGR'16 y CIC → CIC-DDoS-2019, y escribir la sección del paper.

## 6.43 UGR'16, CIC-DDoS-2019 y CTU-13 v3 en el paper (2026-11-15, 08:40)

**UGR'16** (reglas ya corregidas), FPR 10⁻³:

| | `proteus` | reglas de tasa |
|---|---|---|
| jul → ago | 19,2/h: DoS 22/26, botnet 7/7, escaneos 5/26 | 23,9/h: DoS 3/26, escaneos 1/26 |
| ago → jul | 20,3/h: DoS 19/20, botnet 4/4, escaneos 16/16 (recall 0,75–0,87); a 10⁻⁴: 2,0/h, igual | 40,2/h: DoS 19/20, botnet 4/4, escaneos 12/16 (recall ~0,2); a 10⁻⁴: 28,0/h, 8/16 |
| 2017 → UGR'16 (12 días) | 25,1/h: DoS 32/46, escaneos 31/42 (recall ~0), botnet 4/11 | (repetición pendiente) |

- Certificadas de `proteus_cert`: julio, DoS 14/20 y botnet 4/4 a 7,0/h; agosto, DoS 3/26.
- Spam, SSH y UDP: casi nada.

**CIC-DDoS-2019:**
- 2017 → todo salvo 10 de las 12 SYN; 2018 → todo.
- FPR fuera de objetivo en todos: 1,2 % (2017), 4,9 % (2018), 19 % (reglas). Solo hay ~50.000 benignos
  al día. Solo sirve como comprobación de detección.

**CTU-13** (decisión: ponderar por horas, s11 aparte):
- Fold B: 9,3 alarmas/h, 2,0 por entidad.
- Fold A sin s11: 9,4 y 1,9; con s11, 56,6.

Paper:
- Datos de UGR'16 y CIC-DDoS-2019 en "Data".
- Párrafo de CTU-13 reescrito con v3.
- Párrafos nuevos de UGR'16 y CIC-DDoS-2019.
- Introducción: en UGR'16, a igual FPR, las reglas dan 28 alarmas/h y detectan la mitad de los escaneos.
- Discusión: unas dos alarmas por entidad y hora en CTU-13, salvo la captura de otra semana.

Quedan:
- `\todo` de fronteras sobre víctimas con tráfico (UGR'16, CTU-13);
- cifras finales (conclusión, Y/Z del resumen);
- confirmar la declaración de IA.

Reglas de tasa locales en UGR'16 (las de la ejecución 2017 → UGR'16, ya corregidas): a 10⁻³,
17,2 alarmas/h, ningún DoS ni escaneo (spam 3/46, botnet 1/11). Proteus: 25,1/h, DoS 32/46,
escaneos 31/42. Añadido al paper.

## 6.44 Cierre de decisiones (2026-11-15, 10:40)

Antonio delega las decisiones pendientes. Tomadas:
- **Resumen y conclusión:** se da el daño frente al atacante adaptativo en la dirección en que
  Proteus gana (2018 → 2017: hasta 7× menos que las reglas, 4–170× menos que el modelo sin
  restricciones o KitNET) y se dice que en la otra las reglas dejan menos daño con 3× sus falsas
  alarmas (commit 03aee96 del paper).
- **Fronteras sobre víctimas con tráfico:** se hacen. `frontier_exp --busy` apunta cada campaña al
  destino con más flujos benignos en el puerto atacado ese día, no implicado en ataques (sin
  escaneos). Lanzado en los dos sentidos para `proteus` y `proteus_cert` (`busy.sh`).
- **CTU-SME-11:** abandonado; el paper solo lo cita como ejemplo de registros Zeek.
- **Diagnóstico pendiente del resultado mixto de 17 → 18:** `alarms.py` sobre 2018 (`diag18.sh`)
  para ver qué subnúcleo y qué entidades dan las falsas alarmas del detector de todas las escalas.
- Sigue en manos de los autores: la declaración de uso de IA.

## 6.45 Fronteras sobre una víctima con tráfico, 2018 → 2017 (2026-11-15, 11:30)

`frontier_exp --busy`: misma campaña contra el destino con más flujos benignos en el puerto atacado
(servidor web externo 178.255.83.1:80, 227 flujos benignos/h; FTP 185.170.48.239:21, 15/h). Flujos/h:

| Ataque (real) | Proteus: inactiva → con tráfico | Proteus-cert plana | Proteus-cert certificada |
|---|---|---|---|
| Hulk (518.525) | 1.407 → 22.171 | 5.427 → 11.135 | 11.291 → 11.272 |
| GoldenEye (44.976) | 1.497 → 22.066 | 5.441 → 7.931 | 8.139 → 8.022 |
| Slowloris (10.461) | 811 → 12.200 (pasa) | 3.996 → 4.014 | 6.002 → 5.829 |
| Slowhttptest (5.107) | 629 → 11.542 (pasa) | 3.756 → 3.877 | 5.476 → 5.595 |
| LOIC-HTTP (290.167) | 2.174 → 75.717 | 9.376 → 19.091 | 28.728 → 28.860 |
| FTP (3.910) | 432 → 10 | 17.165 → 1.358 | 19.786 → 6.238 |

- La frontera plana de Proteus (exceso sobre el historial) sube un orden de magnitud con solo 227
  flujos/h de carga. La de Proteus-cert (subnúcleos brutos y de pares) casi no se mueve.
- En el paper: cierra el último `\todo` experimental. 17 → 18 sigue corriendo.
- OOM n.º 10 (11:06): `alarms.py` sobre los 10 días de 2018 (28 GB). Relanzado con dos días.

## 6.46 Diagnóstico de alarmas en 2018 y variantes de alerta en 2018 → 2017 (2026-11-15, 14:30)

**Diagnóstico** (`alarms.py`, miércoles 14 y jueves 15 de feb. de 2018; calibración en muestra y solo
dos días, así que es orientativo):
- Las alarmas "benignas" de `proteus` son, sobre todo, **orígenes externos contra RDP (3389)**:
  185.222.211.106 y 194.28.112.179 con RST a 788–1.600 veces su nivel normal, y pares
  origen→host:3389 con miles de flujos. Son atacantes reales de Internet contra la red en AWS,
  etiquetados como benignos (igual que en CTU-13).
- El resto: subidas grandes a S3 (52.219.x:443), una alarma por destino.
- `proteus_cert`: casi todo es el servidor DNS interno 172.31.0.2 (90 alarmas, subnúcleo de
  destino bruto, flujos sin respuesta).

**Variantes en 2018 → 2017** (`__v3_variants`, FPR 10⁻³; vol./escaneo, todas, alarmas/h):

| | base | +ent (suelo por destino) | +k2n5 (persistencia) | ambas |
|---|---|---|---|---|
| `proteus` | 11/11, 13/21, 2,72 | 9/11, 9/21, 2,32 | 9/11, 11/21, 1,88 | 7/11, 7/21, 1,69 |
| `proteus_cert` | 9/11, 10/21, 4,35 | 9/11, 10/21, 1,99 | 7/11, 7/21, 3,39 | 7/11, 7/21, 1,13 |
| `proteus_cert@cert` | 8/11, 9/21, 1,48 | 7/11, 8/21, 0,46 | 7/11, 7/21, 1,33 | 6/11, 6/21, 0,30 |
| reglas | 9/11, 14/21, 36,3 | 9/11, 13/21, 27,7 | 7/11, 12/21, 30,2 | 7/11, 11/21, 22,7 |

- La persistencia no compensa: pierde escaneos y campañas cortas y sube el TTD a ~51 s.
- El suelo por destino ayuda a `proteus_cert` (4,35 → 1,99 alarmas/h sin perder campañas;
  certificadas 1,48 → 0,46 perdiendo una). A `proteus` le quita dos escaneos y cuatro campañas.
- Pendiente 17 → 18, que es donde importa.

## 6.47 Fronteras sobre un servicio con carga, 2017 → 2018 (2026-11-15, 15:20)

Destino: 169.254.169.254:80 (metadatos de la instancia), ~31.000 flujos benignos/h. SSH: 172.31.65.76:22
(269/h). Flujos/h, víctima original → con carga:

| Ataque (real) | Proteus | Proteus-cert plana | Proteus-cert certificada |
|---|---|---|---|
| Hulk (8,38 M) | 14.114 → 16.876 | 20.817 → 27.697 | 28.011 → 28.033 |
| GoldenEye (38.445) | 5.523 → 11.512 | 14.819 → 19.446 | 16.301 → 19.696 |
| Slowloris (12.184) | 2.223 → 3.374 | 3.470 → 3.374 | 5.058 → 4.810 |
| LOIC-HTTP (275.992) | 1.317 → sin cota (> 360.000) | 102.979 → sin cota | 188.314 → sin cota |
| HOIC (1,19 M) | 179.605 → sin cota | 72.618 → 52.353 | 126.517 → 89.954 |
| SSH (62.340) | 11.963 → 30.268 | 11.963 → 20.716 | 12.105 → 31.178 |

- DoS de un solo origen: la frontera sube como mucho 2× y sigue bajo la campaña real.
- DDoS: con 31.000 flujos/h de carga, LOIC-HTTP pasa a su ritmo real en ambos detectores; HOIC solo
  lo acota Proteus-cert. Añadido al paper como límite.

## 6.48 Variantes de alerta en 2017 → 2018 y cierre (2026-11-15, 17:20)

FPR 10⁻³ (vol./escaneo, todas, alarmas/h), base → suelo por destino (+ent):

| | base | +ent |
|---|---|---|
| `proteus` | 13/13, 14/25, 16,0 | 13/13, 14/25, 11,8 (recall 0,78 → 0,66) |
| `proteus_cert` | 13/13, 14/25, 42,0 | 11/13, 12/25, 3,1 |
| `proteus_cert@cert` | 6/13, 7/25, 17,0 | 5/13, 6/25, 0,22 |
| reglas | 13/13, 15/25, 45,5 | 9/13, 10/25, 18,1 |

- El suelo recorta mucho las alarmas del detector certificado (17,0 → 0,22 por una campaña), pero la
  calibración por presupuesto ya daba algo mejor (`proteus_cert` 13/13 a 0,40/h, §6.34).
- En 18 → 17 le cuesta a `proteus` dos escaneos (§6.46). No sustituye a nada; va al paper como
  variante probada.
- La persistencia queda descartada.
- Paper: una frase sobre los atacantes RDP sin etiquetar de 2018 y las dos variantes (evaluación,
  tras el párrafo de presupuestos).
- Con esto no quedan experimentos en cola ni `\todo` en el paper.

## 6.49 Revisión 2 (`r2`), 2018 → 2017: el lunes cambia las falsas alarmas (2026-11-15, 20:00)

`r2` = líneas base corregidas (minutos enmascarados descontados), los cinco días de prueba en las
alarmas (antes el lunes, sin ataques, no contaba), alertas atribuidas al subnúcleo que dispara.
FPR 10⁻³, umbral local; alarmas/h por (destino, minuto) y por entidad alertada y ventana de 10 min:

| Detector | Campañas (vol./escaneo) | Alarmas/h r2 | v3 | Por entidad r2 | v3 |
|---|---|---|---|---|---|
| `proteus` | 13/21 (11/11) | **63,1** | 2,7 | 1,75 | 1,15 |
| `proteus_cert` | 10/21 (9/11) | **191,2** | 4,4 | 1,87 | 1,51 |
| `proteus_cert@cert` | 9/21 (8/11) | **167,6** | 1,5 | 0,86 | 0,43 |
| `proteus_cert_r` (nuevo) | 13/21 (9/11) | 14,5 | — | 3,05 | — |
| `proteus_cert_r@certr` | 11/21 (8/11) | 5,2 | — | 1,73 | — |
| `proteus_cert@certr` | 1/21 | 0,0 | 0,0 | 0,0 | 0,0 |
| `proteus_free` | 15/21 (8/11) | 9,5 | 5,7 | 4,43 | 4,53 |
| `core_mono_dst_x` | 9/21 (9/11) | 3,4 | 4,1 | 1,08 | 1,26 |
| reglas de tasa | 14/21 (9/11) | 33,6 | 36,1 | 8,95 | 9,36 |
| `flow_clf` | 14/21 (11/11) | 33,3 | 31,1 | 23,1 | — |

- **La detección no cambia** (mismas campañas): el efecto del error de las líneas base es pequeño.
- **Las alarmas por (destino, minuto) de Proteus pasan de 2,7 a 63,1/h**, y todo viene del lunes:
  303 alarmas/h (FPR 1,6 %); martes a viernes, 0,4–9,3. Proteus-cert: 937/h el lunes.
- Causa (`alarms.py`): un único host interno, 192.168.10.25, alertado por el subnúcleo de **origen**
  (134 destinos sin respuesta en 443/53/80, 3× su nivel normal a 1 h). Es una entidad, pero cuenta
  una alarma por cada destino y minuto. Por entidad alertada el lunes son 3,3 alarmas/h.
- Con la calibración dejando el día fuera, el lunes es además el día menos parecido a los demás.
- **Consecuencia para el paper:** el titular "2,7 falsas alarmas/h, trece veces menos que las reglas"
  no se sostiene con los cinco días. En la métrica por (destino, minuto) Proteus queda peor que las
  reglas (63 frente a 34). Por entidad alertada sigue mejor: 1,75 frente a 8,95 (5×), y frente al
  clasificador por flujo, 13×. La métrica principal debe ser la de entidad alertada (una alerta
  sobre un origen que sondea 134 destinos es una alarma para el analista), dando las dos y el
  desglose por día.
- **Resistente a reutilización (`proteus_cert_r`):** funciona. Sus alertas certificadas, también
  frente a reutilización, cubren 11/21 campañas (8/11 volumétricos y escaneos) a 5,2 alarmas/h
  (1,7 por entidad), frente a 1/21 del detector anterior. A 10⁻⁴ caen a 4/21 (2/11).
- Criterio estricto: apenas cambia (Proteus 12/21 en vez de 13; el clasificador por flujo baja de
  14 a 11).

## 6.50 Líneas base clásicas en CIC-IDS-2017 (2026-11-15, 22:30)

`proteus classic` (sin red de entrenamiento; umbral = cuantil del benigno limpio de los otros días).
Conexión fallida = sin respuesta o rechazada (RST). FPR 10⁻³:

| Detector | Vol./escaneo | Escaneos | Alarmas/h (destino-minuto) | Por entidad |
|---|---|---|---|---|
| TRW por host (Jung et al.) | 1/11 | 1/6 | 7,0 | 0,59 |
| TRW por servicio | 3/11 | 3/6 (recall 0,42) | 26,4 | 0,44 |
| CUSUM de flujos fallidos (Wang et al., adaptado) | 5/11 | 4/6 (recall 0,67) | 12,9 | 2,92 |
| `proteus` (r2) | 11/11 | 6/6 (recall 0,82) | 63,1 | 1,75 |

- El TRW original (por host) no ve los escaneos de CIC-IDS-2017, que son verticales (un host, muchos
  puertos); la variante por servicio ve la mitad.
- El CUSUM no ve los DoS de aplicación (Hulk, GoldenEye), que completan sus conexiones.
- Ninguno alcanza a Proteus en detección. En alarmas por entidad el TRW es más bajo (0,4–0,6 frente
  a 1,75).

## 6.51 Revisión 2 (`r2`), 2017 → 2018, KitNET y líneas base clásicas en 2018 (2026-11-15, 23:30)

FPR 10⁻³, umbral local, diez días de prueba (alarmas/h por destino-minuto y por entidad alertada):

| Detector | Campañas (vol./escaneo) | Alarmas/h r2 (v3) | Por entidad r2 (v3) |
|---|---|---|---|
| `proteus` | 14/25 (13/13) | 24,9 (16,0) | **1,62** (6,76) |
| `proteus_cert` | 14/25 (13/13) | 42,1 (42,0) | 3,68 (7,32) |
| `proteus_cert@cert` | 7/25 (6/13) | 16,8 (17,0) | 2,22 (2,26) |
| `proteus_sys` (Proteus ∪ Proteus-cert) | 14/25 (13/13) | 60,9 | 5,04 |
| `proteus_cert_r` | 14/25 (12/13) | 48,8 | 7,28 |
| `proteus_cert_r@certr` | 8/25 (6/13) | 32,0 | 6,13 |
| `proteus_cert@certr` | 0/25 | 0 | 0 |
| `proteus_free` | 17/25 (13/13) | 58,2 (62,9) | 17,8 (24,8) |
| `core_free_dst_b` | 16/25 (13/13) | 135,8 (124,6) | 32,4 |
| reglas de tasa | 15/25 (13/13) | 45,3 (45,5) | 10,8 (13,5) |
| `flow_clf` | 9/25 (9/13) | 273,7 | 140,1 |

- **Detección sin cambios** respecto a v3; el efecto del error de las líneas base es pequeño aquí
  también (las alarmas de Proteus suben de 16,0 a 24,9 por destino-minuto).
- **Por entidad alertada, Proteus baja de 6,76 a 1,62**: antes sus alertas del subnúcleo de origen
  se contaban una vez por destino. Frente a las reglas: 1,62 contra 10,8 (6,6×). En los dos sentidos
  Proteus da 5–7 veces menos alarmas por entidad que las reglas.
- **Sistema desplegado** (`proteus_sys`): mismas campañas, 60,9 alarmas/h (5,0 por entidad); a 10⁻⁴,
  16,5 (0,95 por entidad) con las 13 campañas y criterio estricto 13/13.
- **Resistente a reutilización:** certificadas también frente a reutilización, 8/25 (6/13) a 32/h
  (6,1 por entidad); antes 0/25.
- Criterio estricto: a 10⁻⁴ Proteus conserva 13/13 con "algún flujo" pero solo 9/13 estrictas; el
  sistema desplegado, 13/13 estrictas.

**KitNET 18 → 17 (r2):** 11/21 (9/11), 10,4 alarmas/h, 3,98 por entidad (v3: 9/11 a 11,8/h).

**Líneas base clásicas en CSE-CIC-IDS-2018** (FPR 10⁻³): TRW por host 0/13 (274 alarmas/h); TRW por
servicio 6/13 (los 6 escaneos, recall 0,14) a 250/h; CUSUM 6/13 (los 6 escaneos) a 43,5/h y 5,8 por
entidad. Ninguno detecta los DoS/DDoS de aplicación.

**Fallo corregido (commit 3e4e35f):** los umbrales por presupuesto de los detectores locales se
evaluaban sin el lado de la alerta y agrupaban por destino. En 18 → 17 Proteus salía con 35 alarmas
por entidad/h a presupuesto 0,5 (el host del lunes contado por cada destino). Ahora el presupuesto
y las alarmas por entidad usan la entidad alertada. 18 → 17 se reevalúa como `r2b`; 17 → 18 habrá que
repetirlo con `--reuse` para los presupuestos.

**`r2b`, 18 → 17 a igual presupuesto de alarmas por entidad** (volumétricos y escaneos, alarmas por
entidad/h realizadas):

| Presupuesto | `proteus` | `proteus_cert_r` | reglas | `core_free_dst_b` | `proteus_free` |
|---|---|---|---|---|---|
| 0,5/h | 11/11 a 1,0 | 8/11 a 0,4 | 9/11 a 5,3 | 7/11 a 1,3 | 8/11 a 0,7 |
| 3/h | 11/11 a 2,6 | 9/11 a 1,9 | 9/11 a 5,9 | 8/11 a 2,9 | 8/11 a 2,8 |
| 10/h | 11/11 a 7,0 | 9/11 a 3,7 | 9/11 a 9,4 | 9/11 a 7,5 | 8/11 a 7,1 |

Con el presupuesto por entidad alertada, Proteus es el único con las 11 campañas a cualquier
presupuesto. Las reglas no bajan de 5,3 alarmas por entidad/h. 17 → 18 en cola (`r2b.sh`).

## 6.52 `r2b`, 2017 → 2018 a igual presupuesto de alarmas por entidad (2026-11-16, 02:40)

Volumétricos y escaneos detectados con el criterio estricto (de 13) y alarmas por entidad/h
realizadas, con el presupuesto contado por entidad alertada:

| Presupuesto | `proteus` | `proteus_cert` | `proteus_sys` | reglas | `core_free_dst_b` | `proteus_free` |
|---|---|---|---|---|---|---|
| 0,5/h | 8 a 0,20 | 13 a 0,12 | 13 a 0,27 | 13 a 1,31 | 13 a 0,56 | 9 a 0,28 |
| 1/h | 11 a 0,42 | 13 a 0,15 | 13 a 0,52 | 13 a 1,93 | 13 a 0,85 | 9 a 0,29 |
| 3/h | 13 a 1,02 | 13 a 0,20 | 13 a 1,09 | 13 a 2,50 | 13 a 1,73 | 9 a 0,30 |
| 10/h | 13 a 2,18 | 13 a 4,23 | 13 a 5,70 | 13 a 4,97 | 13 a 3,26 | 12 a 5,82 |

- Con las alarmas contadas por entidad alertada, **el resultado mixto de v3 desaparece**: el sistema
  desplegado (`proteus_sys`) detecta las 13 a 0,27 alarmas por entidad/h; las reglas no bajan de
  1,31 (5×) y el núcleo sin restricciones necesita 0,56 (2×).
- `proteus` solo llega a las 13 estrictas a 1,02 (parecido a las reglas); el que rinde con pocas
  alarmas es el detector de 10 min. Coherente con v3: en esta red las escalas largas cuestan.
- `proteus_free` (cuatro subnúcleos sin restricciones) es el peor a presupuestos bajos: 9/13.
- Certificadas de `proteus_cert`: 6/13 a 0,05 alarmas por entidad/h. Resistente a reutilización:
  6/13 certificadas frente a reutilización a 0,07.
- Junto con 18 → 17 (§6.51: Proteus 11/11 a 1,0; reglas 9/11 a 5,3): **en los dos sentidos el sistema
  detecta todas las campañas volumétricas y escaneos con 5× menos alarmas por entidad que las
  reglas de tasa.** Este pasa a ser el resultado central de detección.

## 6.53 Detección de cada campaña sin los demás ataques del día (2026-11-16, 06:15)

`proteus isolated` (18 → 17, r2, FPR 10⁻³): cada campaña se puntúa sobre el tráfico de su día sin
los flujos de ningún otro ataque (objeción del revisor: evidencia arrastrada entre campañas).

| Detector | Vol./escaneo en el día real | Aisladas | Recall medio | TTD mediano |
|---|---|---|---|---|
| `proteus` | 11/11 | 11/11 | 0,90 → 0,89 | 5,0 → 7,5 s |
| `proteus_cert` | 9/11 | 9/11 | 0,81 → 0,80 | 1,1 → 1,1 s |
| `proteus_cert_r` | 9/11 (12/21) | 9/11 (11/21) | 0,80 → 0,74 | 1,2 → 1,6 s |

- La detección no depende del arrastre. Sí el tiempo de detección de las campañas que siguen a
  otra en el mismo servidor: GoldenEye 5 → 64 s, Slowhttptest 10 → 74 s, LOIC-HTTP 10 → 15 s.
- En el paper (párrafo "Carry-over between campaigns"). 2018 en cola (`isolated18.sh`).

## 6.54 Atacante adaptativo con reutilización, ráfagas y reparto, 2018 → 2017 (2026-11-16, 06:50)

`adaptive` con los planes estructurados (20 peticiones por conexión, ráfagas, ambas; aparte, lo mismo
repartido entre 100 orígenes) sobre los modelos r2. Daño = ritmo más alto (peticiones/h) sin alerta
propia, FPR 10⁻³. Las uniones se calculan con la escalera (mismo plan y ritmo para todos sus miembros).

| Ataque (real) | Proteus | Sistema de 2 | **Sistema de 3** | Reglas | Sin restr. (4 subnúcleos) | Sin restr. (destino) | KitNET |
|---|---|---|---|---|---|---|---|
| LOIC-HTTP (290.167) | 28.995 | 28.995 | **28.995** | 55.122 | 4.220 | 199.218 | 199.218 |
| Escaneo vie. (107.850) | 323 | 323 | **170** | 1.168 | 4.220 | 15.252 | 2.220 |
| Escaneo jue. (10.418) | 7 | 7 | **7** | 47 | 323 | 170 | 1.168 |
| FTP (3.910) | 8.023 | 8.023 | **8.023** | 15.252 | 15.252 | 720.000 | 28.995 |
| SSH (1.541) | 15.252 | 4.220 | **2.220** | 1.168 | 2.220 | 720.000 | 199.218 |
| GoldenEye (44.976) | 15.252 | 15.252 | **4.220** | 2.220 | 2.220 | 199.218 | 104.792 |
| Hulk (518.525) | 28.995 | 28.995 | **4.220** | 4.220 | 2.220 | 199.218 | 720.000 |
| Slowhttptest (5.107) | 15.252 | 8.023 | **2.220** | 1.168 | 2.220 | 199.218 | 55.122 |
| Slowloris (10.461) | 15.252 | 8.023 | **2.220** | 1.168 | 1.168 | 199.218 | 55.122 |

Sistema de 2 = Proteus ∪ Proteus-cert; de 3 = además `proteus_cert_r` (resistente a reutilización).

- **La reutilización de conexiones rompe a Proteus solo**: su daño sube de 0,6–1,2 k a 15–29 k
  peticiones/h (el mejor plan contra él es siempre `reuse`); Slowloris, Slowhttptest, FTP y SSH pasan a
  su ritmo real. El revisor tenía razón: el titular "el menor daño en los nueve ataques" dependía de
  un atacante que no reutilizaba conexiones.
- **El detector resistente a reutilización lo arregla**: contra `proteus_cert_r` el mejor plan es el
  ataque simple, y el sistema de tres baja a 2–4 k en los DoS.
- **Frente a las reglas de tasa el resultado es parejo**: el sistema gana en LOIC-HTTP, los dos
  escaneos y FTP (1,9–7×); empata en Hulk; las reglas ganan en SSH, GoldenEye, Slowhttptest y
  Slowloris por un escalón de la rejilla (1,9×). Las reglas son las únicas que alertan el SSH a su
  ritmo real.
- Frente a los modelos sin garantía: el núcleo de destino sin restricciones y KitNET dejan pasar
  50–350× más. Los cuatro subnúcleos sin restricciones aguantan la reutilización, pero con reparto
  entre 100 orígenes caen (escaneo del jueves 104.792; DoS 29 k), y el sistema no se mueve.
- Certificado también frente a reutilización (`proteus_cert_r`, frontera certificada): Hulk 8.023,
  GoldenEye 4.220, Slowloris y Slowhttptest 2.220 (todas bajo su campaña real), LOIC-HTTP 199.218,
  escaneos 323; SSH 2.220 y FTP 28.995 quedan por encima de la campaña real.
- Alarmas del sistema de 3: 4,17 por entidad/h a FPR 10⁻³ (reglas 8,97); a presupuesto 0,5, 11/11 a
  1,40 (reglas 9/11 a 5,3). En 17 → 18: 13/13 a 0,30 por entidad/h a presupuesto 0,5.

**Consecuencias para el paper** (fase D):
1. El sistema desplegado pasa a ser de tres detectores, y las tablas y fronteras se dan para él.
2. El resumen ya no puede decir "el menor daño en los nueve ataques, hasta 7× menos que las reglas".
   Lo que se sostiene: daño parejo al de las reglas de tasa con 2–4× menos falsas alarmas por entidad
   (5× a igual presupuesto), 50–350× menos daño que los modelos sin garantía, y un certificado que
   cubre también la reutilización.
3. Decisión de método: no se añaden más detectores a la vista de estos resultados (p. ej. subnúcleos
   resistentes a reutilización en todas las escalas), para no ajustar el diseño sobre los datos de
   prueba.

## 6.55 Comprobación del certificado con los detectores r2 y reglas con selección (2026-11-16, 07:45)

**`free_ops` sobre r2 (18 → 17)**, ventana de 10 min por campaña, 20 combinaciones aleatorias de
operaciones gratuitas y reutilización con 5, 20 y 100 peticiones por conexión, para `proteus`,
`proteus_cert` y `proteus_cert_r`:
- 0 violaciones exactas (ninguna puntuación original baja sin re-temporizar) y 0 alertas
  certificadas perdidas, en los tres.
- 0 violaciones del certificado de reutilización: las alertas de `proteus_cert_r` certificadas
  frente a reutilización (GoldenEye, Hulk, Slowhttptest, Slowloris, un escaneo) sobreviven a las tres
  intensidades de reutilización; la víctima sigue alertada en el 100 % de las variantes.
- `proteus_cert` certifica en esa ventana los cinco DoS/DDoS y un escaneo; `proteus` (todas las
  escalas) solo Hulk.

**Reglas de tasa con selección (`rate_rules_sel`), 18 → 17.** Rasgos elegidos en 2018: los 10 son
excesos de flujos y paquetes hacia el destino (`dhost`/`dsvc` `flows`/`fpkts` `__x`), casi todos de
escala corta.

| | Vol./escaneo | Alarmas por entidad/h |
|---|---|---|
| FPR 10⁻³ | 9/11 | 1,93 |
| FPR 10⁻⁴ | 9/11 | 0,44 |
| Presupuesto 0,5 | 9/11 | 0,24 |
| Presupuesto 10 | 9/11 | 8,50 |
| Certificadas, 10⁻³ | 6/11 | 0,21 |

- Es una línea base fuerte: con diez rasgos elegidos con etiquetas baja las alarmas de las reglas de
  8,97 a 1,93 por entidad/h, al nivel de Proteus (1,75). **La ventaja de Proteus en alarmas frente a
  unas reglas bien elegidas desaparece**; lo que conserva es la cobertura: 11/11 frente a 9/11 (las
  reglas con selección no pasan de 9 a ningún presupuesto).
- Sus rasgos son conteos por conexión de escala corta, justo lo que la reutilización baja: hay que
  medir su daño frente al atacante adaptativo (`adaptsel.sh`, en cola) antes de concluir.

## 6.56 El sistema de tres detectores a FPR fija y a presupuesto; saturación de Proteus-cert-R en 2018 (2026-11-16, 11:40)

Al unificar «el sistema» como Proteus ∪ Proteus-cert ∪ Proteus-cert-R (`proteus_sys_r`) en tablas,
figura y texto, con las ejecuciones `r2c` (18 → 17) y `r2b` (17 → 18):

| Punto de operación | 18 → 17 | 17 → 18 |
|---|---|---|
| Sistema, cada miembro a FPR 10⁻³ | 11/11 a 4,17 alarmas por entidad/h | 13/13 a 11,88 |
| Sistema, cada miembro a FPR 10⁻⁴ | 9/11 a 0,83 | 13/13 a 7,86 |
| Sistema, presupuesto 0,5 por miembro | 11/11 a 1,40 | 13/13 a 0,30 |
| Sistema de dos (sin cert-R), presupuesto 0,5 | 11/11 a 1,08 | 13/13 a 0,27 |
| Proteus solo, presupuesto | 11/11 a 1,01 | 13/13 a 1,02 |
| Reglas de tasa, presupuesto | 9/11, mínimo 5,28 | 13/13 a 1,31 |

- A FPR fija la unión suma las alarmas de sus miembros; el paper pasa a decir que el sistema se opera
  a presupuesto. En 18 → 17 Proteus solo es más barato que cualquier unión; el tercer detector cuesta
  0,3 alarmas por entidad/h y solo se justifica por la reutilización de conexiones (§6.54).
- **Proteus-cert-R satura en 2018.** En 17 → 18 da exactamente lo mismo con el umbral local a 10⁻³ y
  a 10⁻⁴: FPR benigno realizado 0,29 %, 7,28 alarmas por entidad/h (6,13 las certificadas), y 0,076 a
  cualquier presupuesto. Más del 0,1 % de los flujos benignos empata en la puntuación máxima de algún
  subnúcleo, así que el cuantil no puede bajar de ahí y el umbral cae en el empate. Es el mismo
  mecanismo que en CTU-13, donde se usa `--exclude-saturated 1e-3`. Aplicar esa regla solo en CTU-13
  es ajustar por dataset; lo coherente es aplicarla en todas las ejecuciones o en ninguna.
  Diagnóstico en cola (`sat_1817`, `sat_1718`, etiqueta `r2_sat`): mismas ejecuciones con la
  exclusión. Si solo cambia cert-R en 2018, se adopta como regla general y se declara.
- De paso: `tables curves` archivaba las ejecuciones 17 → 18 en el panel 18 → 17 (corregido, commit
  25763c3); la figura nunca se había compilado, así que no afectó a ninguna cifra publicada.

## 6.57 Apollon entre redes, 2018 → 2017 (2026-11-16, 13:20)

`ap_1817` (etiqueta `r2_apollon`, 17 min en paralelo con el adaptativo, con tope de memoria): Apollon
(`ApollonFlow`) y el clasificador por flujo sobre las mismas 83 estadísticas por flujo.

| Detector | Campañas volumétricas y escaneos (criterio estricto) | Alarmas por entidad/h | A presupuesto |
|---|---|---|---|
| Apollon | 7/11 (los 6 escaneos y Slowloris; recall 0,26 y 0,04) | 21,3 (igual a 10⁻³ y 10⁻⁴) | ninguna alerta |
| Clasificador por flujo | 10/11 a 10⁻³; 6/11 a 10⁻⁴ | 23,1 y 6,7 | 6/11 a 0,57–2,67 |
| Proteus | 11/11 | 1,75 | 11/11 a 1,0 |

- La puntuación de Apollon (probabilidad del miembro elegido por el bandit) empata en el 0,6 % de los
  flujos benignos de la red nueva: el umbral local cae en el empate, da lo mismo a los dos FPR
  objetivo y a presupuesto de alarmas no queda ninguna alerta. Mismo mecanismo de saturación que en
  §6.56.
- Fuera de escaneos y Slowloris no detecta nada (ni Hulk, GoldenEye o LOIC-HTTP).
- El paper lo cuenta como «se comporta como el clasificador por flujo» (commit del paper). Falta
  17 → 18 (`ap_1718`, bajo el cerrojo) y su fila en la comparación conjunta.

## 6.58 Exclusión de subnúcleos saturados en 2018 → 2017: no cambia nada (2026-11-16, 13:30)

`sat_1817` (etiqueta `r2_sat`): las mismas puntuaciones de `r2c` para Proteus, Proteus-cert y
Proteus-cert-R con `--exclude-saturated 1e-3`.

- Con umbrales locales a 10⁻³ y 10⁻⁴, detección y alarmas por entidad son **idénticas** a `r2c` en
  los tres detectores, en sus alertas certificadas y en las dos uniones: ningún subnúcleo satura en
  la red pequeña.
- A presupuesto la detección tampoco cambia; las alarmas realizadas suben algo en los presupuestos
  altos (Proteus a presupuesto 10: 6,58 → 8,14; sistema de tres: 9,48 → 11,38) y nada en 0,5.
- Falta `sat_1718`, que es donde Proteus-cert-R satura (§6.56). Si allí la regla arregla cert-R sin
  tocar lo demás, se adopta para todas las ejecuciones.

## 6.59 Temporizador de recálculo con r2, 2018 → 2017 (2026-11-16, 14:00)

`timer10_1817` y `timer60_1817` (`PROTEUS_TIMER_S`, holgura (2Δ + δ)/τ), sobre los modelos de `r2`.

| δ | Cert.: campañas, recall medio de flujos, alarmas por entidad/h | Cert.-R |
|---|---|---|
| 0 s | 8/11, 0,863, 0,865 | 8/11, 0,712, 1,735 |
| 10 s | 8/11, 0,863, 0,840 | 8/11, 0,711, 1,735 |
| 60 s | 8/11, 0,860, 0,815 | 8/11, 0,707, 1,662 |

Las alertas sin certificar no cambian (Proteus 11/11 a 1,75; Proteus-cert 9/11 a 1,88). Como en v3,
el temporizador no cuesta campañas certificadas. Llevado al apéndice del paper.
