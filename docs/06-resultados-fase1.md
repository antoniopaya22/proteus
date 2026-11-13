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
