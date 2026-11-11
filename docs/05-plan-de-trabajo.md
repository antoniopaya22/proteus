# 5. Plan de trabajo

Fecha: 2026-11-10 (segunda versión, alineada con el diseño de
`04-diseno-proteus.md`: evidencia conservada, núcleo monótono, frontera de daño y
cáscara con realimentación).

Las duraciones son estimaciones mías para una persona a tiempo parcial; no hay datos
detrás. Total aproximado: 26–28 semanas.

## 5.1 Resumen de fases

| Fase | Contenido | Semanas | Sale de aquí |
|---|---|---|---|
| 0 | Infraestructura y datos | 3 | Registros de flujo etiquetados y entorno reproducible |
| 1 | Prototipo del núcleo (comprobación temprana de H1) | 2 | Decisión de seguir o replantear |
| 2 | Apollon v1 y selección aleatoria | 3 | Sección "Revisiting Apollon" |
| 3 | Modelo de transformaciones y marco de ataques | 4 | Ataques en espacio de tráfico contra cualquier detector |
| 4 | Núcleo completo, garantía y frontera de daño | 4 | Núcleo certificado |
| 5 | Cáscara, realimentación y ataques adaptativos | 4 | Proteus completo |
| 6 | Evaluación completa | 4 | Todas las tablas y figuras |
| 7 | Redacción y artefacto | 4 | Paper enviado y código publicado |

El orden pone primero lo que puede tumbar el enfoque: la fase 1 comprueba H1 con el
mínimo código posible, antes de invertir en ataques o en reproducir v1.

### Estado a 2026-11-11

| Fase | Estado | Pendiente |
|---|---|---|
| 0 | Hecha para CIC-17/18 (corregidos), CTU-13, UNSW-NB15. En curso: UGR'16 (espejo HF), CIC-DDoS-2019, CTU-SME-11 (Zeek). Pcaps de CIC-17 bajando | Pcaps para ataques en espacio de tráfico |
| 1 | Hecha. H1 se cumple para DoS/DDoS y escaneos entre redes | — |
| 2 | Corrección de v1 publicada (PR #1). Ataques directos ZOO/HSJA en marcha (`aml_feature`), con recuento de consultas | Resultados y tabla |
| 3 | Operadores gratuitos y costosos sobre registros de flujo (`attacks/operators.py`) | Ataques sobre pcaps (NetMasquerade) |
| 4 | Núcleos rápido y certificado, línea base por entidad, frontera (destino y escaneo horizontal). Evidencia v2 con flujos sin respuesta en prueba | Comprobación empírica de H3 en cola (`free_ops`); fronteras en víctimas ocupadas |
| 5 | Calibración del contador de realimentación (`feedback`) en cola | Implementarlo en el núcleo y medir H5; escalado |
| 6 | Parcial (docs/06) | UGR'16, DDoS-2019, CTU-SME-11; baselines Kitsune/HyperVision/BARS/CertTA |
| 7 | Borrador: introducción, trabajo relacionado, modelo de amenaza, diseño, Apollon, evaluación parcial | Discusión, conclusión, figuras |

## 5.2 Fase 0 — Infraestructura y datos

**Objetivo:** registros de flujo con marca de tiempo y etiqueta fiables, y
experimentos repetibles con un comando.

Tareas:

1. Entorno: git, `uv`, dependencias fijadas, `ruff`, `pytest`.
2. Datos:
   - CIC-IDS-2017 con etiquetas corregidas (Engelen et al. 2021, Liu et al. 2022;
     alternativa LYCOS-IDS2017). Hacen falta los pcap para la fase 3.
   - CSE-CIC-IDS-2018 (más hosts; subconjunto de días).
   - UNSW-NB15.
   - UGR'16: NetFlow real de un ISP durante meses. Sirve para la línea base y las
     escalas largas. Sus etiquetas son débiles; se usa sobre todo como tráfico de
     fondo.
   - CIC-IoT-2023, opcional.
3. `proteus.datasets`:
   - esquema común de registro de flujo (tiempos, 5-tupla, paquetes y bytes por
     sentido, flags, estado de la conexión);
   - lector de pcap a registros de flujo y a secuencias de paquetes (NFStream o
     extractor propio);
   - unión con etiquetas y validación contra las cifras publicadas.
4. Particiones temporales: entrenar con los primeros días, probar con los
   siguientes.
5. Definir las unidades de evaluación:
   - **ventana de entidad:** maliciosa si contiene actividad de ataque de esa
     entidad;
   - **campaña:** conjunto de flujos de un mismo ataque, con inicio y fin.
6. Registro de experimentos: configuración, semilla, versión del código y métricas
   en `experiments/outputs/`.

Entregables: datos en Parquet e informe breve con flujos, entidades y campañas por
dataset.

Punto de decisión: si el etiquetado propio se desvía más de un 1–2% por clase de
las versiones corregidas, se usa un extractor ya validado.

## 5.3 Fase 1 — Prototipo del núcleo

**Objetivo:** saber cuanto antes si la evidencia conservada basta para detectar
(H1, H2, H6). Dos semanas, sin ataques todavía.

Tareas:

1. Contadores aditivos por servicio de destino, host de destino y host de origen,
   en tres escalas. Solo conteos.
2. Gradient boosting monótono sobre esos contadores.
3. Mismo modelo sin restricción de monotonía, y un clasificador por flujo estándar,
   como referencias.
4. Medir por clase de ataque: campañas detectadas, tiempo hasta la detección,
   falsos positivos por hora y por entidad.

Entregable: tabla por clase de ataque con núcleo monótono, núcleo sin restricción y
clasificador por flujo.

Punto de decisión (H1):

- Si el núcleo detecta la mayoría de las campañas de DoS, DDoS, escaneo y fuerza
  bruta con falsos positivos asumibles, se sigue con el plan.
- Si falla en varias de esas clases, se revisan entidades, escalas y línea base
  durante una semana más. Si sigue fallando, se vuelve al diseño de comité (está en
  el historial de este documento) o se replantea.

## 5.4 Fase 2 — Apollon v1 y selección aleatoria

**Objetivo:** la evidencia que motiva abandonar la selección aleatoria.

Tareas:

1. `proteus.baselines.apollon_v1`: variante "código" (comportamiento del repo
   público) y variante "paper" (lo que el paper describe).
2. Reproducir las tablas 2–7 del paper original, incluida su evaluación por
   transferencia.
3. Ataques directos contra v1 como caja negra: HSJA y ZOO consultando al sistema,
   versión con promediado, extracción de surrogate y reintento simple.
4. Resultado analítico: con selección de un modelo al azar y reintentos, el éxito
   del atacante tiende al del modelo más fácil de engañar. Comprobarlo con una
   mezcla sintética y con v1.
5. Curvas de éxito frente a consultas para v1, el mejor modelo único, voto y OR de
   todos los modelos.

Entregables: figura de transferencia frente a ataque directo y figura del efecto
del eslabón más débil.

Punto de decisión: si v1 resiste mejor que el OR de todos los modelos, el análisis
de la sección cambia de tono, pero el resto del plan no depende de ello.

Pendiente del autor: confirmar si el repo público es el código del paper.

## 5.5 Fase 3 — Modelo de transformaciones y marco de ataques

**Objetivo:** definir con precisión qué puede hacer el atacante y poder ejecutarlo
contra cualquier detector contando consultas, alertas y pérdida de eficacia.

Tareas:

1. Especificación escrita de cada operación de 4.3: precondiciones, efecto sobre
   el registro de flujo y coste.
2. `proteus.attacks.operators`, sobre secuencias de paquetes y sobre trazas:
   - gratuitas: relleno, inserción de paquetes, flujos señuelo, dilución con
     tráfico benigno, división de flujos, cambio de puertos, reparto entre orígenes;
   - costosas: ralentización y reducción de la actividad.
3. Medida de eficacia por clase de ataque (peticiones por segundo, intentos por
   hora, puertos por hora) para calcular el coste de las operaciones costosas.
4. Oráculo de consultas: devuelve pasa/bloquea y cuenta consultas, alertas y
   orígenes.
5. Ataques:
   - transferencia con surrogate;
   - búsqueda de etiqueta dura sobre los operadores (aleatoria, evolutiva);
   - política RL amortizada al estilo de Domico et al.;
   - NetMasquerade, si su código público es utilizable (sin comprobar).
6. Validación: regenerar el pcap de una muestra de trazas perturbadas y comprobar
   que el extractor da los mismos registros que el simulador.
7. Opcional: banco de pruebas con contenedores para una clase de ataque.

Entregables: biblioteca de ataques con tests por operador y curvas de éxito contra
un clasificador por flujo estándar.

Punto de decisión: los ataques tienen que romper el clasificador por flujo
estándar. Si no lo rompen, se revisan antes de evaluar ninguna defensa.

Limitación conocida: el simulador supone que las respuestas de la víctima no
cambian al perturbar el tráfico de ida. Se declara y se comprueba en el paso 7.

## 5.6 Fase 4 — Núcleo completo, garantía y frontera de daño

**Objetivo:** el núcleo certificado. Comprueba H2, H3 y H4.

Tareas:

1. `proteus.evidence`:
   - jerarquía completa de entidades;
   - contadores con decaimiento exponencial a varias vidas medias;
   - conteos de elementos distintos (puertos, destinos, orígenes) con estructuras
     aproximadas de memoria fija;
   - persistencia de pares.
2. Tabla de clasificación de características: solo-aumento, no controlable o
   controlable, con la justificación de cada una. Es una tabla del paper.
3. Línea base por entidad: cuantiles de la historia, actualización solo con
   periodos sin alerta y tope de crecimiento.
4. `proteus.core`: gradient boosting monótono, calibración del umbral por
   presupuesto de falsos positivos y atribución de cada alerta a contadores y
   orígenes.
5. Verificación de la garantía:
   - tests de propiedades: para trazas aleatorias y operaciones gratuitas
     aleatorias, la evidencia no baja en ninguna coordenada y la puntuación tampoco;
   - comprobación formal de la monotonía del modelo entrenado, recorriendo los
     árboles;
   - ataques de la fase 3 restringidos a operaciones gratuitas: el éxito tiene que
     ser cero.
6. `proteus.core.frontier`: cálculo de la frontera de daño por clase de ataque,
   entidad y umbral, y su validación empírica con ataques ralentizados.
7. Curva de compromiso: falsos positivos frente a frontera de daño.

Entregables:

- Tabla de características y su clasificación.
- Resultado de H3: evasiones con operaciones gratuitas (esperado: ninguna).
- Tabla de frontera de daño por clase de ataque.
- Precio de la monotonía frente al modelo sin restricciones.

Puntos de decisión:

- H3: cualquier evasión con operaciones gratuitas es un error de clasificación de
  alguna característica. Se corrige y se documenta en el paper como lección.
- H4: si la frontera de una clase queda cerca de la tasa normal del ataque, la
  garantía no sirve para esa clase y se dice.

## 5.7 Fase 5 — Cáscara, realimentación y ataques adaptativos

**Objetivo:** Proteus completo y su evaluación frente a un atacante que conoce todo
el diseño. Comprueba H5.

Tareas:

1. `proteus.shell`: clasificador por flujo de alta precisión.
2. Acoplamiento:
   - realimentación: las alertas de la cáscara como contador de la entidad;
   - escalado: umbral de la cáscara más estricto en entidades con alerta.
3. Experimento de H5: ataques por consultas contra la cáscara en modo en línea.
   Medir cuántas sondas admite el núcleo antes de alertar y cuántas necesita el
   ataque para converger.
4. Ataques adaptativos contra Proteus completo:
   - ralentización óptima: pegarse a la frontera de daño;
   - reparto entre entidades: poco a cada destino, desde muchos orígenes;
   - envenenamiento lento de la línea base;
   - sondeo de la cáscara contra otra entidad de la misma red para atacar después
     a la víctima;
   - inflado de alertas e incriminación de terceros con origen suplantado.
5. Documentar todos los intentos, también los que no funcionan.

Entregables:

- Figura: sondas necesarias para el ataque frente a sondas toleradas.
- Tabla de ataques adaptativos: qué consigue cada uno y a qué coste.

Punto de decisión (H5): si el núcleo no reacciona antes de que el ataque converja,
la realimentación pasa a ser una aportación menor y el paper se centra en la
garantía y la frontera.

## 5.8 Fase 6 — Evaluación completa

Preguntas de investigación:

| RQ | Pregunta |
|---|---|
| RQ1 | ¿Por qué la selección aleatoria de modelos no protege, y qué medía la evaluación de Apollon v1? |
| RQ2 | ¿Qué clases de ataque se detectan con garantía y a qué precio en limpio? |
| RQ3 | ¿Se cumple la garantía frente a ataques en espacio de tráfico? |
| RQ4 | ¿Cuánto daño pasa sin alerta, comparado con otras defensas? |
| RQ5 | ¿Se vuelven contraproducentes los ataques por consultas? |
| RQ6 | ¿Qué consigue un atacante adaptativo con conocimiento completo? |
| RQ7 | ¿Cuánto cuesta en latencia, memoria y falsos positivos? |

Métricas:

- **Daño sin alerta:** actividad de ataque completada antes de la primera alerta, y
  tasa máxima sostenida sin alerta. Métrica principal.
- **Éxito silencioso:** campañas que terminan sin ninguna alerta.
- **Éxito de evasión a presupuesto Q**, para comparar con la literatura.
- **Recall certificado:** fracción de campañas cuya detección está cubierta por la
  garantía.
- **En limpio:** campañas detectadas, tiempo hasta la detección, falsos positivos
  por entidad y hora; precisión y recall por flujo de la cáscara.
- **Coste:** flujos por segundo, latencia, memoria de los contadores.

Baselines:

| Baseline | Estado |
|---|---|
| Clasificador por flujo estándar | Propio |
| Mismo núcleo sin monotonía | Propio |
| Umbrales fijos por contador (detección clásica por tasa) | Propio |
| Apollon v1 | Fase 2 |
| Adversarial training en espacio de tráfico | Propio |
| Eliminación de características perturbables | Propio |
| CertTA o BARS | Hay artefacto público de CertTA; comprobar que se puede usar |
| MTD-AD | Reimplementar si no hay código; comprobar |

El baseline de umbrales fijos es importante: demuestra qué aporta aprender el
modelo frente a la detección por tasa de toda la vida.

Ablaciones: sin línea base; una sola escala; solo entidades de destino; ratios en
lugar de conteos (debe caer ante dilución); sin realimentación; sin escalado; sin
cáscara.

Rigor:

- 5 semillas como mínimo e intervalos de confianza por bootstrap.
- Particiones temporales y prueba cruzada entre datasets.
- Falsos positivos medidos también sobre UGR'16 como tráfico real de fondo.
- El atacante adaptativo se diseña con el sistema congelado.

## 5.9 Fase 7 — Redacción y artefacto

1. Redactar según el esqueleto de `paper/` (hay que actualizar las secciones al
   nuevo diseño).
2. Figuras de arquitectura y de modelo de transformaciones.
3. Enunciado formal de la garantía y su demostración.
4. Limitaciones: ataques sin rastro conservado, validez de la garantía respecto al
   modelo de transformaciones, simulador frente a tráfico real.
5. Búsqueda sistemática de trabajo previo sobre monotonía y evidencia agregada en
   NIDS, para ajustar las afirmaciones de novedad.
6. Artefacto: código, configuraciones y scripts que regeneran cada tabla y figura.

Venue: con garantía formal y frontera de daño, el objetivo natural sube a IEEE
TDSC, TIFS o una conferencia de seguridad (ACSAC, RAID, EuroS&P). Computers &
Security queda como opción segura. Decidir al acabar la fase 6.

## 5.10 Figuras y tablas previstas

| Elemento | Fase | Contenido |
|---|---|---|
| Fig. 1 | 7 | Arquitectura de Proteus |
| Fig. 2 | 2 | Apollon v1: transferencia frente a ataque directo |
| Fig. 3 | 2 | Efecto del eslabón más débil en la selección aleatoria |
| Fig. 4 | 4 | Falsos positivos frente a frontera de daño |
| Fig. 5 | 6 | Daño sin alerta frente a presupuesto del atacante, por defensa |
| Fig. 6 | 5 | Sondas necesarias frente a sondas toleradas |
| Tab. 1 | 3 | Operaciones del atacante y su coste |
| Tab. 2 | 4 | Características y su clasificación |
| Tab. 3 | 4 | Detectabilidad robusta por clase de ataque y frontera de daño |
| Tab. 4 | 6 | Resultados principales por defensa y nivel de atacante |
| Tab. 5 | 5 | Ataques adaptativos |
| Tab. 6 | 6 | Ablaciones y coste |

## 5.11 Estructura del código

| Módulo | Contenido | Fase |
|---|---|---|
| `proteus.datasets` | lectura, esquema de flujo, etiquetas, particiones, campañas | 0 |
| `proteus.evidence` | entidades, contadores con decaimiento, distintos, línea base | 1, 4 |
| `proteus.core` | núcleo monótono, calibración, atribución, verificación, frontera | 1, 4 |
| `proteus.shell` | clasificador por flujo, realimentación y escalado | 5 |
| `proteus.attacks` | operadores, oráculo, ataques, ataques adaptativos | 3, 5 |
| `proteus.baselines` | Apollon v1 y demás defensas | 2, 6 |
| `proteus.evaluation` | métricas, ejecutores, tablas y figuras | todas |

Los módulos `pool`, `selector` y `stateful` del esqueleto actual corresponden al
diseño anterior; se sustituyen por `evidence`, `core` y `shell` al empezar a
programar.

Reglas de trabajo:

- Tests de propiedades para operadores, evidencia y monotonía: son las piezas donde
  un error invalida la garantía sin que se note.
- Cada experimento se lanza desde una configuración y guarda lo necesario para
  repetirlo.
- Ninguna cifra entra en el paper si no la genera un script del repo.

## 5.12 Riesgos

| Riesgo | Probabilidad | Mitigación |
|---|---|---|
| El núcleo no detecta lo suficiente (H1) | Media | Se comprueba en la fase 1, antes de invertir en el resto |
| Demasiados falsos positivos por picos benignos (H6) | Media | Línea base por entidad, contexto no controlable, UGR'16 para medirlo con tráfico real |
| Una característica "solo-aumento" resulta reducible | Media | Tests de propiedades, ataques dirigidos y banco de pruebas |
| "Es detección por tasa de siempre" | Media | Baseline de umbrales fijos, garantía formal, frontera de daño y realimentación como diferencias medibles |
| Trabajo previo equivalente en NIDS | Baja–media | Búsqueda sistemática antes de redactar; ajustar las afirmaciones |
| Datasets con pocas entidades (CIC-IDS-2017) | Alta | CSE-CIC-IDS-2018 y UGR'16; evaluación por campaña, no por flujo |
| Coste de los ataques RL | Media | El núcleo no los necesita para su garantía; se usan contra la cáscara y los baselines |
| El simulador no refleja el tráfico real | Media | Validación con pcap regenerado y banco de pruebas |

## 5.13 Decisiones pendientes del autor

1. ¿El repo público de v1 es el código exacto del paper?
2. ¿Qué cómputo hay disponible? El núcleo es ligero; los ataques RL no.
3. Coautores y fecha objetivo de envío.
4. Venue preferido.

## 5.14 Primeros pasos

1. Inicializar git y fijar el entorno.
2. Descargar CIC-IDS-2017 corregido y CSE-CIC-IDS-2018.
3. Esquema de flujo y contadores mínimos.
4. Prototipo de la fase 1 y tabla de H1.
