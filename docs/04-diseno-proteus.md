# 4. Diseño de Proteus

Fecha: 2026-11-10 (segunda versión). Sustituye por completo al diseño anterior,
basado en un comité de modelos con selección por clave. Aquel diseño heredaba la
estrategia de Apollon (ocultar qué modelo responde). Este parte de otra pregunta:
**¿qué no puede cambiar el atacante sin que su ataque deje de funcionar?**

Lo que sigue es un diseño con hipótesis. El plan (`05-plan-de-trabajo.md`) dice con
qué experimento se comprueba cada una.

## 4.1 Por qué se abandona la estrategia de Apollon

1. **Elegir modelos al azar favorece al atacante.** Si un flujo lo decide un modelo
   al azar, basta engañar al más débil y reintentar. Arreglarlo con un comité y
   regla OR lleva, en el límite, a usar siempre todos los modelos: la aleatoriedad
   deja de aportar robustez y solo ahorra cómputo.
2. **Ocultar no es garantizar.** Frente a un atacante que conoce el diseño, la
   incertidumbre sobre qué modelo responde retrasa el ataque, pero no lo impide.
   NetMasquerade tolera un 30% de ruido en la respuesta.
3. **La causa de fondo es otra.** Los detectores caen porque se apoyan en rasgos
   *incidentales* del ataque (tamaños de paquete, tiempos, flags), que el atacante
   cambia gratis. Ningún mecanismo de selección arregla un pool cuyos modelos
   miran todos rasgos incidentales.

## 4.2 Idea central

Un ataque puede cambiar de forma, pero no puede dejar de hacer lo que necesita
hacer. Un DoS necesita volumen sobre la víctima. Un escaneo necesita tocar muchos
puertos. Una fuerza bruta necesita muchos intentos. Esa parte es **conservada**: el
atacante puede añadirle tráfico encima, pero no puede quitarla sin perder eficacia.

Proteus detecta sobre esa parte conservada, con un modelo construido de forma que
**añadir tráfico nunca pueda bajar la puntuación**. El resultado es una garantía por
construcción, no una probabilidad:

- Las transformaciones gratuitas del atacante (relleno, paquetes y flujos de
  relleno, división en más flujos, reparto entre más orígenes, dilución con tráfico
  benigno) no pueden evadir.
- La única vía de evasión es reducir la actividad del ataque, y el sistema dice
  cuánto: la **frontera de daño** es la tasa máxima de ataque que pasa sin alerta.

El nombre encaja con el mito: Proteo cambia de forma para escapar, y Menelao lo
vence sujetándolo sin soltar a través de todas las transformaciones.

## 4.3 Modelo de transformaciones del atacante

El atacante controla solo el tráfico que emiten sus hosts. Sus operaciones:

| Operación | Coste para el atacante | Efecto sobre la evidencia conservada |
|---|---|---|
| Añadir relleno a paquetes | Gratis | Solo aumenta bytes |
| Insertar paquetes de relleno | Gratis | Solo aumenta paquetes |
| Añadir flujos señuelo o benignos (dilución) | Gratis | Solo aumenta conteos |
| Dividir un flujo en varios, cambiar puertos de origen | Gratis | Conserva bytes; aumenta flujos |
| Repartir entre más orígenes | Barato (necesita bots) | Sin cambio en los agregados por destino |
| Cambiar tamaños, flags, opciones, orden | Gratis | Sin efecto: esos rasgos no se usan |
| Reutilizar conexiones (varias peticiones por flujo, keep-alive) | Gratis | **Baja el conteo de flujos**; paquetes y bytes de ida se conservan salvo el saludo TCP |
| Elegir peticiones con respuesta pequeña | Gratis | **Baja paquetes y bytes de vuelta** (los emite la víctima) |
| Retrasar o ralentizar | **Costoso**: reduce la tasa del ataque | Baja la evidencia por ventana |
| Hacer menos (menos intentos, menos puertos) | **Costoso**: reduce la eficacia | Baja la evidencia |

Las operaciones gratuitas solo *añaden* eventos o los reparten. Las que quitan
evidencia cuestan eficacia. Sobre esa asimetría se construye todo.

Las dos últimas filas son excepciones detectadas al implementar los contadores
(fase 1). Consecuencias:

- Los contadores de respuesta de la víctima (paquetes y bytes de vuelta) quedan
  fuera del núcleo estricto. Se evalúa también una variante que los incluye, para
  medir qué se pierde.
- El conteo de flujos se mantiene en la fase 1, pero la garantía no cubre la
  reutilización de conexiones. Opciones para la fase 4: sustituirlo por paquetes de
  ida (que sí se conservan) o acotar la reducción por el número máximo de
  peticiones por conexión que admite el servicio. Se decide con los resultados.
- Los conteos por host de origen bajan si el atacante reparte el ataque entre más
  orígenes. No rompen la garantía para operaciones gratuitas, porque repartir no es
  gratis (necesita bots), y los agregados por destino no cambian.

Modos de despliegue: pasivo (el atacante no ve nada) y en línea (ve pasa/bloquea).
Niveles de atacante, de transferencia sin consultas a adaptativo que conoce el
diseño completo, incluidos los pesos. El núcleo no tiene secretos que proteger.

## 4.4 Arquitectura

```
registros de flujo ──► evidencia conservada por entidad y escala ──► núcleo monótono ──► alerta de entidad
        │                         ▲                                        │
        │                         │ alertas de la cáscara                  │ escalado
        ▼                         │ (evidencia que solo se acumula)        ▼
   cáscara por flujo ─────────────┴──────────────────────────────► alerta de flujo / bloqueo
```

### 4.4.1 Evidencia conservada

Para cada **entidad** y cada **escala temporal** se mantienen contadores aditivos de
eventos.

- **Entidades**, en jerarquía: servicio de destino (IP, puerto), host de destino,
  host de origen, par origen–destino, subred, red completa. Los agregados por
  destino no cambian si el atacante reparte el ataque entre orígenes; los de subred
  y red cubren los ataques repartidos entre muchos destinos.
- **Escalas:** contadores con decaimiento exponencial a varias vidas medias (de
  segundos a un día). Cubren ráfagas y ataques lentos, y no tienen bordes de ventana
  que el atacante pueda aprovechar.
- **Contadores:** flujos, paquetes, bytes, conexiones sin completar, respuestas de
  rechazo emitidas por el destino, conexiones concurrentes abiertas, puertos
  distintos tocados, destinos distintos contactados, orígenes distintos, periodos
  de actividad del par (persistencia) y alertas de la cáscara (4.4.4).
- **Línea base:** cada contador se expresa como exceso sobre el perfil normal de
  esa entidad (cuantiles de su historia). El atacante no controla el tráfico ajeno.

Reglas que mantienen la garantía:

- **Conteos, nunca ratios.** Un ratio (fallos entre intentos) se diluye añadiendo
  tráfico benigno. Un conteo de fallos no.
- **Cada característica se clasifica** como solo-aumento, no controlable o
  controlable en ambos sentidos. Las del último tipo no entran en el núcleo.
- **La línea base se actualiza de forma robusta:** solo con periodos sin alerta y
  con un tope de crecimiento, para que no se pueda envenenar subiendo poco a poco.

Todo esto se calcula desde registros de flujo (NetFlow/IPFIX). El núcleo no
necesita paquetes ni contenido, funciona con tráfico cifrado y con coste constante
por flujo.

### 4.4.2 Núcleo monótono

Modelo de gradient boosting con restricción de monotonía creciente en todas las
características de evidencia. Puede usar sin restricción características de
contexto que el atacante no controla (hora, tipo de servicio, nivel de la línea
base).

**Garantía.** Sea `X` una traza y `X'` cualquier traza obtenida de `X` con
operaciones gratuitas. Como esas operaciones solo añaden eventos, la evidencia de
`X'` es mayor o igual que la de `X` en todas las coordenadas; como el modelo es
monótono, su puntuación no baja. Si Proteus alerta con `X`, alerta con `X'`.

**Corrección (fase 1, 2026-11-10).** El argumento anterior solo es exacto para
las operaciones que no mueven en el tiempo el registro de un flujo: relleno,
paquetes insertados dentro del flujo, flujos señuelo y cambio de puerto de origen.
La evidencia se apunta cuando el exportador emite el registro, al final del flujo.
Dividir un flujo hace que los trozos se exporten antes, y para el final original ya
han decaído. Alargar un flujo con paquetes al final retrasa su exportación. En los
dos casos la evidencia puede bajar en un instante dado (hay un test que lo
demuestra).

Garantía corregida. Si el exportador emite cada registro como mucho Δ después de
sus paquetes (Δ es el tiempo máximo de flujo activo, que fija el defensor; 120 s
en CIC-IDS-2017/2018), toda variante X' obtenida con operaciones gratuitas cumple,
para cada contador con decaimiento τ:

    E_X'(t + Δ) ≥ exp(−2Δ/τ) · E_X(t)

En escala log1p, cada característica pierde como mucho 2Δ/τ. Gracias a la
monotonía, el peor caso sobre todas las variantes cuesta **una sola evaluación del
modelo**: f(x − margen). Una alerta está *certificada* si esa puntuación sigue
superando el umbral; entonces cualquier variante alerta como mucho Δ después.
Consecuencias:

- Con Δ = 120 s, los contadores de 10 s quedan anulados para la certificación (el
  margen es 24 en escala log), los de 60 s se debilitan (4) y los de 600 s apenas
  cambian (0,4). La certificación descansa en las escalas largas, y Δ es un
  parámetro del despliegue que el defensor puede bajar.
- El núcleo debe puntuar el estado de las entidades también por reloj (cada Δ como
  mucho), no solo al llegar flujos, para que "alerta Δ después" tenga sentido.
- La métrica principal pasa a ser el **recall certificado**: fracción de campañas
  con al menos una alerta certificada (`proteus.core.certify`).

Resultado de la fase 1: el núcleo con todas las escalas no certifica casi nada,
y un núcleo solo con la escala de 600 s certifica casi todos los DoS/DDoS entre
datasets (doc 06 §6.6). De ahí **dos núcleos**: uno rápido sin certificar, con
todas las escalas, y uno lento certificado, con las escalas largas. Las alertas
del lento son el suelo de garantía.

La garantía sigue sin depender de un presupuesto de perturbación sobre las
características, no tiene secretos y su coste en inferencia es de una evaluación
extra. Vale respecto al modelo de transformaciones de 4.3; si una
característica está mal clasificada, se rompe. Por eso la clasificación se
justifica por escrito y se intenta violar con ataques (fase 3 y 5 del plan).

Antecedentes: clasificación monótona en malware (Incer et al., 2018) y propiedades
globales verificadas en clasificadores de seguridad (Chen et al., CCS 2021). No he
encontrado su aplicación a NIDS con evidencia agregada por entidad; hay que
confirmarlo con una búsqueda sistemática antes de afirmarlo en el paper.

### 4.4.3 Frontera de daño

Para las operaciones costosas, la garantía es cuantitativa. Dado el umbral y la
línea base de una entidad, se calcula la mayor cantidad de actividad de ataque por
unidad de tiempo que mantiene la puntuación por debajo del umbral en todas las
escalas. Ejemplos de lo que se informaría:

- intentos de autenticación por hora que pasan sin alerta;
- puertos por hora que se pueden escanear sin alerta;
- peticiones por segundo de un DoS que pasan sin alerta.

Es una métrica que un operador entiende, y permite comparar defensas por el daño
que dejan pasar en lugar de por una tasa de evasión.

### 4.4.4 Cáscara por flujo y realimentación

El núcleo no ve los ataques de pocos flujos (inyección SQL, XSS, explotación
puntual). Para ellos y para ganar precisión hay una **cáscara**: un clasificador
por flujo convencional, de alta precisión, sin garantía.

La cáscara se acopla al núcleo de dos formas, ambas monótonas:

- **Realimentación.** Cada alerta de la cáscara es un evento más en los contadores
  de la entidad. Un atacante que sondea la cáscara para aprender a evadirla genera
  sondas bloqueadas, y cada una suma evidencia que no puede borrar. Las mil o dos
  mil sondas que necesita NetMasquerade se convierten en una alerta de entidad.
- **Escalado.** Cuando el núcleo alerta sobre una entidad, la cáscara baja su
  umbral para los flujos de esa entidad. Evadir la cáscara es más difícil justo
  donde hay un ataque en curso.

La decisión final es el OR de núcleo y cáscara. Lo que el núcleo detecta queda
certificado; lo que solo detecta la cáscara, no.

### 4.4.5 Salida

- Alertas por entidad y escala, con los orígenes y contadores que más contribuyen.
- Alertas por flujo de la cáscara.
- El número de alertas de entidad está acotado por el número de entidades y
  escalas, lo que limita los ataques de inflado de alertas.

## 4.5 Qué garantiza y qué no

| Situación | Resultado |
|---|---|
| Ataque de volumen o repetitivo, con cualquier combinación de operaciones gratuitas | Certificado: si se detectaba, se sigue detectando |
| El mismo ataque ralentizado | Acotado: pasa solo por debajo de la frontera de daño |
| Sondeo de la cáscara en modo en línea | Las sondas bloqueadas acumulan evidencia; acotado por la frontera |
| Ataque de pocos flujos sin rastro agregado | Sin garantía: depende de la cáscara |
| Atacante que controla el tráfico de la línea base durante semanas | Acotado por el tope de crecimiento de la línea base |
| Suplantación de origen para incriminar a otro (UDP) | La alerta por destino es correcta; la atribución por origen no es fiable |

Límite honesto: hay ataques que no dejan rastro conservado en los metadatos de red.
Ningún detector de flujos puede detectarlos de forma robusta; los que hoy lo hacen
se apoyan en rasgos incidentales. Decirlo y medirlo es parte de la aportación.

## 4.6 Aportaciones del paper

1. **Análisis de la selección aleatoria de modelos.** Demostración y experimento de
   que beneficia al atacante, con Apollon v1 como caso.
2. **Detección certificada por construcción en espacio de tráfico.** Evidencia
   conservada, núcleo monótono y garantía exacta frente a operaciones gratuitas.
3. **Frontera de daño.** Métrica de robustez para NIDS basada en el daño que pasa
   sin alerta.
4. **Realimentación de evidencia.** Los ataques por consultas se vuelven
   contraproducentes.
5. **Mapa de detectabilidad robusta.** Qué clases de ataque se pueden detectar con
   garantía desde metadatos de red, cuáles no y a qué precio.

## 4.7 Hipótesis

| # | Hipótesis | Si es falsa |
|---|---|---|
| H1 | El núcleo detecta las clases de volumen y repetitivas (DoS, DDoS, escaneo, fuerza bruta) con pocos falsos positivos | Sin núcleo útil no hay paper con este enfoque; se revisan entidades, escalas y línea base antes de abandonar |
| H2 | El precio de la monotonía es moderado frente a un modelo sin restricciones sobre las mismas características | Se informa como coste; si es muy alto, se relajan restricciones en características bien justificadas |
| H3 | Ningún ataque con operaciones gratuitas evade al núcleo | Un contraejemplo indica una característica mal clasificada; se corrige y se documenta |
| H4 | La frontera de daño es baja frente a la tasa normal de cada ataque | La garantía existe pero es poco útil para esa clase; se declara |
| H5 | El sondeo de la cáscara dispara al núcleo antes de que el ataque converja | La realimentación se queda en aportación menor |
| H6 | Los falsos positivos por picos benignos son manejables con la línea base por entidad | Añadir contexto no controlable o subir umbrales, con el coste en frontera de daño |

H1 es la que decide. Se comprueba pronto y con poco código (fase 3).

## 4.8 Fuera de la primera versión

- Selección aleatoria de modelos, claves y rotación.
- Certificación de la cáscara (se compara con CertTA y BARS, no se compite).
- Inspección de contenido.
- Aprendizaje en producción más allá de la línea base.

## 4.9 Referencias de este documento

- Incer et al., "Adversarially Robust Malware Detection Using Monotonic
  Classification" (IWSPA 2018): https://people.eecs.berkeley.edu/~daw/papers/monotonic-iwspa18.pdf
- Chen et al., "Learning Security Classifiers with Verified Global Robustness
  Properties" (CCS 2021): https://arxiv.org/abs/2105.11363
- Chen et al., "Cost-Aware Robust Tree Ensembles for Security Applications"
  (USENIX Security 2021): https://arxiv.org/abs/1912.01149
- CertTA (USENIX Security 2025): https://www.usenix.org/conference/usenixsecurity25/presentation/yan-jinzhu
- BARS (NDSS 2023): https://www.ndss-symposium.org/ndss-paper/bars-local-robustness-certification-for-deep-learning-based-traffic-analysis-systems
- NetMasquerade (NDSS 2026): https://arxiv.org/abs/2510.14906
- Perturb-ability Score: https://arxiv.org/abs/2409.07448
- Hashemi et al., "Towards Evaluation of NIDSs in Adversarial Setting":
  https://par.nsf.gov/servlets/purl/10182659
- UGR'16: https://nesg.ugr.es/nesg-ugr16/
