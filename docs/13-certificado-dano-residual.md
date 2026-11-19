# 13. Propuesta: certificado de daño residual (2026-11-19)

Antonio pidió una propuesta nueva, sin contar con lo desarrollado y solo con los datasets,
que pueda llegar a un 8 con un revisor externo. Después aclaró que no hace falta conservar
Apollon: Proteus puede sustituirlo. Este documento recoge la propuesta tal como quedó tras
repasarla; **no está medida ni aprobada como rumbo del paper**. Lo primero es la
comprobación de §13.6, que decide si se sigue.

## 13.1 Diagnóstico

- Apollon sortea qué modelo responde, pero todos los modelos miran las mismas
  características por flujo, que el atacante escribe. Un atacante con consultas optimiza
  contra la decisión esperada y el ruido solo lo retrasa.
- Las defensas certificadas (BARS, CertTA) certifican en el espacio de entrada con un
  presupuesto de perturbación; el atacante se sale del presupuesto.
- El diseño actual (núcleo monótono) se queda en 4–5/10 por tres objeciones que se
  repiten: el certificado cubre solo añadir tráfico, la detección viene de la parte sin
  certificar y la ventaja sobre reglas de tasa no es significativa.
- §6.104 c de docs/06: cuatro contadores de daño con umbral, sin entrenar, igualan la
  detección del sistema. Lo que limita es la evidencia y lo que se mide, no el modelo.

## 13.2 Tesis

Certificar en el espacio del **objetivo del atacante**: todo tráfico que no levanta alerta
deja a cada servicio dentro de una envolvente publicada de daño, haga lo que haga el
atacante con sus paquetes, conozca lo que conozca y consulte cuanto quiera. Sin presupuesto
de perturbación, sin lista de operaciones, sin ejemplos adversarios y sin etiquetas de
ataque.

## 13.3 Diseño

1. **Testigos de daño por víctima** (`proteus.envelope.witness`): totales en la víctima que
   el ataque no puede bajar sin renunciar al daño, con cualquier número de orígenes.

   | Daño | Unidad | Testigo |
   |---|---|---|
   | Agotamiento de conexiones (Slowloris, Slowhttptest) | conexiones retenidas | conexiones abiertas a la vez contra el servicio (`conc`) |
   | Inundación de peticiones (Hulk, GoldenEye, LOIC, HOIC) | peticiones/s | paquetes y bytes hacia el servicio, conexiones ÷ peticiones por conexión (`pkts`, `bytes`, `conn`) |
   | Inundación volumétrica (UDP) | paquetes/s | `pkts`, `bytes` |
   | Adivinación (fuerza bruta SSH, FTP) | intentos/s | `conn` × intentos máximos por conexión |
   | Exploración (escaneo vertical) | puertos por ventana | puertos distintos por host (`ports`) |

   No se usan ratios, medias ni entropías (se diluyen con señuelos) ni nada por origen
   (se reparte entre orígenes).
2. **Envolvente por entidad** (`proteus.envelope.calibrate`): el umbral de cada testigo es
   λ × el máximo que el propio servicio alcanzó en sus días de referencia; λ, uno por
   testigo, se fija sobre las puntuaciones normalizadas de todas las entidades juntas para
   cumplir el presupuesto de alarmas (calibración conforme agrupada). Las entidades sin
   historial quedan bajo un nivel único de red con parte del presupuesto, así que toda
   entidad tiene cota. Protocolo causal: solo días anteriores y solo el veredicto del
   analista sobre las alertas (ninguna etiqueta fuera de línea).
3. **Peor caso exacto** (`proteus.envelope.attacker`): contra umbrales sobre testigos, el
   mayor daño que no alerta en una ventana es el mínimo, entre testigos, de la holgura
   (umbral menos tráfico propio de la víctima) dividida por el coste mínimo del daño en ese
   testigo. Fórmula cerrada, sin búsqueda; ningún plan del atacante lo mejora.
4. **Certificado y mapa de protección**: por servicio y clase de daño, el daño residual al
   presupuesto. Para la denegación de servicio se lee como «un atacante no detectado no
   lleva al servicio más allá de una carga que ya ha soportado».

Siguiente paso de diseño, si la comprobación sale bien: repartir el presupuesto entre
monitores para minimizar el peor daño (programa convexo), y varias escalas de tiempo.

## 13.4 Lo que se descarta y por qué

- **Sortear el punto de operación** (herencia de Apollon). El umbral se aplica a la carga
  total, y la carga benigna ya varía sin que el atacante la vea, así que la ganancia del
  modelo idealizado (c = θ₀·(a+1)^(−1/a) con cola de Pareto) no se sostiene tal cual, y las
  alertas dejan de ser reproducibles. Fuera del núcleo.
- **Conjunto de modelos, bandit y árboles monótonos entrenados con ataques.** El detector
  no ve ningún ataque al ajustarse; los datasets de ataques son solo prueba. Desaparecen
  las objeciones de diseño ajustado en las redes de prueba, etiquetas en la calibración y
  dependencia del balance de clases (§6.118).
- **METIS dentro del detector.** Queda en la evaluación: banco de dosis y fidelidad del
  tráfico inyectado. No sostiene ninguna afirmación central.
- **Apollon** pasa a motivación breve y fila en las comparaciones.

## 13.5 Límites que hay que declarar

- Fuera del certificado: ataques de un solo disparo (web, Heartbleed, infiltración),
  denegación asimétrica (pocas peticiones muy caras) y el daño en peticiones dentro de una
  conexión, que los flujos no ven (la cota en peticiones usa el coste mínimo del protocolo
  y es holgada).
- Novedad: un revisor puede ver umbrales por entidad de siempre. Lo nuevo es el
  certificado en el espacio del objetivo, la calibración sin ejemplos de ataque y el peor
  caso exacto. Trabajo previo a verificar antes de citar: umbrales óptimos frente a
  atacantes estratégicos (Laszka et al. 2016), operación aleatorizada (Lisý et al. 2014;
  Dritsoula et al. 2017), características conservadas en malware (Tong et al. 2019), TRW
  para escaneos (Jung et al. 2004).
- El fondo de UGR'16 no está verificado como benigno.

## 13.6 Comprobaciones antes de escribir

1. **Decisiva.** `python -m proteus.evaluation.envelope_exp --test ugr16 --raw <semanas>
   --templates csecicids2018 --alarm-budget 0.5`: ataques de 2018 contra víctimas reales de
   UGR'16. Sirve si la parte del daño que conserva el atacante queda en una mediana del
   10 % o menos a 0,5 alarmas/h o menos (referencia de §6.115, en otras unidades: 16,9 % el
   sistema, 54 % las reglas), y si la envolvente mejora con claridad a la regla única sobre
   los mismos testigos y presupuesto. Si no, la propuesta no llega a 8 y se abandona.
2. Detección de las campañas propias de CIC-IDS-2017 y CSE-CIC-IDS-2018 con el protocolo
   causal, al menos como el sistema actual (11 de 11 y 12–13 de 13 a 0,5 alarmas/h).
3. Testigos frente a exportadores reales (CICFlowMeter, YAF, softflowd) sobre los pcap de
   CIC-IDS-2017: ninguna manipulación baja un testigo sin bajar el daño.
4. Reparto del presupuesto: mejora de al menos un 20 % sobre el reparto uniforme.

Evaluación retenida prevista si se sigue: semanas de UGR'16 aún sin abrir y CTU-SME-11, con
el diseño congelado en un commit etiquetado antes de abrirlas.
