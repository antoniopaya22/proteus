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

5. **Segunda escala de tiempo** (`witness.coarsen`, `attacker.kept`; opción `--span`): los
   totales de `conn`, `pkts`, `bytes` y `ports` sobre varias ventanas seguidas (36 ventanas
   de 10 minutos, 6 horas), con su propia envolvente y su parte del presupuesto. Responde
   al ataque lento y largo: quien se queda justo bajo el pico de 10 minutos durante horas
   pasa la prueba de cada ventana, pero su total supera el de cualquier tramo que el
   servicio haya tenido. Es la lección de Urbina et al. (§13.7): las pruebas con memoria
   limitan más que las pruebas por instante. El peor caso sigue siendo exacto, con dos
   formas según el daño:
   - *tasa sostenida* (denegación de servicio): la mayor tasa constante que pasa todas
     las pruebas;
   - *total acumulado* (adivinación, exploración): el mayor total con la tasa libre de
     cambiar de ventana a ventana.

   Una ventana en la que el servicio queda bajo todos los suelos no se guarda y no suma
   al total, así que el atacante puede esconderse en las ventanas ociosas a la tasa del
   suelo (0,2 intentos/s en SSH); la fórmula lo tiene en cuenta y un test la contrasta
   con la búsqueda exhaustiva de planes en 200 casos aleatorios. En la red sintética de
   los tests, la adivinación sostenida todo el día conserva con dos escalas el 2,5 % de
   la tasa de la campaña, frente al 100 % con una sola (no es un resultado, solo
   comprueba el mecanismo).

Siguiente paso de diseño, si la comprobación sale bien: repartir el presupuesto entre
monitores para minimizar el peor daño (programa convexo).

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
- Ver §13.7: el precedente más cercano está en sistemas de control industrial y hay que
  citarlo como origen de la idea, no esconderlo.

## 13.6 Comprobaciones antes de escribir

1. **Decisiva.** `python -m proteus.evaluation.envelope_exp --test ugr16 --raw <semanas>
   --templates csecicids2018 --alarm-budget 0.5 --span 36 --attack-windows 3 36 144`:
   ataques de 2018 de 30 minutos, 6 horas y un día contra víctimas reales de UGR'16, con
   una escala (`envelope`, `rules`) y con dos (`envelope2`, `rules2`) al mismo presupuesto
   total. Sirve si la parte del daño que conserva el atacante queda en una mediana del
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

## 13.7 Trabajo previo verificado (2026-11-19)

Comprobado en la web (existencia, autores, sede); el contenido solo por resumen salvo que
se diga lo contrario. En `paper/references.bib` ya estaban Jung et al. y Tong et al.; se
añade Urbina et al.; el resto no está.

| Trabajo | Sede | Qué hace | Relación |
|---|---|---|---|
| Urbina, Giraldo, Cárdenas, Tippenhauer, Valente, Faisal, Ruths, Candell, Sandberg, «Limiting the Impact of Stealthy Attacks on Industrial Control Systems» | ACM CCS 2016, DOI 10.1145/2976749.2978388 | Métrica nueva: impacto del ataque que no se detecta frente a la cota de falsas alarmas; atacante que imita el comportamiento esperado | **Precedente más cercano.** Misma pregunta (cuánto daño cabe sin alertar, a un nivel de alarmas dado), en señales de sensores y control. Leído el PDF (§3–4): la métrica es la desviación máxima por unidad de tiempo que impone un ataque sin detectar frente al tiempo esperado entre falsas alarmas, con un atacante que se adapta al umbral; concluyen que las pruebas con estado limitan más que las sin estado |
| Renganathan et al., «Distributionally Robust Tuning of Anomaly Detectors» (arXiv 1909.12506) y «Higher-Order Moment-Based Anomaly Detection» (arXiv 2011.01522) | preprints | Umbral con cota de falsas alarmas y conjunto alcanzable por el atacante sigiloso | Misma línea de control; el conjunto alcanzable sale de un modelo lineal del sistema, que una red no tiene |
| Laszka, Abbas, Sastry, Vorobeychik, Koutsoukos, «Optimal Thresholds for Intrusion Detection Systems» | HotSoS 2016, pp. 72–81, DOI 10.1145/2898375.2898399 | Juego atacante–defensor para fijar umbrales con coste de falsas alarmas | Reparto del presupuesto entre monitores (comprobación 4) |
| Lisý, Kessl, Pevný, «Randomized Operating Point Selection in Adversarial Classification» | ECML PKDD 2014, LNCS 8725, pp. 240–255 | Umbral sorteado sobre la curva ROC frente a quien ataca justo bajo el umbral | Lo que §13.4 descarta; se cita como alternativa |
| Dritsoula, Loiseau, Musacchio, «A Game-Theoretic Analysis of Adversarial Classification» | IEEE TIFS 12(12), 2017, pp. 3094–3109 (DOI por confirmar en IEEE Xplore) | Equilibrios de Nash entre clasificador y atacante que elige características | Igual que el anterior |
| Tong, Li, Hajaj, Xiao, Zhang, Vorobeychik, «Improving Robustness of ML Classifiers against Realizable Evasion Attacks Using Conserved Features» | USENIX Security 2019, pp. 285–302 | Características que el atacante no puede cambiar sin perder la función maliciosa (malware PDF) | Los testigos de daño son el análogo en red: totales que no bajan sin bajar el daño |
| Jung, Paxson, Berger, Balakrishnan, «Fast Portscan Detection Using Sequential Hypothesis Testing» | IEEE S&P 2004, DOI 10.1109/SECPRI.2004.1301325 | TRW por origen con cotas de fallo y falsa alarma | Decide por origen; el testigo `ports` es por víctima y no se reparte entre orígenes |

Descartados tras mirarlos: arXiv 2605.24696 (aparecía como «CALIBURN», umbral conforme con
presupuesto de alertas) fue rehecho y hoy trata de cómo se montan los flujos de evaluación,
sin detector calibrado; arXiv 2605.13642 es una librería de detección conforme de anomalías
(p-valores y control de descubrimientos falsos), sin atacante. Rheey y Park, «Toward Reliable Intrusion Monitoring for O-RAN
Based Networks with Conformal False Alarm Control» (taller AI4NextG de ICML 2026, póster):
un umbral único fijado por predicción conforme sobre el error de un autoencoder, con
garantía de tasa de falsas alarmas y sin atacante; es calibración conforme global, no por
entidad, y no acota lo que pasa sin alertar.

Consecuencias para la propuesta:

- La novedad no puede enunciarse como «primera cota del daño de un ataque no detectado»:
  eso existe en control industrial desde 2016. Lo que se sostiene es llevarlo a la detección
  en red, donde no hay modelo físico del sistema: los testigos hacen de modelo (totales en
  la víctima que el ataque no baja sin renunciar al daño, con cualquier número de orígenes),
  la envolvente por servicio se fija sin ejemplos de ataque y el peor caso tiene fórmula
  cerrada. En mi búsqueda no apareció ninguna cota de este tipo para detectores de flujos
  de red; es una búsqueda corta, no una revisión sistemática.
- La métrica de Urbina et al. (impacto sin detectar frente a falsas alarmas) es la misma
  forma que la frontera de daño del paper actual y que la curva daño–alarmas de R4-1. Hay
  que citarla allí también, se adopte o no el rediseño. Hecho en `paper/` (trabajo
  relacionado, detectores agregados; `urbina2016stealthy` en la bibliografía).
