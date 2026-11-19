# 11. Plan de revisión tras la revisión interna (2026-11-15)

Una revisión independiente del manuscrito (como revisor de Computers & Security) dio 5/10, revisión
mayor, y una del código encontró dos errores que afectan a cifras. Antonio decide hacer el plan
completo. Este documento es la lista de trabajo; se actualiza al cerrar cada punto.

Las salidas nuevas llevan la etiqueta `r2` (`experiments/outputs/h1/*__r2*`); las anteriores (`v3*`)
se conservan para comparar y no se citan en la versión final.

## Bucle de mejora y revisión

Antonio pide iterar hasta la máxima nota posible. Protocolo:

1. Cada ronda es una lista de casillas. Al completarla (y con el paper compilado sin overfull) se
   lanza **un** revisor independiente, con el mismo encargo que el primero y sin darle la revisión
   anterior ni nuestras conclusiones.
2. Su nota y sus objeciones se apuntan abajo; cada objeción válida pasa a ser casilla de la ronda
   siguiente.
3. Se para con nota ≥ 9, o cuando dos rondas seguidas no suban la nota y lo que quede sean límites
   del método ya declarados.

| Ronda | Fecha | Nota | Veredicto | Objeciones principales |
|---|---|---|---|---|
| 0 | 2026-11-15 | 5/10 | revisión mayor | reutilización de conexiones fuera del certificado; valor frente a reglas de tasa no establecido; criterio de detección vacío; sistema no evaluado como conjunto; atacante adaptativo débil; calibración optimista y una semilla; comparaciones indirectas; trabajo relacionado; presentación de cuaderno |
| 1 (diagnóstico, a mitad de ronda) | 2026-11-17 | 4/10 | revisión mayor | los bytes de carga no se conservan respecto al daño (peticiones mínimas) y el atacante nunca lo prueba; cifras de cabecera a presupuesto 0,5 y robustez a FPR 10⁻³; evaluación adversaria en un solo sentido y sobre víctimas sin carga; ventaja frente a reglas y núcleo sin restricciones dentro del ruido; sin intervalos ni semillas; calibración con etiquetas; líneas base propias; el sistema evaluado no incluye la capa por flujo; título y resumen prometen de más; 13 900 palabras |
| 1 (diagnóstico 2, a mitad de ronda) | 2026-11-17 22:00 | 5/10 | revisión mayor | puntos de operación mezclados (envenenamiento, consultas, ablación, servidor con carga, tab:h1 a FPR 10⁻³; la conclusión del envenenamiento no vale al presupuesto); el certificado cubre lo que menos importa y el título vende de más; novedad limitada frente a reglas; «daño» en flujos y no en servicio denegado; validez externa y ajuste sobre las redes de prueba; calibración con etiquetas (umbrales); comparación con alarmas reales distintas; atacantes aprendidos no ejecutados; certificado de reutilización sin prueba formal; (A4) demasiado fuerte; desalojo de estado; exportador del chequeo de paquetes; extensión |
| 2 (tras los cambios de R2, pedida por Antonio) | 2026-11-17 23:50 | 4/10 | revisión mayor | el certificado protege donde no hace falta y peticiones mínimas + reutilización tumban a Proteus-cert (Slowloris ~370 conexiones > 256); lo que añade el modelo frente a reglas no está establecido (por ataque las reglas dejan menos daño en 5 de 9 en 18 → 17; métrica de alarmas por destino-minuto al revés); frontera/adaptativo contradicen tab:h1 al mismo punto (escaneos 2018, LOIC-HTTP 2018, FTP 2017); validez externa (víctimas ociosas, etiquetas en la calibración, UGR'16 y CTU-13 no al presupuesto, Δ desconocido en tráfico real); saturación de los árboles monótonos; supuestos (caché del exportador, muestreo, «free» inconsistente); atacante adaptativo débil (sin optimizador de caja blanca); faltan defensas robustas publicadas; novedad estrecha; extensión |
| 4 | 2026-11-19 04:00 | 5/10 | revisión mayor | el certificado cubre el movimiento más débil y la detección viene de Proteus-fast sin certificar; novedad estrecha (Incer, Fleshman, Tong); (A1) en manos del atacante (FIN/RST insertados, caché) y sin probar con exportadores reales; ventaja sobre reglas débil (p = 0,08, una semilla, rejilla gruesa, inyección 6,5 frente a 8,8 %); diseño ajustado en las redes de prueba y etiquetas en la calibración; tráfico real flojo y fuera del punto de operación; «daño» en flujos/h; atacante limitado en lo no cubierto (pulsos frente a τ, botnets, caja blanca); capa por flujo/Apollon débiles; extensión |

**Criterio de parada (Antonio, 2026-11-17):** cuando los resultados y la funcionalidad estén a nivel de
un 8, se para de añadir experimentos y se hace una revisión a fondo del paper: coherencia de principio a
fin, que cada sección tenga sentido y cuadre con las demás, cifras y nombres consistentes, extensión
de revista, y que tenga gancho y sea interesante. Un rechazo de Computers & Security por la moratoria
de IA/ML es aceptable: se envía entonces a otra revista.

La ronda 1 son las fases A–E de abajo.

### Revisión de diagnóstico del 2026-11-17 (pedida por Antonio; no cuenta como la revisión de la ronda)

Nota **4/10**. Con todos los pendientes (`\todo`) entregados en línea con lo mostrado el revisor
esperaría **5,5–6**; resolviendo además las objeciones 1, 2, 4, 5 y 7, **7–8**. Reconoce como puntos
fuertes la garantía sobre operaciones, la frontera de daño, la franqueza y que casi todas las cifras
cuadran con las tablas. Objeciones, por gravedad, y qué hacemos con cada una:

- [~] **O1. Los bytes de carga no se conservan respecto al daño.** (Medido: §6.85–6.91. El certificado sobre paquetes no lo arregla; se declara (A5) y se mide. Falta escribir la sección de daño con las cifras a presupuesto.) Una inundación o una fuerza bruta
      puede encoger cada petición (GET mínimo, menos cabeceras) sin perder efecto, y Proteus-cert se
      apoya en bytes y recuentos distintos; en un DoS de un origen los recuentos distintos valen 1.
      Todos nuestros planes rellenan hacia arriba. Además, «los bytes no cambian con la reutilización»
      es falso con saludo de aplicación por conexión (TLS, SSH) o compresión de cabeceras (HTTP/2).
      **Válida y grave: es un hueco del argumento, no de la redacción.** Hacer: operador «petición
      mínima» (bytes de carga por petición hasta un suelo por protocolo) en `adaptive`, `query_attack`
      y la frontera; medir el daño; declarar el supuesto de bytes de la reutilización como A5; ajustar
      el texto («nada gratuito ayuda») a lo que salga.
- [ ] **O2. Un solo punto de operación.** Cabecera a presupuesto 0,5 (1,35 y 0,26 alarmas); frontera,
      daño, consultas, envenenamiento, comparación y cobertura certificada a FPR 10⁻³ (4,10 y 8,48). A
      10⁻⁴ el atacante conserva el 21 %. **Válida.** Hacer: umbrales de presupuesto en `adaptive`,
      `query_attack`, `frontier_exp` y `poisoning`, y repetir a presupuesto 0,5; cobertura certificada
      (8/11 y 6/13; ningún escaneo de 2018 ni las inundaciones HTTP distribuidas) en el resumen.
- [ ] **O3. Un sentido y víctimas sin carga.** 17 → 18 en cola. El «servicio con tráfico» tiene 227
      flujos/h; pide carga realista (10⁴–10⁶ flujos/h). Proteus-cert satura en 2018 (7,28 alarmas a
      las dos FPR; 0,08 a todo presupuesto). Hacer: lo de la cola, más un experimento con carga
      sintética sobre la víctima.
- [ ] **O4. La ventaja medida está dentro del ruido.** 5,8 % frente a 9,2 % (reglas) y 10 % (sin
      restricciones); compuestos 0,42 y 0,41; la diferencia sale de dos escaneos, y en cuatro de cinco
      DoS los competidores dejan menos. Nueve ataques, una red, una semilla. «But not under an adaptive
      attacker» solo vale para las reglas con selección. **Válida.** Hacer: semillas y 17 → 18; decir en
      el resumen que las reglas sobre todos los rasgos son casi igual de robustas y que lo que aporta
      Proteus es la garantía y las alarmas; no vender más.
- [ ] **O5. Sin soporte estadístico.** La discusión cita intervalos de Wilson y bootstrap que no están
      en el paper. La comparación con Apollon y la capa por flujo se apoya en 79 flujos. Hacer:
      intervalos en tabla (ya los calcula `tables summary`) o quitar las frases; ampliar el experimento
      de la capa por flujo o suavizar la motivación.
- [ ] **O6. Calibración con etiquetas y días futuros; diseño ajustado en las dos redes de prueba.**
      Hacer: `prior_none` (hecho, §6.95), y evaluar el sistema final, congelado, en UGR'16 y CTU-13;
      llevar al resumen las alarmas en tráfico real. CTU-13 hecho; falta UGR'16 sin exclusión.
- [ ] **O7. Líneas base de construcción propia.** KitNET con nuestros contadores, «BARS»
      reimplementado, ninguna defensa de la tabla 1 con su código. Hacer lo viable: Kitsune tal como
      se publicó sobre paquetes (hay pcap de CIC-IDS-2017) y declarar el resto; comparar el núcleo sin
      restricciones con Proteus-fast de forma coherente.
- [ ] **O8. El sistema evaluado no es el descrito.** La decisión final es capa por flujo ∪ núcleo,
      pero «Proteus» en las tablas es fast ∪ cert, sin la capa (23 y 140 alarmas sola). Hacer: definir
      Proteus sin la capa o evaluarla dentro; decirlo.
- [ ] **O9. Huecos del modelo de amenaza.** Atacante con conocimiento completo sin instanciar; reparto
      entre 100 orígenes archivado como «costoso» aunque deja pasar ataques; exportación estable en
      dirección sin declarar; el jitter viola A2 tal como está escrito; Δ de UGR'16, CTU-13 y UNSW sin
      dar; «sin respuesta» en NetFlow unidireccional sin explicar. Hacer: declarar y precisar.
- [ ] **O10. Título, extensión y pulido.** «Certified robustness to adversarial evasion» promete de
      más para una garantía sobre operaciones aditivas que cubre 14 de 24 campañas; 13 900 palabras;
      la sección de tráfico real parece un cuaderno.
**Estado (2026-11-17, tarde; Antonio: «arregla todo lo que pida el revisor»; la máquina se ampliará
a una con GPU para las defensas publicadas):**
- O1 y O2: código hecho (commit 9ec24f0: `operators.shrink_requests`, planes `shrink*` en `adaptive`,
  modo `--shrink` en `query_attack`, `--alarm-budget` en ambos con `h1.budget_threshold`; 221 tests).
  Corriendo sobre 2017 a presupuesto 0,5: `adaptb_1817` y después `qab_1817` (unidad `proteus-op`).
- O8: hecho en el texto (Proteus = los dos detectores del núcleo; la capa por flujo se mide aparte).
- O10: título nuevo provisional («Certifying Network Intrusion Alerts against Adversarial Traffic
  Manipulation», pendiente de que Antonio lo confirme; la web sigue con el anterior), resumen con la
  cobertura certificada en el punto de operación (10 de 24) y sin «but not under an adaptive
  attacker»; destacado «certified away» reescrito.
- Discrepancias: corregidas 19 de 23 (commit 08d140a del paper). Quedan las de la sección de tráfico
  real (UGR'16 13/12 días, cifras de CTU-13, nombres antiguos), que se reescribe con `ctu*_nox` y
  UGR'16, y la del daño certificado de LOIC-HTTP, que se explica cuando esté la tabla a presupuesto.

**Vías cortas (2026-11-17, pedido por Antonio: «haz todo lo que puedas; ¿no podemos hacer pruebas
con campañas o vías más cortas?»).** Todo lo que queda se mide en el punto de operación (presupuesto
0,5), con versiones cortas por delante de las largas:
- `~/tools/fast.sh` (bajo el cerrojo): `adaptb_1718` (rejilla de 16, 2 variantes, cinco detectores),
  semillas 1 y 2 solo con los detectores del paper (`seedb_*`), líneas base causales (`priorb_none`)
  y atacante por consultas en 2018 a presupuesto (`qab_1718`, 100 consultas).
- Sobre 2017 en paralelo: `adaptb_1817` y `qab_1817` (unidad `proteus-op2`).
- Marcas tocadas para que `master.sh` salte lo que queda superado (lista en `~/tools/m/SKIPPED`):
  `adapt_1718` y las ocho fronteras de 2018 a FPR fija (la tabla de frontera saldrá del atacante a
  presupuesto: columnas simple y certificada), `ablc_1718` y lo de `proteus2` y el certificado
  antiguo, las ocho semillas con siete detectores, `prior_none` y `qa_1718` a FPR fija.
- Umbrales a presupuesto en los atacantes: `h1.budget_threshold` puntúa solo los candidatos de cada
  día (2 % superior), en la escala del oráculo y por entidad alertada (commit 1a82da8). Una primera
  versión comparaba en otra escala y el detector no alertaba nunca; se detectó en la primera fila del
  resultado y el test de extremo a extremo lo cubre ahora.
- Siguientes, sin GPU: estudio de inyección sobre víctimas con carga real y atacante fuerte (vías 1 y
  2 de la conversación del 2026-11-17); con GPU: defensas publicadas con su código.

**Hecho mientras calcula (2026-11-17, mañana):**
- Estudio de inyección (`proteus.evaluation.injection`, commit 3efa64b, 225 tests): cada ataque del día
  contra 16 víctimas reales sin ataques, repartidas en carga, con los planes del adaptativo (los de
  peticiones mínimas aparte) y el ritmo certificado. Encolado sobre 2017 a presupuesto 0,5
  (`inj_1817`, unidad `proteus-inj`, espera a `proteus-op2`).
- Paper: CTU-13 reescrito con el sistema final (§6.84); ataques por flujo y Apollon sin afirmar más de
  lo que soportan 79 flujos (objeción O5); discusión recortada. Cuerpo: 11 620 palabras.

**Incidente (2026-11-17, 11:27 UTC):** el adaptativo de 2018 a presupuesto (`adaptb_1718`) llegó a 20 GB
y la máquina se quedó sin memoria: el núcleo mató los dos trabajos paralelos de 2017 (`adaptb_1817`, en
6 de 9 ataques, y `inj_1817`). El adaptativo solo escribía al final, así que se perdió su escalera.
Arreglo (commit e115ecc): `adaptive` e `injection` guardan tras cada escenario y admiten `--resume`, y
los trabajos de 2017 pasan a `~/tools/run2017.sh` (unidad `proteus-2017`, tope 10 GB): cada uno espera
a que no haya ningún trabajo probando sobre 2018 y haya 12 GB libres, y se reintenta si lo matan.

**O7, Kitsune tal como se publicó (2026-11-17, commit f8d7dd1):** extractor AfterImage sobre paquetes
(115 rasgos, cinco λ) y KitNET entrenado con los primeros 100 000 paquetes del viernes de CIC-IDS-2017,
umbral al presupuesto de 0,5 alarmas/h sobre la hora benigna siguiente; detección de las campañas del
día y las campañas de 172.16.0.1 (escaneo, LOIC) repetidas con las operaciones gratuitas a nivel de
paquete del chequeo del certificado y con mimetismo. Encolado (`kitsune_fri`, unidad
`proteus-kitsune`, misma espera de memoria). Responde a «KitNET con nuestros contadores» y da la
comparación directa en paquetes: certificado (que se sostuvo en esas variantes) frente a detector
publicado sin garantía.

- [~] **Discrepancias (23).** Corregir todas: daño certificado de LOIC-HTTP en `tab:adaptive` (204k)
      frente a la frontera (164 536); dos columnas «Cert.» con significados distintos (1,73 / 6,13
      frente a 3,01 / 7,28); frases que no cuadran con sus tablas (escaneos que «para antes»
      Proteus-fast, mejor puntuación de alarmas 0,75 frente a 0,76, «29 veces», recall de la capa por
      flujo «por debajo de 0,1», «ningún variante a nivel de paquete quitó una alerta certificada»
      cuando ese ataque no se certifica); textos antiguos (cuatro días de prueba, 13 frente a 12 días
      de UGR'16, bots «dos o tres órdenes por debajo»); «todo detector se enfrenta al mismo atacante»;
      una evaluación extra frente a dos en el algoritmo; 119 frente a 152 contadores; bytes
      «forward» frente a «payload»; leyenda de la figura; la nota de la bibliografía.

### Revisión 5 (2026-11-19 21:45; la pidió Antonio a mitad de la ronda 4, con R4-2 a R4-7 abiertas)

Nota **5/10** (revisión mayor con dudas serias); «con los cambios prioritarios podría llegar a 7».
Paper de `main` tras los recortes del día (25 páginas, S1–S7). Puntos fuertes que reconoce: alcance de
la garantía bien delimitado (tablas de hipótesis), línea base fuerte y admitida, resultados negativos
publicados, ablación de la monotonía por familias de planes («la evidencia más convincente»),
consistencia numérica alta (recalculó medias geométricas, test de signos, razones, Wilson), métrica
en unidades del ataque. Objeciones por gravedad y casillas (R5):

- [ ] **R5-1. Manuscrito inacabado** (válida; lo más barato de arreglar). Tres `\todo` visibles
      (§5.3.3, ap. B.3, ap. D.2); UGR'16 a FPR 1e-3 y con el detector certificado anterior mientras
      §6.5 dice «presupuesto 0,5 y nada más»; KitNET sin presupuesto ni ataque en la red grande;
      ablación sin Proteus-cert en 17 → 18; «original certified detector» sin definir (ap. B.1).
      = R4-4. Hacer: UGR'16 con el sistema final al presupuesto, balances (en cola), ablación.
- [ ] **R5-2. Ventaja sobre la regla trivial no establecida** (válida; ya declarada): 2,1× con IC
      0,97–4,3, p = 0,08, rejilla a pasos de 2,26× en la red grande; reglas seleccionadas 13/13 a
      0,61 y 8,4 % frente a 6,1 %. Hacer: bisección o rejilla fina en 17 → 18, más semillas en el
      atacante, y rebajar «6 % frente a 12–13 %» en resumen, highlights y conclusión con el intervalo.
- [ ] **R5-3. Comparación no a alarmas iguales; métrica de cabecera favorable** (válida): por
      destino y minuto Proteus es el peor detector agregado (60,4 frente a 22,2 / 1,8 / 0,8). Hacer:
      curvas daño–alarmas con las dos métricas (lo que falta de R4-1) y dar las dos al mismo nivel.
- [ ] **R5-4. Cobertura certificada escasa y frágil al reparto entre orígenes** (válida y nueva en
      esta forma): GoldenEye, Slowloris y Slowhttptest pasan Proteus-cert repartidos entre ≤ 100
      orígenes (S7), y la tabla de hipótesis y §5.2 dicen que repartir no baja la evidencia de
      destino. Hacer: variante de Proteus-cert certificada solo con evidencia de destino y medir qué
      cobertura queda; o declarar el reparto como límite del certificado en resumen y tabla 2.
- [ ] **R5-5. Tráfico real débil y sin tabla** (válida): CTU-13, UGR'16, inyección con víctimas casi
      ociosas (mediana 36 flujos/h); el núcleo sin restricción conserva 6,9 % frente al 17 % en
      UGR'16, dicho en media frase. Hacer: tablas, víctimas de carga alta, discutir el 6,9 %.
- [ ] **R5-6. El certificado cubre movimientos que el atacante no haría; (A1) sin exportadores
      reales** (válida; = R4-2). RQ3 como comprobación de implementación; límite de recursos del
      exportador frente a «sin presupuesto».
- [ ] **R5-7. Atacante propio y débil** (válida; = R4-6, R3-5, R2-6): semilla 0; la búsqueda por
      consultas queda por debajo del ataque sin modificar en el escaneo del jueves (12 frente a 104);
      sin atacante aprendido ni caja blanca; sin banco de pruebas (= R4-7).
- [ ] **R5-8. Defensas externas sin ejecutar** (válida; = R3-6): CertTA/BARS con su código, Whisper
      o HyperVision; o reducir la tabla 1 y RQ5.
- [ ] **R5-9. Muestras pequeñas y pseudo-replicación** (válida; = O5, R4-3): episodios de escaneo
      como campañas, 3 semillas, diseño ajustado en las redes de prueba; quitar el sub-núcleo de
      origen mejora en 18 → 17 (ablación). Hacer: agrupar por ataque y víctima, ≥ 10 semillas,
      evaluación retenida.
- [ ] **R5-10. Calibración y cómputo no realizables en despliegue** (válida; = V4): etiquetas de la
      red de prueba, días posteriores, orden de evento y no de llegada, TTD sin el retraso de
      exportación. Hacer: evaluación causal en orden de llegada.
- [ ] **R5-11. Motivación sobre Apollon no sustentada por los 79 flujos** (válida): dejarla en el
      argumento analítico; redacción respetuosa (un solo sistema).
- [ ] **R5-12. Componentes no evaluados extremo a extremo** (capa por flujo, contador de
      realimentación, compuesto METIS). Justificar o retirar.
- [ ] **R5-13. Claridad y extensión** (= R4-5): objetivo 16–18 páginas; resultados en prosa a tablas;
      puntos de operación mezclados (FPR 1e-3 en apéndices, §6.3 y S2 sin decirlo); «Certified»
      frente a «Cert.»; comentarios internos del `.tex`; φ(r) de los contadores de RST en el ap. C.
- [ ] **R5-14. Discrepancias texto–tablas** (13; redacción salvo la 2): LOIC-UDP del miércoles
      certificada al 99 % en la tabla de detección y «nada certificado» en frontera y adaptativo;
      «behind in both directions» del núcleo sin restricción (9+0 a 0,28 frente a 8+1 a 0,20);
      «certifies nearly everything it alerts on»; §6.3 y S2 con otro umbral; rango de inundaciones sin
      el > 887; 680/681; 13 o 12 días de UGR'16; escaneos de bots (2 de 4 detectados frente a «todos
      bajo la frontera»); «the search confirms our plans»; 0,08 frente a 0,07; «evaded as often»;
      compuestos de S1 con λ.

Lectura: misma nota que la revisión 4 y casi las mismas objeciones de fondo (ventaja sobre reglas,
alarmas iguales, exportadores reales, atacante, defensas externas, evaluación retenida). Lo nuevo y
accionable ya: R5-1, R5-4, R5-14 y la parte de redacción de R5-2, R5-3, R5-11 y R5-13.

### Revisión 4 (2026-11-19 04:00)

Nota **5/10** (sube de 4). Con los `\todo` entregados, 5,5. Reconoce: modelo de amenaza y supuestos
ejemplares, la holgura del exportador como aportación, «ritmo que conserva el atacante» como medida
correcta, amplitud de la evaluación. Discrepancias 1–18: corregidas en el paper salvo 10 (punto de
operación de ablación, evidencia, UGR, CIC-DDoS, S2, S3), 13 (nombres), 17 (KitNET en la figura).
Casillas (R4):

- [~] **R4-1. Afirmaciones.** (intervalo bootstrap: reglas 2,1× el daño, IC 0,97–4,3; seleccionadas 2,8×, 1,1–7,1; resumen y conclusión suavizados; las dos métricas de alarmas ya en el resumen, 250 palabras; faltan curvas daño–alarmas) Cobertura certificada por clase sobre todas las campañas; las dos
      métricas de alarmas en el resumen; «la mitad que las reglas» con curvas daño–alarmas a varios
      presupuestos e incertidumbre (bootstrap sobre ataques y semillas) o suavizarlo.
- [ ] **R4-2. (A1) con exportadores reales** (CICFlowMeter, nProbe/YAF/softflowd) y variantes con
      FIN/RST insertados y presión sobre la caché; normalización como requisito de despliegue.
- [ ] **R4-3. Evaluación retenida:** diseño congelado sobre un dataset intacto (UNSW-NB15 de nuevo, o
      otro), calibración sin etiquetas (V4: veredictos del analista) y CTU-13 con los sospechosos.
- [ ] **R4-4. Un punto de operación:** UGR'16 (en cola), CIC-DDoS-2019, ablación, tabla de evidencia,
      S2 y S3 al presupuesto; resumen con el tráfico real.
- [~] **R4-5. Extensión ~10k palabras** (2026-11-19: envenenamiento y ataques a la capa por flujo al suplementario, S5 y S6, con resumen en el texto; «otros detectores» más corto; RQ5 más corto y atacante por consultas al suplementario, S7; 17 905 → 17 216 palabras con tablas, 14 400 de prosa sin apéndice (evaluación 7 000, diseño 2 600), 25 páginas; 20:30 UTC: preparación, RQ1, RQ2, RQ3, frontera, CTU-13 y coste apretados, evaluación 6 977 → 6 758 palabras de prosa; apretar frases rinde un 3 % por pasada, así que lo que queda es mover contenido entero: objetivo realista ~12 000 de prosa sin apéndice, con el detalle de tráfico real, semillas y uniones de reglas al suplementario y el diseño a ~2 100); capa por flujo y Apollon más cortos (sin perder el linaje v1→v2);
      puntuación de Apollon justa (voto blando o desempate) para el presupuesto.
- [ ] **R4-6. Atacante sobre lo no cubierto:** pulsos ajustados a τ, reparto a escala de botnet,
      búsqueda de caja blanca.
- [ ] **R4-7. Daño en servicio medido en un banco de pruebas** (Slowloris, Slowhttptest, una
      inundación HTTP).
- [x] **R4-8. Trabajo relacionado:** detectores monótonos/no negativos de malware (Fleshman), inserción
      y tiempos en NIDS (Hashemi, TANTRA), ataques con restricciones (FENCE, Sheatsley), detectores de
      flujo con recuentos decaídos (MIDAS).

**Máquina (2026-11-19, 08:26 UTC).** La estación se reinició redimensionada (62 GB de memoria y una
Tesla T4) y se perdieron `adaptf_1718` (su escalera parcial está guardada; se reanuda con `--resume`)
y `bal_type_entity_1817`. Relanzados `extra11.sh` y `extra.sh` a las 08:33; minutos después el nombre
dejó de resolver otra vez (otro reinicio en curso). Al volver: comprobar `master.log` y relanzar los
dos guiones (saltan lo hecho). Con la GPU quedan al alcance las defensas publicadas con su código
(BARS, CertTA, PANTS) y un atacante aprendido tipo NetMasquerade.

**Propuesta de rediseño (2026-11-19; docs/13).** A petición de Antonio, y sin obligación de conservar
Apollon, se plantea un diseño alternativo: certificado de daño residual (umbrales sobre testigos de
daño por víctima, envolvente por entidad calibrada al presupuesto sin ejemplos de ataque, peor caso
del atacante en fórmula cerrada). No está medido ni aprobado como rumbo del paper.
- [x] Código de la comprobación decisiva: `proteus.envelope` (`witness`, `calibrate`, `attacker`) y
      `proteus.evaluation.envelope_exp`, con 9 tests (254 en total).
- [x] Lanzarla en la máquina cuando vuelva (lleva caída desde las 08:36 UTC): tablas de testigos de
      UGR'16 desde las semanas en bruto y ataques de 2018 contra sus víctimas, a presupuesto 0,5;
      después CIC-IDS-2017 y CSE-CIC-IDS-2018 con el protocolo causal. Criterio en docs/13 §13.6.
- [x] Trabajo previo de la propuesta verificado (docs/13 §13.7). El precedente más cercano es
      Urbina et al. (CCS 2016, control industrial): impacto del ataque sin detectar frente al
      tiempo entre falsas alarmas. La novedad no puede enunciarse como «primera cota del daño sin
      detectar»; sí como llevarla a la detección en red sin modelo físico. El paper actual ya lo
      cita como precedente de la frontera de daño (26 páginas, sin overfull).
- [x] Lectura de UGR'16 día a día y reanudable, con test (10 tests de la envolvente); lanzador
      `envelope.sh` preparado para `~/tools`.
- [x] Segunda escala de tiempo (totales de 6 horas con su envolvente) y peor caso exacto contra las
      dos escalas, para tasa sostenida y para total acumulado; contrastado con búsqueda exhaustiva
      (14 tests de la envolvente). El lanzador pide ataques de 30 minutos, 6 horas y un día.
- [x] Ensayo a escala con tablas sintéticas: corregido el segundo día del protocolo causal (378 →
      0,66 alarmas/h), ajuste tres veces más rápido, modo `--build-only` para ver el tamaño de las
      tablas antes de calibrar; lanzador en `scripts/queue_envelope.sh` (16 tests de la envolvente).
- **Orden al volver la máquina (Antonio, 2026-11-19, «lo que tú consideres»):** primero la
  comprobación decisiva (tablas de UGR'16, tamaño, ejecución), antes que `extra11.sh` y `extra.sh`;
  si pasa, esos trabajos del diseño actual dejan de hacer falta, y si no, se relanzan después.
- **Máquina de vuelta (2026-11-19, 16:48 UTC):** disco conservado (363 GB, 117 marcas), sin otros
  usuarios. Los 16 tests de la envolvente pasan allí (pandas 3.1.1). Lanzado `~/tools/envelope.sh`:
  tablas de UGR'16 desde `july_week5` y `august_week1` (unos 5,8 M de registros y 50 000
  ventanas de servicio por hora, unos 45 s por hora de datos; calculo unas 3 horas), y encadenada
  la comprobación (`ENV_GO=1`) para cuando termine: con ~1,3 M de filas por día la memoria no es
  problema. `extra11.sh` y `extra.sh` quedan retenidos.
- **Borrador del paper nuevo (2026-11-19, a petición de Antonio):** rama `residual-harm` de
  `paper/`, sin tocar `main`. Título provisional «Proteus: Bounding the Harm of Network Attacks
  That Raise No Alert». Escritos diseño, modelo de amenaza, introducción, resumen, motivación,
  trabajo relacionado, discusión, conclusión y apéndice con las dos proposiciones; la evaluación
  es un esqueleto con marcas `\todo` sin ninguna cifra. 12 páginas, 7 400 palabras, sin overfull.
  Redactarlo destapó cuatro huecos de solidez, ya corregidos en el código (costes de peticiones
  e intentos, puertos que la víctima ya usa, volumen por host) y dos abiertos (deriva de la
  referencia y unión de flujos largos; docs/13 §13.6). Las tablas de UGR'16 se reconstruyeron
  con los testigos de host (relanzado a las 16:56 UTC, comprobación encadenada).
- La web, el README y la cita no se tocan hasta que la comprobación pase: son públicos y aún no
  hay ninguna cifra que los sostenga. Entonces irán en la misma pasada que la fusión de la rama.
- Hasta tener ese número no se toca el paper de `main` ni se recorta (R4-5).
- [x] Opción `--ref-rank` (referencia como n-ésimo día más alto, contra la deriva) y tabla de
      niveles ajustados por ejecución (`levels.csv`).
- **RESULTADO (2026-11-19, 18:30 UTC; docs/06 §6.119, docs/13 §13.8): la comprobación decisiva no
  pasa y el rediseño se abandona.** En UGR'16 a 0,5 alarmas/h el atacante óptimo conserva de media
  el 72–91 % del daño (mediana 100 %; el umbral era 10 %), sin mejora sobre la regla única y con
  0,69–0,77 alarmas/h reales. En 2017 y 2018 la mediana es 16–68 % y la detección de campañas es
  peor que la del sistema actual. Diagnóstico: el pico diario por servicio no es estable en una red
  real (márgenes de 40× a 4 300×) y en los servidores grandes la holgura absoluta supera a los
  ataques; no es cuestión de un parámetro.
- Resultados retenidos (19:30 UTC): `adaptf_1718` (docs/06 §6.120: `proteus_cert_f` solo deja al
  atacante el 77 % del ritmo, no cierra Slowloris; descartado) y `bal_type_entity_1817` (§6.121:
  11+7 a 0,87, mejor que el balance del paper en esa red; pendiente el otro sentido, y en todo caso
  es sensibilidad de apéndice, no cabecera: O6).
- Consecuencias: el paper sigue siendo el de `main` (sistema actual, nota 5/10 de la ronda 4); la
  rama `residual-harm` queda archivada sin fusionar; la web, el README y la cita no cambian.
  Relanzados `extra11.sh` y `extra.sh` a las 18:31 UTC. Se retoma la ronda 4 (R4-2 a R4-7). El óptimo
  exacto del atacante (`proteus.envelope.attacker`) se reutiliza para V5.

### Orientación v2 (decidida con Antonio el 2026-11-18)

Antonio: Proteus es la v2 de Apollon; METIS debe tener un papel (saldrá en preprint y se espera
publicado durante la revisión); vale cualquier cambio que lleve a un revisor a **8 o más**.
Tesis: «Apollon elegía, Proteus garantiza, METIS mide». Análisis en docs/06 §6.104–6.105.

- [~] **V1. Evidencia que acota el daño** (1 semana; `@certk` no certifica nada en HTTP, §6.111; hecho: certificado de reutilización con el límite de peticiones por conexión de cada servicio, `@certk`, y `proteus_cert_f` sobre conexiones y recuentos distintos, certificado también frente a peticiones mínimas; unión `proteus_pcf`; en cola `cf_*` en `extra8.sh`): conexiones simultáneas contra el servicio
      como evidencia certificada (comprobar su conservación frente a operaciones aditivas y
      reutilización física; el abandono de conexiones la baja: estudiarlo), daño en sus unidades
      (trabajadores ocupados, peticiones, puertos, intentos), reescritura de la estimación de Little.
- [ ] **V2. Apollon dentro de la v2** (3–5 días): Apollon como capa por flujo, con sus sondas
      bloqueadas como evidencia del origen; tabla «qué se conserva, qué cambia»; cara a cara v1/v2
      con el mismo atacante (test de 79 flujos ampliado).
- [~] **V3. METIS** (1–2 semanas; `injection --templates` hecho: ataques de 2018 inyectados en víctimas reales de UGR'16 con detectores de 2017, en cola como `inj_ugr`): calibración por entidad entre dos referencias (ruido benigno del
      servicio, daño que importa) y exclusión de lo que no separa; banco de dosis inyectado en
      UGR'16 con criterio estadístico; comparación multicriterio con Pareto primero (ya hecha).
- [ ] **V4. Calibración solo con veredictos del analista** como protocolo principal (medido en
      §6.105: 0,70 y 0,67 alarmas/h sin etiquetas fuera de línea).
- [ ] **V5. Atacante óptimo exacto** para detectores monótonos (peor caso, no búsqueda).
- [ ] Descartados con datos: bandit repartidor del presupuesto (§6.105), complemento de fidelidad
      (§6.71), entrenamiento adversario y modelos profundos (sin techo en la evidencia).

### Revisión 3 (2026-11-17 23:50, tras aplicar R2; la pidió Antonio)

Nota **4/10** (baja de 5; revisor nuevo cada vez, varianza ±1, y la tabla por ataque al presupuesto
dejó ver contradicciones con la frontera). Con los `\todo` entregados, 5; con prioridades 1–3 y 7,
6–7. Casillas (R3):

- [x] **R3-1. Frontera/adaptativo frente a tab:h1.** (explicado en el paper; `iso_1718`: la detección de 2018 no depende de campañas anteriores) Escaneos 2018 (6/6 en tab:h1, pasan en la
      frontera), LOIC-HTTP 2018 (0/1 frente a factor 4,4), FTP 2017 (0/1 frente a factor 11).
      Declarar el criterio de la frontera (cualquier flujo alertado, víctima sola, origen nuevo,
      minutos ruidosos descontados) frente al estricto; reconciliar fila a fila; `iso_1718` (en cola).
- [~] **R3-2. Lo que añade el modelo.** (hecho en 18 → 17: lineal monótono 8+1 a 0,84, unión de reglas 9+8 a 30,8, frente a 11+3 a 1,35; por ataque empatados con las reglas, p = 0,45/0,29; faltan `lin_1718`, `rules_1718` y el adaptativo de la unión de reglas) Unión monótona no aprendida (reglas de tasa sobre la
      evidencia de cert ∪ reglas sobre la de fast) al mismo presupuesto; comparación por ataque con
      prueba de signos o bootstrap; las dos métricas de alarmas en el resumen; `proteus_lin` (en cola).
- [x] **R3-3. Alcance en resumen y conclusión.** (tab:families: lo aditivo no mueve a los monótonos y sube al núcleo sin restricciones de 6,5 % a 27 % y de 26 % a 47 %, KitNET de 19 % a 39 %; resumen y conclusión con peticiones mínimas y DoS lento) Peticiones mínimas + reutilización dejan pasar los
      DoS lentos (~370 conexiones > 256): al resumen/conclusión. Desglose por tipo de plan (solo
      aditivas / reutilización / ráfagas / mínimas) para núcleo sin restricciones y KitNET: ¿alguna
      operación solo aditiva evade un detector no monótono?
- [~] **R3-4. Tráfico real al presupuesto.** (UGR sin certificado por Δ desconocido; saturación explicada; inyección de 2018 en 176 víctimas reales de UGR'16 hecha, §6.115; falta la subsección de UGR'16 al presupuesto) UGR'16 (en cola), CTU-13 al presupuesto ya; no dar
      alertas certificadas donde Δ es desconocido; saturación de los árboles monótonos (empates,
      alternativas que siguen creciendo).
- [~] **R3-0. Reutilización físicamente consistente** (operador corregido y probado, commit «fix(attacks): connection reuse…»; adaptativo repetido en cola: `adaptp_1817` en `run2017q.sh`, `adaptp_1718` en `extra7.sh`; faltan consultas e inyección y reescribir el paper) (encontrado el 2026-11-18, §6.104): el operador
      fusiona conexiones simultáneas; no fusionar flujos que se solapan, límite por protocolo (HTTP
      100, SSH 6, FTP 3, DoS lento y escaneos 1), partir por Δ; rehacer adaptativo, consultas e
      inyección; corregir en el paper «los DoS lentos pasan» de 18 → 17 y las «~370 conexiones».
- [ ] **R3-5. Atacante más fuerte.** Optimizador de caja blanca sobre ritmo, orígenes, tamaño de
      petición y ráfagas contra cada modelo monótono; consultas y envenenamiento al presupuesto (en
      cola); envenenamiento + remodelado.
- [ ] **R3-6. Defensa robusta publicada** (Whisper, HyperVision, CertTA/BARS con su código); quitar o
      reducir Apollon/clasificador por flujo/BARS reimplementado en el cuerpo.
- [ ] **R3-7. Extensión ~10k palabras**, un punto de operación y un esquema de nombres; resultados
      solo en texto a tablas (inyección, real); quitar METIS o dejar solo Pareto.
- [~] **R3-8. (A1) con un exportador de producción** (muestreo y caché llena ya en la tabla de supuestos; falta el exportador de producción); caché del exportador y muestreo en supuestos.
- [~] **R3-9. Discrepancias 2–16** (hechas todas salvo 6, nombres de columnas, que se unifica en la revisión final) (escaneo del viernes certificado; «más alarmas» de cert en la
      discusión; KitNET «not run» pero en h1_1e-3; «0» frente a «<4»; nombres Certified/Cert./Bound;
      carry-over y δ a FPR sin decirlo; spreading solo en consultas; 38k es del presupuesto; coste;
      CTU-13 22,2 frente a 3,68; cabecera de intervals; «free» inconsistente; pair «optional»).
- [x] **R3-10. Menores.** Entidades del argmax; Algoritmo 1 «0 for baselines»; TTD con Δ.

### Revisión de diagnóstico 2 (2026-11-17 22:00, pedida por Antonio; no cuenta como la de la ronda)

Nota **5/10** (sube de 4). Con los `\todo` entregados, ~6; con además las prioridades 1–5, ~7.
Reconoce: lema correcto, tabla de supuestos ejemplar, franqueza, evaluación adversaria en espacio
de tráfico, frontera como métrica operativa, reproducibilidad. Casillas:

- [~] **R2-1. Un solo punto de operación.** (tab:h1 al presupuesto, FPR al apéndice; envenenamiento y consultas con su umbral en el pie y la conclusión del envenenamiento corregida; `poib_*` y `qab_*` en cola; ablación a FPR declarada) Envenenamiento, atacante por consultas (`qab_*` en cola),
      ablación, servidor con carga (inyección `inj_1817` en marcha) y una tabla por ataque al
      presupuesto; o umbral en cada pie y ninguna comparación entre umbrales (D3–D7). La conclusión
      del envenenamiento (escaneo del jueves acotado por Proteus-cert) no vale al presupuesto: medir
      cuánto mueve el envenenamiento a Proteus-fast al presupuesto.
- [x] **R2-2. Afirmaciones a la medida del certificado.** (título «Additive», resumen, conclusión, highlights, introducción, web y walkthrough) Título/resumen/conclusión: «aditivas»;
      cobertura certificada y fronteras certificadas al presupuesto junto a la detección; D1, D9;
      «held on every real campaign» → lo probado.
- [~] **R2-3. Evaluación congelada en datos no vistos.** (saturación de CTU-13 explicada; UGR'16 y semillas 17 → 18 en cola) UGR'16 al presupuesto con Proteus-cert
      (`ugr*_nox` en cola), semillas en 17 → 18 (en cola); explicar la saturación de Proteus-cert en
      CTU-13.
- [~] **R2-4. Daño en servicio.** (conexiones simultáneas por la ley de Little: ~70 frente a 256 trabajadores; inyección en 16 víctimas: 7,4 % frente a 10 %, sin tendencia con la carga; falta medirlo en un servidor real) Degradación del servicio en la frontera para los DoS HTTP (réplica
      contra un servidor real o modelo de concurrencia); víctimas con carga realista (inyección).
- [~] **R2-5. Líneas base que aíslen el modelo.** (`proteus_lin` implementado y en cola, `lin_*`; robustez a alarmas desiguales declarada; Whisper/HyperVision pendientes) Modelo monótono simple (lineal no negativo) en la
      misma arquitectura; Whisper o HyperVision si es viable; robustez a alarmas reales iguales
      (unión calibrada al mismo presupuesto realizado).
- [ ] **R2-6. Un atacante aprendido publicado** en espacio de tráfico (NetMasquerade si hay código;
      máquina con GPU).
- [x] **R2-7. Rigor.** (proposición y prueba del certificado de reutilización con (A5), (A6) y ρ; (A4) matizado; tabla de operaciones por detector; exportador nombrado; desalojo como ataque. Falta repetir con un segundo exportador.) Enunciado y prueba formal del certificado de reutilización con ρ definido;
      matizar (A4) y las entradas «exact» de la tabla de operaciones por detector; nombrar el
      exportador del chequeo de paquetes (y repetir con otro); desalojo de estado en el modelo de
      amenaza.
- [~] **R2-8. Forma.** (suplementario: BARS, METIS, contador, CIC-DDoS; UNSW fuera; métrica «entity alarms per hour»; columna «Bound»; el recorte a ~10k palabras queda para la revisión final) ~10k palabras (a suplementario: CIC-DDoS-2019, UNSW-NB15, Kitsune en paquetes,
      contador de realimentación, BARS, METIS); renombrar la métrica de alarmas y quizá los detectores;
      «Cert.» frente a «Certified».
- [~] **R2-9. Discrepancias D1–D16** (hechas D1, D2, D5, D8, D9, D10, D11, D12, D13, D16; UNSW-NB15
      fuera del paper; CIC-DDoS-2019 con r2; envenenamiento al presupuesto encolado: `poib_*` en
      `run2017p.sh`; D14 verificada: 1,57 es la semilla 1 de verdad (§6.90); quedan D3/D4 con `qab_*`,
      D6/D7 con `poib_*`, D15 con el balance) (cifras): D1 cobertura 10 frente a 14; D2 clasificador por flujo
      4 de 4; D3/D4 consultas frente a planes; D5 «equals» solo en 17 → 18; D6/D7 envenenamiento;
      D8 LOIC-UDP >887; D9 filas sin cota certificada; D10 nombres viejos (UNSW, CIC-DDoS, CTU-SME-11);
      D11 12 frente a 13 días; D12 TRW/CUSUM; D13 párrafo del servidor con carga; D14 semilla 1,57;
      D15 balance; D16 «significativo».
- [x] **R2-10. Menores.** (sensibilidad a λ: Proteus primero con λ = 1, 3, 10; frase de alarmas del resumen; «three training seeds» ligado a 2017) METIS (autocita en revisión, λ = 3 sin sensibilidad); frase de alarmas del
      resumen; «three seeds» solo en un sentido.

### Revista destino (decidido con Antonio el 2026-11-16)

> **Aviso (2026-11-16, tarde): decisión en revisión.** Computers & Security mantiene desde principios
> de 2024 una moratoria: no considera envíos con IA o ML como componente significativo, ni la
> aplicación de técnicas de IA/ML a seguridad (texto en la página de Elsevier de la revista y en su
> guía de autores). Proteus entra de lleno. JISA excluye solo la «aplicación rutinaria de modelos
> existentes» y pide una visión de seguridad novedosa. Pendiente: revisar el alcance de cada
> candidata (JISA, Computer Networks, JNCA, IEEE TIFS/TDSC/TNSM, IJIS) y decidir con Antonio.

**Decisión de Antonio (2026-11-16, tarde):** intentar primero Computers & Security, reduciendo al
mínimo el vocabulario de IA/ML en todo el texto, sin faltar a la verdad. Esto sustituye, para esta
versión, a «AML como gancho»: el gancho pasa a ser la evasión adversaria y la robustez certificada.
Reglas: el método sigue diciendo qué modelo es (árboles de gradiente monótonos, entrenados con
etiquetas) en diseño y apéndice; no se oculta ningún hecho; la carta al editor explica por qué el
trabajo es de seguridad de redes (el certificado vale para detectores no aprendidos).
- [x] Resumen, palabras clave, introducción, conclusión y *highlights* (commit 4c05c27 del paper).
- [ ] Evaluación (tras la pasada de estilo), trabajo relacionado y discusión: repasar «machine
      learning», «learned», «trained», «classifier».
- [x] Evaluación, trabajo relacionado y discusión repasados: solo quedan términos factuales.
- Antonio (2026-11-16): «Adversarial Machine Learning» vuelve como primera palabra clave, pese a la
  moratoria; el resto del texto sigue sin el término.
- Antonio decide (2026-11-16): no se redacta carta al editor por ahora y la sección de ataques por
  flujo se queda en el cuerpo (es donde el revisor ve la comparación con Apollon). Reserva si hay
  rechazo sin revisión: JISA.

### Pasada de redacción (2026-11-16)

- [x] Estilo en contexto, motivación, modelo de amenaza, diseño, discusión y la parte al día de la
      evaluación (tres revisores de estilo; comprobación mecánica de que no cambió ninguna cifra,
      cita ni etiqueta: `guard.py` en el scratchpad). Commits 4c05c27, c38e3a2 y 8d3ab4e del paper.
- [x] **«El sistema» = Proteus ∪ Proteus-cert ∪ Proteus-cert-R** en tablas (`tables h1 --set r2`),
      figura y texto. A FPR 10⁻³ la unión suma las alarmas de sus miembros (4,17 y 11,88 por entidad
      y hora), así que se opera a presupuesto: 11/11 a 1,4 y 13/13 a 0,30. En 18 → 17 Proteus solo
      es más barato (1,0). Proteus-cert-R en 2018 da la misma tasa a 10⁻³ y 10⁻⁴ (7,28): mirar por qué.
- [x] Resumen a 250 palabras; quitado de la discusión el experimento de línea base por pares (cifras
      antiguas, no se repite).
- [x] Marcas `\todo` en todo pasaje con cifras anteriores a r2 (certificados de presupuesto,
      frontera, adaptativo, comparación conjunta, tráfico real, envenenamiento, temporizador,
      balance de clases, ablación).
- [~] Redacción según los papers de referencia (`docs/12-analisis-redaccion.md`): hechos los
      cambios 1–5 (contribuciones, certificado como lema y teorema, tabla de supuestos, figura
      conceptual, tabla de variantes); pendientes la evaluación en cuatro partes con conclusiones, el
      traslado de resultados fuera de la discusión y el bloque de revistas.
- [~] **Extensión** (la guía de la revista habla de 5 000–10 000 palabras): cuerpo de unas 15 200 a
      13958 tras pasar al apéndice cinco bloques secundarios con puntero en el cuerpo (arrastre entre
      campañas, ablación de subnúcleos, certificados de presupuesto, CIC-DDoS-2019 y UNSW-NB15,
      calibración del contador de realimentación; commit c4d9570 del paper). Presupuesto objetivo al
      reescribir: introducción 950, contexto 900, motivación 400, amenaza 550, diseño 2 100,
      evaluación 4 300, discusión 800, conclusión 250.
- [~] **Acelerar el adaptativo** (pedido por Antonio el 2026-11-16). Paralelizar por planes o por
      días no cabe en 30 GB: una sola campaña con los nueve detectores pasó de 11 GB (la mató el tope
      de su unidad; el recuento de `dmesg` incluye esas muertes). El coste está en los ritmos altos.
      Hecho (commit 60af145): un detector monótono que alertó en dos ritmos seguidos ya no se puntúa
      en los superiores (el ataque es anidado: más flujos solo añaden evidencia); los detectores sin
      restricciones se siguen puntuando en todos, porque en la escalera r2 tres series de
      `proteus_free`/`core_free_dst_b` vuelven a callar a ritmos altos. `--days` permite repartir
      por días cuando haya más memoria. En marcha: regresión código anterior ↔ nuevo
      (`reg_old`/`reg_full`/`reg_stop`) y medida de tiempo (`prof2`/`prof3`).
      Resultado: la regresión es exacta (tablas y escalera idénticas en dos ataques y nueve
      detectores) y el corte ahorra un 12 % (§6.60 de docs/06).
- [x] Temporizador δ = 10 y 60 s repetido en r2 (`timer10_1817`, `timer60_1817`); falta llevarlo al
      apéndice.
- [ ] Repeticiones encoladas tras `master.sh` (`~/tools/extra.sh`): temporizador δ = 10 y 60 s
      (`timer*_1817`) y balance de clases en ambos sentidos (`bal_*`).
- [x] Exclusión de subnúcleos saturados en 2017 → 2018 (`sat_1718`, §6.65 de docs/06): **no se
      adopta como regla general** (rompe Proteus-cert-R); el sistema se opera a presupuesto de alarmas.
- [ ] Una sola regla para todos los datasets: CTU-13 y UGR'16 sin exclusión, reutilizando los modelos
      de los pliegues r2 (`~/tools/extra2.sh`: `ctuB_nox`, `ctuA_nox`, `ugrJA_nox`, `ugrAJ_nox`; empieza
      al acabar `master.sh` y `extra.sh`). Si a presupuesto dan lo mismo, se quita `--exclude-saturated`
      del paper y de la discusión.
- [x] Atacante por consultas 18 → 17 con todos los candidatos y pasada de transferencia (`qa3_1817`,
      §6.69 de docs/06): `proteus2` 0,4 % del ritmo real, P ∪ cR 6,7 %, reglas 11 %, Proteus 19 %,
      reglas con selección 85 %. Falta 17 → 18 (se encola tras `adapt_1718`).
- [x] Adaptativo a FPR 10⁻⁴ (`adapteq_1817`, §6.70): a igual nivel de alarmas `proteus2` y P ∪ cR
      quedan iguales (18 % y 21 %).
- [x] Complemento de fidelidad en 2018 (`wf300_1718`, §6.71): no se sostiene; **descartado** del sistema.
- [x] **Sistema final = Proteus ∪ Proteus-cert-R, operado a presupuesto de alarmas** (2026-11-17,
      §6.70–6.72 de docs/06). Fuera Proteus-cert (redundante en detección y en daño), fuera la
      fidelidad (no se transfiere a 2018, no aporta robustez) y `proteus2` como variante evaluada
      (empata en 2017 a igual nivel de alarmas y en 2018 detecta 8/13 a presupuesto y 12/13 a 10
      alarmas). Pendiente de que Antonio lo confirme; se sigue con ello mientras tanto.
- [ ] Cifras de la unión de dos (`proteus_pcr` en `h1.UNIONS`): `pcr_1817` (en paralelo) y
      `p2_all_1718` (bajo el cerrojo). Con ellas: tablas de detección (`--set r2` con el sistema de
      dos), figura de curvas, `tab:variants`, texto de RQ1–RQ2.
- [ ] Atacante por consultas 17 → 18 (`qa_1718`, `~/tools/extra3.sh`, al final de la cola).
- [~] **Reescritura del paper con el sistema de dos** (nombres: Proteus = el sistema, Proteus-fast =
      todas las escalas, Proteus-cert = el certificado sobre evidencia que la reutilización no baja;
      el antiguo Proteus-cert pasa a ablación de la evidencia, apéndice `app:evidence`).
  - [x] Diseño (`tab:variants`, «The two detectors», algoritmo) y apéndice `tab:evidence`.
  - [x] Generador: `tables h1|adaptive|query --set paper`, curvas con `proteus_pcr`, ablación por
        entidad.
  - [x] Discusión (alcance del certificado, amenazas a la validez), tabla de detectores.
  - [x] RQ3 (comprobación del certificado), apéndices de presupuesto, temporizador y arrastre.
  - [x] Envenenamiento contra Proteus-cert como tabla (`tab:poisoning`); falta Proteus-fast (`poi_prot`).
  - [x] Daño bajo ataque (rejilla y atacante por consultas) en 2018 → 2017 (`tab:adaptive`,
        `tab:query`); falta 2017 → 2018 (`adapt_1718`, `qa_1718`).
  - [x] Detección RQ1–RQ2 con el sistema (tablas `--set paper`, tabla `tab:budgets` con todos los
        umbrales, curvas, precio de la monotonía, otros detectores); punto de operación: presupuesto
        0,5 por detector (§6.79 de docs/06).
  - [x] Frontera (RQ4) del sistema en 2018 → 2017, compacta y sin figura (§6.80); falta 2017 → 2018
        (`fr_*_1718`).
  - [x] Comparación de defensas (`tab:bench`) con el sistema en 2018 → 2017; falta 2017 → 2018.
  - [x] Introducción: los dos detectores.
  - [ ] Tráfico real (CTU-13, UGR'16) con el sistema: espera a `ctuA/ctuB`, `ugr*` y sus `_nox`.
  - [x] Resumen (250 palabras), conclusión y destacados con las cifras del sistema a presupuesto.
        PDF enviado a Antonio el 2026-11-17.
  - [x] Coste de los dos detectores en un hilo y un núcleo (§6.78); `paper_tables.sh` genera las
        tablas y figuras nuevas idénticas a las del paper.
  - [~] Apéndice: tabla a 10⁻⁴ hecha; faltan ablación (ambos detectores, ambos sentidos), balance
        de clases, CIC-DDoS-2019 y UNSW.
  - [ ] Recorte hacia 10 000 palabras una vez todo esté con cifras r2.

**Computers & Security** (Elsevier), por la vía de suscripción (sin coste); reserva: *Journal of
Information Security and Applications*. Se buscaron números especiales abiertos y gratuitos y no hay
ninguno que encaje (el de C&S sobre detección robusta cerró en dic. 2024). El paper ya usa `elsarticle`
con las declaraciones de Elsevier (CRediT, intereses, IA, datos) y `highlights.txt` aparte. El revisor
de cada ronda sigue calibrado para esa revista. Antes de enviar: mirar la página de convocatorias de
C&S por si hubiera número especial nuevo, comprobar cuartil en el JCR y preguntar en biblioteca por el
acuerdo CRUE-CSIC (acceso abierto sin coste).

### Cola de la VM (desde 2026-11-16 07:43 UTC)

Una sola cola ordenada, `~/tools/master.sh` (copia en el scratchpad, `q/master.sh`). Cada paso se
ejecuta bajo el cerrojo y deja su marca en `~/tools/m/<paso>` solo si termina bien; el progreso está en
`~/tools/master.log` (`start`, `done`, `FAIL`). Para relanzar tras un fallo: arreglar y volver a
ejecutar `master.sh` (salta lo ya hecho). Sustituye a `rev2c`, `adapt2`, `sel`, `adaptsel`,
`isolated18` y `seeds`.

Desde el 2026-11-16 09:08 UTC la cola corre en la máquina de equipo (`ws-8f74c60c…`, compartida con
Sergio): se copiaron `~/proteus` (datos, salidas, entorno) y `~/tools` desde la anterior, con tamaños
idénticos y una comparación en seco de `rsync` sin diferencias. La anterior queda sin uso.

### Rediseño `proteus2` (decidido con Antonio el 2026-11-16)

Tras ver que la reutilización de conexiones multiplica por ~20 el daño contra Proteus (§6.54 de
docs/06), se prueba `proteus2`: los mismos cuatro subnúcleos, en todas las escalas, solo con evidencia
que ninguna operación gratuita ni la reutilización pueden bajar (bytes de carga y conteos distintos).
`proteus2_sys` = `proteus2` ∪ `proteus_cert_r`. El diseño se cambia a la vista de los datos de prueba:
se contará así en el paper y se valida la detección en UGR'16 y CTU-13. Si sale peor que el sistema de
tres detectores, se queda el de tres y se cuenta.

- [ ] `proteus2` 18 → 17: detección, alarmas, presupuestos (`p2_fit_1817`, `p2_all_1817`).
- [x] Atacante adaptativo 18 → 17 con rejilla de 30 ritmos y todos los detectores, incluidas las
      reglas con selección (`adapt_1817`; rehecho al presupuesto 0,5 como `adaptb_1817`).
- [~] Lo mismo en 17 → 18 (`adaptb_1718` hecho; adaptativo en el paper en los dos sentidos al
      presupuesto 0,5 desde el commit 6b365ce del paper), CTU-13 y UGR'16.
- [ ] Decidir el sistema final (Proteus ∪ cert ∪ cert-R frente a `proteus2_sys`) con todo delante.

## A. Corrección (hecho en código, commit 5c08e7b; cómputo en marcha)

- [x] `baseline.day_table`: los minutos enmascarados no se descontaban (ns frente a µs).
- [x] Días sin campañas: sus falsas alarmas cuentan (fila `(none)` en `campaigns.csv`).
- [x] Alertas de los detectores locales atribuidas al subnúcleo que dispara.
- [x] `h1` falla con modelos desconocidos, variantes sin presupuestos y resultados incompletos;
      escribe `run.json`.
- [x] `rev2.sh`: líneas base regeneradas, ambos sentidos reentrenados y evaluados, KitNET
      (§6.49–6.51 de docs/06). `r2b`: presupuestos por entidad alertada (18 → 17 hecho; 17 → 18 en cola).
- [ ] `freeops.sh` (en cola): comprobación empírica del certificado y del de reutilización sobre
      los detectores r2 (`free_ops` ya recalibra el máximo en local).
- [ ] `rev2c.sh` (en cola): Después: CTU-13, UGR'16, CIC-DDoS-2019, fronteras
      (inactiva y con carga), adaptativo, envenenamiento, ablación, paquetes, realimentación.
- [ ] Medir cuánto cambian las cifras respecto a `v3` y apuntarlo en docs/06.

## B. Ciencia que falta

- [x] `proteus_cert_r`: subnúcleos solo con evidencia que la reutilización no baja (bytes de carga y
      conteos distintos), τ ≥ 10 min. Se entrena en `rev2.sh`.
- [ ] Informar su cobertura certificada frente a reutilización y fusión por puerto.
- [x] Tabla del modelo de amenaza: mantener una quíntupla viva fusiona registros (A3), cubierto
      por el certificado de reutilización.
- [x] Atacante adaptativo con planes estructurados (commit del código): reutilización (20
      peticiones por conexión), ráfagas, ambas, y reparto entre 100 orígenes (aparte, por ser
      costoso). En cola en los dos sentidos (`adapt2.sh`). Falta: llevar el resultado al paper.

## C. Método

- [x] `detected_strict` (≥ 5 flujos alertados y ≥ 1 % de la campaña) junto a `detected`.
- [x] Detección de cada campaña sin los demás ataques (`proteus isolated`): 2017 hecho y en el
      paper (§6.53); 2018 en cola. El TTD se mide al final del registro; dicho en el texto.
- [x] Una configuración desplegada única en `h1` (`proteus_sys` = Proteus ∪ Proteus-cert;
      `proteus_sys_r` añade el resistente a reutilización): detección y alarmas. Falta: reevaluar
      18 → 17 con `--reuse` (el run r2 empezó antes) y la frontera de esa configuración.
- [ ] 5 semillas (0 = r2; 1–4 en `seeds.sh`, que espera a `rev2c` y `adapt2`): dispersión de
      detección y alarmas en ambos sentidos.
- [x] Curvas campañas detectadas frente a alarmas por entidad/h: `tables curves` genera la figura
      (probada con 18 → 17). Falta: generarla con los dos sentidos y meterla en el paper (fase D).
- [x] Líneas base clásicas: TRW (por host y por servicio) y CUSUM de flujos fallidos
      (`proteus classic`, commit 0541084). 2017 hecho (`classic__cicids2017__r2`); 2018 en cola.
- [x] Línea base `rate_rules_sel`: reglas sobre los 10 rasgos que mejor separan en la red de
      entrenamiento (commit del código). En cola en los dos sentidos (`sel.sh`).
- [x] Tabla de detección r2 (`tables h1 --set r2`): Proteus, sistema, certificadas, certificadas
      frente a reutilización, `proteus_free`, reglas, KitNET, flujo; alarmas por entidad y por
      destino-minuto; criterio estricto. Falta `proteus_free` en daño y banco (con `adapt2`).
- [x] Líneas base causales y sin etiquetas (`--baseline prior --mask none`) en 18 → 17, en
      `seeds.sh`. Los umbrales siguen usando las etiquetas para elegir el benigno limpio: decirlo.
      (Hecho: misma detección, 1,37 frente a 1,35 alarmas; en el paper y en §6.95.)
- [ ] UGR'16: alarmas/h corregidas por el muestreo del 1 % o cota declarada.

## Indicaciones de Antonio (2026-11-16)

- **Apollon se evalúa como un solo sistema**: la versión 2.0.0 de su repositorio. El lector de un
  sucesor quiere ver la diferencia con el original, así que Apollon entra como detector por flujo en
  la detección entre redes y en la comparación conjunta.
  - [x] `ApollonFlow` (`--models apollon`, commit 759823d) y texto del paper (commit 4030357 del
        paper: motivación, tabla de ataques por flujo, tabla de detectores).
  - [~] `ap_1817` hecho (§6.57 de docs/06: 7/11 a 21,3 alarmas por entidad/h; satura) y en la tabla
        de detección. Falta `ap_1718`.
  - [x] `ap_1718` hecho (§6.64): 7/13 a 266 alarmas por entidad/h; en la tabla de detección.
  - [ ] (queda) Apollon en la comparación conjunta; resultados `ap_1718` (cola aparte `~/tools/apollon.sh`, mismo cerrojo): columna
        en la tabla de detección y fila en la comparación conjunta; medir qué miembro responde.
- **AML como gancho.** «Adversarial machine learning» es la palabra clave que atrae lectores: debe
  estar en título, resumen, introducción y palabras clave, y los ataques deben contarse como AML en
  el espacio de tráfico, no solo como «atacante adaptativo».
  - [x] Palabras clave: Adversarial Machine Learning, Evasion Attacks, … (en `main.tex`, sin subir).
  - [x] Resumen, introducción, conclusión y *highlights* reescritos con ese marco y solo cifras r2
        (commit 621bb3b del paper). Título propuesto en `main.tex` (pendiente de confirmar por
        Antonio): «Proteus: Certified Robustness to Adversarial Evasion in Network Intrusion
        Detection». Quedan sin cifras, hasta que salgan sus ejecuciones r2: frontera, daño
        adaptativo, envenenamiento, suavizado y tráfico real. El resumen tiene ~275 palabras:
        recortar a 250 antes de enviar.
  - [~] **Atacante por consultas implementado** (`proteus query-attack`, commit 289a4ed): búsqueda
        (1+1) con etiqueta dura sobre la forma del tráfico (relleno, paquetes insertados, partición,
        señuelos, puertos, peticiones por conexión, ráfagas y, como opción costosa, número de
        orígenes) con carrera de ritmos; objetivo = un detector o una unión. `adaptive.py` expone
        `day_models` y `Oracle`, que comparten los dos atacantes. Falta ejecutarlo (prueba de humo en
        marcha) y compararlo con la rejilla.
        2026-11-16: la primera ejecución completa murió por memoria (la búsqueda sube a ritmos cuyo
        tráfico no cabe); relanzada con `--max-flows 300000` (cota inferior), sin KitNET ni los
        detectores sin restricciones, y guardando tras cada objetivo (`qa_1817`, etiqueta `b150`).
        `tables query` genera su tabla (commit siguiente).
  - [ ] (texto original) **Atacante que usa AML para generar mejores ataques**: búsqueda por consultas con etiqueta
        dura (sin conocer el modelo) sobre los parámetros de las operaciones (ritmo, relleno,
        partición, reutilización, reparto entre orígenes, pulsos), que maximiza el daño sin ser
        detectado, contra Proteus y contra cada línea base; comparar con la rejilla actual y contar
        consultas. Responde también a la objeción del atacante adaptativo débil.
- **Complemento al estilo de METIS** (idea de Antonio, 2026-11-16): comparar la ventana reciente de
  cada entidad con el tráfico benigno real, sin etiquetas, en el lugar de la capa por flujo.
  - [x] Piloto en 2017 (§6.61 de docs/06): con ventanas de 300 s detecta fuerza bruta FTP y SSH e
        infiltración, que Proteus no ve, a 0,59 alarmas por entidad/h.
  - [ ] Decidir con Antonio si entra en el paper. Para ello: criterio de `h1`, 2018, unión con
        Proteus y atacarlo con el atacante por consultas.
- **Buscar el mejor Proteus** (pedido por Antonio el 2026-11-16: evaluar Proteus, Apollon y METIS
  como experto, proponer varias opciones y probarlas).
  Debilidades medidas: la reutilización rompe a Proteus solo; el sistema de tres suma las alarmas
  de sus miembros; fuera de inundaciones y escaneos detecta 1 de 10 campañas.
  - [~] A: un solo máximo calibrado sobre todos los subnúcleos (`a&b` en `combined`). B: reglas de
        tasa sobre evidencia que la reutilización no baja (`rate_rules_r`). C: complemento de
        fidelidad por ventana. Trece candidatos en 2017 con las métricas del paper
        (`h1 --export-alerts` + `proteus.evaluation.unions`; ejecución `r2_opt`/`r2_unions`).
  - [x] Resultado en 2017 (§6.64 de docs/06): A y B descartadas; Proteus-cert sobra (Proteus ∪
        cert-R da lo mismo); la fidelidad por ventana sube la cobertura de 11+3 a 11+5 por 0,6
        alarmas. Finalistas: Proteus ∪ cert-R ∪ fidelidad, y `proteus2` ∪ fidelidad.
  - [x] Oráculo adaptado a detectores que puntúan flujos crudos (`WindowFidelity.flow_alerts`) y
        objetivos-unión en el atacante por consultas (`--union`); commit 3aea8d8.
  - [~] Atacante por consultas contra los finalistas en 2017 (`qa2_1817`, etiqueta `fin`:
        fidelidad sola, Proteus ∪ cert-R, con fidelidad, y `proteus2` ∪ fidelidad), en marcha.
  - [ ] D: alertas con memoria (persistencia, suelo por entidad). Repetir en 2018
        (`alerts_1718`, `wf300_1718` en cola). Daño a umbral estricto (`adapteq_1817`).
  - [ ] E (entrenar con ataques disfrazados) y F (marcadores por subred): solo si A–D no bastan.
- **La GPU no es un límite.** No se escribe que algo «necesita GPU»; la máquina se ampliará.
  - [x] Quitadas las menciones del paper (BARS, entorno).
  - [ ] Fase con GPU (cuando esté): código original de BARS, PANTS y CertTA sobre los mismos datos,
        y un atacante con política aprendida al estilo de NetMasquerade.

## D. Reescritura

- [~] (en curso) Configuración, métricas, tabla de detección, reutilización, presupuestos y precio de
      la monotonía ya reescritos con r2 (commit del paper); quedan RQ3–RQ6 y el apéndice.
- [ ] **Sistema = Proteus ∪ Proteus-cert ∪ Proteus-cert-R** (decidido tras §6.54 de docs/06): tabla
      de detección, presupuestos, fronteras, daño y banco para esa unión (`proteus_sys_r`; daño con la
      escalera de `adaptive`). Añadir a `adaptive`/`tables` el cálculo de uniones.
- [ ] Evaluación en torno a un solo sistema; detectores superados y "we tried" a material
      suplementario; prosa numérica a tablas y figuras; frontera en ambos sentidos.
- [~] Figura de detección frente a alarmas por entidad (`figures/curves.tex`, `tables curves
      --detectors`), con TRW, CUSUM y reglas con selección en el texto (commit e260ce5 del paper). Se
      corrigió de paso que `curve_points` archivaba las ejecuciones 17 → 18 en 18 → 17. Falta la curva
      de reglas con selección en 17 → 18 (`p2_fit_1718`) y regenerarla con el sistema final; en el
      texto «el sistema» aún es el de dos detectores (1,1 alarmas) y la figura muestra el de tres (1,4).
- [x] `uv.lock` versionado y sincronizado con `pyproject.toml` (commit eee6d3c).
- [x] Nomenclatura única: «rate thresholds», «unconstrained core» (también en la leyenda de la
      figura), «alarm budget»; «shell» es el componente y «per-flow classifier» el detector de la
      comparación. Quedan «certified core/detector» en pasajes que se reescriben con r2.
- [x] Trabajo relacionado (commit del paper): Tong et al. 2019 verificado (USENIX Security, pp. 285–302),
      Pierazzi 2020, Lowd y Meek 2005, Dalvi 2004, Sommer y Paxson 2010, robustez de árboles,
      Whisper como defensa.
- [ ] Resumen, introducción, título y conclusión ajustados a lo demostrado (reutilización, reglas,
      empates). Integrar el reencuadre pendiente (marco + instancia).
- [x] f(x−s) como cota; agotamiento de estado; tope n = 200 del suavizado (1,83 comprobado).
- [ ] Las 18 discrepancias texto-tablas de la revisión (con las cifras r2); formato Elsevier.
- [ ] Métrica principal de falsas alarmas: por entidad alertada, dando también (destino, minuto) y
      el desglose por día; explicar el lunes de CIC-IDS-2017 (§6.49 de docs/06).

## E. Artefacto

- [x] Test de extremo a extremo con un mini-dataset sintético (commit 7d4aa7d; 78 s).
- [~] `reproduce.sh` y `paper_tables.sh` reescritos con las órdenes r2 reales (2026-11-16): etapas
      nuevas (`baselines`, `systems`, `cert`, `query`, `robustness`), pasada en seco (`DRY=1`) y tablas
      desde cualquier copia de los resultados; `paper_tables.sh` regenera idénticas las dos tablas de
      detección y la figura de curvas del paper. Tests: nombres de módulos y detectores del script
      contra el código (`test_scripts.py`, `test_end_to_end.py`). Falta: repasarlo cuando el sistema
      final y las tablas del paper estén fijados, probarlo en un clon limpio y la tabla de tiempo,
      memoria y disco.
- [ ] API `Detector` (`fit / calibrate / score / explain / save / load`) y `proteus fit | score |
      explain`; documentación "usar Proteus con tus flujos".
- [ ] Streaming real (estado persistente, `tick`, validación de unidades): después del paper.
