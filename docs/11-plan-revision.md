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

La ronda 1 son las fases A–E de abajo.

### Revisión de diagnóstico del 2026-11-17 (pedida por Antonio; no cuenta como la revisión de la ronda)

Nota **4/10**. Con todos los pendientes (`\todo`) entregados en línea con lo mostrado el revisor
esperaría **5,5–6**; resolviendo además las objeciones 1, 2, 4, 5 y 7, **7–8**. Reconoce como puntos
fuertes la garantía sobre operaciones, la frontera de daño, la franqueza y que casi todas las cifras
cuadran con las tablas. Objeciones, por gravedad, y qué hacemos con cada una:

- [ ] **O1. Los bytes de carga no se conservan respecto al daño.** Una inundación o una fuerza bruta
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
      Hacer: `prior_none` (en cola), y evaluar el sistema final, congelado, en UGR'16 y CTU-13; llevar
      al resumen las alarmas en tráfico real.
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

- [~] **Discrepancias (23).** Corregir todas: daño certificado de LOIC-HTTP en `tab:adaptive` (204k)
      frente a la frontera (164 536); dos columnas «Cert.» con significados distintos (1,73 / 6,13
      frente a 3,01 / 7,28); frases que no cuadran con sus tablas (escaneos que «para antes»
      Proteus-fast, mejor puntuación de alarmas 0,75 frente a 0,76, «29 veces», recall de la capa por
      flujo «por debajo de 0,1», «ningún variante a nivel de paquete quitó una alerta certificada»
      cuando ese ataque no se certifica); textos antiguos (cuatro días de prueba, 13 frente a 12 días
      de UGR'16, bots «dos o tres órdenes por debajo»); «todo detector se enfrenta al mismo atacante»;
      una evaluación extra frente a dos en el algoritmo; 119 frente a 152 contadores; bytes
      «forward» frente a «payload»; leyenda de la figura; la nota de la bibliografía.

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
- [ ] Atacante adaptativo 18 → 17 con rejilla de 30 ritmos y todos los detectores, incluidas las
      reglas con selección (`adapt_1817`).
- [ ] Lo mismo en 17 → 18 (`p2_fit_1718`, `p2_all_1718`, `adapt_1718`), CTU-13 y UGR'16.
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
- [ ] Líneas base causales y sin etiquetas (`--baseline prior --mask none`) en 18 → 17, en
      `seeds.sh`. Los umbrales siguen usando las etiquetas para elegir el benigno limpio: decirlo.
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
