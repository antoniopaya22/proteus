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

La ronda 1 son las fases A–E de abajo.

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
- [ ] Repeticiones encoladas tras `master.sh` (`~/tools/extra.sh`): temporizador δ = 10 y 60 s
      (`timer*_1817`) y balance de clases en ambos sentidos (`bal_*`).

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
  - [ ] Resultados `ap_1817` y `ap_1718` (cola aparte `~/tools/apollon.sh`, mismo cerrojo): columna
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
  - [ ] **Atacante que usa AML para generar mejores ataques**: búsqueda por consultas con etiqueta
        dura (sin conocer el modelo) sobre los parámetros de las operaciones (ritmo, relleno,
        partición, reutilización, reparto entre orígenes, pulsos), que maximiza el daño sin ser
        detectado, contra Proteus y contra cada línea base; comparar con la rejilla actual y contar
        consultas. Responde también a la objeción del atacante adaptativo débil.
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
- [ ] Nomenclatura única (rate thresholds; unconstrained; Proteus-cert frente a alertas certificadas).
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
- [ ] `reproduce.sh` que funcione en un clon limpio y cubra todas las salidas citadas; `uv.lock`
      versionado; tabla de tiempo, memoria y disco.
- [ ] API `Detector` (`fit / calibrate / score / explain / save / load`) y `proteus fit | score |
      explain`; documentación "usar Proteus con tus flujos".
- [ ] Streaming real (estado persistente, `tick`, validación de unidades): después del paper.
