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

## A. Corrección (hecho en código, commit 5c08e7b; cómputo en marcha)

- [x] `baseline.day_table`: los minutos enmascarados no se descontaban (ns frente a µs).
- [x] Días sin campañas: sus falsas alarmas cuentan (fila `(none)` en `campaigns.csv`).
- [x] Alertas de los detectores locales atribuidas al subnúcleo que dispara.
- [x] `h1` falla con modelos desconocidos, variantes sin presupuestos y resultados incompletos;
      escribe `run.json`.
- [x] `rev2.sh`: líneas base regeneradas, ambos sentidos reentrenados y evaluados, KitNET
      (§6.49–6.51 de docs/06). `r2b`: presupuestos por entidad alertada (18 → 17 hecho; 17 → 18 en cola).
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
- [ ] Estado limpio entre campañas o detección atribuible; retardo de exportación en el TTD.
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
- [ ] `proteus_free` (homólogo justo sin restricciones) en las tablas de detección, daño y banco.
- [ ] Líneas base causales y sin etiquetas (`--baseline prior --mask none`) en 18 → 17, en
      `seeds.sh`. Los umbrales siguen usando las etiquetas para elegir el benigno limpio: decirlo.
- [ ] UGR'16: alarmas/h corregidas por el muestreo del 1 % o cota declarada.

## D. Reescritura

- [ ] Evaluación en torno a un solo sistema; detectores superados y "we tried" a material
      suplementario; prosa numérica a tablas y figuras; frontera en ambos sentidos.
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
