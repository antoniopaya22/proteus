# 11. Plan de revisión tras la revisión interna (2026-11-15)

Una revisión independiente del manuscrito (como revisor de Computers & Security) dio 5/10, revisión
mayor, y una del código encontró dos errores que afectan a cifras. Antonio decide hacer el plan
completo. Este documento es la lista de trabajo; se actualiza al cerrar cada punto.

Las salidas nuevas llevan la etiqueta `r2` (`experiments/outputs/h1/*__r2*`); las anteriores (`v3*`)
se conservan para comparar y no se citan en la versión final.

## A. Corrección (hecho en código, commit 5c08e7b; cómputo en marcha)

- [x] `baseline.day_table`: los minutos enmascarados no se descontaban (ns frente a µs).
- [x] Días sin campañas: sus falsas alarmas cuentan (fila `(none)` en `campaigns.csv`).
- [x] Alertas de los detectores locales atribuidas al subnúcleo que dispara.
- [x] `h1` falla con modelos desconocidos, variantes sin presupuestos y resultados incompletos;
      escribe `run.json`.
- [ ] `rev2.sh`: regenerar líneas base (2017, 2018), reentrenar y evaluar ambos sentidos con
      presupuestos; KitNET con `--reuse`. Después: CTU-13, UGR'16, CIC-DDoS-2019, fronteras
      (inactiva y con carga), adaptativo, envenenamiento, ablación, paquetes, realimentación.
- [ ] Medir cuánto cambian las cifras respecto a `v3` y apuntarlo en docs/06.

## B. Ciencia que falta

- [x] `proteus_cert_r`: subnúcleos solo con evidencia que la reutilización no baja (bytes de carga y
      conteos distintos), τ ≥ 10 min. Se entrena en `rev2.sh`.
- [ ] Informar su cobertura certificada frente a reutilización y fusión por puerto.
- [ ] Corregir la tabla del modelo de amenaza: fijar el puerto origen y puentear el tiempo de
      inactividad fusionan registros (violan A3).
- [ ] Atacante adaptativo con búsqueda: reutilización, reparto entre orígenes, replanificación
      temporal (ráfagas y suavizado).

## C. Método

- [x] `detected_strict` (≥ 5 flujos alertados y ≥ 1 % de la campaña) junto a `detected`.
- [ ] Estado limpio entre campañas o detección atribuible; retardo de exportación en el TTD.
- [ ] Una configuración desplegada única (Proteus ∪ Proteus-cert ± cáscara): detección, alarmas y
      frontera de esa misma configuración.
- [ ] 5–10 semillas con dispersión para los detectores principales.
- [ ] Curvas campañas detectadas frente a alarmas/h (figura principal), ambos sentidos.
- [ ] Líneas base: reglas con selección de rasgos; TRW para escaneos; CUSUM de SYN.
- [ ] `proteus_free` (homólogo justo sin restricciones) en las tablas de detección, daño y banco.
- [ ] Calibración sin etiquetas y causal (`--baseline prior --mask none`) como comprobación.
- [ ] UGR'16: alarmas/h corregidas por el muestreo del 1 % o cota declarada.

## D. Reescritura

- [ ] Evaluación en torno a un solo sistema; detectores superados y "we tried" a material
      suplementario; prosa numérica a tablas y figuras; frontera en ambos sentidos.
- [ ] Nomenclatura única (rate thresholds; unconstrained; Proteus-cert frente a alertas certificadas).
- [ ] Trabajo relacionado: verificar y posicionarse frente a Tong et al. 2019 (conserved features),
      Pierazzi 2020, Lowd y Meek 2005, Dalvi 2004, Sommer y Paxson 2010, robustez de árboles,
      Whisper como defensa.
- [ ] Resumen, introducción, título y conclusión ajustados a lo demostrado (reutilización, reglas,
      empates). Integrar el reencuadre pendiente (marco + instancia).
- [ ] Las 18 discrepancias texto-tablas de la revisión; f(x−s) como cota; agotamiento de estado y
      el tope n = 200 del suavizado en limitaciones; formato Elsevier de envío.

## E. Artefacto

- [ ] Test de extremo a extremo con un mini-dataset sintético en CI.
- [ ] `reproduce.sh` que funcione en un clon limpio y cubra todas las salidas citadas; `uv.lock`
      versionado; tabla de tiempo, memoria y disco.
- [ ] API `Detector` (`fit / calibrate / score / explain / save / load`) y `proteus fit | score |
      explain`; documentación "usar Proteus con tus flujos".
- [ ] Streaming real (estado persistente, `tick`, validación de unidades): después del paper.
