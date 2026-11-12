# 9. Análisis de Proteus y plan de mejora (2026-11-12)

Estado con los datos de las iteraciones 1–4 (docs 06 y 07). El objetivo es que el
paper muestre que Proteus es una defensa **suficientemente buena y justificada**; Apollon
queda como motivación.

## 9.1 Lo que se sostiene

| Afirmación | Evidencia |
|---|---|
| Las operaciones libres no quitan alertas certificadas | 0 violaciones en 20 variantes por ataque, campañas reales 18→17 (§6.12) |
| ~~Lo volumétrico no se puede envenenar~~ | Artefacto de falsos positivos del fondo; corregido (§6.15) y pendiente de repetir |
| Generaliza entre redes con calibración local | Todo DoS/DDoS y los 6 escaneos, 1,9 alarmas/h (18→17) |
| La monotonía no cuesta detección | Iguala o supera al modelo libre con la mitad de alarmas (H2) |
| El máximo calibrado funciona | `core_mono_dst_x\|core_mono_dst`: misma detección, 1,65 frente a 1,88 alarmas/h |
| Un tope de crecimiento frena el envenenamiento del núcleo certificado | SSH con tope 0,1: de 16.001 a 17.013 intentos/h en 8 días; sin tope, ∞ en 4 días |
| Sondear la cáscara cuesta | ≥ 805 sondas bloqueadas por evasión (§7.5) |
| La garantía se cumple sobre paquetes reales | 0 violaciones, 11 variantes, 1,2 M de paquetes del DDoS LOIC (§6.14) |

## 9.2 Huecos

1. **Ventaja pequeña sobre las reglas de tasa.** Son monótonas, así que tienen la
   misma garantía. El núcleo aprendido da 6 veces menos alarmas en 2017, pero en 2018
   empata (38 frente a 35/h).
2. **El núcleo certificado no ve lo lento.** Frontera SSH 16.001/h frente a la
   campaña real de 1.541/h. Fuerza bruta, botnet, web e infiltración quedan sin
   certificar, y los bots de CTU-13 van cien veces por debajo de la frontera.
3. **La reutilización de conexiones.** Con solo evidencia segura frente a ella
   (`core_cert_r`), se certifica únicamente Hulk (recall 0,16) y 4 de 6 escaneos, y las
   alarmas del núcleo suben a 21/h.
4. **Envenenamiento sin techo.** Ni el núcleo rápido ni el certificado tienen techo en
   fuerza bruta. Con 1–4 días de historia, un tope recorta el 10–21 % de las líneas
   base benignas.
5. Otros: la cáscara no transfiere (bloquea el 3,3 % del benigno en 2018); 1–6
   campañas por tipo; una sola semilla; faltan otras defensas en la comparación.

## 9.3 Mejoras, por impacto

| # | Mejora | Huecos | Estado |
|---|---|---|---|
| A | **Escalas largas** (1 h, 6 h): la frontera de lo lento baja con τ, la holgura 2Δ/τ cae a 0,07–0,01 y el envenenamiento sostenido se vuelve visible | 2, 4, 1 | hecho (v3, e858aab); runs 18→17, 17→18 y CTU en curso |
| B | **Entidad par origen→servicio**, contadores brutos: la fuerza bruta no se diluye en el servicio y no hay línea base que envenenar | 2, 4 | hecho (v3) |
| C | **Línea base por población** (cuantil 0,99 de los pares del mismo puerto) + tope + historia larga (UGR'16) | 4 | implementado como opción (`PROTEUS_PEER=1`, 7d469c1); sin ejecutar: duplica la caché de 2018 (~45 GB) |
| D | **Máximo calibrado como arquitectura**: subnúcleos destino, origen, par y bruto, cada uno calibrado en local (`proteus`, `proteus_cert`). Las reglas de tasa pasan a ser el caso más simple de la familia | 1, 4 | hecho (v3) |
| E | **Reutilización como segundo peor caso**: contadores por conexión al mínimo y paquetes hacia delante con holgura log 5 (`@certr`) | 3 | hecho (b1bbb45) |
| F | **Evaluación**: tabla de daño bajo atacante adaptativo (Proteus frente a núcleo libre, reglas de tasa y KitNET), validación sobre pcaps, UGR'16, intervalos de confianza, ablaciones, coste | todos | pcaps: hecho (0 violaciones, §6.14); IC: `tables summary`; adaptativo y coste: en cola con la v3; UGR y ablaciones: pendiente |

## 9.4 Orden

1. A + B + D: evidencia v3 y reentrenar en 18→17 y 17→18 (en cola).
2. Tabla adaptativa con la v3.
3. C + tope sobre UGR'16 cuando termine de convertirse.
4. E y la validación con pcaps.
5. Semillas, ablaciones y coste.

## 9.5 Hallazgos de método por el camino

- **Los segundos de conexión no se conservan** (comprobación por paquetes): salen del
  núcleo (§6.14).
- **Fronteras de DoS falsamente cercanas a 0** por falsos positivos del fondo de la
  víctima: ahora solo cuentan las alertas atribuibles al ataque (§6.15).
- **El crecimiento benigno de las líneas base es grande** incluso con 9 días de
  historia (2018: el 3–20 % de los pares crece más de 0,1 al día). Un tope uniforme
  sale caro, por eso C usa la población (§6.13).
- **Con 1–6 campañas por tipo, las diferencias de detección no son significativas**
  (Wilson: 11/11 frente a 9/11 se solapan). Lo que separa a los detectores son las
  alarmas (1,9/h [0,3; 4,3] frente a 11,1/h [9,6; 12,6]), la garantía y el daño
  adaptativo. El paper debe apoyarse en eso.
