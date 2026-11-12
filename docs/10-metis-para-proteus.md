# 10. Qué podemos usar de METIS en Proteus (2026-11-12)

METIS (Arroni, Sánchez, Payá, González; en revisión) evalúa datos tabulares sintéticos
con una taxonomía jerárquica (fidelidad, utilidad, privacidad + eje de dominio),
armonización de métricas a [0, 1], agregación jerárquica (media en L1–L2, `ssd` con
λ = 3 en L3–L4), calibración entre referencias empíricas y un banco de defectos
inyectados para validar cada decisión. Código: `SergioArroni/doc`, carpeta `metis`
(`infrastructure/metrics/aggregation/stochastic_dominance.py`,
`calibrate/core/bounds.py`).

No es un paper de detección de intrusiones, pero varias de sus piezas metodológicas
encajan con huecos concretos de Proteus.

## 10.1 Correspondencias

| METIS | Proteus | Uso |
|---|---|---|
| Calibración entre dos referencias empíricas (otra muestra real / ruido), anclas al cuantil 95 % unilateral | Umbrales y máximo calibrado sobre benigno local (solo referencia inferior) | Protocolo de evaluación (§10.2 A) y exclusión de subnúcleos sin señal (C) |
| Excluir una métrica si sus dos referencias no se separan > 5× su ruido | CTU-13: el umbral local cae en la saturación del modelo | **C**: excluir del máximo los subnúcleos que no pueden separar en la red local |
| Agregador `ssd` (equivalente cierto exponencial, entre media y mínimo) y frente de Pareto | Comparamos detectores con tablas sueltas (detección, alarmas, daño) | **A**: puntuación compuesta y frente de Pareto de defensas |
| Banco de defectos conocidos, z ≥ 3 frente a la variabilidad de tablas limpias, «dosis mínima detectada» | Frontera de daño (ritmo mínimo detectado), falsas alarmas en benigno | **B**: banco de ataques inyectados con escaleras de dosis |
| Privacidad = exceso sobre un *holdout* de control, no parecido bruto | Exceso sobre la línea base; alertas atribuibles al ataque (no al fondo) | Mismo principio; citarlo en la discusión |
| Eje de conocimiento de dominio: reglas declaradas, aparte del score, con IC de Wilson | Nada equivalente | **E**: reglas del operador como subnúcleo monótono declarado |
| Lectura a cualquier nivel de la jerarquía y avisos por métrica | Alertas por entidad, sin explicación | **D**: explicar cada alerta (subnúcleo, contador, veces su línea base) |
| 5 semillas, mediana e IQR, Friedman + W de Kendall, Nemenyi | Una semilla | **F**: estadística de la evaluación |
| Operadores y umbrales fijados antes de construir el banco | Algunos parámetros (K, τ, topes) elegidos mirando resultados | **G**: fijar parámetros en datos de desarrollo antes del banco de prueba |

## 10.2 Propuestas, por valor para el paper

**A. Evaluación multidimensional de defensas.** La revisión de defensas (doc 08)
concluye que no hay un protocolo común para comparar defensas de NIDS. Con la
maquinaria de METIS:

- dimensiones: **detección** (recall por campaña), **falsas alarmas** (alarmas/h),
  **robustez** (fracción certificada, daño bajo atacante adaptativo, envenenamiento) y
  **coste** (flujos/s);
- cada métrica armonizada a [0, 1] y calibrada entre dos referencias: la inferior, un
  detector trivial (alertar todo o nada, o reglas fijas); la superior, el mejor
  resultado medido en la misma red;
- agregación con `ssd` (λ = 3): una dimensión a cero no se compensa. Un detector que
  detecta todo pero se evade gratis, como KitNET con 150 veces el ritmo real, no puede
  quedar arriba;
- frente de Pareto de defensas (Proteus, reglas de tasa, núcleo libre, KitNET,
  cáscara, Apollon, entrenamiento adversario), y la puntuación compuesta solo como
  segunda lectura.

Es una contribución metodológica propia (cita a METIS) y responde a la falta de
banco común.

**B. Banco de ataques inyectados con escaleras de dosis.** Al estilo del banco de
defectos de METIS:

- se inyectan campañas reales (forma real, víctima real, fondo real) a ritmos
  crecientes, con y sin operaciones libres;
- un ataque cuenta como detectado si su puntuación se separa z ≥ 3 de la variabilidad
  de los días limpios;
- la «dosis mínima detectada» es nuestra frontera, ahora con criterio estadístico;
- los días limpios marcados son las falsas alarmas.

Unifica frontera, operaciones libres y atacante adaptativo en una sola tabla, y
permite comparar detectores con el mismo banco.

**C. Excluir subnúcleos sin señal en la red local.** Si en la red de despliegue la
distribución benigna de un subnúcleo no permite el FPR objetivo (umbral en la
saturación del modelo, como en CTU-13), ese subnúcleo solo añade falsas alarmas.
`CalibratedMax.fit` puede detectarlo, porque el cuantil 1−FPR coincide con el máximo
de puntuación, y excluirlo, igual que METIS excluye métricas cuyas referencias no se
separan. Barato. Debe ir como opción para no cambiar los runs en curso.

**D. Explicar cada alerta recorriendo la jerarquía.** Qué subnúcleo dio el máximo,
qué contador y a qué escala, y cuántas veces su línea base. Mejora la usabilidad
para un SOC y la interpretabilidad que pedimos en el paper.

**E. Reglas declaradas por el operador.** Por ejemplo, «este servicio no recibe más
de N conexiones/min» o «este host es un honeypot». Si se expresan como umbrales sobre
contadores conservados, son monótonas y quedan **certificadas gratis**. Se reportan
aparte, como el eje de dominio de METIS, con tasa de violación e IC de Wilson.

**F. Estadística.** Cinco semillas por configuración; mediana e IQR; Friedman con
escenarios de ataque como bloques y W de Kendall para ver si el orden de detectores
es estable. Nemenyi solo separará extremos con tan pocos bloques; decirlo, como
hace METIS.

**G. Fijar antes, probar después.** Elegir K, τ, topes de crecimiento, λ y FPR
objetivo con datos de desarrollo (por ejemplo, 2018→2017) y congelarlos antes del
banco final (17→18, CTU, UGR). Así se evita el sesgo de ajustar mirando resultados.

**Otras sinergias.**

- METIS puede validar la **fidelidad del tráfico que inyectamos**: ataques
  reproducidos y variantes con operaciones libres frente a las campañas reales.
- Si algún día generamos flujos de ataques raros para entrenar, METIS mide su
  fidelidad y utilidad. Su propio banco muestra el problema de privacidad y copia de
  SMOTE, que apoya no usarlo.

## 10.3 Recomendación

1. **A + B** como marco de evaluación del paper: es lo que más lo refuerza y responde
   a la falta de un protocolo común.
2. **C** ya, como opción (no cambia los runs v3 en curso).
3. **D** y **E** como extensiones del diseño, con poco código.
4. **F** y **G** en la evaluación final.
