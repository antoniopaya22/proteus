# Núcleo monótono

El núcleo es la parte de Proteus que convierte la evidencia conservada en alertas. Está
construido para que añadir evidencia nunca pueda bajar su puntuación. Esa propiedad,
junto con la [evidencia conservada](conserved-evidence.md), es lo que hace que las
alertas sean certificables.

## Gradient boosting monótono

Cada modelo del núcleo es un conjunto de árboles con gradient boosting
(`HistGradientBoostingClassifier` de scikit-learn) entrenado con **restricciones de
monotonía creciente** sobre cada característica de evidencia: contadores en bruto y
exceso sobre la línea base. El algoritmo de aprendizaje impone la restricción durante
el entrenamiento, de modo que para dos entradas cualesquiera $x \le x'$ (componente a
componente) el modelo cumple $f(x) \le f(x')$.

El algoritmo de aprendizaje impone la monotonía, pero un error de conexión (un orden de
columnas equivocado, un signo erróneo, una característica que se queda sin restricción)
la anularía en silencio sin cambiar la precisión. Por eso `proteus.core.verify`
comprueba empíricamente cada modelo entrenado sobre datos reservados, aumentando cada
característica y buscando una puntuación que baje.

## Subnúcleos

El núcleo está formado por cuatro **subnúcleos**. Cada uno es un modelo monótono
entrenado con un solo tipo de evidencia:

| Subnúcleo | Evidencia | Por qué va aparte |
|---|---|---|
| Destino | contadores de servicio y host de destino, y su exceso sobre las líneas base | Volumen, intentos y escaneos contra un objetivo; no depende de cuántos orígenes use el atacante |
| Origen | contadores de host de origen y su exceso | Escaneos horizontales que tocan miles de hosts una vez cada uno |
| Par | contadores en bruto del par origen–servicio | Fuerza bruta: un origen que insiste sobre un servicio, diluido en el tráfico total del servicio |
| Destino en bruto | contadores de destino en bruto, sin líneas base | Acota lo que puede ocultar el envenenamiento de una línea base |

Mantener separados los lados evita atajos. Un modelo que ve juntas la evidencia de
destino y la de origen puede aprender que una denegación de servicio procede de un
único origen muy activo, un patrón que se desmonta repartiendo el ataque entre bots. Un
modelo que solo ve el destino no puede aprender ese atajo. Como ningún subnúcleo
depende de otro, derrotar a uno deja a los demás en pie.

## Máximo calibrado

Los subnúcleos se combinan mediante un **máximo calibrado** (`CalibratedMax`). Cada
puntuación de subnúcleo $f_i(x)$ se transforma mediante $F_i$, la función de
distribución empírica de las puntuaciones de ese subnúcleo sobre el tráfico benigno
local, y el núcleo devuelve

$$
f(x) = \max_i F_i\big(f_i(x)\big).
$$

Un máximo simple con un único umbral está dominado por el subnúcleo con las
puntuaciones benignas más altas; al bajar la tasa de falsas alarmas, el umbral sube por
encima de todo lo que producen los demás subnúcleos y los silencia. Tras la
calibración, todos los subnúcleos hablan en la misma unidad (un percentil benigno), y
un único umbral los trata por igual.

Cada $F_i$ es no decreciente y el máximo de funciones no decrecientes es no
decreciente, así que el máximo calibrado es monótono y el certificado se aplica a la
combinación en su conjunto. Las $F_i$ se ajustan solo con tráfico benigno; los
subnúcleos no se vuelven a ajustar.

Un subnúcleo cuyas puntuaciones benignas empatan en su máximo en una proporción mayor
que la tasa de falsos positivos objetivo no puede separar nada a esa tasa. Esto ocurre
cuando un modelo se satura en una red distinta de su red de entrenamiento. Ese
subnúcleo se puede dejar fuera del máximo (`--exclude-saturated` en el experimento H1);
el resultado sigue siendo monótono.

## Umbrales locales

Los umbrales se calibran allí donde se ejecuta el detector, a partir solo del tráfico
benigno de la red de prueba, con una tasa de falsos positivos objetivo y **sin
etiquetas de ataque**. En los experimentos, el umbral de un día de prueba se fija sobre
flujos benignos limpios de los demás días de la misma red.

Un umbral aprendido en la red de entrenamiento no se transfiere a otra red: las
distribuciones de puntuación del tráfico benigno difieren demasiado. La red de
entrenamiento sirve para aprender la *forma* de los subnúcleos; la red de prueba decide
dónde cortar. Los mismos datos de calibración ajustan las $F_i$ del máximo calibrado.

## Proteus y Proteus-cert

Los mismos cuatro subnúcleos se entrenan dos veces, con escalas de tiempo distintas:

| Detector | Escalas de tiempo | Comportamiento |
|---|---|---|
| `proteus` | 10 s, 60 s, 600 s, 1 h, 6 h | Reacciona rápido a las ráfagas. Las características de escala corta conllevan una holgura de certificación grande, así que muchas de sus alertas no están certificadas. |
| `proteus_cert` | 600 s, 1 h, 6 h | Reacciona más despacio, pero su holgura es pequeña, así que sus alertas suelen ser certificables. |

Un despliegue ejecuta ambos: Proteus por rapidez y Proteus-cert como suelo certificado.
La página [Certificado](certificate.md) explica por qué la escala de tiempo determina la
holgura.

## Por qué la monotonía

La monotonía cumple dos propósitos.

**Es el sesgo inductivo adecuado para la evidencia conservada.** Más intentos contra un
servicio, más destinos sin respuesta desde un origen, más bytes hacia una víctima nunca
deberían hacer que el tráfico parezca *menos* sospechoso. Un modelo sin restricciones
es libre de aprender patrones no monótonos que se cumplen en sus datos de
entrenamiento, por ejemplo una caída a una tasa de ataque típica, y un atacante puede
explotarlos añadiendo tráfico. La restricción elimina esa libertad.

**Hace que el peor caso sea calculable.** Si el atacante solo puede aumentar la
evidencia, y el modelo solo puede aumentar su puntuación con la evidencia, el peor caso
sobre todas las variantes obtenidas con operaciones gratuitas es la entrada original.
Cuando algunas operaciones retemporizan flujos, la evidencia puede bajar en una
cantidad conocida por característica, y el peor caso es la entrada desplazada hacia
abajo en esa cantidad. En ambos casos es una sola evaluación del modelo, sin búsqueda
sobre variantes y sin aleatorización.

!!! note "Detectores de comparación"
    Los experimentos también entrenan modelos sin restricciones sobre la misma
    evidencia (`core_free_dst_b`, `proteus_free`) para medir el precio de la
    restricción, umbrales fijos de tasa por característica (`rate_rules_local`), que
    también son monótonos, y KitNET sobre las mismas estadísticas con decaimiento
    (`kitnet_local`). Consulta [Módulos de experimentos](../guide/experiments.md).

## Explicación de alertas y reglas declaradas

Una alerta se puede explicar recorriendo hacia abajo el máximo calibrado
(`proteus.core.explain`): primero el subnúcleo que dio el máximo y, dentro de él, la
evidencia más inusual sobre el tráfico benigno local y cuántas veces supera el nivel
normal de la entidad. Como el modelo es monótono, estas características solo pueden
empujar la puntuación hacia arriba, así que son la evidencia que un analista debería
mirar primero.

Los operadores también pueden declarar reglas como umbrales sobre contadores
conservados (`proteus.core.rules`), como "ningún origen alcanza 100 destinos sin
respuesta por hora" o "el honeypot no recibe flujos". Una regla es un indicador
$x \ge \theta$ sobre una característica conservada, así que es monótona y se certifica
igual que el núcleo. Las reglas se informan aparte del núcleo aprendido.
