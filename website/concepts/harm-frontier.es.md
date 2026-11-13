# Frontera de daño

El [certificado](certificate.md) elimina las operaciones gratuitas de las opciones del
atacante. Lo que le queda es hacer menos: enviar a menor tasa, sondear menos puertos por
hora, probar menos contraseñas por hora. Cualquier detector se puede evadir así a alguna
tasa, de modo que la pregunta útil es *a qué tasa*. La **frontera de daño** la responde.

## Definición

Para un ataque con una forma de flujo dada, contra una víctima dada con su tráfico de
fondo real, la frontera de daño es la **mayor tasa de ataque que no lanza ninguna
alerta atribuible**.

Se expresa en las unidades del propio ataque: flujos por hora, que en los ataques
estudiados aproxima peticiones, sondas o intentos de autenticación (uno por conexión), y
paquetes en sentido directo por hora. Son magnitudes con las que un operador puede
razonar: "un ataque de fuerza bruta por debajo de tantos intentos por hora contra este
servidor SSH pasa desapercibido".

Hay dos fronteras:

| Frontera | Puntúa | Significado |
|---|---|---|
| **Simple** | el núcleo sobre las características del ataque, $f(x)$ | Mayor tasa que no lanza ninguna alerta, para el ataque tal como se observa. |
| **Certificada** | el peor caso sobre las operaciones gratuitas, $f(x - s)$ | Mayor tasa que el atacante puede alcanzar combinando una tasa menor con *cualquier* operación gratuita. |

La frontera certificada es la que acota a un atacante informado. También es la que
cubre a un atacante limitado por su propio ancho de banda, que paga el relleno con
tasa: la combinación de una tasa menor y operaciones gratuitas es justo lo que mide.

Comparar defensas por su frontera es compararlas por el daño que dejan pasar, y no por
una tasa de evasión sobre un conjunto fijo de ejemplos adversarios.

## Alertas atribuibles

Sobre una víctima muy activa, el tráfico de fondo por sí solo cruza a veces el umbral:
son los falsos positivos benignos que el umbral permite. Si esas alertas contaran contra
el atacante, cualquier tasa, por pequeña que fuera, parecería detectada, y la frontera
sería cero sin decir nada sobre el ataque.

Por eso Proteus cuenta solo las **alertas atribuibles**: una alerta, sobre un flujo de
ataque o sobre un flujo de fondo cuya evidencia aumentó el ataque, en un minuto en el
que el fondo por sí solo no lanza ninguna. Los minutos en que el fondo por sí solo
genera alertas (`noisy_minutes`) se calculan una vez por escenario y se excluyen.

## Escenarios

Cada escenario reutiliza datos reales de la red de prueba:

- **objetivo**: la víctima real de una campaña;
- **fondo**: su tráfico real de ese día;
- **formas de flujo**: muestreadas de la campaña real (paquetes, bytes, flags,
  respuestas).

Se admiten dos formas de escenario:

- **Lado del destino** (denegación de servicio, fuerza bruta, escaneo vertical): todos
  los flujos de ataque van a un único objetivo, sobre el tráfico real hacia ese
  objetivo.
- **Lado del origen** (escaneo horizontal): un origen nuevo reproduce las sondas reales
  del origen de escaneo más activo, manteniendo sus destinos y puertos, sobre el tráfico
  real hacia esos destinos (`proteus.evaluation.frontier_scan`).

Las características de un flujo de ataque solo dependen de los flujos que comparten su
servicio, su host de destino o su origen, así que este fondo es exacto para los flujos
de ataque.

## Ataques anidados y bisección

El ataque se genera una sola vez a la tasa máxima $r_{\max}$, y cada evento de ataque
recibe una marca uniforme $u \in [0, 1)$. El ataque a tasa $r$ conserva los eventos con
$u < r / r_{\max}$. Los ataques a tasas distintas están, por tanto, **anidados**: una
tasa mayor es un superconjunto de una menor.

Añadir eventos nunca reduce la evidencia, y el núcleo es monótono, así que "el ataque
lanza una alerta atribuible" es monótono en $r$. Una búsqueda binaria entre $r_{\min}$
y $r_{\max}$ encuentra entonces la frontera exactamente, hasta la resolución elegida. Si
incluso $r_{\min}$ genera alerta, la frontera se indica como inferior a $r_{\min}$; si
$r_{\max}$ pasa desapercibida, como superior a $r_{\max}$.

## Cómo leer una frontera

- **Más baja es mejor para el defensor.** La frontera es lo máximo que puede hacer un
  atacante sin que se note.
- **Compárala con la tasa de la campaña real.** Si el ataque real se ejecutó muy por
  encima de la frontera, el atacante tendría que ralentizarse en ese factor para pasar
  desapercibido; si se ejecutó por debajo, el detector no lo ve tal como está.
- **Es específica de una víctima y su fondo.** Un servidor muy activo con una línea
  base alta oculta más que uno inactivo. Las fronteras se presentan por tipo de ataque
  y víctima.
- **Las escalas de tiempo largas bajan la frontera de los ataques lentos.** Un contador
  con $\tau = 6$ h acumula un goteo sostenido que nunca se nota a escala de minutos.
- **Una frontera infinita** significa que ninguna tasa hasta $r_{\max}$ generó alerta:
  el detector no ve en absoluto esa forma de ataque sobre esa víctima.

## El atacante adaptativo

La frontera fija la forma del ataque y solo varía la tasa. El experimento adaptativo
(`proteus.evaluation.adaptive`) permite al atacante cambiar también la forma. Para cada
escenario, su daño es la mayor tasa a la que ningún flujo del atacante lanza una alerta
atribuible, maximizada sobre:

- el ataque simple;
- combinaciones aleatorias de operaciones gratuitas (relleno, paquetes insertados,
  flujos partidos, señuelos, puertos de origen nuevos);
- **mimetismo**: relleno y paquetes insertados hasta que cada flujo de ataque alcanza la
  mediana de paquetes en sentido directo y de bytes por paquete del tráfico benigno de
  la víctima, solo añadiendo, nunca quitando.

Las tasas se recorren en una rejilla geométrica, sin suponer monotonía en la tasa: al
atacante le basta con una tasa silenciosa, y los detectores sin estructura monótona no
tienen por qué ser monótonos en ella. En los detectores monótonos, las operaciones
gratuitas solo aumentan la evidencia, así que la mejor variante es el ataque simple, y
en los detectores certificados se presenta además la frontera certificada. El mismo
procedimiento se aplica a los detectores de comparación (un núcleo sin restricciones,
umbrales de tasa, KitNET), lo que convierte la comparación en una de daño bajo el mismo
atacante.

## Envenenamiento de la línea base

Las operaciones gratuitas no pueden reducir la evidencia del día que se está puntuando,
pero un atacante que envía tráfico en días *anteriores* puede subir la línea base de una
entidad y reducir así las características de exceso del día siguiente. Este es el otro
ataque adaptativo, modelado en `proteus.core.poisoning` y ejecutado por
`proteus.evaluation.poisoning`.

El atacante más fuerte de este tipo se modela así. En un despliegue, los minutos que
lanzaron una alerta se excluyen de la línea base, de modo que el propio tráfico de
envenenamiento tiene que mantenerse por debajo de la frontera. En cada minuto de
referencia, el atacante envía el ataque justo por debajo de la frontera actual; la línea
base de cada entidad que toca el ataque se recalcula con ese tráfico (nunca por debajo
de la anterior). Iterando se obtiene la frontera tras $k$ actualizaciones de la línea
base (días).

Dos mecanismos lo acotan:

- **Techo.** El núcleo usa los contadores conservados en bruto además del exceso, y los
  subnúcleos de destino en bruto y de par no tienen línea base. Incluso con una línea
  base infinita, la evidencia en bruto permanece. La frontera con la línea base fijada a
  infinito en cada entidad tocada es un límite estricto de lo que puede lograr el
  envenenamiento.
- **Límite de crecimiento.** Un límite opcional restringe cuánto puede subir una línea
  base en cada actualización, en las unidades logarítmicas de los contadores, lo que
  acota la tasa de envenenamiento por día. Un límite también restringe el crecimiento
  legítimo, y el experimento mide con qué frecuencia las líneas base benignas crecen más
  que un límite dado (`--growth-only`).

Las escalas de tiempo largas también ayudan aquí: el tráfico de envenenamiento
sostenido durante días es visible por sí mismo en los contadores de 1 h y 6 h.
