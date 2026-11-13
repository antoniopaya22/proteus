# Certificado

Una alerta de Proteus está **certificada** cuando ninguna combinación de las operaciones
gratuitas del atacante podría haberla evitado: toda variante de la traza del ataque
obtenida con operaciones gratuitas también genera alerta, como mucho $\Delta$ más tarde.
Comprobarlo cuesta una evaluación adicional del núcleo por alerta. Esta página explica
por qué.

## Paso 1: las operaciones gratuitas solo añaden, o retemporizan como mucho Δ

Las operaciones gratuitas actúan sobre los registros de flujo de dos maneras.

- **Adiciones puras.** El relleno, insertar paquetes en un flujo, enviar flujos señuelo
  y cambiar los puertos de origen solo añaden peso a eventos existentes o añaden
  eventos nuevos. Cada contador con decaimiento de cada variante es, en todo instante,
  al menos el original.
- **Retemporización.** Partir un flujo, o mantenerlo abierto añadiendo paquetes, cambia
  además *cuándo* contabiliza el exportador sus paquetes. Las partes de un flujo
  partido se exportan antes; un flujo prolongado se exporta después.

La retemporización está acotada por el exportador. Un exportador NetFlow/IPFIX emite un
registro cuando un flujo termina, tras un tiempo de inactividad o, en los flujos
largos, tras el **tiempo de espera activo del exportador** $\Delta$. Por tanto, cada
paquete se contabiliza en un registro cuyo instante de evento está entre el instante
de envío del paquete y $\Delta$ después, tanto en la traza original como en cualquier
variante.

## Paso 2: una cota para cada contador

Sea un contador con decaimiento de constante de tiempo $\tau$. En la traza original
$X$, un paquete enviado en el instante $p$ se contabiliza en algún
$t_r \in [p, p + \Delta]$. En una variante $X'$, el mismo paquete se contabiliza en
algún $t'_r \in [p, p + \Delta]$, así que $t_r - \Delta \le t'_r \le t_r + \Delta$.
Comparemos el contador de $X'$ en $t + \Delta$ con el de $X$ en $t$. Todo paquete
contado en $X$ hasta el instante $t$ ya está contado en $X'$ hasta el instante
$t + \Delta$, y su contribución ha decaído como mucho durante $2\Delta$ más. La variante
puede tener más contribuciones, nunca menos. Por tanto, para toda entidad $e$, peso $w$ e instante $t$:

$$
C^{w}_{e,\tau}[X'](t + \Delta) \;\ge\; e^{-2\Delta/\tau}\; C^{w}_{e,\tau}[X](t).
$$

La misma cota vale para los recuentos de elementos distintos con decaimiento, porque el
último instante en que se vio cada elemento también se desplaza como mucho $\Delta$.
Cuando ninguna operación retemporiza un flujo, la cota vale con $\Delta = 0$: la
evidencia nunca disminuye.

Las características están en escala $\log(1 + \cdot)$, y
$\log(1 + a c) \ge \log(1 + c) + \log a$ para $0 < a \le 1$. Así, toda característica
de evidencia de cualquier variante, leída $\Delta$ más tarde, es al menos la
característica original menos una **holgura**

$$
s_\tau = \frac{2\Delta}{\tau}.
$$

Las líneas base están fijas mientras se puntúa un día, así que las características de
línea base no necesitan holgura. El exceso $x - b$ hereda la holgura de $x$.

## Paso 3: una evaluación adicional

Sea $s$ el vector de holguras, una por característica, y $f$ el núcleo monótono. Toda
variante obtenida con operaciones gratuitas tiene características al menos $x - s$ en
el instante correspondiente, y $f$ es monótono, así que

$$
f(x') \;\ge\; f(x - s) \quad \text{for every variant } x'.
$$

El peor caso sobre el conjunto infinito de variantes es una única evaluación. Una
alerta está certificada cuando

$$
f(x - s) \;\ge\; \theta,
$$

donde $\theta$ es el umbral local. Entonces la misma entidad genera alerta en todas las
variantes, como mucho $\Delta$ más tarde. Este es el cálculo de
`proteus.core.certify`: `slack` construye $s$ a partir de la constante de tiempo
codificada en el nombre de cada característica, y `worst_case_features` devuelve
$x - s$.

No interviene ninguna aleatorización, ningún secreto ni ningún presupuesto de
perturbación sobre las características. La garantía se cumple frente a un atacante que
conoce el modelo, sus pesos, las líneas base y los umbrales.

## Holgura por escala de tiempo

La holgura solo depende del tiempo de espera activo del exportador y de la constante de
tiempo del contador. Para $\Delta = 120$ s, el tiempo de espera activo del exportador
usado en los datasets CIC:

| τ | Holgura $2\Delta/\tau$ (unidades logarítmicas) | Fracción de la evidencia garantizada, $e^{-2\Delta/\tau}$ |
|---|---|---|
| 10 s | 24 | ≈ 4 × 10⁻¹¹ |
| 60 s | 4 | ≈ 0.018 |
| 600 s | 0.4 | ≈ 0.67 |
| 1 h | 0.067 | ≈ 0.94 |
| 6 h | 0.011 | ≈ 0.99 |

A diez segundos la holgura borra cualquier evidencia, así que las escalas cortas no
pueden sostener un certificado. A partir de diez minutos, la holgura es un
desplazamiento modesto. Por eso **Proteus-cert** conserva solo las escalas de 600 s o
más, mientras que **Proteus** las conserva todas por rapidez (consulta
[Núcleo monótono](monotone-core.md#proteus-y-proteus-cert)).

El defensor controla $\Delta$: reducir el tiempo de espera activo del exportador reduce
la holgura en todas las escalas.

## Temporizador de re-puntuación δ

"Toda variante genera alerta como mucho $\Delta$ más tarde" presupone que el detector
mira la entidad en ese momento. Un detector que solo puntúa una entidad cuando llega uno
de sus registros podría no hacerlo. Por eso un despliegue también vuelve a puntuar las
entidades activas con un temporizador de periodo $\delta$. La alerta de una variante
llega entonces, como tarde, en $t + \Delta + \delta$, y la holgura pasa a ser

$$
s_\tau = \frac{2\Delta + \delta}{\tau}.
$$

En el código, `slack(..., timer_s=δ)` implementa esto, y los experimentos fijan
$\delta$ con la variable de entorno `PROTEUS_TIMER_S` (0 por defecto).

## Reutilización de conexiones

Transportar muchas peticiones en una conexión (HTTP keep-alive, varios intentos de
inicio de sesión por sesión SSH) es gratuito para muchos ataques, y reduce los
recuentos por conexión. La cota anterior no lo cubre, porque fusiona registros en lugar
de añadirlos o retemporizarlos.

Proteus trata la reutilización de conexiones como un segundo peor caso del mismo modelo
(`reuse_worst_case`). Partiendo de $x - s$:

- los contadores por conexión (`flows`, `rst`, `noreply`) pasan a su mínimo;
- los contadores de paquetes en sentido directo bajan como mucho en un factor $c = 5$,
  es decir, en $\log 5$ en la escala logarítmica (paquetes de establecimiento y cierre
  de conexión ahorrados por petición);
- los bytes en sentido directo y los recuentos de elementos distintos no cambian.

El factor $c$ es una suposición sobre el protocolo: una conexión añade unos cuatro
paquetes en sentido directo de establecimiento y cierre, así que $c = 5$ se cumple
cuando cada petición lleva al menos un paquete propio en sentido directo. Una alerta que
resiste este segundo peor caso está certificada frente a las operaciones gratuitas
combinadas con cualquier reutilización de conexiones, bajo esa suposición.

## Suposiciones

El certificado se cumple cuando:

1. **Retardo de contabilización acotado.** Cada paquete se contabiliza en un registro
   de flujo cuyo instante de evento es, como mucho, $\Delta$ posterior al envío del
   paquete. Esto se cumple en los exportadores NetFlow/IPFIX con tiempo de espera
   activo; no se cumple en los registradores que emiten una conexión larga solo cuando
   termina, como el `conn.log` de Zeek.
2. **Las operaciones gratuitas mantienen el ataque.** Mantienen cada paquete de la
   traza con su instante de envío, sus direcciones, su puerto de destino y su
   protocolo, y solo añaden peso o paquetes.
3. **Sin fusiones.** No fusionan los registros de conexiones distintas. Fusionar es
   reutilizar conexiones, que se trata como un peor caso aparte.
4. **Respuestas del lado del objetivo.** La víctima reinicia, o deja sin respuesta, los
   flujos del atacante en la variante siempre que lo hacía en el original. Esto se
   cumple cuando la respuesta ausente procede del objetivo (un host inexistente, un
   puerto cerrado o filtrado), como en los escaneos. Un atacante que pueda provocar
   respuestas eligiendo sus peticiones puede reducir los recuentos de resets y de
   flujos sin respuesta, y una alerta que se apoye solo en ellos no está certificada
   frente a esa elección.

## Qué no cubre el certificado

| No cubierto | Dónde se trata |
|---|---|
| Enviar a menor tasa, o hacer menos | La [frontera de daño](harm-frontier.md) mide la mayor tasa que pasa desapercibida, simple y certificada. |
| Envenenar las líneas base actuando en días anteriores | Se evalúa como un ataque adaptativo; lo acotan los subnúcleos en bruto y un límite de crecimiento opcional. Consulta [Frontera de daño](harm-frontier.md#envenenamiento-de-la-linea-base). |
| Pedir respuestas pequeñas | Los contadores de respuesta se excluyen del núcleo. |
| Ataques sin huella agregada | Solo los cubre la capa por flujo no certificada. |
| Exportadores sin tiempo de espera activo | La cota necesita un $\Delta$ finito. |

El certificado trata sobre la evidencia y el modelo. No dice nada sobre si el umbral
está bien elegido; eso depende del presupuesto de falsas alarmas de la red.

!!! note "Comprobarlo empíricamente"
    La cota está demostrada, pero sus premisas son fáciles de romper en el código (una
    característica mal clasificada como conservada, un detalle del exportador). El
    repositorio la comprueba sobre registros de flujo (`proteus.evaluation.free_ops`) y
    sobre paquetes reales reexportados como flujos (`proteus.evaluation.packet_check`,
    consulta [Comprobar el certificado con paquetes](../guide/packets.md)).
