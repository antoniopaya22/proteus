# Evidencia conservada

La mayoría de los detectores basados en flujos clasifican cada flujo a partir de sus
estadísticas: tamaños de paquete, tiempos entre llegadas, recuentos de flags, cocientes
entre direcciones. Un atacante controla casi todas ellas en su propio tráfico y puede
moverlas en cualquier sentido sin coste para el ataque. Proteus usa otro tipo de
entrada: contadores por entidad que las operaciones gratuitas del atacante solo pueden
aumentar.

## Qué se conserva

Una evidencia está **conservada** si ninguna operación gratuita del atacante puede
reducirla. Las operaciones gratuitas son las que no reducen lo que consigue el ataque:
relleno de paquetes, insertar paquetes adicionales, partir un flujo en varios, enviar
flujos señuelo, cambiar los puertos de origen (consulta el
[Modelo de amenaza](threat-model.md)). Todas tienen algo en común: *añaden* bytes,
paquetes o flujos, o reagrupan los mismos paquetes en registros distintos. Nunca
eliminan un paquete que el ataque necesita.

Los recuentos de eventos por entidad, por tanto, solo crecen bajo estas operaciones,
siempre que se respeten dos reglas:

- **Recuentos, nunca cocientes.** Un cociente como intentos fallidos entre intentos
  totales se puede diluir añadiendo tráfico de apariencia benigna. El recuento de
  intentos fallidos, no.
- **Solo lo que envía el atacante, o lo que no puede influir.** Los paquetes y bytes en
  sentido directo los envía el atacante. Los resets y las respuestas ausentes proceden
  del objetivo, y el atacante no puede convertir un flujo sin respuesta en uno con
  respuesta si el host o el puerto no responde. El *volumen* de las respuestas de la
  víctima, en cambio, puede reducirse pidiendo recursos pequeños, así que no se
  conserva.

## Entidades y contadores

Cada registro de flujo es un evento en el instante de su último paquete, cuando lo
emitiría un exportador. El registro contribuye a cuatro entidades:

| Entidad | Clave | Propósito |
|---|---|---|
| Servicio de destino (`dsvc`) | IP de destino, puerto de destino, protocolo | Volumen e intentos contra un servicio |
| Host de destino (`dhost`) | IP de destino | Actividad contra un host a través de sus puertos |
| Host de origen (`shost`) | IP de origen | Lo que hace un origen a través de los destinos (escaneos horizontales) |
| Par origen–servicio (`spair`) | IP de origen, IP de destino, puerto, protocolo | Un origen que insiste sobre un servicio (fuerza bruta), algo que de otro modo se diluye en el tráfico total del servicio |

Para cada entidad, Proteus mantiene sumas con decaimiento exponencial de los pesos de
los eventos,

$$
C^{w}_{e,\tau}(t) = \sum_{r \in e,\ t_r \le t} w(r)\, e^{-(t - t_r)/\tau},
$$

y recuentos de elementos distintos con decaimiento,

$$
D_{e,\tau}(t) = \sum_{j} e^{-(t - \ell_j(t))/\tau},
$$

donde $\ell_j(t)$ es el último instante en que se vio el elemento $j$ (un puerto, un
interlocutor, un servicio). Repetir un elemento no infla $D$, e insertar eventos solo
retrasa $\ell_j$ o añade elementos, así que ambas cantidades son no decrecientes al
insertar eventos. Las características son $\log(1 + C)$ y $\log(1 + D)$.

| Peso | Significado | Clase |
|---|---|---|
| `flows` | uno por registro de flujo | conservado (salvo con reutilización de conexiones) |
| `fpkts` | paquetes en sentido directo | conservado |
| `fbytes` | bytes en sentido directo | conservado |
| `rst` | flujos reiniciados por el que responde | conservado |
| `noreply` | flujos sin ningún paquete de vuelta (versión 2 de la evidencia y posteriores) | conservado |
| `bpkts`, `bbytes` | paquetes y bytes en sentido inverso | respuesta: excluido del núcleo monótono |
| `conn_s` | segundos de conexión (duraciones de los flujos) | no conservado: excluido del núcleo monótono |

| Entidad | Recuentos de elementos distintos |
|---|---|
| `dsvc` | orígenes |
| `dhost` | orígenes, puertos de destino |
| `shost` | hosts de destino, servicios de destino, hosts de destino sin respuesta (versión 2 y posteriores) |
| `spair` | ninguno; solo `flows`, `fbytes`, `rst` y `noreply` |

Los nombres de las características siguen el patrón `<entity>__<counter>__t<τ>`, por
ejemplo `dsvc__flows__t600` o `shost__n_dhost_nr__t3600`.

## Escalas de tiempo

Cada contador se mantiene con varias constantes de tiempo:

| τ | Captura |
|---|---|
| 10 s, 60 s | Ráfagas: inundaciones, escaneos rápidos |
| 600 s | Actividad sostenida durante minutos |
| 1 h, 6 h | Ataques lentos que se acumulan durante horas (versión 3 de la evidencia) |

Los contadores con decaimiento no tienen bordes de ventana en torno a los cuales un
atacante pueda temporizar su tráfico. Las dos escalas largas solo se mantienen para
contadores que un ataque lento no puede evitar acumular: flujos, bytes en sentido
directo, resets, flujos sin respuesta y recuentos de elementos distintos. Las escalas
largas también importan para el [certificado](certificate.md): la holgura que debe
admitir se reduce como $2\Delta/\tau$.

## Líneas base y exceso

Un servidor DNS muy cargado y un servidor web inactivo no deberían compartir umbral.
Para cada entidad y característica, Proteus calcula una **línea base** a partir de
otros días de la misma red, sin etiquetas: el percentil 95, sobre todos los minutos del
periodo de referencia, del máximo por minuto de la característica (0 en los minutos en
que la entidad estuvo inactiva). Los servicios poco usados tienen así una línea base
de 0.

- Los días de referencia son o bien todos los demás días de la captura (`loo`, dejar
  un día fuera, la configuración usada con los datasets de 5–10 días) o bien solo los
  días anteriores (`prior`, la configuración causal). En un despliegue, la referencia
  es el tráfico pasado.
- Los minutos en que la entidad estuvo bajo ataque, y los diez minutos siguientes, se
  excluyen de la línea base (en un despliegue: los minutos que lanzaron alertas).
- El núcleo recibe la característica en bruto $x$ y el **exceso** $x - b_e$, pero no la
  línea base $b_e$ por sí sola. Un modelo que recibe la línea base aprende que las
  entidades poco usadas son sospechosas y entonces marca cualquier tráfico hacia un
  destino nuevo.
- Los contadores de pares no tienen línea base: casi todos los pares son nuevos. Una
  línea base de pares opcional (`PROTEUS_PAIRBASE=1`) compara un par con el par normal
  más activo del mismo servicio, y una línea base de población opcional
  (`PROTEUS_PEER=1`) compara un servicio con los demás servicios del mismo puerto y
  protocolo. Ambas son experimentales.

La línea base está fija mientras se puntúa un día, y el exceso $x - b_e$ es creciente
en $x$, así que las líneas base no debilitan la garantía frente a las operaciones
gratuitas. Un atacante solo puede influir en una línea base enviando tráfico en días
anteriores: eso es el **envenenamiento de la línea base**, un ataque adaptativo costoso
que se evalúa por separado (consulta
[Frontera de daño](harm-frontier.md#envenenamiento-de-la-linea-base)).

## Operaciones gratuitas y su efecto

La tabla muestra cómo afecta cada operación gratuita a cada contador conservado de las
entidades del atacante. "≥" significa que el contador solo puede mantenerse igual o
crecer; "retemporizado" significa que el instante en que el exportador contabiliza
algunos paquetes se desplaza, como mucho, el tiempo de espera activo $\Delta$.

| Operación gratuita | `flows` | `fpkts` | `fbytes` | `rst`, `noreply` | recuentos de distintos | Temporización |
|---|---|---|---|---|---|---|
| Relleno de paquetes | = | = | ≥ | = | = | sin cambios |
| Insertar paquetes en un flujo | = | ≥ | ≥ | = | = | sin cambios, o retemporizado si se añaden al final |
| Enviar flujos señuelo o de apariencia benigna | ≥ | ≥ | ≥ | ≥ | ≥ | sin cambios |
| Cambiar los puertos de origen de conexiones nuevas | = | = | = | = | = | sin cambios |
| Partir un flujo (p. ej., saltar de puerto de origen a mitad de conexión) | ≥ | ≥ | = | ≥ | = | retemporizado (las partes se exportan antes) |
| Mantener un flujo abierto más tiempo | = | ≥ | ≥ | = | = | retemporizado (se exporta después) |

Las operaciones que no retemporizan flujos dan una garantía exacta: la evidencia de cada
variante es, en todo instante, al menos la evidencia del original. Las operaciones que
retemporizan flujos necesitan una holgura, que el [certificado](certificate.md) tiene en
cuenta.

Tres operaciones gratuitas *no* están en esta tabla porque reducen contadores
concretos:

- **La reutilización de conexiones** (varias peticiones en una conexión, p. ej., HTTP
  keep-alive) reduce los recuentos por conexión (`flows`, `rst`, `noreply`) y ahorra
  paquetes del establecimiento de conexión. Proteus la trata como un segundo peor caso
  con un presupuesto de protocolo explícito (consulta
  [Certificado](certificate.md#reutilizacion-de-conexiones)).
- **Pedir respuestas pequeñas** reduce el volumen de respuesta de la víctima, y por eso
  `bpkts` y `bbytes` se excluyen del núcleo monótono.
- **Abandonar una conexión por otra nueva** reduce las duraciones en los registros de
  flujo.

## Por qué las características por flujo no se conservan

Las estadísticas por flujo (tamaño medio de paquete, tiempos entre llegadas, cocientes
de flags, bytes por paquete, duración del flujo) describen *cómo* envía el atacante, no
*cuánto* hace. El atacante puede mover cada una de ellas en cualquier sentido con
relleno, paquetes adicionales o temporización, sin coste para el ataque. Un detector
construido sobre ellas se puede evadir dando forma al tráfico, y ninguna restricción de
monotonía puede arreglarlo, porque no hay ningún sentido en el que el atacante esté
limitado. Estas características siguen siendo útiles para ataques sin huella agregada,
y Proteus las usa en su capa por flujo no certificada.

## Las duraciones no se conservan

Los segundos de conexión parecen una evidencia natural de los ataques lentos de
denegación de servicio, que mantienen abiertas muchas conexiones. No se conservan. Un
atacante que traslada una conexión a un nuevo puerto de origen parte su registro de
flujo, y los huecos entre las partes se pierden de los registros, mientras que el
servidor puede mantener abierta la conexión abandonada.

Esto no era evidente solo a partir de los registros de flujo. La
[comprobación del certificado a nivel de paquete](../guide/packets.md), que aplica
operaciones gratuitas a paquetes de ataque reales y los vuelve a exportar como flujos,
lo puso de manifiesto. Desde entonces, `conn_s` se clasifica como no conservado y solo
lo usan modelos de comparación sin restricciones.
