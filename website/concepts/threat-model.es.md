# Modelo de amenaza

Esta página recoge lo que Proteus supone sobre la red, el atacante y el despliegue, y lo
que queda fuera de su alcance.

## Contexto

Proteus supervisa una red desde un punto de observación que ve el tráfico de los hosts
protegidos y lo resume como **registros de flujo** (NetFlow/IPFIX). El detector solo usa
campos que proporciona cualquier exportador de flujos:

- extremos, puertos y protocolo;
- instantes de inicio y fin;
- recuentos de paquetes y bytes por dirección;
- flags TCP (en particular, los resets que envía el que responde).

El exportador de flujos emite un registro cuando un flujo termina o, en los flujos
largos, tras un **tiempo de espera activo** $\Delta$ elegido por el defensor. Por tanto,
cada paquete se contabiliza como mucho $\Delta$ después de enviarse. En los datasets CIC,
$\Delta = 120$ s.

Se consideran dos despliegues:

- **Pasivo.** El detector lanza alertas; el atacante no ve nada.
- **En línea.** Una alerta también bloquea el origen infractor, lo que da al atacante
  una señal de paso/bloqueo que puede consultar.

## Objetivo del atacante

El atacante quiere completar un ataque (agotar un servicio, encontrar puertos abiertos,
adivinar credenciales) sin generar alertas. Los ataques se miden por lo que consiguen
por unidad de tiempo: peticiones por segundo contra la víctima, puertos sondeados por
hora, intentos de autenticación por hora. Un ataque que nunca genera alertas pero no
consigue nada no es un éxito. Por eso la [frontera de daño](harm-frontier.md) se
expresa como una tasa.

## Capacidades

El atacante controla los paquetes que envían sus propios hosts, y nada más. No puede:

- modificar el tráfico de otros hosts;
- cambiar las respuestas de la víctima más allá de lo que provocan sus propias
  peticiones;
- manipular el sensor, el exportador ni el detector;
- inyectar datos de entrenamiento.

Puede controlar varios orígenes, con un coste proporcional a su número. También puede
actuar en días anteriores para desplazar las líneas base por entidad (envenenamiento de
la línea base), lo que se evalúa como un ataque adaptativo.

## Conocimiento

| Nivel | Conoce | Se usa para evaluar |
|---|---|---|
| Transferencia | Nada del detector desplegado; construye el tráfico contra modelos sustitutos | Capa por flujo y detectores de comparación |
| Consultas | La señal de paso/bloqueo en línea | Capa por flujo, contador de realimentación |
| Conocimiento completo | El diseño, las características, el modelo entrenado, los umbrales y las líneas base | El certificado y la frontera de daño |

El certificado no depende de ningún secreto. Se cumple frente al atacante con
conocimiento completo.

## Operaciones gratuitas y costosas

Las operaciones sobre una traza de ataque se dividen según su coste para el atacante.

Las operaciones **gratuitas** no reducen el efecto del ataque:

| Operación | Efecto sobre la evidencia | Lo cubre |
|---|---|---|
| Relleno de paquetes, insertar paquetes en un flujo | Los bytes y paquetes solo crecen | Certificado (exacto) |
| Flujos señuelo, tráfico de apariencia benigna (dilución) | Solo se añaden eventos | Certificado (exacto) |
| Cambiar los puertos de origen | Ninguno; los contadores ignoran los puertos de origen | Certificado (exacto) |
| Partir un flujo, mantener un flujo abierto | El instante de contabilización se desplaza como mucho $\Delta$ | Certificado (holgura $2\Delta/\tau$) |
| Cambiar flags, opciones, orden de paquetes, tiempos entre llegadas | No los usa el núcleo | — |
| Reutilizar una conexión para muchas peticiones | Bajan los recuentos por conexión | Peor caso de reutilización |
| Pedir respuestas pequeñas | Baja el volumen de respuesta | Los contadores de respuesta no están en el núcleo |
| Abandonar una conexión por otra nueva | Bajan las duraciones de los registros | Las duraciones no están en el núcleo |

Las operaciones **costosas** reducen el efecto del ataque o requieren recursos:

| Operación | Efecto sobre la evidencia | Lo cubre |
|---|---|---|
| Enviar a menor tasa, hacer menos | La evidencia baja con el ataque | Frontera de daño |
| Repartir entre más orígenes | La evidencia del lado del origen se divide | Evidencia de destino; frontera de daño |
| Subir las líneas base a lo largo de días (envenenamiento) | Baja el exceso sobre la línea base | Subnúcleos en bruto y de par; límite de crecimiento |
| Sondear la capa en línea | Las sondas bloqueadas se acumulan contra el origen | Contador de realimentación |

El relleno y los paquetes insertados son gratuitos siempre que el atacante no esté
limitado por su propio ancho de banda. Una inundación que ya satura el enlace de subida
del atacante paga el relleno con tasa; la frontera certificada cubre esa combinación.

## Suposiciones

- **Retardo de exportación acotado.** El exportador tiene un tiempo de espera activo
  $\Delta$ finito. El `conn.log` de Zeek solo emite las conexiones largas cuando
  terminan, así que la garantía no está acotada en los datasets construidos a partir de
  él (CTU-SME-11).
- **Exportación de flujos honesta.** Los registros reflejan los paquetes en la red; el
  exportador no está comprometido y no descarta registros de forma selectiva.
- **Respuestas del lado del objetivo.** Los resets y las respuestas ausentes los produce
  el objetivo. Un atacante capaz de hacer que un puerto cerrado responda queda fuera del
  modelo para esos contadores.
- **Datos de calibración benignos.** Los umbrales y los máximos calibrados se ajustan
  sobre tráfico benigno de la red de despliegue. Los minutos que lanzaron alertas se
  excluyen de las líneas base.

## Fuera del alcance

- **Ataques sin huella agregada**, como una única petición de explotación o una
  inyección SQL en una sola conexión. Una petición benigna puede parecer idéntica a
  nivel de flujo, así que ningún detector basado en flujos puede detectarlos con
  garantía. Proteus los cubre con la capa por flujo no certificada y declara este
  límite.
- **Compromiso del sensor, del exportador o de la cadena de entrenamiento.**
- **Inundación de alertas.** El número de alertas por entidad está acotado por el
  número de entidades y de escalas de tiempo, lo que limita su efecto, pero no forma
  parte de la garantía.
- **Suplantación del origen para la atribución.** Con orígenes UDP falsificados, la
  alerta sobre el destino es correcta, pero el origen que señala puede no ser el
  atacante.
- **Inspección de contenido.** Proteus no examina las cargas útiles; funciona igual
  sobre tráfico cifrado.
