# Comprobar el certificado con paquetes

El [certificado](../concepts/certificate.md) se demuestra sobre registros de flujo, bajo
suposiciones sobre cómo convierte un exportador los paquetes en registros. Los
experimentos que aplican operaciones gratuitas directamente a los registros de flujo
(`free_ops`) heredan esas suposiciones. La comprobación a nivel de paquete elimina ese
atajo: aplica las operaciones gratuitas a *paquetes* de ataque reales, exporta tanto la
traza original como la modificada a registros de flujo con el mismo exportador, calcula
la evidencia de ambas y comprueba la cota.

## Qué se comprueba

Para una ventana de una captura real $X$ y una variante a nivel de paquete $X'$, el
certificado predice, para todo contador con decaimiento $E$ de constante de tiempo
$\tau$ y todo instante $t$,

$$
E_{X'}(t + \Delta) \;\ge\; e^{-2\Delta/\tau}\, E_X(t).
$$

`proteus.evaluation.packet_check` comprueba esta desigualdad al final de cada flujo de
$X$ para:

- los contadores de **servicio de destino** y **host de destino** de la víctima, y
- los contadores de **host de origen** y de **par origen–servicio** de cada atacante,

en todos los contadores conservados y escalas de tiempo (por defecto
$\tau \in \{10, 60, 600, 3600, 21600\}$ s). Informa del número de violaciones (lo
esperado: ninguna) y del cociente observado más ajustado
$E_{X'}(t + \Delta) / E_X(t)$ junto a la cota $e^{-2\Delta/\tau}$. La primera variante
es la identidad, como comprobación de cordura.

## Componentes

| Módulo | Función |
|---|---|
| `proteus.packets.pcap` | Lee paquetes IPv4 TCP/UDP de un fichero pcap o pcapng (con `dpkt`), quedándose con los paquetes desde o hacia unos hosts dados en una ventana de tiempo |
| `proteus.packets.exporter` | Convierte paquetes en registros de flujo bidireccionales, como haría un exportador NetFlow/IPFIX |
| `proteus.packets.ops` | Operaciones gratuitas sobre los propios paquetes del atacante |
| `proteus.evidence.features` | El mismo cálculo de evidencia que se usa en todo lo demás |

El exportador identifica un flujo por su 5-tupla, toma como iniciador al emisor del
primer paquete y exporta un registro cuando:

- el flujo lleva activo `active_s` (el tiempo de espera activo $\Delta$);
- no se ha visto ningún paquete durante `idle_s` (tiempo de inactividad);
- se ve un RST, o ambos lados han enviado un FIN.

Así, cada paquete se contabiliza en un registro cuyo instante final está entre el
instante del paquete y $\Delta$ después, que es la premisa del certificado.

## Operaciones gratuitas sobre paquetes

Ninguna de estas operaciones elimina ni retrasa un paquete del atacante. Añaden bytes,
añaden paquetes o cambian campos de cabecera que controla el atacante, lo que puede
cambiar cómo se agrupan los paquetes en flujos.

| Operación | Función | Qué hace | Efecto sobre los registros |
|---|---|---|---|
| Relleno | `ops.pad` | Añade un número fijo de bytes a cada paquete del atacante | Más bytes |
| Paquetes insertados | `ops.insert` | Tras una fracción aleatoria de los paquetes del atacante, envía un paquete pequeño más de la misma conexión (p. ej., un ACK duplicado) | Más paquetes; puede prolongar flujos |
| Salto de puerto de origen | `ops.hop_ports` | Traslada cada conexión del atacante a un puerto de origen nuevo cada *n* de sus paquetes; las respuestas siguen al nuevo puerto | Parte los registros; las partes se exportan antes |
| Señuelos | `ops.decoys` | Envía paquetes SYN sueltos desde los hosts del atacante hacia objetivos dados, repartidos a lo largo de la traza | Flujos nuevos, muchos sin respuesta |

Cada variante sortea una combinación aleatoria: relleno de 0, 40 o 400 bytes; paquetes
insertados tras el 0 %, el 20 % o el 100 % de los paquetes del atacante; salto de puerto
cada 3 o 20 paquetes, o ninguno; y 0, 500 o 5000 señuelos hacia el servicio atacado y
otro puerto de la víctima.

## Ejecución

La comprobación necesita el extra `packets` (`dpkt`) y `Friday-WorkingHours.pcap` de la
captura original de CIC-IDS2017 (consulta [Datasets](datasets.md)). La ventana usada en
el manuscrito cubre el DDoS con LOIC contra el servidor web:

```bash
PROTEUS_EVIDENCE=v3 python -m proteus.evaluation.packet_check \
    --pcap data/raw/cicids2017_pcap/Friday-WorkingHours.pcap \
    --packets experiments/outputs/packet_check/loic_packets.parquet \
    --victim 192.168.10.50 --attackers 172.16.0.1 --port 80 \
    --start 1499453400 --minutes 25 \
    --out experiments/outputs/packet_check_v3
```

o simplemente `bash scripts/reproduce.sh packets`.

| Opción | Significado |
|---|---|
| `--pcap` | Fichero de captura |
| `--packets` | Caché Parquet de los paquetes filtrados; se lee de ella si existe |
| `--victim`, `--attackers`, `--port` | Dirección de la víctima, direcciones de los atacantes y puerto atacado |
| `--start`, `--minutes` | Inicio de la ventana (segundos desde epoch) y duración |
| `--delta` | Tiempo de espera activo del exportador $\Delta$ (por defecto 120 s) |
| `--variants` | Número de variantes, la primera de ellas la identidad (por defecto 12) |
| `--taus` | Constantes de tiempo comprobadas |
| `--seed`, `--out` | Semilla y directorio de salida |

Leer el pcap es la parte lenta; la caché `--packets` hace rápidas las ejecuciones
posteriores. Los resultados se escriben en `packet_check_<victim>_<port>.csv` dentro del
directorio de salida, con una fila por variante, contador y entidad: puntos
comprobados, violaciones, el cociente más ajustado y la cota.

## Qué encontró

Además de confirmar la cota para los contadores conservados, la comprobación a nivel de
paquete es lo que permitió descubrir que las **duraciones de las conexiones** no se
conservan. El salto de puerto de origen parte una conexión en varios registros, y los
huecos entre las partes desaparecen de los registros, mientras que el servidor puede
mantener abierta la conexión abandonada. Los experimentos a nivel de flujo no podían
mostrarlo, porque modifican los registros directamente. Desde entonces, los segundos de
conexión se clasifican como no conservados y se excluyen del núcleo monótono (consulta
[Evidencia conservada](../concepts/conserved-evidence.md#las-duraciones-no-se-conservan)).
