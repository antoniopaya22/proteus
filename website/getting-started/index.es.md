# Primeros pasos

Proteus es un código de investigación. Contiene el detector, la cadena de procesamiento
de la evidencia, los conversores de datasets y todos los experimentos del manuscrito que
lo acompaña. No hay ningún servicio empaquetado que desplegar: se instala el paquete de
Python, se convierten los datasets necesarios y se ejecutan los experimentos desde la
línea de comandos.

Obtener un primer resultado lleva tres pasos.

| Paso | Qué se hace | Página |
|---|---|---|
| 1. Instalar | Crear un entorno virtual, instalar el paquete con sus extras de desarrollo y ejecutar los tests. | [Instalación](installation.md) |
| 2. Preparar los datos | Descargar un dataset CIC corregido y convertirlo al esquema común de flujos en Parquet. | [Inicio rápido](quickstart.md#2-convertir-un-dataset) |
| 3. Ejecutar una etapa | Ejecutar la etapa de detección entre redes y regenerar las tablas. | [Inicio rápido](quickstart.md#3-ejecutar-la-etapa-de-deteccion-entre-redes) |

Antes de lanzar los experimentos más grandes conviene leer
[Cómo funciona Proteus](../concepts/index.md): los resultados hablan de evidencia
conservada, subnúcleos, alertas certificadas y fronteras de daño, y esos términos se
definen allí.

!!! note "Hardware"
    Los tests unitarios se ejecutan en un portátil. Los experimentos completos se
    ejecutaron en una máquina de 16 vCPU con 32 GB de RAM, y las ejecuciones que evalúan
    sobre CSE-CIC-IDS2018 necesitan 16–18 GB cada una.
    Consulta [Instalación](installation.md#hardware).
