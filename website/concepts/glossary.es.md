# Glosario

Definiciones llanas de los términos que se usan en esta documentación.

| Término | Significado |
|---|---|
| **Registro de flujo** | Resumen de una conexión tal como lo exporta un router o un sensor: quién habló con quién, cuándo, y cuántos paquetes y bytes fueron en cada sentido. Proteus trabaja con ellos, no con el contenido de los paquetes. |
| **Entidad** | Aquello sobre lo que trata una alerta: un servicio de destino (dirección y puerto), una máquina de destino, una máquina de origen o un par origen–servicio. |
| **Contador (marcador)** | Un total acumulado por entidad, como las conexiones recibidas o los orígenes distintos vistos. Se va borrando con el tiempo; la *escala de tiempo* dice a qué ritmo (de diez segundos a seis horas). |
| **Línea base** | El nivel normal de un contador para una entidad, aprendido de días corrientes de la misma red. |
| **Operación gratuita** | Algo que un atacante puede hacer con su propio tráfico sin debilitar el ataque: rellenar paquetes, insertar paquetes, partir una conexión, añadir conexiones señuelo, cambiar puertos de origen. |
| **Operación costosa** | Algo que sí debilita el ataque o exige recursos: enviar menos, ir más despacio, usar muchas máquinas. |
| **Evidencia conservada** | Contadores que las operaciones gratuitas solo pueden mantener o subir, nunca bajar. |
| **Modelo monótono** | Un modelo cuya puntuación no puede bajar cuando sube cualquiera de sus entradas. |
| **Alerta** | Proteus diciendo que una entidad está siendo atacada ahora, con los contadores que la han disparado. |
| **Alerta certificada** | Una alerta con la prueba de que ninguna combinación de operaciones gratuitas la habría evitado. |
| **Holgura** | Lo poco que puede bajar un contador por el *momento* en que el sensor contabiliza los paquetes. El certificado la resta antes de volver a comprobar la alerta. |
| **Reutilización de conexiones** | Llevar muchas peticiones en una misma conexión. Baja los contadores por conexión, así que tiene su propio certificado, sobre evidencia que no puede bajar. |
| **Frontera de daño** | El ritmo de ataque más alto que no levanta ninguna alerta: lo que el atacante conserva yendo más despacio. |
| **Campaña** | Un episodio de un tipo de ataque, separado del siguiente por más de diez minutos. La detección se cuenta por campañas. |
| **Falsa alarma (por entidad)** | Una entidad alertada con tráfico benigno, contada una vez cada diez minutos. |
| **Calibración local** | Fijar los umbrales con tráfico benigno de la red que se protege, sin etiquetas de ataque de esa red. |
| **Capa por flujo** | Un detector corriente que juzga cada conexión, puesto junto al núcleo para los ataques que caben en pocas conexiones. No tiene garantía. |
| **Atacante adaptativo** | Un atacante que elige su ritmo y su disfraz de una lista de planes, conociendo el detector. |
| **Atacante por consultas** | Un atacante que no sabe nada del detector y busca un disfraz, enterándose tras cada intento solo de si fue alertado. |
