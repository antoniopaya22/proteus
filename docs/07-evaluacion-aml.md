# 7. Evaluación frente a AML (borrador, 2026-11-11)

Hasta la fase 1 solo se ha comprobado que Proteus **detecta** bien y que su garantía
es correcta en teoría y en tests. **Todavía no se ha atacado.** Este documento fija
cómo hacerlo para que el resultado sea comparable con el estado del arte y, a la
vez, honesto sobre qué ataques son realistas. Se completará con la revisión de
defensas en curso (doc 08).

## 7.1 Dos espacios de ataque, dos preguntas

| | Espacio de características | Espacio del tráfico (problema) |
|---|---|---|
| Qué modifica el atacante | Los números del vector de entrada | Los paquetes y flujos que emiten sus máquinas |
| Quién lo usa | Casi toda la literatura AML-NIDS (ZOO, HSJA, C&W, PGD, GAN), Apollon v1 | NetMasquerade (NDSS 2026), Domico et al. (RL), relleno adversario |
| Restricciones | Ninguna o pocas (características "funcionales") | Las de la red: no puede quitar paquetes que el ataque necesita |
| Qué responde | Comparabilidad con el estado del arte | Robustez real |

Proteus solo promete la segunda. En el espacio de características, un atacante sin
restricciones puede "bajar" un contador sin coste, cosa imposible en la red; con
eso cualquier detector cae. El paper debe mostrar las dos cosas y separarlas:

1. **Ataques de característica, como el estado del arte**, sobre el clasificador por
   flujo (la cáscara) y sobre los baselines. Mismos ataques, presupuestos y
   métricas que los papers con los que nos comparamos.
2. **Ataques de característica sobre el núcleo**, en dos versiones:
   - **sin restricciones**: se informa, pero se explica que no es realizable;
   - **realizables**: el atacante solo puede mover las características como lo
     harían sus operaciones gratuitas (subir conteos, nunca bajarlos; re-temporizar
     dentro de Δ). Aquí la garantía dice que el éxito es 0 para las alertas
     certificadas, y se comprueba empíricamente.
3. **Ataques en el espacio del tráfico**, sobre registros de flujo (operadores de
   `proteus.attacks`) y, en la fase 3, sobre pcaps reproducidos.

## 7.2 Ataques

| Grupo | Ataques | Contra |
|---|---|---|
| Transferencia | ejemplos generados contra modelos sustitutos | todos |
| Consulta, característica | ZOO, HSJA (como v1); PGD/C&W cuando hay gradiente | cáscara, baselines, Apollon v1 |
| Consulta, tráfico | NetMasquerade (código público), RL de Domico et al. | Proteus completo, baselines |
| Gratuitos combinados | relleno, inserción, señuelos, división, cambio de puertos | núcleo (garantía), cáscara |
| Costosos | ralentizar, repartir entre orígenes | frontera de daño |
| Adaptativos | envenenar la línea base, sondear la cáscara para no subir contadores, inflar alertas | Proteus completo |

## 7.3 Métricas

- **Éxito del ataque (ASR)** frente al presupuesto de consultas.
- **Recall certificado**: campañas con al menos una alerta certificada.
- **Frontera de daño**: tasa máxima sin alerta, normal y certificada, en unidades del
  ataque (intentos/h, puertos/h, peticiones/s).
- **Rendimiento en limpio** en el formato de cada paper de referencia (F1 por flujo,
  FPR) y en el nuestro (campañas, tiempo hasta detección, falsas alarmas/hora).
- **Coste**: latencia por flujo y memoria por entidad.

## 7.4 Rendimiento en entornos normales

El núcleo mide por entidad y campaña; los papers de referencia dan F1 por flujo,
casi siempre con particiones aleatorias dentro de un mismo dataset. Para no quedar
por debajo:

- la cáscara por flujo debe igualar a los clasificadores por flujo de referencia en
  su protocolo (partición aleatoria, mismo dataset);
- el sistema completo (núcleo O cáscara) se reporta también por flujo;
- se añaden los protocolos exigentes (temporal y entre datasets), donde el
  estado del arte suele caer, como aportación metodológica.

## 7.5 Pendiente

- Elegir las 3–5 defensas de referencia y sus datasets (doc 08).
- Implementar la cáscara (fase 5 del plan, se adelanta).
- Integrar ZOO/HSJA (ART) y NetMasquerade.
