# 3. Propuesta: sucesor de Apollon

Fecha: 2026-11-10. Nombre del sistema: **Proteus**.

**Documento superado.** Es el esbozo inicial, basado en un pool de modelos con
selector. El diseño vigente (evidencia conservada y núcleo monótono) está en
`04-diseno-proteus.md` y el plan en `05-plan-de-trabajo.md`. Se conserva como
registro de por qué se descartó ese camino.

## 3.1 Tesis del paper

Paper de tipo "romper y arreglar":

1. Un ataque directo y adaptativo muestra que Apollon v1, y las mezclas aleatorias
   ingenuas en general, no resisten a un atacante que consulta el sistema.
2. Un sistema nuevo eleva de forma medible el coste en consultas del atacante,
   evaluado contra los ataques amortizados de 2026 y en espacio de tráfico.

El claim es "coste de consultas medido más detección de sondeo", no "robusto". Los
ensembles aleatorios no son robustos por sí mismos (ARC, ICML 2022).

## 3.2 Modelo de amenaza

- Atacante externo que solo observa si su tráfico pasa o se bloquea.
- Controla únicamente sus propios hosts (perturbaciones host-space).
- Tiene un presupuesto de sondas.
- Conoce el diseño del sistema, pero no la clave secreta ni los pesos.

## 3.3 Diseño

1. **El pool pesa más que el selector.** Si una perturbación factible engaña a todos
   los modelos, ninguna política de selección ayuda. El pool se construye para
   minimizar la transferencia cruzada:
   - vistas distintas del tráfico (estadísticas de flujo, secuencia de paquetes,
     grafo de hosts);
   - subconjuntos de características disjuntos;
   - al menos un modelo que solo use características que el atacante no puede
     perturbar.
2. **Selector como juego.** Se mide la matriz de transferencia `T[i][j]`: éxito
   sobre el modelo `j` de un ejemplo creado contra el modelo `i`. Se resuelve el
   minimax para la mezcla `p` con un suelo de entropía. El valor del juego es una
   cota medible del éxito del atacante.
3. **Selección con clave, no aleatoria por consulta.** El modelo se elige con una
   función pseudoaleatoria de (flujo, clave secreta, época):
   - la misma sonda recibe siempre la misma respuesta, así que el atacante no puede
     promediar;
   - la clave rota por época o por presupuesto de consultas, como en Morphence, y lo
     aprendido caduca.

   Esto responde al dato de NetMasquerade: un 30% de ruido solo ralentiza el ataque.
4. **Capa con estado.** Huella por origen de sondas casi idénticas, adaptada a
   flujos (estilo QPA). Ante sospecha: rotación anticipada de clave, ensemble
   completo o respuesta señuelo.
5. **Actualización sin etiquetas.** El selector se ajusta con el desacuerdo entre
   modelos y el feedback diferido del analista, con protección ante envenenamiento
   lento.
6. **Brazo certificado (opcional).** Smoothing solo sobre las características
   perturbables, como en TA-RS.

## 3.4 Evaluación

Preguntas de investigación:

1. ¿Cuántas consultas cuesta romper v1, una mezcla estática, MTD-AD y el nuevo
   sistema?
2. ¿Cuánto aporta cada pieza (pool, selector, clave, capa con estado)?
3. ¿Se sostiene el resultado en espacio de tráfico?
4. ¿Qué cuesta en tráfico limpio y en latencia?

Protocolo:

- **Ataques.** Siempre contra el sistema completo, nunca contra modelos sueltos:
  NetMasquerade, política RL de Domico et al., HSJA y ZOO con presupuesto alto,
  extracción con surrogate, ARC sobre la mezcla y un ataque adaptativo propio que
  conoce el diseño.
- **Métricas.** Éxito del ataque frente al número de consultas (métrica principal);
  F1 y precisión de la clase ataque, no macro; tasa de falsos positivos; throughput
  y latencia.
- **Datos.** Versiones corregidas de CIC-IDS-2017 y CSE-CIC-IDS-2018,
  CIC-UNSW-NB15, un dataset de IoT y al menos una prueba con pcap reproducido.
- **Baselines.** Apollon v1 reimplementado, mejor modelo único, ensemble por voto,
  adversarial training, MTD-AD, y BARS o TA-RS.
- **Ablaciones.** Quitar una pieza cada vez: diversidad del pool, minimax frente a
  mezcla uniforme, clave frente a aleatoriedad por consulta, capa con estado.

## 3.5 Riesgos

| Riesgo | Mitigación |
|---|---|
| La diversidad baja la precisión en limpio | Informar la curva robustez–precisión, no un solo punto |
| El ataque adaptativo propio rompe el sistema | Publicar igualmente la cota; el claim es coste medido, no inmunidad |
| Reproducir NetMasquerade es caro | Empezar con Domico et al. (más simple) y HSJA directo |
| El repo público de v1 no es el código del paper | Aclararlo antes de describir v1 (ver documento 1, sección 1.3) |

## 3.6 Plan de trabajo

1. Reimplementar v1 de forma fiel y atacarlo directamente. Si no se rompe, el paper
   cambia de enfoque.
2. Construir el pool y medir la matriz de transferencia.
3. Implementar el selector con clave y la rotación.
4. Añadir la capa con estado.
5. Evaluación completa, ablaciones y redacción.

Venue: IEEE TDSC o TIFS si el minimax da una cota limpia; Computers & Security si el
resultado queda empírico. La plantilla en `paper/` usa `elsarticle` (Elsevier).

## 3.7 Nombre

El sistema se llama **Proteus**. En el mito, Proteo cambia de forma para escapar y
Menelao lo vence sujetándolo a través de todas las transformaciones. "Artemis" quedó
descartado.
