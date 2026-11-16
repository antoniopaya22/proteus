# 12. Cómo están escritos los papers de referencia y qué copiar (2026-11-16)

Antonio pide analizar papers relacionados y muy citados para usar su redacción y formato como
modelo. Se leyeron completos nueve artículos en dos bloques (el tercero, artículos de revista y guía
de autores de Computers & Security, se añade al final cuando termine), con la misma plantilla:
anatomía del resumen, introducción y contribuciones, modelo de amenaza, presentación del método y de
las garantías, organización de la evaluación, figuras y tablas, limitaciones y recursos de redacción.
Los recuentos de citas son de Semantic Scholar (2026-11-16); Google Scholar no se pudo consultar y
suele dar cifras más altas.

| Artículo | Sede | Citas |
|---|---|---|
| Cohen et al., *Certified Adversarial Robustness via Randomized Smoothing* | ICML 2019 | 2 756 |
| Sommer y Paxson, *Outside the Closed World* | IEEE S&P 2010 | 2 331 |
| Mirsky et al., *Kitsune* | NDSS 2018 | 1 090 |
| Arp et al., *Dos and Don'ts of Machine Learning in Computer Security* | USENIX Security 2022 | 480 |
| Pierazzi et al., *Intriguing Properties of Adversarial ML Attacks in the Problem Space* | IEEE S&P 2020 | 408 |
| Fu et al., *Whisper* | ACM CCS 2021 | 276 |
| Fu et al., *HyperVision* | NDSS 2023 | 169 |
| Tong et al., *… Realizable Evasion Attacks Using Conserved Features* | USENIX Security 2019 | 100 |
| Wang et al., *BARS* | NDSS 2023 | 29 |

Tong et al. y BARS tienen pocas citas, pero son los dos más cercanos a nuestro tema (rasgos
conservados y certificación en tráfico) y por eso se analizan.

## Síntesis: lo que hacen casi todos

1. **Una idea en una frase**, la misma en resumen, introducción y conclusión, y pocas cosas con
   nombre definidas una sola vez.
2. **Algo visual en la página 1 o 2** que enseña la idea o el mapa (no la arquitectura): una figura
   conceptual o una matriz de comparación con ✓/×.
3. **Introducción con arco fijo**: contexto, hueco explícito, «presentamos X», idea, método por
   pasos, un párrafo de cifras titulares, y dos a cinco contribuciones cortas con verbo y puntero a
   sección, casi sin cifras.
4. **Modelo de amenaza corto y pronto**, con supuestos y exclusiones dichos de forma explícita.
5. **La garantía en cuatro tiempos**: enunciado en palabras, teorema corto con nombre, cómo leerlo
   (qué no supone, qué no cubre) y esbozo de prueba con la prueba completa en el apéndice.
6. **Evaluación guiada por preguntas**: bloque fijo de configuración, métricas definidas antes de los
   resultados, una subsección por pregunta y una frase de conclusión al cerrar cada una.
7. **Discusión breve y sin resultados nuevos**: las limitaciones se dicen llanamente y una vez.

## Cambios para Proteus, por orden de valor

Los detalles (qué hace cada modelo, línea del nuestro y cambio concreto) están en las dos notas de
abajo. Estado al final de este documento.

1. **Hecho** (commit a345ff9 del paper). Contribuciones: de seis viñetas con cifras a cuatro cortas
   con puntero a sección; párrafo «Results in brief» con las cifras titulares; hoja de ruta; la idea
   en una frase («an attacker can always send more, but it cannot send less without weakening the
   attack»).
2. **Hecho.** El certificado en cuatro tiempos: enunciado en palabras, lema de conservación, teorema
   de la alerta certificada en el cuerpo, «cómo leerlo» en viñetas y esbozo de prueba.
3. **Hecho.** Tabla de supuestos (A1)–(A4): quién lo controla, cuándo falla y qué pasa entonces.
4. **Hecho** (commit siguiente). Figura conceptual del certificado en la página 2.
5. **Hecho a medias.** Tabla de variantes de Proteus en el diseño (Proteus, -cert, -cert-R, sistema).
   Falta el glosario de métricas en la configuración.
6. **Pendiente**, junto con la reescritura de las secciones que esperan resultados: evaluación en
   cuatro partes (detección; ¿se cumple el certificado?; qué conserva el adversario; tráfico real),
   con frase de conclusión por parte.
7. **Pendiente** (mismo momento): sacar de la discusión el envenenamiento y el coste.
8. **A decidir** con el bloque de revistas: modelo de amenaza antes y trabajo relacionado más corto
   o más tarde.

---

# Bloque A. Cómo están escritos cuatro artículos muy citados sobre detección de intrusiones en red

Análisis de oficio de escritura (estructura, formato, retórica), no de contenido técnico.
Fecha: 2026-11-16.

### Fuentes y verificación

| Artículo | Versión leída (texto completo) | Páginas | Citas (Semantic Scholar) |
|---|---|---|---|
| Kitsune (NDSS 2018) | arXiv:1802.09089v2 | 15 | 1 090 |
| Whisper (CCS 2021) | arXiv:2106.14707v3 (versión de cámara de ACM) | 16 (12 de cuerpo, 2 de referencias, 3 de apéndice) | 276 |
| HyperVision (NDSS 2023) | arXiv:2301.13686v1 | 18 (13,4 de cuerpo, 1,6 de referencias, 3,4 de apéndice) | 169 |
| Sommer y Paxson (IEEE S&P 2010) | PDF de los autores (icir.org) | 12 | 2 331 |

- Los cuatro se recuperaron y se leyeron completos; no hizo falta sustituir ninguno.
- Citas: API Graph de Semantic Scholar (consulta por lotes, 2026-11-16). Google Scholar no
  se consultó (bloquea el acceso automatizado) y suele dar cifras bastante más altas.
  OpenAlex devolvió 441 (Kitsune) y 255 (Whisper) antes de agotar su cuota diaria; no se
  pudo consultar para los otros dos.
- Aviso: Whisper y HyperVision quedan por debajo de 300 citas en Semantic Scholar. Se
  mantienen porque fueron pedidos expresamente y son el modelo de estilo más cercano.
- Los recuentos de palabras y frases salen de `pdftotext` y un guion propio; las cuotas por
  sección se estiman por posición en página (margen de unos 2 puntos). Los recuentos de
  figuras y tablas se comprobaron página a página.

---

#### 1. Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection

**Título.** Nombre del sistema, dos puntos, mecanismo («An Ensemble of Autoencoders») y
tarea («for Online Network Intrusion Detection»). No afirma nada; el único adjetivo que
vende es «Online».

**Resumen.** 210 palabras, 11 frases, dos párrafos, ningún número.
1. Contexto: las redes neuronales son populares en NIDS.
2. Contexto: por qué encajan.
3. Hueco 1: recursos de entrenamiento.
4. Hueco 1, concretado: los routers no tienen memoria ni CPU.
5. Hueco 2 («More importantly»): son supervisadas.
6. Consecuencia del hueco 2: un experto debe etiquetar.
7. Sistema («In this paper, we present Kitsune: a plug and play NIDS…»).
8. Método: KitNET, conjunto de autoencoders.
9. Método: extracción de características.
10. Resultado, cualitativo: comparable a detectores offline, «even on a Raspberry PI».
11. Implicación: práctico y económico.

El segundo párrafo empieza con el sistema: el corte de párrafo separa problema y solución.

**Introducción** (1,9 páginas).
1. Contexto: crecen los ataques, qué es un NIDS, despliegue puntual frente a distribuido.
2. Aprendizaje automático y redes neuronales.
3. El enfoque habitual, como lista numerada de 4 pasos.
4. «We argue that it is impractical…»: tres problemas con encabezado en negrita en línea
   (**Offline Processing**, **Supervised Learning**, **High Complexity**).
5. Tres restricciones de diseño que son el espejo exacto de los tres problemas
   (**Online Processing**, **Unsupervised Learning**, **Low Complexity**).
6. Presentación del sistema y explicación del nombre (el zorro del folclore japonés).
7. Arquitectura en un párrafo, apoyado en la Fig. 1 (página 2).
8. Justificación: «The reason we use autoencoders is because (1)… (2)…» y cifra titular
   («by a factor of five»).
9. Contribuciones: 4 viñetas que empiezan por sintagma nominal («A novel…», «A feature
   extraction framework…», «An online technique…», «Experimental results…»), sin números;
   nota al pie con el código.
10. Párrafo de hoja de ruta.

La idea clave no está en una frase única: se reparte entre los párrafos 5 a 8. El recurso
fuerte es la simetría problema/requisito.

**Modelo de amenaza.** No hay sección. Los supuestos se formulan como restricciones de
despliegue en la introducción. El adversario aparece al final, en la Sección VI
(«Adversarial Attacks & Countermeasures», 0,4 páginas). Lo que queda fuera no se declara de
forma explícita.

**Diseño** (Sección III de fundamentos, 2,3 páginas; Sección IV, 4,9 páginas).
- Figura de arquitectura (Fig. 3) y, justo después, un recorrido numerado en 6 pasos de lo
  que le ocurre a un paquete: es el ejemplo conductor.
- Componentes con nombre y sigla (FE, FM, AD, KitNET), usados sin variación.
- Dos tablas de referencia (estadísticas incrementales y lista de características).
- 5 algoritmos en pseudocódigo.
- Cada componente se abre con el problema («it is important to extract features which
  capture the context…», con el ejemplo del SYN) antes de la solución.
- Análisis de complejidad como subsección de cierre.

**Evaluación** (3,5 páginas). Subsecciones fijas: Datasets, Experiment Setup, Evaluation
Metrics, Detection Performance, Runtime Performance. Sin preguntas de investigación. Los
baselines se presentan en un párrafo, agrupados por clase (offline, online, firmas). El
resultado titular está en la Fig. 9, a toda página, y en la frase «Overall, it is clear
that Kitsune out performs both algorithms…». No hay recuadros; cada subsección termina con
una frase de consecuencia («This means that Kitsune is an inexpensive and reliable
distributed NIDS solution»). Los resultados flojos se reencuadran antes de mostrarse: los
algoritmos offline se declaran cota superior, de modo que quedar cerca ya es un éxito.

**Figuras y tablas.** 11 figuras (2 de arquitectura, 3 ilustrativas, 2 del banco de pruebas,
4 de resultados), 5 tablas, 5 algoritmos. Primera figura en la página 2.
Pies de una línea; solo los de las Figs. 9 y 10 explican los paneles.

**Discusión y limitaciones.** Sección VI, 0,4 páginas, tono de consejo al usuario («a user
should be aware of this risk»), con contramedidas concretas.

**Recursos retóricos.** Nombre memorable y explicado; simetría problema/requisito;
encabezados en negrita en línea; «We note that…» y «We remind the reader that…» como
señalización.
- «In this paper, we present Kitsune: a novel ANN-based NIDS which is online, unsupervised, and efficient.»
- «We argue that it is impractical to use ANN-based classifiers with this approach for several reasons:»
- «Therefore, these algorithms serve as an optimum goal for us to achieve.»

**Cuota por sección** (cuerpo sin referencias): resumen e introducción 13 %, trabajo
relacionado 2 %, fundamentos 17 %, diseño 35 %, evaluación 27 %, adversario 3 %,
conclusión 2 %.

---

#### 2. Realtime Robust Malicious Traffic Detection via Frequency Domain Analysis (Whisper)

**Título.** Sin nombre de sistema ni dos puntos. Patrón «propiedades + tarea + via +
técnica». Los dos adjetivos («Realtime Robust») son la afirmación.

**Resumen.** 205 palabras, 9 frases, un párrafo. 3 números (42 ataques, 18,36 % de AUC,
90 %) más «two orders of magnitude».
1. Contexto: detección con aprendizaje, complementaria a las reglas.
2. Hueco: baja precisión y bajo caudal.
3. Consecuencia: no hay tiempo real.
4. Hueco 2: evasión fácil.
5. Sistema («To this end, we propose Whisper, a realtime ML based…»).
6. Mecanismo ligado a propiedad (información secuencial, pérdida acotada).
7. Por qué es robusto.
8. Resultado con números frente al estado del arte.
9. Resultado bajo evasión.

**Introducción** (2,4 páginas, con la Tabla 1 y la Fig. 1).
1. Contexto: reglas, no detectan ataques de día cero.
2. Promesa y límites del aprendizaje, apoyado en la Tabla 1 (matriz de ✓/× de métodos por
   propiedades, página 2).
3. Hueco de robustez, cerrado con una frase de hueco explícita.
4. Sistema e idea clave, seguida del reto («However, it is non-trivial to…»).
5. Método en tres pasos («First… Second… Third…»).
6. Selección automática de parámetros.
7. Teoría («We theoretically prove…», de nuevo First/Second/Third).
8. Prototipo y evaluación con las cifras titulares (42 conjuntos, AUC 0,891–0,999,
   1 310 000 PPS, 35 %, 0,06 s).
9. Contribuciones: «five-fold», 5 viñetas de una a tres líneas, todas con «We + verbo»
   (present, perform, develop, develop, prototype), sin números.
10. Hoja de ruta.

La idea clave está en el párrafo 4 y se repite casi literal en el resumen, en la Sección 3
y en la conclusión: las características en frecuencia «are not disturbed by the injected
noise packets».

**Modelo de amenaza.** Sección 2, «Threat Model and Design Goals», inmediatamente después
de la introducción; 0,35 páginas. Dos párrafos de modelo (despliegue por port mirroring,
«We assume that the detection system does not have any prior knowledge on threats») y
exclusiones con fórmula fija («We do not consider detecting passive attacks…»). Después,
dos objetivos de diseño con encabezado en negrita.

**Diseño.** Fig. 1 de visión general en la página 3, con módulos numerados y, bajo cada
caja, para qué sirve («Reducing the Scale of Features», «Addressing Numeric Instability»).
Sección 3 «Overview» (0,5 páginas): un párrafo por módulo con encabezado en negrita, que
termina con un puntero («We will present the details of this module in Section 4.1»).
Sección 4: una subsección por módulo. Sin pseudocódigo ni tabla de notación. La Fig. 2
enseña las características sobre tres ataques reales antes de formalizar. La Sección 5
(teoría) enuncia 6 teoremas y manda las demostraciones al apéndice.

**Evaluación** (4,4 páginas). Se abre con tres preguntas numeradas, cada una con su sección
entre paréntesis (6.3, 6.4, 6.5): correspondencia uno a uno. Antes, 6.1 Implementation y
6.2 Experiment Setup con encabezados en negrita en orden fijo: **Baselines** (viñetas),
**Testbed**, **Datasets** (viñetas por grupo de ataque, más la Tabla 4), **Metrics**. El
resultado titular va en la tercera frase de 6.3 («We find that Whisper can detect all 14
attacks with AUC ranging between 0.932 and 0.999…») y en la Tabla 5. Cada bloque termina
con «Thus, we can conclude that…» o «In summary, …»; no hay recuadros. Los resultados
flojos propios se mencionan de pasada y sin comentario (FAE, un baseline construido con sus
mismas características, supera a Whisper en un ataque: 0,973 frente a 0,932).

**Figuras y tablas.** 10 figuras (8 en el cuerpo, 2 en el apéndice: 1 de arquitectura, 1
ilustrativa, ROC, barras, CDF) y 5 tablas (comparativa, complejidad, hiperparámetros,
conjuntos de datos, resultados). Primer elemento visual: Tabla 1 en la página 2. Algunos
pies llevan la conclusión dentro (Fig. 2: «…and observe that a small number of malicious
packets incur significant changes…»).

**Discusión y limitaciones.** No hay sección. Trabajo relacionado al final (0,4 páginas),
con encabezados en negrita y una frase de contraste al cierre de cada párrafo («All these
defenses are orthogonal to our Whisper»). Tono afirmativo, sin límites declarados.

**Recursos retóricos.** Frase de hueco explícita; matriz de ✓/×; «First/Second/Third»;
«Note that,» (7 veces); punteros hacia delante; conclusión que repite las cifras.
- «Thus, realtime robust machine learning based detection that is ready for real deployment is still missing.»
- «In particular, the experiments will answer the three questions:»
- «According to figure 6, we conclude that attackers cannot evade Whisper by injecting benign traffic into the malicious traffic.»

**Cuota por sección** (cuerpo): resumen e introducción 20 %, amenaza y objetivos 3 %, visión
general 5 %, diseño 19 %, teoría 10 %, evaluación 37 %, trabajo relacionado 4 %,
conclusión 2 %.

---

#### 3. Detecting Unknown Encrypted Malicious Traffic in Real Time via Flow Interaction Graph Analysis (HyperVision)

**Título.** Sin nombre de sistema. Gerundio de tarea («Detecting…») con tres calificativos
(unknown, encrypted, real time) más «via + técnica». Mismo molde que Whisper, mismo grupo.

**Resumen.** 279 palabras, 14 frases, dos párrafos, 7 números (92 conjuntos, 48 ataques,
0,92 AUC, 0,86 F1, 50 %, 80,6 Gb/s, 0,83 s).
1. Contexto: el tráfico se cifra.
2. Problema: los atacantes lo aprovechan.
3. Por qué es difícil.
4. Hueco: los métodos son supervisados.
5. Problema abierto, dicho como tal («…is still an open problem»).
6. Sistema.
7. Idea: grafo compacto en memoria.
8. Qué captura el grafo.
9. Método.
10. Teoría.
11. Escala de la evaluación.
12. Resultado de precisión.
13. Fracaso de los baselines.
14. Rendimiento.

**Introducción** (2,2 páginas).
1. Contexto con dos cifras (80 % de HTTPS, 70 % del tráfico malicioso cifrado).
2. Hueco, apoyado en la Tabla I (matriz ✓/×, página 2).
3. «In a nutshell, …»: hueco resumido, idea clave («However, it is still feasible… because
   these attacks involve multiple attack steps with different flow interactions»), ejemplo
   concreto (bots de spam) y frase de tesis.
4. Sistema.
5. Reto («However, it is challenging to build the graph for realtime detection») y
   solución, motivada por un hecho medido («Inspired by the study of the flow size
   distribution…»).
6. Método en cuatro pasos («First… Second… Third… Finally…»).
7. Teoría.
8. Prototipo y cifras titulares (92 conjuntos, 13,9–36,1 %, 0,92 AUC, 44 ataques que
   ningún baseline detecta, 100 Gb/s).
9. Contribuciones: «five-fold», 5 viñetas de una o dos líneas, «We + verbo» (propose,
   develop, design, develop, prototype), sin números; nota al pie con código y datos.
10. Hoja de ruta.

**Modelo de amenaza.** Sección II, «Threat Model and Design Goals», 0,3 páginas, tres
párrafos: despliegue, alcance («we focus on detecting active attacks…», «We do not consider
passive attacks that do not generate traffic to victims») y objetivos («First… Second…
Third…»).

**Diseño.** Fig. 1 en la página 3, con tres etapas numeradas. Sección III «Overview» con un
párrafo en negrita por etapa y puntero a su sección. Secciones IV a VI, una por etapa. Cada
subsección empieza por la necesidad en una frase («We need to reduce the density of the
graph for analysis.») y por una figura de datos reales que la motiva (Fig. 2, distribución
de flujos; Fig. 3, grafo antes y después). El pseudocódigo (2 algoritmos) y la tabla de
hiperparámetros van al apéndice. La Sección VII (teoría) resume sus resultados en tres
hallazgos numerados, uno al frente de cada párrafo.

**Evaluación** (4,7 páginas). A. Experiment Setup con encabezados en negrita:
**Implementation**, **Testbed**, **Datasets** (viñetas por grupo), **Baselines** (viñetas
con la categoría del método entre paréntesis), **Metrics**. B. Accuracy Evaluation:
empieza por la Tabla III, un resumen de medias por grupo con el porcentaje de mejora, y por
el titular («In general, HyperVision achieves average F1 ranging between 0.927 and
0.978…»); sigue un bloque en negrita por grupo de ataques. C. Performance Results
(Throughput, Latency, Resource Consumption). Sin preguntas de investigación. Cada cifra va
seguida de su causa («The reason why HyperVision can detect… is that…»). La tabla
detallada marca en color el mejor y el peor valor. Lo desfavorable se concede en una
subordinada («Although Whisper has slightly better AUC in some cases, we find that…») y los
fallos de los baselines se omiten «due to the page limits».

**Figuras y tablas.** 18 figuras (1 de arquitectura, varias de motivación con datos
reales, ROC/PRC, mapas de calor, subgrafos de casos, CDF) y 7 tablas (4 en el cuerpo, 3 en el
apéndice). Primer elemento visual: Tabla I en la página 2; Fig. 1 en la 3. Pies muy cortos
(«The overview of HyperVision.»), no autocontenidos; las leyendas van en notas de tabla.

**Discusión y limitaciones.** No hay sección; la robustez ante evasión se remite al
apéndice. Trabajo relacionado al final (0,6 páginas), con encabezados en negrita.

**Recursos retóricos.** «In a nutshell»; hallazgos numerados; ejemplo concreto pegado a la
idea; frase de tesis; «Note that,» (14 veces).
- «Thus, this paper explores utilizing interaction patterns among various flows for malicious traffic detection.»
- «However, it is challenging to build the graph for realtime detection.»
- «(1) HyperVision maintains more information using the graph than the existing methods.»

**Cuota por sección** (cuerpo): resumen e introducción 16 %, amenaza y objetivos 2 %, visión
general 6 %, diseño 18 %, teoría 15 %, evaluación 35 %, trabajo relacionado 5 %,
conclusión 2 %.

---

#### 4. Outside the Closed World: On Using Machine Learning for Network Intrusion Detection

**Título.** Imagen evocadora, dos puntos, descripción llana («On Using…»). Sin sistema. La
tesis va implícita en la metáfora del mundo cerrado.

**Resumen.** 150 palabras, 5 frases largas (21 a 38 palabras), ningún número.
1. Contexto: la detección de anomalías con aprendizaje.
2. Enigma: «a striking gap» entre investigación y despliegue.
3. Qué se examina.
4. Tesis («Our main claim is that…»).
5. Apoyo y aportación (retos y directrices).

**Introducción** (0,9 páginas, 7 párrafos).
1. Taxonomía y desequilibrio en los despliegues.
2. El enigma: el aprendizaje triunfa en otros dominios.
3. Objetivo, tesis («Our main claim…») y premisa que se discute.
4. Cinco características enumeradas en línea, de (i) a (v).
5. Acotación del propio argumento («We stress that we do not consider machine-learning an
   inappropriate tool…»).
6. Alcance y terminología.
7. Hoja de ruta.

Las contribuciones van en prosa, sin viñetas ni números.

**Modelo de amenaza.** No hay sección propia. Aparece como reto (III-E.3, «Adversarial
Setting») y como recomendación (IV-A, «Understanding the Threat Model»), formulada con
cuatro preguntas en viñetas. El alcance se declara en la introducción («We focus on network
intrusion detection as that is our main area of expertise»).

**Presentación del argumento** (hace las veces de diseño). La Sección III (retos) y la IV
(recomendaciones) son espejo una de otra. Cada subsección abre con su tesis en una frase,
sigue con una analogía de otro dominio (recomendaciones de Amazon, OCR, spam, que se
retoman a lo largo del texto como ejemplos conductores) y cierra con la consecuencia. La
recomendación central va destacada y cabe en seis palabras. Señala un estudio ajeno como
modelo. Sin figuras, tablas ni pseudocódigo.

**Evaluación.** No hay: es un artículo de posición. La evidencia son citas y ejemplos.

**Figuras y tablas.** Ninguna.

**Discusión y limitaciones.** Repartidas por el texto. Tono mesurado, en primera persona
del plural, con reconocimiento explícito de límites («we are network security researchers,
not experts on machine-learning»; las directrices son «touchstones rather than as firm
rules»).

**Recursos retóricos.** Tesis anunciada con marcador («Our main claim is…»); estructura en
espejo; preguntas como encabezado («Why?»); listas (i) a (v) repetidas en la introducción y
en la conclusión; acotar la tesis para hacerla creíble.
- «Understand what the system is doing.»
- «We stress that we do not consider machine-learning an inappropriate tool for intrusion detection.»
- «…we are working in an area where insight matters much more than just numerical results.»

**Cuota por sección:** resumen e introducción 11 %, antecedentes 5 %, retos 47 %,
recomendaciones 34 %, conclusión 4 %.

---

### Patrones comunes

Los cinco más fuertes:

1. **Un elemento visual que sitúa al lector en las páginas 2 o 3.** Kitsune pone la figura
   del algoritmo en la página 2; Whisper y HyperVision ponen en la página 2 una matriz de
   ✓/× (métodos por propiedades, con la fila propia al final) y en la página 3 la figura de
   visión general.
2. **Arco fijo de introducción.** Contexto, hueco dicho en una frase, «In this paper, we
   present/propose X», idea clave con su «because», reto («However, it is non-trivial/
   challenging…»), método por pasos, un párrafo con las cifras titulares, contribuciones y
   hoja de ruta. Las contribuciones son 4 o 5 viñetas de una a tres líneas, sin números;
   los números viven en el párrafo anterior. Los cuatro artículos tienen párrafo de hoja
   de ruta.
3. **Modelo de amenaza corto, pegado a la introducción y unido a los objetivos de diseño**
   (Whisper y HyperVision: Sección 2, un tercio de página). Las exclusiones usan una
   fórmula fija: «We do not consider…». El trabajo relacionado va al final y ocupa media
   página.
4. **Visión general antes del detalle, con nombres estables.** Una sección «Overview» con
   un párrafo en negrita por componente y puntero a su sección; después, una subsección por
   componente que empieza por la necesidad. Pocos nombres (3 o 4 módulos) y siempre los
   mismos.
5. **Evaluación guiada.** Preguntas numeradas con su sección (Whisper) o bloques fijos; un
   bloque de configuración con encabezados en negrita en orden casi idéntico
   (Implementation, Testbed, Datasets, Baselines, Metrics) y una tabla de conjuntos de
   datos; cada subsección abre con su titular y cierra con «Thus, we can conclude…» o «In
   summary…». No hay recuadros de resumen en ninguno de los cuatro: el resumen es una
   frase.

Otros patrones:

6. **Resumen de 150 a 280 palabras**, una función por frase, con el nombre del sistema en la
   frase central y su definición en aposición. Los números, si los hay (0, 3, 7, 0), van al
   final.
7. **La idea clave se repite casi literal** en resumen, introducción, visión general y
   conclusión.
8. **Predominio de figuras sobre tablas**: 11/5, 10/5 y 18/7. Hay figuras de motivación con
   datos reales antes de cada decisión de diseño. Los pies son cortos, y los mejores llevan
   dentro la conclusión.
9. **Cada cifra va seguida de su causa** («The reason why… is that…») y la tabla principal
   resalta el mejor valor.
10. **Las limitaciones casi no existen en los tres artículos de sistema** (0,4 páginas en
    Kitsune, nada en los otros dos). Sommer y Paxson hacen lo contrario y ganan
    credibilidad acotando su tesis. En esto nuestro manuscrito ya sigue el mejor de los dos
    modelos; no conviene imitar a los otros tres.

---

### Cambios propuestos para nuestro manuscrito

Estado actual, medido sobre `paper/main.pdf` y los `.tex`: 23 páginas; 4 figuras, 11 tablas
en el cuerpo y 1 algoritmo; primer flotante en la página 4 (Tabla 1), primera figura en la
página 6; resumen de 253 palabras y 10 frases. Cuota por palabras del cuerpo: introducción
7 %, antecedentes 7 %, motivación 3 %, modelo de amenaza 5 %, diseño 16 %, evaluación 48 %,
discusión 10 %, conclusiones 3,5 %.

Ningún cambio añade experimentos ni afirmaciones; todos reordenan o representan lo que ya
está.

#### 1. Poner un elemento visual en la página 2: la comparativa de defensas como matriz de ✓/×
- **Modelos.** Whisper (Tabla 1) y HyperVision (Tabla I) abren con una matriz de métodos
  por propiedades en la página 2; Kitsune pone su figura en la página 2.
- **Nosotros.** Las páginas 1 a 3 son solo texto. La Tabla 1 (`background.tex`, l. 79–103)
  cae en la página 4 y mezcla texto libre («weighted ensemble, adversarial training») con
  una columna doble («Adaptive / Across networks»).
- **Cambio.** Convertirla en una matriz de ✓/× con una propiedad por columna (garantía por
  alerta, sin presupuesto de perturbación, en espacio de tráfico, sin secreto, evaluada
  con atacante adaptativo, evaluada entre redes), mantener la nota *a*, y citarla desde el
  segundo párrafo de la introducción (`introduction.tex`, l. 21–32) para que flote en la
  página 2.

#### 2. Adelgazar las contribuciones, sacar de ellas los números y añadir la hoja de ruta
- **Modelos.** 4 o 5 viñetas de una a tres líneas, con «We + verbo» o un sintagma nominal,
  sin cifras; las cifras titulares van en el párrafo anterior; los cuatro cierran con «The
  rest of the paper is organized as follows».
- **Nosotros.** `introduction.tex`, l. 68–111: 6 viñetas, 470 palabras (el 40 % de la
  introducción) y más de veinte cifras; la cuarta viñeta es un párrafo de resultados. No
  hay hoja de ruta: la sección termina en el enlace al código (l. 112–113), aunque el
  artículo tiene 8 secciones y 3 apéndices.
- **Cambio.** Cinco viñetas de dos líneas como máximo (certificado; frontera de daño;
  detección entre redes sin etiquetas locales; evaluación adversaria de cada capa; código y
  resultados). Un párrafo previo de «cifras titulares» con tres o cuatro números. Un
  párrafo final de hoja de ruta. Además reduce el coste de mantener cifras que aún van a
  cambiar.

#### 3. Modelo de amenaza y objetivos de diseño justo después de la introducción; trabajo relacionado más corto o al final
- **Modelos.** Whisper y HyperVision: Sección 2 = «Threat Model and Design Goals», un
  tercio de página; trabajo relacionado al final, media página.
- **Nosotros.** El lector llega al modelo de amenaza en la página 4 y al diseño en la 5,
  tras 2,3 páginas de antecedentes y motivación. Los requisitos R1–R3 están al final de
  `motivation.tex` (l. 44–55) y las exclusiones al final de `threat_model.tex`
  (l. 86–92).
- **Cambio.** Orden propuesto: introducción, motivación (Apollon, breve), modelo de amenaza
  y objetivos (con R1–R3 como encabezados en negrita y las exclusiones como lista «We do
  not consider…»), diseño, evaluación, trabajo relacionado, discusión, conclusiones. Si la
  revista pide antecedentes al principio, alternativa mínima: mover R1–R3 a la sección de
  amenaza y llevar el párrafo «Evaluation pitfalls and datasets» (`background.tex`,
  l. 126–141) a la configuración de la evaluación.

#### 4. Abrir el diseño con una visión general que nombre todas las piezas una sola vez, y seguir un ejemplo conductor
- **Modelos.** Sección «Overview» con un párrafo en negrita por módulo y puntero a su
  sección (Whisper §3, HyperVision §III); recorrido numerado de un paquete en Kitsune
  (IV-A); ejemplo concreto pegado a la idea en HyperVision.
- **Nosotros.** La visión general es un párrafo de 8 líneas (`design.tex`, l. 16–23). Las
  variantes se presentan a trozos: \sysname-cert en `design.tex`, l. 154–163;
  \sysname-cert-R no aparece en el diseño y se define en la evaluación (`evaluation.tex`,
  Tabla 3 en l. 95–119 y párrafo en l. 184–196); «System» solo en esa tabla. La figura de
  arquitectura no muestra las variantes. El único ejemplo trabajado es una alerta explicada
  al final (`design.tex`, l. 248–257).
- **Cambio.** Subsección 5.1 «Overview» con encabezados en negrita (evidencia conservada,
  núcleo monótono y sub-núcleos, certificado, los tres detectores y el sistema, frontera de
  daño, capa por flujo), cada uno con su puntero. Definir ahí \sysname-cert-R y «System» y
  reflejarlos en la figura. Elegir una campaña ya evaluada (por ejemplo DoS Hulk contra el
  servidor web) y seguirla por contadores, holgura, certificado y frontera con las cifras
  que ya figuran en las tablas.

#### 5. Una subsección por pregunta de investigación, con la respuesta en una frase al cierre
- **Modelos.** Whisper: tres preguntas numeradas, cada una con su sección; cada bloque
  termina con «Thus, we can conclude…» o «In summary…». HyperVision: hallazgos numerados al
  frente de cada párrafo.
- **Nosotros.** `evaluation.tex`, l. 7–18: seis preguntas en un párrafo corrido. La
  correspondencia no es uno a uno: RQ1 y RQ2 comparten subsección (l. 121); RQ3, RQ5 y RQ6
  ocupan dos cada una; «Budget certificates and free operations» (l. 360) no pertenece a
  ninguna; solo tres encabezados llevan la etiqueta RQ (l. 121, 315, 416). Ninguna
  subsección cierra con su respuesta, y la evaluación es el 48 % del texto.
- **Cambio.** Lista enumerada de preguntas con su sección. Una subsección por pregunta, con
  la pregunta en el título: sacar «Price of monotonicity» (l. 229) a subsección propia;
  agrupar certificado, paquetes y presupuesto bajo RQ3; atacante adaptativo y comparación
  de defensas bajo RQ5. Cerrar cada una con un párrafo de una frase y encabezado en negrita
  («Answer to RQn»).

#### 6. Configuración experimental como bloque de consulta: tabla de conjuntos de datos y glosario de métricas; tabla principal más ligera
- **Modelos.** Bloque fijo con encabezados en negrita y tabla de conjuntos de datos
  (Whisper, Tabla 4; Kitsune, Tabla III). HyperVision antepone una tabla resumen de medias
  (Tabla III) a la detallada y resalta el mejor valor.
- **Nosotros.** Seis conjuntos descritos en prosa con sus tamaños (`evaluation.tex`,
  l. 23–41), sin tabla. Las definiciones de campaña detectada, falsa alarma, los dos
  recuentos de alarmas y los presupuestos ocupan cuatro párrafos (l. 50–77). El pie de la
  Tabla 4 tiene 9 líneas y define siete abreviaturas (l. 126–134); la tabla tiene 9
  columnas de celdas «n/m (recall)» en `\scriptsize`.
- **Cambio.** Tabla de conjuntos de datos (flujos, días, tipo de red, etiquetas, papel en
  el artículo). Párrafo «Metrics» como lista de definiciones con el término en negrita.
  Llevar las abreviaturas de columna a la Tabla 3, que ya existe, y dejar en el pie de la
  Tabla 4 solo lo que hay que mirar. Anteponer una tabla resumen pequeña (por dirección:
  campañas volumétricas detectadas, alarmas por entidad y hora, cobertura certificada) y
  marcar en negrita el mejor valor de cada fila.

#### 7. Sacar los resultados de la discusión y llevarlos a la evaluación
- **Modelos.** En los tres artículos de sistema, todo número medido está en la evaluación
  (Kitsune V-E «Runtime Performance», HyperVision VIII-C «Performance Results»); las
  secciones finales no traen resultados nuevos.
- **Nosotros.** El experimento de envenenamiento de la línea base, con su Fig. 4 y cuatro
  párrafos, está en `discussion.tex`, l. 54–103, aunque RQ5 lo anuncia en la evaluación
  («its rate, its free operations and its history», `evaluation.tex`, l. 13–15). Las
  cifras de coste (170 000 y 25 000 flujos por segundo, 10 MB) están en `discussion.tex`,
  l. 119–130, y las de escaneos lentos de CTU-13 en l. 23–39.
- **Cambio.** Mover el envenenamiento a la subsección de RQ5 y el coste a una subsección
  breve «Cost» de la evaluación. La discusión queda como interpretación y límites (alcance
  del certificado, ataques lentos, inflación de alertas, validez), con referencias a las
  tablas y sin cifras nuevas.

#### 8. Reequilibrar tablas y figuras: que las afirmaciones centrales se vean
- **Modelos.** Proporción de figuras a tablas de 11/5, 10/5 y 18/7; figuras con datos
  reales antes de cada decisión; pies que llevan la conclusión (Whisper, Fig. 2).
- **Nosotros.** 4 figuras frente a 11 tablas. Las páginas 15 y 16 solo tienen tablas y las
  páginas 7 y 14 son texto sin flotantes. La comparación más visual del artículo, radios
  certificados por debajo de 2 frente a desplazamientos de 10 a 250, está en una tabla
  (`evaluation.tex`, l. 378–402).
- **Cambio.** Representar la Tabla 6 (radio frente a desplazamiento por campaña) como
  figura con eje logarítmico. Representar la Tabla 9 (detección, falsas alarmas, robustez)
  como gráfico de las tres dimensiones con el frente de Pareto marcado. Pasar al apéndice
  la Tabla 11 (calibración del contador, l. 772–790) y la Tabla 5 (ablación, l. 305–313),
  dejando en el texto una frase con su conclusión. Escribir los pies de modo que digan qué
  se ve, como ya hace el de la Fig. 3.

---

# Bloque B. Cómo están escritos cinco artículos de referencia sobre robustez adversaria y defensas certificadas

Notas de análisis de escritura (estructura, formato y retórica), no de contenido técnico.
Fecha: 2026-11-16.

## Método y cautelas

- Los cinco artículos pedidos se recuperaron completos; no hizo falta sustituir ninguno.
- Versiones leídas:
  - Pierazzi et al.: arXiv 1911.02142**v2** (marzo de 2020, 18 páginas, formato IEEE; es la versión de S&P). La v3 de arXiv es una versión extendida en formato ACM (36 páginas) y no se ha usado.
  - Tong et al.: PDF abierto de USENIX (`sec19-tong.pdf`, 19 páginas con portada).
  - Cohen et al.: arXiv 1902.02918v2 (junio de 2019; 9 páginas de cuerpo y 24 de apéndices).
  - Wang et al. (BARS): PDF abierto de NDSS (18 páginas).
  - Arp et al.: PDF abierto de USENIX (`sec22-arp.pdf`, 19 páginas con portada).
- El texto se extrajo con `pdftotext`. En artículos a dos columnas el orden de los párrafos sale mezclado, así que los recuentos de párrafos y el reparto por secciones son aproximados (calculados por posición de página). Las palabras y frases de cada resumen se contaron con un script; los números de figuras y tablas, por sus pies.
- Comprobé a la vista (página renderizada) los recuadros de Arp, los encabezados en negrita de BARS y las definiciones de Pierazzi. El resto del formato visual (negritas, cursivas) se infiere del texto.
- El papel de cada frase del resumen y de cada párrafo de la introducción es lectura mía.

### Citas (recuento aproximado)

Fuente: API de Semantic Scholar, consultada el 2026-11-16. Google Scholar no se pudo consultar (redirige a una página de sincronización), así que no hay cifra de Google Scholar verificada; suele dar valores más altos.

| Artículo | Semantic Scholar | Otra fuente |
|---|---|---|
| Pierazzi et al., S&P 2020 | 408 (más 20 en el registro separado de la versión extendida) | Crossref: 274 |
| Tong et al., USENIX Security 2019 | 100 | — |
| Cohen et al., ICML 2019 | 2 756 | — |
| Wang et al. (BARS), NDSS 2023 | 29 | Crossref: 20 |
| Arp et al., USENIX Security 2022 | 480 | — |

Aviso: Tong et al. y BARS quedan por debajo de 200 citas en esta fuente. Se analizan porque estaban en la lista y se pudieron leer completos; son además los dos más cercanos a nuestro tema (características conservadas y certificación en tráfico).

---

## 1. Pierazzi et al., "Intriguing Properties of Adversarial ML Attacks in the Problem Space" (IEEE S&P 2020)

**Patrón del título.** Guiño a un título célebre («Intriguing properties of neural networks») seguido del objeto de estudio. Sin dos puntos, sin nombre de sistema. Promete hallazgos conceptuales, no una herramienta.

**Resumen.** Unas 300 palabras, 13 frases, tres párrafos. Es el más largo de los cinco.
1. Contexto (ataques en el espacio del problema).
2. Hueco («remain underexplored»).
3. Anuncio: «This paper makes two major contributions».
4. Contribución 1: formalización, con sus cuatro restricciones enumeradas.
5. Concepto nuevo con nombre (*side-effect features*).
6. Resultado teórico (condiciones necesarias y suficientes).
7. Validación de la formalización (describe ataques previos).
8. Contribución 2: ataque nuevo.
9. Escala del experimento.
10. Implicación con eslogan («adversarial-malware as a service»).
11. Dato de contraste sobre el campo.
12. Implicación para la investigación.
13. Publicación de código y datos.

Números: 170K apps, 2017–2018, «1600+ papers», «roughly 40». Ninguno es una métrica de rendimiento; sirven para dar escala y urgencia.

**Introducción.** Tres párrafos y una lista.
- P1: contexto, dificultad central (el problema inverso del mapeo de características), lista de dominios con citas y hueco.
- P2: «In this paper… we propose a novel formalization», con las cuatro restricciones presentadas como cuatro preguntas («which… which… which… how…») y el concepto con nombre.
- P3: qué revela la formalización sobre tres ataques previos, uno por frase, y cómo eso motiva el ataque propio.
- Contribuciones: «In summary, this paper has two major contributions», dos viñetas largas, cada una con punteros a sección (§II, §III, §IV). Verbos: *propose*, *introduce*, *demonstrate*. Lleva una sola cifra (170K apps) y una magnitud («in the order of minutes»).
- No hay párrafo de hoja de ruta: los punteros de las viñetas y una frase final (§V, §VII) hacen ese papel.
- La idea clave no es una frase única; es el término *side-effect features*, que aparece en resumen, introducción, definición 13 y figura 1.

**Modelo de amenaza y formalización.** Es el corazón del artículo (§II, unas 5 páginas).
- Catorce definiciones numeradas y con nombre entre paréntesis («Definition 8 (Available Transformations)»). Cada una va precedida de una frase de motivación y seguida de un ejemplo de dominio («For example, the pixels of an image…»).
- Las restricciones del atacante se presentan primero como lista numerada en prosa (1–4) y después se formalizan una a una. Se agrupan en un símbolo, Γ = {T, Υ, Π, Λ}, que se reutiliza hasta el final.
- El modelo de amenaza del ataque concreto (§III-A) ocupa un tercio de columna: conocimiento perfecto escrito como tupla, θ_PK = (D, X, g, w), y justificado con el principio de Kerckhoffs. El detalle de conocimiento y capacidades va al apéndice B.
- Tabla de símbolos en el apéndice A, anunciada al abrir §II.
- La tabla I describe nueve ataques con las mismas columnas que las definiciones: la formalización se demuestra útil usándola.
- La §III repite las cuatro restricciones como subsecciones (B, C, D, E), una por restricción.

**Teoremas.** Dos, más un corolario.
- Intuición antes: una frase dice para qué sirve el resultado («we can verify whether a feature-space attack exists, which is a necessary condition»).
- Enunciado formal con nombre («Theorem 1 (Necessary Condition for Problem-Space Attacks)»).
- Pruebas en el apéndice C, con una frase de puntero.
- Después de los dos enunciados, una paráfrasis que empieza por «Informally,…» para el lector no teórico.
- Las hipótesis no llevan etiquetas; están dentro del enunciado.

**Evaluación.** Corta (unas 2 páginas, en torno al 16 %).
- §IV-A, configuración, con encabezados en negrita: *Prototype*, *Classifiers*, *Attack Confidence*, *Dataset*, *Dataset Split*, *Testing*. Cada decisión dudosa se justifica en el sitio (por qué una partición aleatoria y no temporal).
- §IV-B, resultados: *Attack Success Rate*, *Runtime Overhead*.
- El resultado titular (100 % de evasión) aparece en el primer párrafo de resultados.
- No hay preguntas de investigación ni recuadros. Los párrafos terminan con una frase de lectura («This demonstrates that measuring attacker effort with lp perturbations… overestimates the robustness of the defense»).
- Los fallos de la herramienta se declaran y se llevan al apéndice G.

**Figuras y tablas.** Cinco figuras y una tabla en el cuerpo; tabla de símbolos y algoritmos en el apéndice. La primera figura, en la página 5, es conceptual (la proyección que genera las *side-effect features*) y tiene un pie de siete líneas que se entiende sin el texto. Los pies de las figuras de resultados son de una o dos líneas.

**Discusión y limitaciones.** §V, «Discussion on attack and results», media página, con encabezados en negrita. No hay sección de limitaciones; se reparten por el texto y las notas al pie. Tono seguro («for the first time»).

**Recursos que copiar.**
- Definiciones con nombre, cada una con su ejemplo.
- Un símbolo que agrupa las restricciones y que organiza después la tabla comparativa y las subsecciones.
- La paráfrasis «Informally,…» tras cada teorema.
- Citas:
  - "This paper makes two major contributions."
  - "We call side-effect features η the features that are altered in z′ = T(z) specifically for the satisfaction of problem-space constraints."
  - "When designing a novel problem-space attack, it is fundamental to explicitly define these four types of constraints, to clarify strengths and weaknesses."

**Reparto aproximado (13,3 páginas de cuerpo).** Introducción 10 %; formalización 38 %; ataque 22 %; evaluación 16 %; discusión 5 %; trabajo relacionado 8 %; disponibilidad y conclusiones 2 %.

---

## 2. Tong et al., "Improving Robustness of ML Classifiers against Realizable Evasion Attacks Using Conserved Features" (USENIX Security 2019)

**Patrón del título.** Gerundio de objetivo, «against» más la amenaza, «Using» más el mecanismo. El concepto que el artículo bautiza va en el título.

**Resumen.** 197 palabras, 7 frases, ningún número.
1. Contexto.
2. Problema (evasión).
3. Enfoque convencional (modelos en el espacio de características).
4. Pregunta del artículo.
5. Hallazgo 1, matizado («limited effectiveness, but… effective with content-based detectors»).
6. Idea y hallazgo 2: las *conserved features*, definidas en un paréntesis dentro del propio resumen.
7. Hallazgo 3 (robustez generalizada).

**Introducción.** Siete párrafos, sin viñetas y sin hoja de ruta.
- P1–P3: contexto, ataques, defensas.
- P4: el hueco, con dos objeciones («First… Second…»), cada una con un ejemplo concreto de PDF, y el objetivo en una frase.
- P5–P7: un párrafo por contribución («Our first contribution is…», «Our second…», «Our third…»). Los tres llevan el resultado en palabras, sin cifras.
- La idea clave está en P6 y se anuncia con «The key idea is…».

**Modelo de amenaza y formalización.** No hay sección titulada «Threat model».
- §2.2 distingue en prosa los ataques realizables de los del espacio de características, con «our running example» (malware PDF).
- §3 da el modelo conceptual: un juego de Stackelberg en el que el ataque es un oráculo O(h; D), una ecuación y un procedimiento en cuatro pasos numerados.
- Las capacidades de cada ataque concreto se describen en §4.3, ataque por ataque.
- No hay entornos de definición; los términos nuevos se introducen en cursiva con «We call…» o «We term…».

**Garantías.** No hay teoremas propios. El apoyo formal es una cita («a variant of iterative retraining with provable guarantees»). Todo el peso es empírico y las afirmaciones se formulan con cautela («appear to have limited effectiveness»).

**Evaluación.** Organizada por afirmaciones, no por experimentos.
- §4, metodología, separada de los resultados (unas 3 páginas: clasificadores, ataques, modelo, datos, implementación, métricas).
- §5 valida el enfoque convencional; §6 presenta las características conservadas; §7 prueba la generalización, con una subsección por ataque.
- Abreviaturas con «henceforth» (RAR, FSR, CFR, CF) usadas igual en texto, leyendas y pies.
- §6.1 plantea «four natural questions» numeradas y las responde una a una («To address question (2)…»).
- Los resultados negativos se dan en el mismo registro que los positivos: un clasificador solo con características conservadas es «impractical»; frente al ataque a medida, «CF robustness is 0». Una nota al pie explica por qué un resultado difiere del artículo original.
- No hay recuadros.

**Figuras y tablas.** Catorce figuras, todas con la misma forma (robustez a la izquierda, ROC a la derecha), y tres tablas (una en el apéndice). La primera figura llega tarde, en la séptima página. Pies formularios y breves; no se entienden sin el texto.

**Discusión y limitaciones.** §9, «Discussion and Conclusion», unos tres cuartos de página: resumen de hallazgos, extensión a otros dominios y un párrafo de limitaciones que empieza de frente. Tono franco, con cautelas («our evidence is mixed»).

**Recursos que copiar.**
- Bautizar el concepto y definirlo en una subordinada cada vez que reaparece.
- Preguntas numeradas respondidas por orden.
- Abreviaturas fijas para las variantes comparadas.
- Citas:
  - "The key idea is to identify conserved features, that is, features that cannot be unilaterally modified without compromising malicious functionality."
  - "In other words, the nature of the feature space can matter a great deal."
  - "The main limitation of our study is in the specific choices we had to make to ensure that it is tractable."

**Reparto aproximado (14 páginas de cuerpo).** Introducción 9 %; antecedentes 8 %; modelo conceptual 7 %; metodología 23 %; resultados (§5–§7) 43 %; trabajo relacionado 6 %; discusión y conclusión 5 %.

---

## 3. Cohen, Rosenfeld y Kolter, "Certified Adversarial Robustness via Randomized Smoothing" (ICML 2019)

**Patrón del título.** «Propiedad conseguida via método». Cinco palabras de contenido, sin acrónimo.

**Resumen.** Unas 140 palabras, 8 frases. Empieza por el resultado, no por el contexto.
1. Qué se demuestra («We show how to turn any classifier…»).
2. Hueco (las garantías existentes son holgadas).
3. Contribución teórica (garantía ajustada).
4. Resultado titular.
5. Posicionamiento («No certified defense has been shown feasible on ImageNet except for smoothing»).
6. Resultado secundario.
7. Implicación.
8. Código.

Números: un único dato, expresado con su unidad y su traducción (49 % de exactitud certificada con norma ℓ2 menor que 0,5, «=127/255»).

**Introducción.** Siete párrafos, sin lista de contribuciones y sin hoja de ruta.
- P1: contexto y hueco (las defensas heurísticas se rompen; las certificadas no escalan).
- P2: la técnica, definida en palabras y con la notación mínima.
- P3: la propiedad que aporta.
- P4: trabajo previo y la contribución en una frase («In this paper, we prove the first tight robustness guarantee…»).
- P5: la limitación, anunciada sin rodeos («Randomized smoothing has one major drawback»).
- P6: ventajas («Despite this drawback…»).
- P7: resultado titular con la cifra y puntero a la tabla 1.

En las dos primeras páginas hay dos figuras y una tabla: la figura 1 ilustra la definición, la tabla 1 da el resultado titular y la figura 2 da la intuición («drown out»).

**Modelo de amenaza y formalización.** No hay sección. El adversario es una perturbación de norma ℓ2 acotada y queda definido por la propia garantía. La escala se explica en el pie de la tabla 1 con un ejemplo («a perturbation with ℓ2 radius 1.0 could change one pixel by 255, ten pixels by 80…»). No hay tabla de notación: se usan media docena de símbolos, introducidos uno a uno.

**Garantía.** Es el modelo más útil para nosotros (§3.1).
1. Un párrafo en palabras que termina con «Our main result is that…» y la fórmula del radio.
2. El teorema 1, corto, con la hipótesis en una ecuación numerada (2).
3. «We now make several observations about Theorem 1», en tres viñetas: lo que no supone («Theorem 1 assumes nothing about f»), cuándo es grande el radio y un caso límite que da confianza.
4. Comparación con las garantías previas y el teorema 2 (la garantía es ajustada), seguido de una frase de lectura.
5. «The complete proofs… are in Appendix A. We now sketch the proofs in the special case…»: versión binaria del teorema y esbozo de prueba de un párrafo, con una figura (la 3) que dibuja el peor caso.
6. Un caso de control («Linear base classifier») donde la garantía coincide con lo que se sabe.

En §3.2, la parte práctica: seudocódigo de `PREDICT` y `CERTIFY` y dos proposiciones que dicen qué garantiza cada algoritmo, con paráfrasis entre paréntesis («Equivalently: the probability that… is at most α»). Los límites se cuentan ahí mismo, con encabezados en negrita («Certifying large radii requires many samples»), no en la discusión.

**Evaluación.** Unas 2,2 páginas.
- Empieza definiendo la métrica (*certified test set accuracy at radius r*) y su versión aproximada, y dice por qué la diferencia es despreciable.
- Encabezados en negrita: *ImageNet and CIFAR-10 results*, *Comparison to baselines*, *Prediction*, *Empirical tightness of bound*.
- Los competidores se presentan en una frase cada uno; solo el más fuerte se compara en el cuerpo y los otros dos van al apéndice H.
- El resultado titular no está en la evaluación: está en el resumen, en la introducción y en la tabla 1 de la página 2.
- Los límites se reportan con cifras: por qué las curvas caen a cero en un radio dado, cuánto se abstiene el predictor (12 %, 4 %, 1 %) y con qué frecuencia un ataque rompe el clasificador justo fuera del radio (17 % a 1,5R; 53 % a 2R).

**Figuras y tablas.** Ocho figuras y una tabla en nueve páginas; primera figura en la página 1. Pies largos y autosuficientes: el de la figura 7 explica cada línea y advierte de que compara garantías deterministas con probabilísticas.

**Discusión y limitaciones.** No hay sección. La conclusión son dos párrafos: lectura del teorema 2 y una frase de posición. Las limitaciones van donde nacen (introducción, §3.2, §4). Tono sobrio; el superlativo se reserva para lo demostrado («the first tight»).

**Recursos que copiar.**
- Resultado en palabras, luego teorema, luego «observaciones», luego esbozo de prueba con figura.
- Decir primero lo que el teorema no supone.
- Traducir el radio a algo tangible.
- Anunciar la limitación principal en la introducción.
- Citas:
  - "Theorem 1 assumes nothing about f."
  - "Randomized smoothing has one major drawback."
  - "In this paper, we prove the first tight robustness guarantee for randomized smoothing."

**Reparto aproximado (8,6 páginas de cuerpo).** Introducción con sus figuras 22 %; trabajo relacionado 12 %; método y teoría 37 %; experimentos 26 %; conclusión 3 %. Los apéndices triplican el cuerpo.

---

## 4. Wang et al., "BARS: Local Robustness Certification for Deep Learning based Traffic Analysis Systems" (NDSS 2023)

**Patrón del título.** «ACRÓNIMO: sintagma técnico para un dominio». El acrónimo se despliega en el cuerpo, no en el título.

**Resumen.** 192 palabras, 12 frases cortas (16 palabras de media).
1. Contexto.
2. Problema.
3. Línea de trabajo existente.
4. Hueco.
5. Objetivo, como tres atributos numerados (1), (2), (3).
6. Propuesta con nombre.
7. Mecanismo.
8–9. Componentes.
10. Implementación (tres sistemas).
11. Resultado, cualitativo («tighter»).
12. Aplicaciones (cinco casos).

Números: solo recuentos (tres atributos, tres sistemas, cinco casos). Ninguna medida.

**Introducción.** Unos diez bloques, varios con encabezado en negrita.
- Contexto, y certificación con su hueco.
- Tres atributos del dominio, numerados I–III, cada uno con citas.
- Certificación global frente a local.
- Crítica de los métodos existentes, uno por uno, cerrando cada vez con la misma frase («It conflicts with the attribute N…»).
- **Our Solution.**
- Cómo BARS cumple cada atributo.
- **Implementation and Evaluations.** Aquí está el único número de la introducción («reduced by 99% on average»).
- **Contributions.** «This paper makes three contributions», tres viñetas de dos o tres líneas con *We propose*, *We implement… and evaluate*, *We apply*. Sin cifras; el código va en nota al pie.
- No hay párrafo de hoja de ruta; lo sustituye la figura 1 («The workflow of this paper»), con las secciones marcadas sobre el diagrama.
- La tabla I, en la página 1, compara los métodos con las columnas que salen de los tres atributos.

**Modelo de amenaza y formalización.** §III, «Problem Scope», alrededor de una página.
- A. *Threat Model*, un tercio de columna: dos «modelos de amenaza» cualitativos (ataque de evasión y falsas alarmas), sin conocimiento ni capacidades del atacante. Es el punto más débil del artículo, y es por donde lo critican los trabajos posteriores.
- B. *Certification Goal*: la región de robustez Ω y el vector de radios por dimensión, con ecuaciones numeradas.
- C. Visión general del sistema en dos etapas.
- Tabla II de notación en el cuerpo, anunciada al abrir la sección.

**Teoremas.** §IV. Primero una subsección de motivación (IV-A), después el diseño, después el teorema 1 (caso lineal) y el teorema 2 (caso general), con las pruebas en los apéndices A y B. Las hipótesis van dentro del enunciado («Suppose that…»). El sentido práctico no se explica junto al teorema: se da después, con una métrica con nombre (MRR, *mean robustness radius*) y con los cinco casos de aplicación.

**Evaluación.** §VII, unas 4,6 páginas (35 %), diez subsecciones.
- Párrafo de apertura con puntero a cada subsección y figura 4, «The roadmap of experiments».
- A, configuración (sistemas, métodos de referencia con el enlace a su código, datos, hardware); B, hiperparámetros; C y D, comparación con métodos de referencia; E–I, cinco casos de aplicación; J, ablación.
- Cada experimento sigue la misma plantilla de tres encabezados en negrita: **Experiment motivation.** / **Experiment design.** / **Experiment results.** Los resultados se dan como viñetas tras «From the results, we have the following observations:».
- Lectura de la métrica dicha de antemano («larger MRR indicates tighter robustness guarantee»).
- «For experiment fairness» se repite al justificar cada decisión de comparación.
- Los resultados negativos van como una viñeta más: un método de referencia no puede certificar uno de los sistemas; MRR no depende del número de distribuciones; con ruido aleatorio gana el método de referencia.

**Figuras y tablas.** Nueve figuras y diez tablas (una en el apéndice). Tabla en la página 1 y figura en la 2. Pies de una línea, poco autosuficientes; las tablas llevan leyenda de símbolos al pie.

**Discusión y limitaciones.** §VIII, un tercio de página, dos encabezados: *Applications for more domains* y *Limitation and future work* («First… Second… Third…»). Breve, orientada al futuro; cada limitación se convierte en trabajo futuro.

**Recursos que copiar.**
- Requisitos numerados que sirven de criterio en la tabla comparativa y de argumento contra cada alternativa.
- Diagrama-hoja de ruta con secciones.
- Plantilla fija por experimento.
- Métrica con nombre y sentido declarado.
- Citas:
  - "It conflicts with the attribute III of traffic analyzers."
  - "From the results, we have the following observations:"
  - "Between certification methods, larger MRR indicates tighter robustness guarantee."

**Reparto aproximado (13,3 páginas de cuerpo).** Introducción 14 %; antecedentes 7 %; alcance del problema 8 %; certificación (teoría) 19 %; optimización del ruido 10 %; estrategia práctica 5 %; experimentos 35 %; discusión y conclusión 3 %.

---

## 5. Arp et al., "Dos and Don'ts of Machine Learning in Computer Security" (USENIX Security 2022)

**Patrón del título.** Expresión hecha («Dos and Don'ts of X in Y»). Prescriptivo, memorable, sin dos puntos ni tecnicismos.

**Resumen.** 195 palabras, 9 frases, dos párrafos (problema y aportación).
1–2. Contexto.
3. Problema («subtle pitfalls»).
4. Postura («we look at this problem with critical eyes»).
5. Contribución 1 (identificar).
6. Estudio de prevalencia.
7. Análisis de impacto.
8. Remedio (recomendaciones).
9. Problemas abiertos.

Números: dos (30 artículos, 10 años).

**Introducción.** Cuatro párrafos, lista y recuadro.
- P1: contexto.
- P2: giro («Machine learning, however, has no clairvoyant abilities…») y hueco.
- P3: consecuencias.
- P4: «In this paper, we identify ten common—yet subtle—pitfalls…», con el hallazgo titular en palabras («each paper suffers from at least three pitfalls»).
- Contribuciones: lista numerada de tres, cada una con etiqueta en negrita (**Pitfall Identification.**, **Prevalence Analysis.**, **Impact Analysis.**) y puntero a sección. Verbos: *identify*, *analyze*, *experimentally analyze*. Solo llevan recuentos (ten, 30, four).
- Un recuadro «Remark» fija el tono: no es un ejercicio de señalar culpables.
- Sin hoja de ruta: los punteros de las contribuciones bastan.
- Figura 1 en la segunda página: el flujo de trabajo con los diez fallos colocados encima. Es el mapa de todo el artículo.

**Modelo de amenaza y formalización.** No aplica como tal, pero el artículo prescribe (P10, «Inappropriate Threat Model») definir el modelo con precisión, evaluar respecto a él y suponer un adversario adaptativo. La «formalización» es una taxonomía:
- cada fallo tiene identificador (P1–P10) y una definición de una frase en recuadro;
- le siguen tres encabezados fijos en negrita: *Description*, *Security implications*, *Recommendations*;
- una barra de color da su prevalencia.

Los identificadores se usan después en todo el texto, entre paréntesis, como referencias cruzadas.

**Garantías.** No hay. La evidencia es un estudio de prevalencia (§3) y cuatro casos (§4).

**Evaluación.**
- §3, análisis de prevalencia: criterios, figura 3 y un párrafo «Takeaways.».
- §4, análisis de impacto: abre con una lista que asigna a cada subsección sus fallos («§4.1: mobile malware detection (P1, P4, and P7)»).
- Cada caso repite encabezados en negrita: *Dataset collection*, *Dataset analysis*, *Experimental setup*, *Results*.
- §4.5, «Takeaways», cierra la sección.
- Los métodos criticados se presentan con un recuadro que explica por qué se eligieron y los elogia.
- El resultado de cada caso está en una tabla pequeña junto al texto.

**Figuras y tablas.** En el cuerpo, ocho figuras y cinco tablas; en el apéndice, una figura y tres tablas. Primera figura en la segunda página. Pies de dos a cuatro líneas que dicen qué mirar.

**Discusión y limitaciones.** §5, «Limitations and Threats to Validity», media página, con un encabezado en negrita por cada parte del estudio (*Pitfalls*, *Prevalence analysis*, *Impact analysis*). Tono franco y conciliador: reconoce el sesgo de selección y dice por qué no invalida la conclusión.

**Recursos que copiar.**
- Identificadores cortos reutilizados en todo el texto.
- Definición de una frase en recuadro.
- Plantilla fija por elemento.
- Lista que asigna experimentos a afirmaciones.
- Párrafos «Takeaways».
- Recuadros «Remark» para controlar el tono.
- Citas:
  - "This work should not be interpreted as a finger-pointing exercise."
  - "Hence, threat models should be defined precisely and systems evaluated with respect to them."
  - "To our surprise, each paper suffers from at least three pitfalls"

**Reparto aproximado (13,6 páginas de cuerpo).** Introducción 10 %; fallos y recomendaciones 33 %; prevalencia 13 %; impacto 31 %; limitaciones 4 %; trabajo relacionado 6 %; conclusión 2 %.

---

## Patrones comunes

1. **Un vocabulario formal, fijado pronto, organiza todo el artículo.** Pierazzi: cuatro restricciones, que pasan a ser definiciones, columnas de la tabla I y subsecciones de §III. BARS: tres atributos, que pasan a ser criterios de la tabla I y argumento contra cada alternativa. Arp: P1–P10, que organizan la prevalencia y el impacto. El lector aprende la estructura una vez.

2. **La garantía se presenta en cuatro tiempos.** Enunciado en palabras; teorema corto y con nombre; lectura (observaciones, «Informally…», lo que no supone); esbozo o puntero, con la prueba completa en el apéndice. Los límites de la garantía se cuentan junto a ella (Cohen: «one major drawback», «requires many samples»), no se dejan para la discusión.

3. **Pocas cosas con nombre, definidas una vez y repetidas igual.** *Side-effect features*, *conserved features*, *realizable attacks*, *base/smoothed classifier*, MRR, P1–P10; abreviaturas con «henceforth». La definición corta se repite en resumen, introducción y cuerpo.

4. **Contribuciones cortas, con verbo y casi sin cifras.** Dos o tres, en viñetas con puntero a sección (Pierazzi, BARS, Arp) o en un párrafo cada una (Tong); Cohen las reduce a una frase. Los resúmenes llevan de cero a dos cifras de resultado. Cuando hay una cifra titular (Cohen), es una sola y se repite igual en resumen, introducción y primera tabla.

5. **Evaluación por preguntas o afirmaciones, con plantilla fija.** La métrica se define antes de los resultados y se dice cómo leerla (Cohen, BARS). Cada experimento repite la misma secuencia de encabezados (BARS, Arp). La conclusión de cada bloque está escrita: «Takeaways» (Arp), viñetas de observaciones (BARS), «To address question (2)» (Tong).

6. **La primera figura o tabla llega en la página 1 o 2 y enseña la idea o el mapa, no la arquitectura.** Cohen: figura 1 en la página 1. BARS: tabla I en la página 1 y diagrama-hoja de ruta en la 2. Arp: mapa de fallos en la segunda página. Las excepciones (Pierazzi, página 5; Tong, séptima página) son los que no tienen sistema que dibujar.

7. **Encabezados en negrita al inicio de párrafo como señalización principal.** Ninguno de los cinco tiene el párrafo clásico «The rest of the paper is organised…». Lo sustituyen punteros a sección en las contribuciones, mini hojas de ruta al abrir cada sección o un diagrama.

8. **Limitaciones breves, llanas y sin resultados nuevos.** Entre un tercio de página y una página, en sección propia (Arp, BARS, Tong) o donde nacen (Cohen). Los resultados negativos se dan en el mismo registro que los positivos. La discusión no introduce experimentos.

9. **El modelo de amenaza del cuerpo es corto y remite al apéndice.** Un tercio de columna en Pierazzi y BARS, con el conocimiento del atacante como tupla y Kerckhoffs como justificación. Donde el modelo es la contribución (Pierazzi), se formaliza con definiciones; donde se despacha en dos frases (BARS), es la debilidad que otros explotan después.

10. **Proporciones.** La parte formal o de método ocupa entre el 30 y el 40 %; la evaluación, entre el 16 y el 45 %; la introducción, alrededor del 10 % (22 % en Cohen por sus figuras); discusión y conclusión juntas, menos del 8 %.

---

## Nuestro manuscrito frente a esos patrones

Leído: `paper/main.tex` y `paper/sections/*.tex`. No se ha editado nada. Las cifras de los pasajes `\todo{...}` se ignoran.

**Datos de partida.**
- Resumen: 253 palabras, 10 frases, tres cifras de resultado (1,8 y 1,6 alarmas; 1,2 millones de paquetes). Está dentro del rango de los modelos (140–300 palabras).
- Reparto aproximado del cuerpo: introducción 8 %; antecedentes 8 %; motivación 4 %; modelo de amenaza 5 %; diseño 16 %; evaluación 44 %; discusión 11 %; conclusiones 3 %.
- Cuatro figuras, doce tablas y un algoritmo. La primera figura (la arquitectura) está en la página 6; la primera tabla (comparación de defensas), en la página 4.

**Lo que ya hace bien (no tocar).**
- El modelo de amenaza está separado en párrafos con encabezado (entorno, objetivo, capacidades, conocimiento, transformaciones, fuera de alcance), más completo que el de BARS.
- La tabla 2 de operaciones cumple el papel de la tabla I de Pierazzi.
- Casi todos los párrafos de la evaluación empiezan por la afirmación.
- Los resultados negativos se cuentan sin rodeos (la comparación con umbrales de tasa, los escaneos lentos, el coste de la reutilización de conexiones).
- La tabla 1 compara defensas con criterios explícitos.

## Cambios propuestos para nuestro manuscrito

Ocho cambios, ordenados por valor. Ninguno pide experimentos ni afirmaciones nuevas.

### 1. Presentar el certificado en cuatro tiempos, con el teorema del «alerta certificada» en el cuerpo

- **Qué hacen los modelos.** Cohen: resultado en palabras, teorema 1, viñetas de «observaciones» (empezando por lo que no supone), esbozo de prueba y prueba completa en el apéndice. Pierazzi cierra con «Informally,…».
- **Qué hace el nuestro.** En `design.tex`, líneas 108–143, el párrafo «Guarantee» enuncia una proposición sobre los contadores (líneas 115–123), que en realidad es el lema. La afirmación que le importa al lector, qué es una alerta certificada y qué garantiza, está en prosa corrida (líneas 136–143), y su enunciado formal solo aparece como corolario en `appendix.tex`, líneas 80–88.
- **Cambio.** Reordenar el bloque así:
  1. Una frase informal, al estilo de «Our main result is…»: si la alerta sobrevive a restar la holgura, toda variante con operaciones libres vuelve a alertar a las mismas entidades como muy tarde Δ después.
  2. Lema 1 (conservación de la evidencia): la proposición actual.
  3. Teorema 1 (alerta certificada): el corolario, traído del apéndice.
  4. Un bloque «Cómo leer el teorema» con cuatro o cinco viñetas hechas con frases que ya existen: no supone nada sobre el conocimiento ni la búsqueda del atacante; no hay presupuesto (número y magnitud de las operaciones sin cota); cuesta una evaluación; es correcto pero no ajustado (línea 141); habla del estado en t + Δ; no cubre bajar la tasa ni la reutilización.
  5. Un esbozo de prueba de tres o cuatro líneas y el puntero al apéndice B.

  Hacen falta entornos `lemma` y `theorem` en `main.tex` (línea 8). Para compensar el espacio, las cifras del temporizador (líneas 145–152) pueden ir al apéndice junto a su observación.

### 2. Supuestos con nombre, antes del resultado y en una tabla «se cumple cuando / falla cuando / qué pasa entonces»

- **Qué hacen los modelos.** Cohen aísla la única hipótesis en una ecuación numerada y dedica la primera viñeta a lo que no se supone. Pierazzi da nombre a cada restricción y la agrupa en Γ. Arp da a cada elemento identificador y definición de una frase.
- **Qué hace el nuestro.** Los supuestos (A1)–(A4) aparecen después de la proposición, en un párrafo corrido (`design.tex`, líneas 124–134). Sus nombres (*Bounded accounting*, *Free operations only add*, *No merging*, *Unchanged responder*) solo están en `appendix.tex`, líneas 28–43. Cuándo fallan está repartido: Zeek sin temporizador activo en `discussion.tex`, líneas 8–12; la reutilización en `design.tex`, líneas 165–177; las respuestas elegidas por el atacante en `design.tex`, líneas 131–134.
- **Cambio.** Poner antes del lema una tabla compacta con cuatro filas (A1–A4) y estas columnas: nombre, enunciado en una línea, quién lo controla (defensor, atacante o víctima), cuándo falla y qué ocurre entonces (sin certificado, certificado de reutilización, alerta no certificada). Empezar los enunciados con «Under (A1)–(A4)», como ya hace la versión del apéndice. La discusión puede entonces remitir a la tabla en lugar de volver a explicarlo.

### 3. Modelo de amenaza con definiciones numeradas y las operaciones libres como conjunto formal

- **Qué hacen los modelos.** Pierazzi: definiciones numeradas con nombre, cada una con su ejemplo; conocimiento como tupla; tabla de símbolos. BARS: «Certification Goal» formal y tabla de notación al abrir la sección.
- **Qué hace el nuestro.** `threat_model.tex` es todo prosa. «Silent success» se define de pasada (líneas 19–24). La distinción entre operación libre y costosa se da en un párrafo (líneas 44–56) y en la tabla 2 (líneas 58–84). La definición precisa de operación libre es en realidad el supuesto (A2), que no aparece hasta el diseño. No hay tabla de notación, aunque el texto usa Δ, τ, δ, s, c, θ, K, C, D, F_i, b_e y ρ.
- **Cambio.** Añadir `\newtheorem{definition}` y convertir en definiciones breves, con su ejemplo de una línea:
  - Definición 1 (traza y registro).
  - Definición 2 (operación libre): el contenido de A2 y A3, con el conjunto de variantes libres de una traza, por ejemplo 𝓕(X).
  - Definición 3 (operación costosa).
  - Definición 4 (éxito silencioso).

  Así el teorema puede decir «para toda X′ ∈ 𝓕(X)» y la tabla 2 pasa a ser la enumeración de 𝓕 y de su complemento. Escribir los tres niveles de conocimiento como lo que el atacante ve en cada uno. Añadir una tabla de notación pequeña, aquí o en el apéndice.

### 4. Una figura conceptual del certificado en las dos primeras páginas y un ejemplo guía

- **Qué hacen los modelos.** Cohen pone en la página 1 una figura que dibuja la definición, y en el esbozo de prueba otra que dibuja el peor caso. La figura 1 de Pierazzi explica el concepto central por analogía geométrica. Cohen traduce el radio a píxeles en el pie de la tabla 1. Tong mantiene un «running example».
- **Qué hace el nuestro.** La primera figura es la arquitectura, en la página 6 (`design.tex`, líneas 5–14). Ninguna figura muestra por qué una sola evaluación cubre todas las variantes. La idea se cuenta en prosa en `introduction.tex`, líneas 39–51. El único ejemplo concreto del diseño es el de explicación de alertas (`design.tex`, líneas 251–253). La escala de la holgura se da en una frase con cinco valores (`design.tex`, líneas 155–158).
- **Cambio.**
  - Una figura esquemática, sin datos nuevos, citada desde el tercer párrafo de la introducción. Dos ejes de evidencia conservada; el punto x de la traza; la región que alcanzan las variantes libres (todo lo que queda por encima de x − s); el umbral de un modelo monótono; el punto x − s como única evaluación del peor caso. Al lado, en gris, la bola de un certificado con presupuesto, de la que las operaciones libres se salen.
  - Un ejemplo guía que siga una campaña por el modelo de amenaza, la evidencia, el certificado y la frontera, con cifras que ya están en el artículo cuando salgan de las reejecuciones.
  - La holgura por escala como tabla mínima de cinco columnas en lugar de frase.

### 5. La evaluación adversaria como espejo del modelo de amenaza: una pregunta por subsección, tabla-índice y frase de conclusión

- **Qué hacen los modelos.** La §III de Pierazzi repite las restricciones de §II como subsecciones. Arp abre §4 con la lista «subsección: fallos que cubre» y cierra con «Takeaways». BARS da una hoja de ruta de experimentos y la plantilla motivación, diseño y resultados. Tong numera preguntas y las responde por orden. Arp pide evaluar respecto al modelo de amenaza definido.
- **Qué hace el nuestro.** `evaluation.tex`, líneas 7–18, enumera seis preguntas en un párrafo, pero hay diez subsecciones. Solo tres llevan la pregunta en el título (6.2, 6.3 y 6.6). RQ5 y RQ6 cubren dos subsecciones cada una. La 6.4 (paquetes, línea 341) y la 6.5 (certificados con presupuesto, línea 360) no tienen pregunta. Los ataques están repartidos entre 6.3–6.7, 6.10 y la discusión. La tabla 2 dice qué cubre cada operación, pero no dónde se pone a prueba.
- **Cambio.**
  - Agrupar la sección en cuatro partes con título: (A) detección entre redes (RQ1 y RQ2); (B) ¿se cumple el certificado?, con campañas, paquetes y comparación con certificados de presupuesto (RQ3); (C) qué conserva el adversario, con frontera, atacante adaptativo, envenenamiento, ataques a la capa por flujo y comparación de defensas (RQ4 y RQ5); (D) tráfico real (RQ6).
  - Añadir a la tabla 2 una columna «Evaluado en (§)» con el nivel de conocimiento usado, o una tabla-índice al abrir la sección (pregunta, operación del atacante, subsección, tabla o figura).
  - Cerrar cada parte con una frase de conclusión marcada (cursiva o «Takeaway (RQn)»). La mayoría ya existen como primera frase de la subsección.

### 6. Sacar los resultados de la Discusión y dejarla en limitaciones breves ordenadas por supuesto

- **Qué hacen los modelos.** Limitaciones de un tercio de página a una página, sin datos nuevos, con un encabezado por bloque (Arp §5, BARS §VIII, Tong §9). Cohen anuncia la limitación principal en la introducción y la cuantifica en el método.
- **Qué hace el nuestro.** `discussion.tex` ocupa unas dos páginas (11 % del cuerpo). Las líneas 54–104 presentan un experimento completo, el envenenamiento, con su figura (líneas 74–82). Las líneas 119–130 dan medidas de rendimiento y memoria. Las líneas 13–21 repiten cifras de 6.2. La introducción y el modelo de amenaza anuncian el envenenamiento como uno de los tres ataques evaluados, pero el lector lo encuentra fuera de la evaluación.
- **Cambio.** Mover el envenenamiento y su figura a la parte (C) de la evaluación, y el coste al final del diseño o de la evaluación. Dejar la discusión en una página como máximo, con cinco bloques que empiecen cada uno por el límite dicho en una frase: alcance del certificado (remitiendo a la tabla de supuestos), ataques lentos, inflación de alertas, amenazas a la validez y conjuntos de datos.

### 7. Métricas certificadas y variantes del sistema definidas una vez, con nombre y sentido, y usadas igual en todos los pies

- **Qué hacen los modelos.** Cohen define *certified accuracy at radius r* antes de los resultados y no usa otra. BARS define MRR y dice cómo leerla. Tong fija abreviaturas con «henceforth» y las usa en texto, leyendas y pies.
- **Qué hace el nuestro.** La cobertura certificada cambia de nombre y de unidad: «Cert.» y «Cert.-R» por campañas en la tabla 4; «certified flow recall» en `design.tex`, línea 151; «Cert.» como porcentaje de 300 flujos en la tabla 6, cuyo pie tiene que avisar de que no coincide con la tabla 4 (`evaluation.tex`, líneas 378–387); «certified frontier»; «certified damage». Además, \sysname-cert-R y «System» se presentan por primera vez en la tabla 3 de la evaluación (`evaluation.tex`, líneas 95–116 y 184–196). El diseño describe el certificado de reutilización (`design.tex`, líneas 165–177), pero no el detector que lo usa.
- **Cambio.**
  - En el diseño, tras el párrafo «\sysname and \sysname-cert» (línea 154), una tabla de variantes: nombre, evidencia, escalas y certificado que da. La tabla 3 se queda solo con los detectores de comparación.
  - En «Thresholds and metrics» (`evaluation.tex`, línea 50), una lista de métricas con nombre, unidad y sentido (mayor o menor es mejor): campañas detectadas, cobertura certificada por campañas, cobertura certificada por flujos, alarmas por entidad y hora, frontera, frontera certificada, daño y daño certificado.
  - Usar esos nombres exactos en cabeceras y pies, y dar otro rótulo a la columna de la tabla 6 (por ejemplo «Cert. flows»).

### 8. Contribuciones más cortas, con verbo, puntero a sección y una cifra titular; la idea en una frase citable

- **Qué hacen los modelos.** Dos o tres contribuciones de dos a cuatro líneas, con *propose*, *prove*, *implement* o *evaluate* y puntero a sección; las cifras, fuera o reducidas a una (Pierazzi, BARS, Arp). Cohen condensa la contribución en una frase. Tong anuncia la idea con «The key idea is…» y la definición del concepto.
- **Qué hace el nuestro.** `introduction.tex`, líneas 68–110: seis viñetas en unas 42 líneas. La cuarta sola lleva más de diez cifras. La primera mezcla la afirmación, su comprobación, un hallazgo negativo y una comparación. La idea está repartida por el tercer párrafo (líneas 39–51) sin una frase que se pueda citar; la mejor candidata está en el resumen («it cannot send less without weakening the attack»).
- **Cambio.**
  - Reducir a tres o cuatro viñetas de tres líneas como máximo: el certificado (§5); la frontera de daño como medida (§5.3 y §6); la evaluación adversaria en tres capas con detección entre redes (§6); y qué añade y qué no añade el modelo aprendido a la garantía. Cada una con un puntero y, como mucho, una cifra.
  - El detalle numérico de las viñetas actuales pasa a las frases de conclusión de la evaluación (cambio 5).
  - Cerrar el tercer párrafo con la idea en una frase destacada, la misma en resumen, introducción y conclusión.
  - El resumen no necesita recorte. Bastaría partir su octava frase, de 47 palabras, que hoy lleva sola todo el resultado.

---

## Lo que no se pudo recuperar o verificar

- Google Scholar: no accesible; los recuentos son de Semantic Scholar (y Crossref para dos artículos).
- Tong et al. (100) y BARS (29) no llegan a 200 citas en Semantic Scholar.
- De Pierazzi et al. se analizó la v2 de arXiv como equivalente de la versión de S&P; no se cotejó con el PDF de IEEE Xplore.
- Los porcentajes de reparto por sección y el número de párrafos de las introducciones son aproximados.
- De los apéndices solo se leyó la estructura (qué contienen y cómo se enlazan), no el contenido completo.
