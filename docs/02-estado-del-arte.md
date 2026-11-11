# 2. Estado del arte 2024–2026

Fecha: 2026-11-10. Resumen de la búsqueda bibliográfica. Las cifras proceden de los
abstracts o del texto de cada trabajo; conviene releer cada fuente antes de citarla
en el paper.

## 2.1 Ataques

| Ataque | Acceso del atacante | Coste | Por qué importa |
|---|---|---|---|
| NetMasquerade (NDSS 2026) | Solo pasa/bloquea; no conoce modelo ni características | 1,000–2,000 sondas para converger | >96.65% de éxito en 6 detectores y 80 escenarios; evade BARS (defensa certificada) |
| Domico et al. (2026) | Consultas al detector | 1.5–18 consultas por ejemplo, frente a 52–1,100 de la mejor búsqueda | Política RL amortizada; transfiere a detectores y tráfico no vistos |
| Perturbaciones host-space (AsiaCCS 2026) | Solo hosts que controla el atacante | Cambiar un carácter de un comando | Revisión de 316 papers: la mayoría perturba datos ya capturados, algo fuera del alcance de un atacante real |
| Liuer Mihou | Paquetes reproducibles | — | Evade Kitsune por completo; menos eficaz contra modelos clásicos |
| ARC (ICML 2022) y Lattice Climber (2025) | Caja blanca sobre la mezcla | — | Rompen ensembles aleatorios; el PGD adaptativo los sobreestima |
| AdvTG, adversarial pre-padding | Generación con LLM o RL | — | También caen los clasificadores preentrenados tipo ET-BERT |
| Deep PackGen (2023), NIDSGAN (2022) | Caja negra | — | Antecedentes RL y GAN a nivel de paquete |

Dos datos de NetMasquerade condicionan el diseño de cualquier defensa aleatoria:

- Con un 30% de ruido en la respuesta, el ataque se degrada poco y solo converge más
  lento. La aleatoriedad ingenua retrasa, pero no para.
- Los autores reconocen que su entrenamiento asume una frontera de decisión estática
  y proponen la aleatoriedad en inferencia como contramedida, sin evaluarla.

## 2.2 Defensas

| Familia | Representante | Límite conocido |
|---|---|---|
| Adversarial training | APELID+ (2025; dice superar a Apollon y RAIDS) | Trabaja en espacio de características; falla ante ediciones a nivel de paquete |
| Robustez certificada | BARS, MARS, TA-RS (2026), CertTA (USENIX Security 2025) | La cota en espacio de características es pequeña frente a ediciones multi-paso; TA-RS depende mucho del dataset |
| Moving target defense | MTD-AD (TDSC 2025), Morphence (ACSAC 2021) | MTD-AD es el competidor directo y sí evalúa atacantes adaptativos; en malware, los MTD se evaden con poca información |
| Defensas con estado | Blacklight, PIHA, QPA | OARS sube el éxito contra Blacklight y PIHA a ~78–88%; QPA lo baja a ~4%. Casi sin trabajo en NIDS |
| Restricción de características | Perturb-ability Score | Solo usa lo que el atacante no puede tocar; cuesta precisión |
| Teoría de mezclas | Meunier et al. (ICML 2021) | El equilibrio mixto existe, pero requiere diversidad real entre modelos |
| Diversidad de ensembles | DVERGE (NeurIPS 2020) | Evaluado en imágenes; sin evidencia en tráfico tabular |

Trabajo que cita o extiende Apollon:

- Tesis de grado (2025): añade clasificadores y compara selectores (epsilon-greedy,
  Thompson) en CIC-IDS-2017. Ampliar el pool mejora mucho; cambiar el selector apenas.
- APELID+ (2025): usa Apollon como baseline y reporta 98.73% de accuracy bajo ataque.

## 2.3 Metodología y datasets

- **Errores en los datasets.** CIC-IDS-2017 y CSE-CIC-IDS-2018 tienen errores de
  etiquetado documentados (Liu et al., IEEE CNS 2022). Flood et al. (EuroS&P 2024)
  identifican seis "design smells" en siete benchmarks de NIDS.
- **Realismo del modelo de amenaza.** Apruzzese et al. ("Real Attackers Don't
  Compute Gradients", SaTML 2023) piden modelos de amenaza basados en coste.
- **Revisiones sistemáticas.** Espindola et al. (2026, 94 estudios de 2022–2025) y
  Ennaji et al. (2024) señalan sesgo hacia el espacio de características, supuestos
  optimistas sobre el conocimiento del atacante y falta de ataques adaptativos.
- **Deriva y envenenamiento.** Los sistemas que se actualizan en producción son
  vulnerables a envenenamiento lento que se confunde con deriva benigna.

## 2.4 El hueco

Nadie ha medido una defensa aleatoria o móvil para NIDS contra los ataques
amortizados de 2026 (NetMasquerade, Domico et al.), en espacio de tráfico y contando
consultas. MTD-AD es lo más cercano y mueve una sola frontera de decisión. Los
propios autores de NetMasquerade dejan esa evaluación como trabajo futuro.

## 2.5 Fuentes

- Apollon: https://digibuo.uniovi.es/dspace/bitstream/handle/10651/71561/1-s2.0-S016740482300456X-main.pdf?sequence=1
- Repo v1: https://github.com/antonioalfa22/apollon
- Tesis 2025 que extiende Apollon: https://dgaida.github.io/student_projects/2025_ws2425_ba_luti/
- APELID+: https://vjs.ac.vn/jcc/article/view/22884
- NetMasquerade: https://arxiv.org/abs/2510.14906
- Domico et al.: https://arxiv.org/abs/2602.10299
- Host-space perturbations: https://arxiv.org/abs/2605.25822
- Liuer Mihou (tesis Auckland): https://researchspace.auckland.ac.nz/handle/2292/68913
- ARC: https://arxiv.org/abs/2206.06737
- Lattice Climber: https://arxiv.org/abs/2506.10888
- Survey LLM y NIDS (AdvTG): https://arxiv.org/abs/2510.23313
- Adversarial pre-padding: https://arxiv.org/abs/2510.25810
- Deep PackGen: https://arxiv.org/abs/2305.11039
- NIDSGAN: https://arxiv.org/abs/2203.06694
- TA-RS: https://arxiv.org/abs/2607.13801
- CertTA: https://www.usenix.org/system/files/usenixsecurity25-appendix-yan-jinzhu.pdf
- MTD-AD: https://doi.org/10.1109/TDSC.2025.3560246
- Morphence: https://arxiv.org/abs/2108.13952
- MTD en detección de malware: https://arxiv.org/abs/2302.00537
- Blacklight: https://arxiv.org/abs/2006.14042
- OARS: https://arxiv.org/abs/2303.06280
- QPA: https://arxiv.org/abs/2405.20641
- Perturb-ability Score: https://arxiv.org/abs/2409.07448
- Mixed Nash Equilibria in the Adversarial Examples Game: https://arxiv.org/abs/2102.06905
- DVERGE: https://arxiv.org/abs/2009.14720
- Bad Design Smells in Benchmark NIDS Datasets: https://detlearsom.github.io/pubs/BadSmells-EuroSP24-finaldraft.pdf
- Error Prevalence in NIDS datasets: https://archive.cps-vo.org/node/97449
- Real Attackers Don't Compute Gradients: https://real-gradients.github.io/resources/satml23_poster.pdf
- Modeling Realistic Adversarial Attacks against NIDS: https://arxiv.org/abs/2106.09380
- Ennaji et al., survey: https://arxiv.org/abs/2409.18736
- Espindola et al., revisión sistemática: https://doi.org/10.1016/j.cosrev.2026.100995
