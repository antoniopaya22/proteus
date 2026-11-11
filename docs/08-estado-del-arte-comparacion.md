# 8. Estado del arte con el que hay que compararse (2026-11-11)

Revisión hecha para fijar contra qué y cómo comparar Proteus. Citas comprobadas
contra Crossref o la página de la conferencia salvo donde se indica. Complementa el
doc 02 (más amplio y anterior).

## 8.1 Defensas frente a evasión en NIDS

| Defensa | Mecanismo | Datos | Ataques | Cifras clave | Código |
|---|---|---|---|---|---|
| **APELID+** (Nguyen et al., JCSC 41(4), 2025; base APELID, C&S 136:103567, 2024) | Ensemble ponderado (XGB, GBM, CatBoost, BME, DNN) + entrenamiento adversario con ZOO/HSJA + feature squeezing | CSE-CIC-IDS-2018, por flujo, partición aleatoria 70/30, ≤14k/6k por clase | Solo característica: FGSM, JSMA, PGD, DeepFool, CW (contra DNN), ZOO, HSJA (ART 1.19.1). **Sin presupuestos ni ataque adaptativo** | Limpio 99,96 %; todos los ataques 98,73 % (ASR 1,24 %); HSJA 99,92 %, ZOO 99,96 % | No |
| **RAIDS** (Sarıkaya et al., C&S 135:103483, 2023) | Errores de autoencoder + clasificadores sobre subconjuntos aleatorios de características, apilados en LightGBM | CIC-IDS-2017, InSDN | WGAN/CTGAN (característica) | No verificadas en la revista | No |
| **BARS** (Wang et al., NDSS 2023) | Randomized smoothing con ruido optimizado por característica | Kitsune, CADE, ACID (IDS-2018) | ℓp en característica; PGD, BAP | ACID, FTP-BF, ‖δ‖∞≤0,2: éxito de evasión PGD 1,00→0,40; BAP 1,00→0,85 | github.com/KaiWangGitHub/BARS |
| **CertTA** (Yan et al., USENIX Sec 2025) | Smoothing multimodal: selección aleatoria de paquetes + ruido en tamaños y tiempos; certifica en espacio del tráfico | CICDOH20, TII-SSRC-23 (pcap, por flujo, pocas miles de muestras) | Blanket, Amoeba (adaptativo), Prism | Precisión certificada ~99 % (Transformers), >80 % resto; −0,025 macro-F1 en limpio | github.com/InspiringGroup-Lab/CertTA |
| **MTD-AD** (He, Kim, Asghar, TDSC 22(5), 2025) | Desplaza al azar la frontera de decisión de un NIDS de anomalías | IoT (probablemente UQ-IoT/Kitsune; **no verificado**) | "Prácticos" y adaptativos | **No verificadas** (texto de pago) | No encontrado |
| **PANTS** (Jin, Apostolaki, USENIX Sec 2025) | Entrenamiento adversario con muestras de tráfico realizables generadas con ML + SMT | ISCXVPN2016, UTMobileNet2021, VCAML (no NIDS) | Amoeba, BAP; atacante en host o en ruta | +52,72 % de robustez media sin perder precisión | github.com/jinminhao/PANTS |
| **A2PM** (Vitorino et al., FPS 2023; Ann. Telecom. 2023) | Entrenamiento adversario con ataque restringido y realista | CIC-IDS-2017, NewCICIDS (corregido), HIKARI; 24 características temporales | A2PM (caja negra, restringido) | XGB: F1 89,83 % → 0,06 % bajo ataque; con entrenamiento adversario 87,27 % → 86,28 % | No comprobado |
| **Han et al.** (JSAC 39(8), 2021) | Reducción adversaria de características | Kitsune, CIC-IDS-2017 y otros | PSO/GAN en espacio del tráfico | Evasión −50 % en la mayoría de casos | — |

**Ataque de referencia: NetMasquerade** (Liu et al., NDSS 2026; github.com/09nat/NetMasquerade).
Hard-label, RL + Traffic-BERT, >96,65 % de éxito contra 6 detectores en 80
escenarios, y vence a BARS (Fig. 12). Afirma que el entrenamiento adversario y el
smoothing en espacio de características no lo frenan. Propone como contramedidas el
entrenamiento adversario y la certificación en espacio del tráfico y la
aleatoriedad en inferencia. **Ninguna defensa publicada, salvo BARS, se ha medido
contra él.**

Otros: Catillo et al. (ARES/EDCC 2025, solo resúmenes): el entrenamiento adversario
en espacio de características no se transfiere a ataques DoS en espacio del problema.

Revisiones: He et al., IEEE COMST 25(1) 2023; Vitorino et al., SoK, C&S 134:103433
(2023); Ennaji et al., arXiv 2409.18736. **No existe un banco de pruebas común que
compare varias defensas con el mismo protocolo.**

## 8.2 Qué significa "igualar el estado del arte"

**Frente 1: espacio de características, CIC-IDS-2017/2018** (el terreno de Apollon v1
y APELID+).

- Comparar con APELID+ (98,73 % bajo ataques combinados en IDS-2018), con ensembles
  de árboles con entrenamiento adversario (A2PM) y con Apollon v1 (las dos variantes).
- Atacar con ZOO, HSJA y PGD **con presupuestos declarados** y con un **ataque
  adaptativo**; APELID+ no da ninguna de las dos cosas.
- Reejecutar los baselines con la misma partición, sin copiar cifras de otros
  datasets (el fallo de la Tabla 6 de APELID+, que compara con Apollon usando cifras
  de CIC-IDS-2017).
- Métricas: F1 y FPR en limpio, accuracy/detección bajo ataque, ASR.

**Frente 2: espacio del tráfico** (la afirmación fuerte de Proteus).

- Comparar con BARS, CertTA (los dos con código) y entrenamiento adversario tipo PANTS.
- Atacar con NetMasquerade (y Amoeba/Blanket si se puede) sobre flujos desde pcap.
- Métricas: ASR o tasa de defensa frente a la intensidad del ataque (paquetes
  insertados, relleno, retardo), macro-F1 en limpio y latencia.
- MTD-AD es el pariente conceptual más cercano a la aleatorización de Apollon:
  hay que leerlo entero y discutirlo.

**Hueco que Proteus puede ocupar:** primera defensa NIDS evaluada contra
NetMasquerade además de BARS, con garantía en espacio del tráfico sin presupuesto, y
un protocolo común para varias defensas.

## 8.3 Rendimiento en limpio y generalización

**Dentro de un mismo dataset** (partición aleatoria, por flujo, binario): el campo
satura en ~0,99 de accuracy/F1. Las diferencias reales están en F1 por clase o macro
y en FPR.

| Referencia | Protocolo | Cifras |
|---|---|---|
| Engelen et al., WTMC 2021 | RF, 75/25 aleatorio, CIC-IDS-2017 original vs corregido | F1 ponderado 0,99 en todas; por clase: Bot 0,60→0,99, Web BF 0,77→0,95, XSS 0,18→0,79 (atajos por RST y flujos "apéndice") |
| Cantone et al., IEEE Access 12, 2024 | XGB/RF, 80/20 | F1: CIC-17 99,8; CIC-18 original 97,0; LycoS-17 99,9; LycoS-Unicas-18 99,8 |
| Sarhan et al., arXiv 2104.07183 | RF, NetFlow v2 | NF-CSE-CIC-IDS2018-v2: F1 0,98, detección 96,82 %, falsa alarma 0,17 % |
| Neto et al., Sensors 23, 2023 (CIC-IoT-2023) | RF, 80/20 | 34 clases: accuracy 0,992, F1 0,714 (macro) |
| Pekar y Jozsa, Comput. Netw. 2024 | RF por día, sin IPs ni puertos | RF apenas cambia entre versiones corregidas: rendimiento alto no implica datos buenos |

**Entre datasets** (lo más parecido a nuestro protocolo):

| Referencia | Protocolo | Cifras |
|---|---|---|
| **Cantone et al. 2024** | Entrenar con un dataset entero, probar con el otro; LDA/DT/RF/XGB, 77 características | CIC-18→CIC-17: F1 25,8–39,1, AUROC 59–82. CIC-17→CIC-18: F1 33,9–51,2, AUROC 58–85. MCC medio 94,6 dentro, 29,4 entre datasets |
| Layeghy y Portmann (C&EE 108, 2023) | 4 datasets NetFlow v2, 12 pares | Supervisados pierden 56 % de F1 de media; muy asimétrico |
| **XeNIDS** (Apruzzese et al., TNSM 19(4), 2022) | CTU13, UNSW-NB15, CIC-18, CIC-DDoS-19 | Ataques no vistos de otras redes: F1 38–83. **Aviso**: detectores con benigno de la red destino y ataques de otra llegan a 99,9 F1 porque aprenden "red ajena = ataque" |

Nuestro protocolo **no** mezcla en entrenamiento benigno de la red destino con
ataques de otra (se entrena entero en la red origen; de la red destino solo se usa
benigno para fijar el umbral). Aun así hay que demostrar con una ablación que el
umbral local no explota esa diferencia.

**Detectores agregados o por ventana** (nuestros comparables más cercanos):
Kitsune (NDSS 2018; estadísticas amortiguadas por host/canal), Whisper (CCS 2021;
dominio de frecuencia, AUC 0,999), HyperVision (NDSS 2023; grafo de interacción,
F1 ≥ 0,86 en 92 datasets), Peregrine (2024; Kitsune en switch). Reportan AUC, EER,
TPR a FPR fija y latencia; **casi nadie reporta alarmas por hora ni por entidad**.

**Metodología**: Arp et al. (USENIX Sec 2022): curvas PR, MCC, AUC acotada a FPR
baja, falacia de la tasa base. Su caso NIDS: un umbral de tasa de paquetes por
ventana de 10 s (boxplot) supera a Kitsune (TPR 0,996 frente a 0,882 a FPR 10⁻³).
Alahmadi et al. (USENIX Sec 2022): los analistas quieren pocas alarmas e
interpretables. Axelsson (TISSEC 2000): FPR ≤ 10⁻⁵ para que sea operativo.

**Qué hay que reportar para no quedar por debajo en limpio:**

1. Dentro de dataset, binario y multiclase, en versiones originales y corregidas,
   con F1 macro y por clase y MCC. Objetivos: ~0,998 F1 en CIC-17 y CIC-18 corregido.
2. TPR a FPR 10⁻³ y 10⁻⁴, alarmas por hora y por entidad, tiempo hasta detección.
3. Entre datasets en las dos direcciones, frente a Cantone (F1 26–51, AUROC 58–85),
   con la ablación de "red ajena".
4. Particiones por tiempo o día, ≥5 semillas, sin IPs/puertos/tiempos como
   características del clasificador por flujo.

Baselines en limpio: RF/XGBoost por flujo, Kitsune, umbral de tasa por entidad de
Arp (ya lo tenemos: `rate_rules_local`), Whisper o HyperVision, Isolation Forest o
autoencoder sobre nuestras propias características agregadas.

## 8.4 Datasets

Requisito para Proteus: por flujo (o por paquete vía pcap), IPs, puertos, protocolo,
tiempos, paquetes y bytes por sentido, idealmente flags; etiquetas por flujo o
ventanas de ataque fiables con IPs de atacante y víctima. Debilidades a corregir de
CIC-IDS-2017/2018: (a) víctimas casi sin tráfico benigno; (b) pocas campañas por
tipo; (c) poca diversidad de redes; (d) pcaps para reproducir y modificar ataques.

Comprobado el 2026-11-11 (página oficial o URL probada), salvo lo marcado.

### Con tráfico de fondo real o parcialmente real

| Dataset | Acceso | Formato | Red y duración | Ataques | Etiquetas y problemas |
|---|---|---|---|---|---|
| **UGR'16** | Web oficial da HTTP 403 ahora; espejo de terceros en Hugging Face (`mehedi107/ugr-16`, CSV semanales) | NetFlow (nfdump), IPs anonimizadas de forma consistente, sin pcap | ISP real, mar–ago 2016, miles de millones de flujos | DoS, escaneos, botnet inyectados desde 25 VMs, muchas campañas; spam y escaneos reales | Fondo no verificado como benigno; etiquetas de detectores; ruido de etiquetas (arXiv 2305.19770) |
| **CTU-13** | HTTP directo, ~1,9 GB, CC-BY | Argus bidireccional con IPs reales; pcap de botnet | Red universitaria real (2011), 13 escenarios | 7 familias de botnet | "Background" = desconocido, no benigno |
| **CTU-SME-11** | Zenodo, ~80 GB comprimido | Zeek con IPs y tiempos; pcap (no verificado) | 11 dispositivos reales con uso humano, 7 días (2023), 99 M flujos | Malware, ataques internos y externos, exfiltración | Etiquetado por expertos; sin auditoría publicada |
| **IoT-23** | HTTP directo | pcap + Zeek | Dispositivos IoT reales | Mirai, Okiru, Torii… | Poco benigno por víctima |
| **LITNET-2020** | GitHub (enlaces de zip sin verificar), "libre para investigación" | Derivado de NetFlow, 85 características; IPs y tiempos (de memoria) | Red académica real (Lituania), 10 meses | 12 tipos emulados | Herramientas de ataque sin documentar |
| **CIDDS-001/002** | ZIP directos (384/204 MB) | NetFlow con IPs, tiempos, flags | Empresa emulada + un servidor real expuesto, 4 y 2 semanas | DoS, fuerza bruta, escaneos | Limpias dentro del testbed; lo externo "sospechoso/desconocido" |
| **UWF-ZeekData22/24** | HTTP directo, CC BY 4.0 | Zeek conn + Parquet + pcap | Cyber range universitario, 4 semanas (24) | Por táctica ATT&CK; 14 familias (24) | En la 22, casi todo es reconocimiento |
| **MAWILab** | HTTP directo | pcap solo cabeceras, anonimizado | Backbone transpacífico real, 15 min/día desde 2001 | Anomalías reales | Etiquetas débiles; sin actualizar desde dic 2024. Útil como benigno "donante" |

### De laboratorio (benigno sintético)

| Dataset | Acceso | Notas |
|---|---|---|
| UNSW-NB15 | SharePoint, manual | 100 GB pcap; atajo por TTL conocido |
| ToN-IoT | SharePoint, manual | Inconsistencias de etiquetas (Booij et al. 2022) |
| Bot-IoT | SharePoint, manual | ~9,5k flujos benignos frente a >70 M de ataque: inservible para benigno |
| NF-*-v3 (UQ) | Enlaces UQ / Kaggle | Mismo esquema NetFlow; v3 añade tiempos de inicio y fin; **etiquetas originales sin corregir** |
| CIC-DDoS-2019 | Formulario CIC, manual | Mismo CICFlowMeter con fallos que 2017/18 |
| CIC-IoT-2023 | Formulario, manual | CSV sin IPs ni tiempos: hay que reextraer de pcap; 54,8 % de filas duplicadas (arXiv 2608.10349) |
| HIKARI-2021 | Zenodo, CC BY | Solo fuerza bruta cifrada y escaneo CMS |
| Kitsune | UCI | CSV sin IPs; una captura por ataque |
| 5G-NIDD | IEEE DataPort / Etsin | Corto |
| BCCC-CIC-IDS2017/2018 | Formulario, manual | Reetiquetado distinto al de Liu et al.: útil como contraste |

**No hay ningún dataset público 2023–2026 que combine fondo real de ISP o campus,
semanas de datos, ataques etiquetados y pcaps.** Lo más cercano: CTU-SME-11 y
UWF-ZeekData24. En la literatura AML-NIDS casi nadie usa datasets con fondo real
(UGR'16, CTU-13): usarlos diferencia el paper.

### Recomendación

1. **UGR'16**: tráfico de ISP real y activo durante meses, muchas campañas. Corrige (a),
   (b) y (c). Manual (web caída; espejo de terceros a contrastar).
2. **CTU-13 + CTU-SME-11 (+ IoT-23)**: campus, pyme e IoT reales, con pcaps. Corrigen
   (a), (c) y (d). Descargables por script.
3. **LITNET-2020**: 10 meses de red académica real. Probablemente por script.
4. **NF-UNSW-NB15-v3 + NF-ToN-IoT-v3**: diversidad de testbeds y herramientas con el
   mismo esquema. No corrigen (a).
5. **Pcaps de UNSW-NB15 y ToN-IoT**: para reproducir y modificar ataques (d). Manual.
6. **UWF-ZeekData24**: campañas ATT&CK durante 4 semanas; Zeek encaja con los contadores.

**Víctimas ocupadas por construcción:** insertar pcaps de ataque (CIC-DDoS-2019,
UNSW-NB15, CTU) en tráfico real de fondo (MAWI, CTU), reasignando atacante y víctima a
hosts reales con mucho tráfico. Sirve también para la fase de reproducción.
