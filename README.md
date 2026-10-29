# vuln-slop-triage

CLI en Rust que hace triage de reportes de vulnerabilidades y emite un
veredicto JSON: `AUTO_CLOSE`, `NEEDS_HUMAN` o `PRIORITIZE`. Primero intenta
**reproducir el PoC** contra un binario que define el mantenedor, en un sandbox
sin red, con un oráculo que no depende del texto del reporte. Las señales de
texto vienen después.

*Rust CLI that triages vulnerability reports into `AUTO_CLOSE` /
`NEEDS_HUMAN` / `PRIORITIZE`. It first tries to reproduce the PoC against a
maintainer-defined binary in a network-less sandbox, using an oracle that is
independent of the report text. Text signals come second.*

## Estado honesto / Honest status

- MVP de un día. El corpus es **sintético y lo escribió el mismo autor que
  fijó los umbrales**. Los números del corpus de desarrollo miden consistencia,
  no generalización.
- Hay un set *held-out* chico (6 reportes) escrito después de fijar los
  umbrales, y **no pasa** los umbrales (ver abajo). Ese resultado es parte del
  hallazgo.
- El objetivo de 200 reportes reales anonimizados **no está hecho**.
- El objetivo de prueba (`fixtures/project`, "toyhttpd") son 5 programas en C
  de 25 a 37 líneas, cada uno con un bug puesto a propósito. No es software real.

## Cómo decide / How it decides

1. **PoC = datos.** El adjunto se pasa por stdin a cada objetivo del
   `project.json`. Si el reporte nombra una función que existe en el árbol, se
   prueban solo los objetivos que la implementan; si no nombra ninguna, se
   prueban todos.
2. **Oráculo independiente:**
   - `crash`: el proceso muere por SIGSEGV, SIGABRT, SIGBUS, SIGILL o SIGFPE;
   - `timeout`: no termina en el límite (2 s por defecto);
   - `canary_leak`: la salida contiene un canario aleatorio que se escribe en
     cada corrida fuera del directorio servido. Quien reporta no puede adivinarlo.
3. **Señales duras** (hechos falsables): CVE con año imposible o número de
   plantilla, función o archivo que no existen en el árbol, `archivo:línea`
   fuera de rango, adjunto vacío, PoC de plantilla (`# exploit code here`).
4. **Señales blandas** (estilo): frases de relleno en EN y ES, plantilla de
   bounty, carta formal, hedging, hosts genéricos, CVSS ≥9 sin reproducción, PoC
   que no reproduce. Los indicadores humanos (hash de commit, versión exacta,
   `archivo:línea` verificado) restan.
5. **Veredicto:**
   - `PRIORITIZE` si el PoC dispara un oráculo.
   - `NEEDS_HUMAN` si además es duplicado probable.
   - `AUTO_CLOSE` solo sin reproducción **y** con (≥2 señales duras, o ≥1 dura
     y puntaje blando ≥3).
   - `NEEDS_HUMAN` en cualquier otro caso.

   Un reporte escrito con estilo de LLM pero con un PoC que reproduce nunca se
   cierra (`v3`, `h6`).
6. **Duplicados** contra un índice de reportes ya aceptados, por dos vías:
   - huella `(objetivo, oráculo)`, solo si no es ambigua;
   - Jaccard de 3-gramas ≥0.20 más un símbolo verificado en común.

   Los duplicados van a `NEEDS_HUMAN` con `duplicate_of`; no se cierran solos.

## Sandbox

| modo | aislamiento | dónde se probó |
|---|---|---|
| `--sandbox local --net isolate` (default) | tmpdir propio, entorno vacío, timeout, `unshare -rn` (solo `lo`) | en esta box y en el job `unit` de CI |
| `--sandbox docker` | `docker run --network=none --cap-drop=ALL --pids-limit 64 --memory 256m` + `timeout` | **solo en el job `docker` de CI**: en la box de desarrollo no hay Docker |
| `--net host` | sin aislar la red; queda registrado en el veredicto | solo para depurar |

Si el sandbox pedido no existe, la herramienta **falla con exit 2**: no hace
fallback silencioso. Si `unshare -rn` no está, falla y pide `--sandbox docker`
o `--net host` explícito. Si falta `docker`, falla con "docker no instalado".
Hay un test que cubre esto.

**No hay** seccomp, rlimits de memoria ni límite de procesos en el modo local.
Solo hay aislamiento de red y de directorio de trabajo. No es apto para PoCs
hostiles arbitrarios: el PoC es un input, no un ejecutable.

## Medición / Measurement

```bash
scripts/measure.sh                                           # corpus de desarrollo (gate)
LABELS=fixtures/heldout/labels.json scripts/measure.sh --no-gate
scripts/measure.sh --no-run                                   # ablación: sin ejecutar PoCs
SANDBOX=docker scripts/measure.sh                             # requiere docker
```

Resultados medidos en la box de desarrollo (8 vCPU Xeon, build release,
29/10/2026, sandbox `local tmpdir + unshare -rn`). Fueron 3 corridas con los
mismos conteos, y `mean_ms` dio entre 103.0 y 103.8.

**Corpus de desarrollo** (20 reportes: 10 slop, 5 válidos, 5 duplicados; los
umbrales se fijaron mirando este set):

```text
n=20 autoclose_precision=1.0000 (10/10) slop_recall=1.0000 valid_closed=0/5
valid_poc_repro=3/3 dup_detected=5/5 controls+=4/4 controls-=5/5
mean_ms=103.0 max_ms=2006 pass=true
```

- Control positivo (CVE inventado, CVE de plantilla, PoC vacío, plantilla en
  ES): 4/4 en `AUTO_CLOSE`.
- Control negativo (5 válidos con formato IBB/GHSA, uno escrito con estilo LLM
  y uno sin PoC): 5/5 en `NEEDS_HUMAN` o `PRIORITIZE`.
- El tiempo medio de triage es de 103 ms por reporte, contra un objetivo de
  <90 s. Lo domina el caso `timeout`, que tarda 2 s.

**Held-out** (6 reportes escritos después de fijar los umbrales):

```text
n=6 autoclose_precision=0.5000 (1/2) slop_recall=0.3333 valid_closed=1/3
valid_poc_repro=1/1 controls-=2/3 pass=false
```

- `h2` es un **falso positivo**. Es un reporte válido, sin PoC, con estilo de
  plantilla y una ruta mal escrita (`src/cookie_parse.c`). La ruta inexistente
  cuenta como señal dura y, junto con el estilo, lo cierra. Es la falla
  principal: una sola señal dura de "archivo inexistente" es débil frente a un
  error de tipeo.
- `h3` y `h4` son slop plausible: nombran funciones reales y no tienen hechos
  falsables. Quedan en `NEEDS_HUMAN` (se escapan, pero no son falsos
  positivos).
- Hubo dos correcciones **después** de ver el held-out, así que estos números
  ya no son ciegos:
  - La huella de duplicado era ambigua cuando el PoC se probaba contra todos
    los objetivos. `h6` salía como duplicado falso.
  - Las frases se cortaban por saltos de línea. `h5` no cerraba.

  En la primera corrida ciega el held-out dio `autoclose_precision=0/1`,
  `valid_closed=1/3` y `h6` marcado como duplicado de `k1`.

**Ablación `--no-run`:** la precisión de `AUTO_CLOSE` sigue en 10/10, porque
los cierres salen de señales de texto. Pero bajan dos cosas:
- reproducción: 0/3 (no se ejecuta nada);
- duplicados detectados: 3/5 (se pierde la vía de huella).

La sandbox aporta `PRIORITIZE` y la huella de duplicados. No aporta los cierres.

**No medido todavía:**
- el job `docker` (corre solo en CI);
- un corpus real de 200 reportes;
- la tasa de reproducción sobre PoCs reales que necesitan compilar o tener red.

## Uso / Usage

```bash
scripts/build-targets.sh
cargo run --release -- triage REPORT.md --poc POC.bin \
  --project fixtures/project/project.json --known fixtures/corpus/known/index.json
# exit: 0 PRIORITIZE, 10 NEEDS_HUMAN, 20 AUTO_CLOSE, 2 error
cargo run --release -- measure fixtures/corpus/labels.json [--rows] [--no-gate]
```

Formato de `labels.json`: `{project, known, items: [{id, report, poc?, label:
slop|valid|dup, dup_of?, control?: positive|negative}]}`. Para escalar el
corpus, se agregan ítems.

## Trabajo previo / Prior art (fuentes leídas el 29/10/2026)

- **VulnRap** ([README en GitHub](https://github.com/REMEDiSSecurity/VulnRap.com)):
  plataforma que puntúa reportes de 0 a 100. Combina fingerprinting
  lingüístico, verificación factual (CVEs, funciones, URLs), análisis
  semántico con LLM opcional y una "verificación activa" de plausibilidad
  contra GitHub/NVD. Recomienda `AUTO_CLOSE / CHALLENGE_REPORTER /
  MANUAL_REVIEW / PRIORITIZE`. Varias señales de texto de esta herramienta
  siguen la misma idea. Según su README, VulnRap evalúa la *plausibilidad* del
  PoC. No encontramos que **ejecute** el PoC contra el objetivo con un oráculo.
  Solo leímos el README, no el código.
- **curl** terminó su bug bounty el 31/01/2026 por el volumen de reportes slop
  ([blog de Daniel Stenberg, 26/01/2026](https://daniel.haxx.se/blog/2026/01/26/);
  [curl/curl#20312](https://github.com/curl/curl/pull/20312)). Según el post,
  en casi 7 años el programa había confirmado 87 vulnerabilidades y pagado más
  de USD 100.000.
- **honeyslop** ([gadievron/honeyslop](https://github.com/gadievron/honeyslop/)):
  pone canarios en el código para que un escáner slop se delate. Es un enfoque
  complementario, del lado del repositorio.

## Financiamiento / Funding

Pensado como candidato para Hacker Initiative 2026 "Signal/Noise". No se
postuló a nada.

## Licencia / License

Apache-2.0. Ver `LICENSE`.
