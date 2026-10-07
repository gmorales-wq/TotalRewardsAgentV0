# AGFTS-Swarm v0.1

Enjambre de cinco agentes que propone revisiones salariales con la gobernanza del TFM
*Gobernanza algorítmica de decisiones retributivas* (escala AGFTS) integrada como controles
verificables. **Prototipo de investigación con datos ficticios. No apto para producción.**

## Principios

1. **Ninguna propuesta llega a nómina sin decisión humana registrada** (art. 22 RGPD; art. 14 AI Act).
2. **El modelo de lenguaje no decide ni calcula.** El importe sale de un motor determinista sobre una
   política versionada con hash; el LLM solo redacta explicaciones a partir de hechos ya calculados, y su
   salida se verifica antes de usarse.
3. **Mínimo privilegio.** Cada agente recibe solo los campos que le asigna `config/capacidades.json`;
   sexo y edad viven en una bóveda que solo lee el auditor de equidad.
4. **Trazabilidad.** Registro encadenado (SHA-256 + HMAC) de cada traspaso y decisión humana.
5. **Sin dependencias externas** en modo simulado (solo biblioteca estándar de Python ≥ 3.10).

## Agentes

| Agente | Función | AGFTS |
|---|---|---|
| `custodio_dato` | Contrato de datos, seudonimización HMAC, separación de atributos protegidos, detección de inyección en comentarios | GOV |
| `analista_retributivo` | Incremento = general + desempeño + competencias + posición en banda, prorrateo presupuestario, suelo de convenio | XAI por construcción |
| `auditor_equidad` | Brecha media/mediana por grupo y sexo antes/después, ampliación, sesgo en la valoración, Simpson, proxies | JUS_PRO, JUS_DIS |
| `guardian_cumplimiento` | Coherencia aritmética, factores permitidos, hash de política, mínimo de convenio, tope, presupuesto; nivel de riesgo | AUT, AUD |
| `explicador` | Explicación individual verificada (cifras exactas, sin atributos protegidos, sin enlaces) + aviso de derechos fijo | XAI |

## Uso (desde la raíz del repositorio)

```bash
export PYTHONPATH=src
python -m agfts_swarm generar-datos --salida datos/plantilla_ficticia.csv
python -m agfts_swarm ejecutar --entrada datos/plantilla_ficticia.csv --salida ejecuciones/demo --fecha-ref 2026-10-01 --demo
python -m agfts_swarm revisar --ejecucion ejecuciones/demo --demo                     # interactivo
python -m agfts_swarm revisar --ejecucion ejecuciones/demo --decisiones ejemplos/decisiones_ejemplo.json --demo
python -m agfts_swarm exportar --ejecucion ejecuciones/demo --entrada datos/plantilla_ficticia.csv --salida nomina.csv --demo
python -m agfts_swarm verificar-registro --ejecucion ejecuciones/demo --demo
python -m unittest discover -s tests -v
```

`ejemplos/decisiones_ejemplo.json` contiene seudónimos de la ejecución de referencia; como la clave demo se
genera en cada instalación, en otra máquina hay que rehacer ese fichero con los seudónimos de `expediente.json`.

- **Parada de emergencia:** crear el fichero `PARADA` en el directorio de ejecución o `AGFTS_PARADA=1`.
- **Política aprobada:** `--hash-politica <sha256>` impide ejecutar si la política en disco cambió.
- **Claude como redactor:** `pip install anthropic`, `ANTHROPIC_API_KEY`, `--backend claude`
  (modelo en `AGFTS_MODELO`). No probado contra la API real en esta versión.
- **Clave maestra:** en producción, `AGFTS_CLAVE_MAESTRA` desde un gestor de secretos y sin `--demo`.

## Interfaz web (Streamlit)

En local: `pip install -r requirements.txt` y `streamlit run streamlit_app.py`.

En Streamlit Community Cloud:

1. Sube el contenido de esta carpeta a un repositorio de GitHub (privado recomendado).
   No subas `.clave_demo`, `datos/`, `ejecuciones/` ni `.streamlit/secrets.toml` (ya están en `.gitignore`).
2. En share.streamlit.io: *Create app* → elige el repositorio, rama y fichero principal `streamlit_app.py`.
   En *Advanced settings* selecciona Python 3.10 o superior.
3. En *Secrets* pega `AGFTS_CLAVE_MAESTRA` (ver `.streamlit/secrets.toml.example`). Sin ella, la app
   funciona con una clave efímera por sesión.
4. Opcional: `ANTHROPIC_API_KEY` en *Secrets* y descomenta `anthropic` en `requirements.txt` para usar Claude
   como redactor.

La interfaz aísla cada sesión en su propio directorio temporal, muestra el texto no verificado escapado y
exige confirmar que un CSV subido es ficticio. **No subas datos salariales reales a un servicio en la nube
de terceros** sin EIPD, contrato de encargo y análisis de transferencias internacionales (RGPD).

## Salidas de una ejecución

`informe_calidad.json`, `expediente.json` (propuestas, dictamen, explicación, nota del responsable,
decisión humana), `informe_equidad.json`, `consumo_modelo.json`, `politica_snapshot.json`,
`manifiesto.json` (hashes de entrada, política y salidas), `registro_auditoria.jsonl`, `resumen.txt`.

## Antes de un piloto real (no implementado)

KMS y rotación de claves · cifrado en reposo · registro en almacenamiento inmutable · agentes en procesos
separados · política real revisada e informada a la RLPT (art. 64.4.d ET) · EIPD (art. 35 RGPD) ·
umbrales heurísticos validados con la organización · comparación por trabajo de igual valor ·
métricas de calidad de la supervisión humana.

El documento de arquitectura y modelo de amenazas detalla controles, normas y riesgo residual.
