"""Interfaz Streamlit de AGFTS-Swarm v0.1.

Despliegue en Streamlit Community Cloud: subir este repositorio a GitHub y
seleccionar `streamlit_app.py` como fichero principal (Python 3.10 o superior).

Seguridad de la interfaz:
- Cada sesión trabaja en su propio directorio temporal: las sesiones no comparten ficheros.
- La clave maestra sale de `st.secrets` (AGFTS_CLAVE_MAESTRA); si no existe, se genera
  una clave efímera en memoria para esa sesión y nunca se escribe en disco.
- Todo texto no verificado (comentarios de responsables, salida del modelo) se muestra
  como texto escapado, nunca como Markdown/HTML interpretado (OWASP LLM05).
- La aplicación está pensada para datos FICTICIOS: un servicio en la nube de terceros no
  es lugar para datos salariales reales sin EIPD y contrato de encargo (arts. 28 y 35 RGPD).
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
import secrets
import sys
import tempfile
import zipfile
from datetime import date
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

RAIZ = Path(__file__).resolve().parent
sys.path.insert(0, str(RAIZ / "src"))

from agfts_swarm import __version__  # noqa: E402
from agfts_swarm.datos_sinteticos import CAMPOS, generar  # noqa: E402
from agfts_swarm.orquestador import ParadaSolicitada, ejecutar  # noqa: E402
from agfts_swarm.registro import RegistroAuditoria  # noqa: E402
from agfts_swarm.seguridad import ErrorSeguridad, cargar_clave_maestra  # noqa: E402
from agfts_swarm.supervision import aplicar_decisiones, exportar  # noqa: E402

CONFIG = RAIZ / "config"
MAX_BYTES = 2 * 1024 * 1024
COLOR_ANTES, COLOR_DESPUES = "#2a78d6", "#eb6834"

st.set_page_config(page_title="AGFTS-Swarm", page_icon="⚖️", layout="wide")


# ---------------------------------------------------------------------------
# Utilidades
# ---------------------------------------------------------------------------

def _secreto(nombre: str) -> str | None:
    try:
        return st.secrets.get(nombre)  # type: ignore[no-any-return]
    except Exception:  # sin secrets.toml
        return None


def clave_sesion() -> bytes:
    if "clave" not in st.session_state:
        valor = _secreto("AGFTS_CLAVE_MAESTRA")
        if valor:
            os.environ["AGFTS_CLAVE_MAESTRA"] = valor
            st.session_state.clave = cargar_clave_maestra(modo_demo=False)
            st.session_state.clave_origen = "secreto configurado"
        else:
            st.session_state.clave = secrets.token_bytes(32)
            st.session_state.clave_origen = "efímera de sesión (solo demostración)"
    return st.session_state.clave


def dir_sesion() -> Path:
    if "dir" not in st.session_state:
        st.session_state.dir = Path(tempfile.mkdtemp(prefix="agfts_"))
        st.session_state.n_ejec = 0
    return st.session_state.dir


_MD = re.compile(r"([\\`*_{}\[\]()<>#+\-.!|~$])")


def texto_seguro(texto: str) -> str:
    """Escapa Markdown/HTML: el texto no verificado se muestra, no se interpreta."""
    return _MD.sub(r"\\\1", texto or "")


def cargar_json(ruta: Path):
    return json.loads(ruta.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Cabecera y barra lateral
# ---------------------------------------------------------------------------

st.title("AGFTS-Swarm · revisión salarial gobernada")
st.caption(f"Prototipo de investigación v{__version__}. Cinco agentes proponen; una persona decide. "
           "Usa solo datos ficticios.")

clave = clave_sesion()
base = dir_sesion()

with st.sidebar:
    st.header("1 · Datos")
    origen = st.radio("Origen", ["Plantilla ficticia generada", "Subir CSV"], index=0)
    semilla = st.number_input("Semilla", value=2026, step=1, disabled=origen != "Plantilla ficticia generada")
    subido = None
    confirmo = False
    if origen == "Subir CSV":
        st.caption("Columnas: " + ", ".join(CAMPOS))
        subido = st.file_uploader("Fichero CSV (UTF-8, máx. 2 MB)", type=["csv"])
        confirmo = st.checkbox("Confirmo que el fichero contiene solo datos ficticios")
    fecha_ref = st.date_input("Fecha de referencia del dato", value=date(2026, 10, 1))

    st.header("2 · Modelo de lenguaje")
    opciones = ["mock"]
    if _secreto("ANTHROPIC_API_KEY"):
        os.environ["ANTHROPIC_API_KEY"] = _secreto("ANTHROPIC_API_KEY") or ""
        opciones.append("claude")
    backend = st.selectbox("Redactor de explicaciones", opciones,
                           help="'claude' aparece solo si ANTHROPIC_API_KEY está en los secretos de la app.")
    st.caption("El modelo solo redacta; nunca calcula importes.")

    ejecutar_btn = st.button("Ejecutar enjambre", type="primary", width="stretch")
    st.divider()
    st.caption(f"Clave: {st.session_state.clave_origen}")

if ejecutar_btn:
    try:
        st.session_state.n_ejec += 1
        dir_ej = base / f"ejecucion_{st.session_state.n_ejec:03d}"
        dir_ej.mkdir(parents=True, exist_ok=True)
        entrada = dir_ej / "entrada.csv"
        if origen == "Subir CSV":
            if subido is None:
                raise ValueError("Sube un fichero CSV.")
            if not confirmo:
                raise ValueError("Confirma que el fichero contiene solo datos ficticios.")
            datos = subido.getvalue()
            if len(datos) > MAX_BYTES:
                raise ValueError("El fichero supera 2 MB.")
            texto = datos.decode("utf-8-sig")
            cabecera = next(csv.reader(io.StringIO(texto)), [])
            faltan = [c for c in CAMPOS if c not in cabecera]
            if faltan:
                raise ValueError(f"Faltan columnas: {', '.join(faltan)}")
            entrada.write_text(texto, encoding="utf-8")
        else:
            generar(entrada, int(semilla), fecha_ref)
        with st.spinner("Ejecutando custodio, analista, auditor, guardián y explicador…"):
            ejecutar(entrada, CONFIG, dir_ej, clave, backend, fecha_ref)
        st.session_state.ejec = dir_ej
        st.session_state.pop("resultado_revision", None)
    except (ErrorSeguridad, ParadaSolicitada) as e:
        st.error(f"Ejecución detenida por un control: {e}")
    except (ValueError, UnicodeDecodeError, csv.Error) as e:
        st.error(f"Entrada no válida: {e}")

if "ejec" not in st.session_state:
    st.info("Configura los datos en la barra lateral y pulsa **Ejecutar enjambre**.")
    st.stop()

dir_ej: Path = st.session_state.ejec
expediente = cargar_json(dir_ej / "expediente.json")
equidad = cargar_json(dir_ej / "informe_equidad.json")
calidad = cargar_json(dir_ej / "informe_calidad.json")
consumo = cargar_json(dir_ej / "consumo_modelo.json")
props = expediente["propuestas"]
pres = expediente["resumen_presupuesto"]

t_res, t_eq, t_rev, t_exp, t_reg, t_out = st.tabs(
    ["Resumen", "Equidad", "Revisión humana", "Explicaciones", "Registro", "Exportar"])

# ---------------------------------------------------------------------------
# Resumen
# ---------------------------------------------------------------------------
with t_res:
    pendientes = sum(1 for p in props if p["decision_humana"] is None)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Registros válidos", f"{calidad['filas_validas']} / {calidad['filas_leidas']}")
    c2.metric("Pendientes de decisión", pendientes)
    c3.metric("Coste / presupuesto", f"{pres['coste_final']:,.0f} / {pres['presupuesto']:,.0f} €".replace(",", "."))
    c4.metric("Grupos con alerta", len(equidad["grupos_con_alerta"]))
    riesgos = pd.Series([p["riesgo"] for p in props]).value_counts().reindex(["alto", "medio", "bajo"]).fillna(0)
    st.write(f"**Riesgo:** alto {int(riesgos['alto'])} · medio {int(riesgos['medio'])} · bajo {int(riesgos['bajo'])}. "
             f"**Bloqueadas:** {sum(1 for p in props if p['estado'] == 'bloqueada')}. "
             f"**Prorrateo presupuestario:** {pres['factor_prorrateo']}.")
    if calidad["rechazos"]:
        st.warning(f"{calidad['filas_rechazadas']} filas no superan el contrato de datos y no reciben propuesta "
                   "hasta que se corrijan.")
        st.dataframe(pd.DataFrame([{"línea": r["linea"], "seudónimo": r.get("id_seudonimo", "—"),
                                    "errores": "; ".join(r["errores"])} for r in calidad["rechazos"]]),
                     hide_index=True, width="stretch")
    if calidad["comentarios_con_sospecha_inyeccion"]:
        st.warning(f"{calidad['comentarios_con_sospecha_inyeccion']} comentarios de responsables contienen posibles "
                   "instrucciones inyectadas. No afectan a los importes; las propuestas afectadas pasan a riesgo alto.")

# ---------------------------------------------------------------------------
# Equidad
# ---------------------------------------------------------------------------
with t_eq:
    st.caption(equidad["metodo"])
    filas = []
    for g, b in list(equidad["por_grupo"].items()) + [("Total", equidad["global"])]:
        filas.append({"grupo": g, "hombres": b["n_hombres"], "mujeres": b["n_mujeres"],
                      "brecha media antes %": b.get("brecha_media_antes_pct"),
                      "brecha media después %": b.get("brecha_media_despues_pct"),
                      "brecha mediana después %": b.get("brecha_mediana_despues_pct"),
                      "incr. medio H %": b.get("incremento_medio_hombres_pct"),
                      "incr. medio M %": b.get("incremento_medio_mujeres_pct"),
                      "alertas": "; ".join(b.get("alertas", [])) or b.get("estado", "")})
    tabla = pd.DataFrame(filas)
    largo = tabla[tabla["grupo"] != "Total"].melt(
        id_vars="grupo", value_vars=["brecha media antes %", "brecha media después %"],
        var_name="momento", value_name="brecha %").dropna()
    largo["momento"] = largo["momento"].map({"brecha media antes %": "Antes", "brecha media después %": "Después"})
    umbral = cargar_json(dir_ej / "politica_snapshot.json")["equidad"]["umbral_brecha_pct"]
    barras = alt.Chart(largo).mark_bar(cornerRadiusEnd=4).encode(
        x=alt.X("grupo:N", title="Grupo profesional", axis=alt.Axis(labelAngle=0)),
        xOffset=alt.XOffset("momento:N", sort=["Antes", "Después"]),
        y=alt.Y("brecha %:Q", title="Brecha media (% sobre media de hombres)"),
        color=alt.Color("momento:N", sort=["Antes", "Después"],
                        scale=alt.Scale(domain=["Antes", "Después"], range=[COLOR_ANTES, COLOR_DESPUES]),
                        legend=alt.Legend(title=None, orient="top")),
        tooltip=["grupo", "momento", alt.Tooltip("brecha %:Q", format=".2f")])
    regla = alt.Chart(pd.DataFrame({"y": [umbral]})).mark_rule(strokeDash=[4, 4], color="#888").encode(y="y:Q")
    st.subheader("Brecha retributiva por grupo, antes y después de la propuesta")
    st.altair_chart((barras + regla).properties(height=320), width="stretch")
    st.caption(f"Línea discontinua: umbral de alerta del {umbral} % (art. 10 Directiva 2023/970 usado como aviso interno).")
    st.dataframe(tabla, hide_index=True, width="stretch")
    if equidad["simpson"]:
        st.warning("Paradoja de Simpson: " + " · ".join(equidad["simpson"]))
    if equidad["proxies"]:
        st.info("Posibles variables proxy: " + " · ".join(
            f"{p['variable']} ~ {p['atributo']} (r = {p['r']}; usada en la decisión: {'sí' if p['usada_en_decision'] else 'no'})"
            for p in equidad["proxies"]))

# ---------------------------------------------------------------------------
# Revisión humana
# ---------------------------------------------------------------------------
with t_rev:
    st.markdown("Cada decisión exige persona revisora y justificación. Riesgo medio y alto se deciden una a una; "
                "las propuestas **bloqueadas** solo pueden modificarse o rechazarse.")
    revisor = st.text_input("Persona revisora (identificador)", key="revisor")
    pend = [p for p in props if p["decision_humana"] is None]
    orden = {"alto": 0, "medio": 1, "bajo": 2}
    pend.sort(key=lambda p: (orden[p["riesgo"]], p["grupo"]))
    if not pend:
        st.success("No quedan propuestas pendientes.")
    else:
        df = pd.DataFrame([{
            "id_seudonimo": p["id_seudonimo"], "grupo": p["grupo"], "riesgo": p["riesgo"], "estado": p["estado"],
            "salario_actual": p["salario_actual"], "incremento_pct": p["incremento_pct"],
            "salario_propuesto": p["salario_propuesto"],
            "motivos": "; ".join(p["violaciones"] + p["motivos_revision"]),
            "nota_responsable (no verificada)": (p.get("nota_responsable") or {}).get("comentario", ""),
            "decision": "", "nuevo_pct": None, "justificacion": "",
        } for p in pend])
        df = df[["id_seudonimo", "grupo", "riesgo", "incremento_pct", "decision", "nuevo_pct", "justificacion",
                 "motivos", "nota_responsable (no verificada)", "estado", "salario_actual", "salario_propuesto"]]
        editado = st.data_editor(
            df, hide_index=True, width="stretch", key="editor",
            disabled=[c for c in df.columns if c not in ("decision", "nuevo_pct", "justificacion")],
            column_config={
                "decision": st.column_config.SelectboxColumn("decisión", options=["", "aprobar", "modificar", "rechazar"]),
                "nuevo_pct": st.column_config.NumberColumn("nuevo %", min_value=0.0, step=0.1, format="%.2f"),
                "justificacion": st.column_config.TextColumn("justificación", max_chars=500),
            })
        if st.button("Registrar decisiones marcadas", type="primary"):
            decisiones = []
            for _, f in editado.iterrows():
                if f["decision"]:
                    d = {"id_seudonimo": f["id_seudonimo"], "accion": f["decision"], "revisor": revisor,
                         "justificacion": f["justificacion"] or ""}
                    if f["decision"] == "modificar":
                        d["nuevo_pct"] = None if pd.isna(f["nuevo_pct"]) else float(f["nuevo_pct"])
                    decisiones.append(d)
            if not decisiones:
                st.warning("No hay ninguna fila con decisión.")
            else:
                st.session_state.resultado_revision = aplicar_decisiones(dir_ej, decisiones, clave)
                st.rerun()

        bajos = [p["id_seudonimo"] for p in pend if p["riesgo"] == "bajo" and p["estado"] != "bloqueada"]
        with st.expander(f"Aprobación en bloque de riesgo bajo ({len(bajos)} propuestas)"):
            just_bloque = st.text_input("Justificación común", key="just_bloque")
            if st.button("Aprobar en bloque", disabled=not bajos):
                st.session_state.resultado_revision = aplicar_decisiones(dir_ej, [{
                    "en_bloque": True, "ids": bajos, "accion": "aprobar", "revisor": revisor,
                    "justificacion": just_bloque}], clave)
                st.rerun()

    res = st.session_state.get("resultado_revision")
    if res:
        st.write(f"Decisiones aplicadas: **{res['aplicadas']}** · rechazadas por validación: "
                 f"**{res['rechazadas_por_validacion']}**")
        for r in res["detalle_rechazos"]:
            st.error(f"{', '.join(map(str, r['ids'] or []))[:120]}: {'; '.join(r['errores'])}")

# ---------------------------------------------------------------------------
# Explicaciones
# ---------------------------------------------------------------------------
with t_exp:
    con_exp = [p for p in props if p.get("explicacion")]
    if con_exp:
        sel = st.selectbox("Persona (seudónimo)", [p["id_seudonimo"] for p in con_exp])
        p = next(x for x in con_exp if x["id_seudonimo"] == sel)
        st.markdown(f"**Grupo {p['grupo']}** · riesgo {p['riesgo']} · origen del texto: `{p['explicacion']['origen']}`")
        st.markdown(texto_seguro(p["explicacion"]["texto"]))
        st.info(p["explicacion"]["aviso_derechos"])
        st.dataframe(pd.DataFrame(p["factores"]), hide_index=True)
        if p.get("nota_responsable"):
            st.caption("Nota del responsable (texto no verificado, no usado en el cálculo):")
            st.code(p["nota_responsable"]["comentario"], language=None)
    st.caption(f"Llamadas al modelo: {consumo['llamadas']} · tokens: "
               f"{consumo['tokens_entrada'] + consumo['tokens_salida']} (estimados en modo simulado). {consumo['nota']}")

# ---------------------------------------------------------------------------
# Registro
# ---------------------------------------------------------------------------
with t_reg:
    ruta_reg = dir_ej / "registro_auditoria.jsonl"
    ver = RegistroAuditoria.verificar(ruta_reg, clave)
    if ver.integro:
        st.success(f"Registro íntegro: {ver.eventos} eventos con cadena de hashes y MAC válidos.")
    else:
        st.error(f"Registro alterado: {ver.error}")
    eventos = [json.loads(l) for l in ruta_reg.read_text(encoding="utf-8").splitlines() if l.strip()]
    st.dataframe(pd.DataFrame([{"seq": e["seq"], "ts": e["ts"], "agente": e["agente"], "evento": e["evento"],
                                "hash": e["hash"][:16] + "…"} for e in eventos]),
                 hide_index=True, width="stretch")
    with st.expander("Detalle del último evento"):
        st.json(eventos[-1])

# ---------------------------------------------------------------------------
# Exportar
# ---------------------------------------------------------------------------
with t_out:
    decididas = sum(1 for p in props if p["decision_humana"] and p["decision_humana"]["accion"] != "rechazar")
    st.write(f"Propuestas listas para nómina: **{decididas}** · pendientes: "
             f"**{sum(1 for p in props if p['decision_humana'] is None)}**.")
    if st.button("Generar fichero para nómina", disabled=decididas == 0):
        try:
            exportar(dir_ej, dir_ej / "entrada.csv", dir_ej / "nomina_para_carga.csv", clave)
            st.success("Fichero generado. El sistema no paga: una persona lo carga en nómina.")
        except ErrorSeguridad as e:
            st.error(str(e))
    if (dir_ej / "nomina_para_carga.csv").exists():
        st.download_button("Descargar nomina_para_carga.csv", (dir_ej / "nomina_para_carga.csv").read_bytes(),
                           file_name="nomina_para_carga.csv", mime="text/csv")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for f in sorted(dir_ej.iterdir()):
            if f.is_file() and f.name not in {"entrada.csv", "nomina_para_carga.csv"}:
                z.write(f, f.name)
    st.download_button("Descargar expediente de auditoría (.zip)", buf.getvalue(),
                       file_name=f"expediente_{dir_ej.name}.zip", mime="application/zip")
    st.caption("El expediente incluye seudónimos y no los identificadores originales; sigue siendo dato personal.")
