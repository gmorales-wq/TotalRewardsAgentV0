"""Los cinco agentes del enjambre retributivo.

Cada agente:
- tiene una identidad propia (firma sus mensajes con su clave derivada);
- recibe solo los campos que su capacidad permite (proyección previa del orquestador);
- registra sus acciones en el registro encadenado;
- no tiene herramientas de ejecución: ningún agente puede escribir en nómina.

Correspondencia con el TFM (escala AGFTS):
  CustodioDato        -> GOV  (calidad, integridad, trazabilidad, uso responsable)
  AnalistaRetributivo -> salario de calificación (7.1.8), XAI por construcción
  AuditorEquidad      -> JUS_PRO / JUS_DIS, sesgos y proxies (7.1.4, 7.1.11)
  GuardianCumplimiento-> AUT acotada, AUD (art. 14 AI Act, art. 22 RGPD)
  Explicador          -> XAI (art. 86 AI Act, arts. 13-15 RGPD, Directiva 2023/970)
"""
from __future__ import annotations

import json
import math
import re
import statistics
from dataclasses import dataclass
from datetime import date
from typing import Any

from .capacidades import Capacidades, Mensaje
from .llm import ETIQUETAS_FACTOR, BackendLLM
from .registro import RegistroAuditoria
from .seguridad import ErrorSeguridad, Firmante, Seudonimizador, detectar_inyeccion, normalizar_texto


@dataclass
class Contexto:
    capacidades: Capacidades
    firmante: Firmante
    registro: RegistroAuditoria
    politica: dict[str, Any]
    hash_politica: str


class Agente:
    nombre = "agente"

    def __init__(self, ctx: Contexto):
        self.ctx = ctx

    def log(self, evento: str, **datos: Any) -> None:
        self.ctx.registro.registrar(self.nombre, evento, datos)

    def emitir(self, tipo: str, contenido: Any) -> Mensaje:
        return Mensaje(self.nombre, tipo, contenido).firmar(self.ctx.firmante)


# ---------------------------------------------------------------------------
# Bóveda de atributos protegidos
# ---------------------------------------------------------------------------

class Boveda:
    """Atributos protegidos separados del flujo operativo.

    Solo el AuditorEquidad puede leerla (capacidad `boveda_leer`), y solo para
    calcular agregados. Sexo y edad no son categorías especiales del art. 9 RGPD:
    la separación responde a minimización (arts. 5.1.c y 25 RGPD) y a impedir su
    uso como variable de decisión (Ley 15/2022, RD 902/2020). Si se añadieran
    categorías especiales para detectar sesgos, aplicaría el art. 4 bis del
    AI Act introducido por el Reglamento (UE) 2026/1744 (antes art. 10.5).
    La base jurídica concreta debe documentarla la empresa en su EIPD.
    """

    def __init__(self, capacidades: Capacidades):
        self._datos: dict[str, dict[str, Any]] = {}
        self._cap = capacidades

    def escribir(self, agente: str, seudonimo: str, atributos: dict[str, Any]) -> None:
        self._cap.exigir_herramienta(agente, "boveda_escribir")
        self._datos[seudonimo] = dict(atributos)

    def leer(self, agente: str) -> dict[str, dict[str, Any]]:
        self._cap.exigir_herramienta(agente, "boveda_leer")
        return {k: dict(v) for k, v in self._datos.items()}


# ---------------------------------------------------------------------------
# A1. Custodio del dato (GOV)
# ---------------------------------------------------------------------------

class CustodioDato(Agente):
    nombre = "custodio_dato"

    def procesar(self, filas: list[dict[str, str]], seud: Seudonimizador, boveda: Boveda,
                 fecha_referencia: date, hash_origen: str) -> Mensaje:
        self.ctx.capacidades.exigir_herramienta(self.nombre, "validar_contrato")
        self.ctx.capacidades.exigir_herramienta(self.nombre, "seudonimizar")
        grupos = self.ctx.politica["grupos_profesionales"]
        max_dias = self.ctx.politica["datos"]["antiguedad_maxima_dias"]
        validos, rechazados, notas = [], [], {}
        vistos: set[str] = set()

        for n, f in enumerate(filas, start=2):  # línea 1 = cabecera
            errores: list[str] = []
            ident = (f.get("id_empleado") or "").strip()
            if not ident:
                rechazados.append({"linea": n, "errores": ["id_empleado vacío"]})
                continue
            sid = seud.seudonimo(ident)
            if sid in vistos:
                errores.append("identificador duplicado")
            vistos.add(sid)

            def num(campo: str, tipo=float, lo=None, hi=None):
                try:
                    v = tipo(str(f.get(campo, "")).strip())
                except ValueError:
                    errores.append(f"{campo} no numérico")
                    return None
                if isinstance(v, float) and not math.isfinite(v):
                    errores.append(f"{campo} no finito")
                    return None
                if (lo is not None and v < lo) or (hi is not None and v > hi):
                    errores.append(f"{campo} fuera de rango [{lo}, {hi}]")
                return v

            grupo = (f.get("grupo") or "").strip()
            if grupo not in grupos:
                errores.append("grupo profesional desconocido")
            salario = num("salario_actual", float, 1, 1_000_000)
            desempeno = num("desempeno", int, 1, 5)
            comp = num("competencias_acreditadas", int, 0, 50)
            antig = num("antiguedad_anios", float, 0, 60)
            jornada = num("jornada_parcial", int, 0, 1)
            edad = num("edad", int, 16, 90)
            sexo = (f.get("sexo") or "").strip().upper()
            if sexo not in {"M", "F", "X", "ND"}:
                errores.append("sexo con valor no admitido")
            try:
                fecha = date.fromisoformat((f.get("fecha_dato") or "").strip())
                if (fecha_referencia - fecha).days > max_dias:
                    errores.append(f"dato desactualizado (> {max_dias} días)")
                if fecha > fecha_referencia:
                    errores.append("fecha_dato futura")
            except ValueError:
                errores.append("fecha_dato inválida")
            if grupo in grupos and salario is not None and salario < grupos[grupo]["minimo_convenio"]:
                errores.append("salario actual por debajo del mínimo de convenio")

            if errores:
                rechazados.append({"linea": n, "id_seudonimo": sid, "errores": errores})
                continue

            comentario = normalizar_texto(f.get("comentario_responsable") or "")[:2000]
            sospechas = detectar_inyeccion(comentario)
            if comentario:
                notas[sid] = {"comentario": comentario, "sospechas_inyeccion": sospechas}
            boveda.escribir(self.nombre, sid, {"sexo": sexo, "edad": edad})
            validos.append({
                "id_seudonimo": sid, "grupo": grupo, "salario_actual": round(salario, 2),
                "desempeno": desempeno, "competencias_acreditadas": comp,
                "antiguedad_anios": antig, "jornada_parcial": jornada,
                "alerta_inyeccion": bool(sospechas),
            })

        informe = {
            "hash_origen": hash_origen,
            "filas_leidas": len(filas),
            "filas_validas": len(validos),
            "filas_rechazadas": len(rechazados),
            "completitud_pct": round(100 * len(validos) / max(len(filas), 1), 2),
            "rechazos": rechazados,
            "comentarios_con_sospecha_inyeccion": sum(1 for v in notas.values() if v["sospechas_inyeccion"]),
            "fecha_referencia": fecha_referencia.isoformat(),
        }
        self.log("contrato_datos_validado", **{k: v for k, v in informe.items() if k != "rechazos"},
                 rechazos=[{"linea": r["linea"], "errores": r["errores"]} for r in rechazados])
        return self.emitir("datos_gobernados", {"registros": validos, "informe": informe, "notas_revisor": notas})


# ---------------------------------------------------------------------------
# A2. Analista retributivo (salario de calificación)
# ---------------------------------------------------------------------------

class AnalistaRetributivo(Agente):
    nombre = "analista_retributivo"

    def proponer(self, registros: list[dict[str, Any]]) -> Mensaje:
        self.ctx.capacidades.exigir_herramienta(self.nombre, "politica_leer")
        permitidos = self.ctx.capacidades.campos(self.nombre)
        for r in registros:
            extra = set(r) - permitidos
            if extra:
                raise ErrorSeguridad(f"{self.nombre} recibió campos no autorizados: {sorted(extra)}")

        pol, inc = self.ctx.politica, self.ctx.politica["incremento"]
        pb = inc["posicion_banda"]
        propuestas = []
        for r in registros:
            g = pol["grupos_profesionales"][r["grupo"]]
            compa = r["salario_actual"] / g["banda_mid"]
            factores = [
                ("general", inc["general_pct"]),
                ("desempeno", inc["desempeno_pct"][str(r["desempeno"])]),
                ("competencias", min(r["competencias_acreditadas"], inc["competencias_max"]) * inc["competencia_acreditada_pct"]),
            ]
            if compa < pb["compa_ratio_bajo"]:
                factores.append(("posicion_banda", pb["ajuste_bajo_pct"]))
            elif compa > pb["compa_ratio_alto"]:
                factores.append(("posicion_banda", pb["ajuste_alto_pct"]))
            bruto = sum(p for _, p in factores)
            propuestas.append({"r": r, "g": g, "compa": compa, "factores": factores,
                               "pct": max(0.0, min(bruto, inc["tope_individual_pct"]))})

        # Restricción presupuestaria: prorrateo proporcional explícito y explicado
        masa = sum(p["r"]["salario_actual"] for p in propuestas)
        presupuesto = masa * inc["presupuesto_masa_salarial_pct"] / 100
        coste = sum(p["r"]["salario_actual"] * p["pct"] / 100 for p in propuestas)
        escala = min(1.0, presupuesto / coste) if coste > 0 else 1.0

        salida = []
        for p in propuestas:
            pct_final = p["pct"] * escala
            facts = [{"factor": f, "pct": round(v, 2)} for f, v in p["factores"] if v != 0]
            suma = sum(v for _, v in p["factores"])
            if abs(pct_final - suma) > 0.005:
                # floor: el redondeo nunca puede hacer superar el presupuesto
                facts.append({"factor": "ajuste_presupuestario", "pct": math.floor((pct_final - suma) * 100) / 100})
            pct_r = round(sum(f["pct"] for f in facts), 2)
            nuevo = round(p["r"]["salario_actual"] * (1 + pct_r / 100), 2)
            if nuevo < p["g"]["minimo_convenio"]:  # suelo legal prevalece
                extra = round((p["g"]["minimo_convenio"] / p["r"]["salario_actual"] - 1) * 100 - pct_r, 2)
                facts.append({"factor": "minimo_convenio", "pct": extra})
                pct_r = round(pct_r + extra, 2)
                nuevo = round(p["r"]["salario_actual"] * (1 + pct_r / 100), 2)
            salida.append({
                "id_seudonimo": p["r"]["id_seudonimo"], "grupo": p["r"]["grupo"],
                "salario_actual": p["r"]["salario_actual"], "incremento_pct": pct_r,
                "salario_propuesto": nuevo, "compa_ratio": round(p["compa"], 3),
                "factores": facts, "version_politica": pol["version"], "hash_politica": self.ctx.hash_politica,
            })
        resumen = {"masa_salarial": round(masa, 2), "presupuesto": round(presupuesto, 2),
                   "coste_bruto": round(coste, 2), "factor_prorrateo": round(escala, 4),
                   "coste_final": round(sum(s["salario_propuesto"] - s["salario_actual"] for s in salida), 2)}
        self.log("propuestas_generadas", n=len(salida), **resumen)
        return self.emitir("propuestas", {"propuestas": salida, "resumen": resumen})


# ---------------------------------------------------------------------------
# A3. Auditor de equidad (JUS_PRO / JUS_DIS)
# ---------------------------------------------------------------------------

def _corr(x: list[float], y: list[float]) -> float | None:
    if len(x) < 3 or len(set(x)) < 2 or len(set(y)) < 2:
        return None
    return statistics.correlation(x, y)


def _brecha(m: list[float], f: list[float]) -> float | None:
    """Brecha retributiva (Directiva 2023/970, art. 3): (media H - media M) / media H."""
    if not m or not f:
        return None
    mm = statistics.fmean(m)
    return round(100 * (mm - statistics.fmean(f)) / mm, 2)


class AuditorEquidad(Agente):
    nombre = "auditor_equidad"

    def auditar(self, registros: list[dict[str, Any]], propuestas: list[dict[str, Any]], boveda: Boveda) -> Mensaje:
        eq = self.ctx.politica["equidad"]
        prot = boveda.leer(self.nombre)
        prop = {p["id_seudonimo"]: p for p in propuestas}
        k = eq["celda_minima"]
        umbral = eq["umbral_brecha_pct"]

        def filas(grupo: str | None):
            return [r for r in registros if grupo is None or r["grupo"] == grupo]

        def bloque(rs: list[dict[str, Any]]) -> dict[str, Any]:
            m = [r for r in rs if prot[r["id_seudonimo"]]["sexo"] == "M"]
            f = [r for r in rs if prot[r["id_seudonimo"]]["sexo"] == "F"]
            out: dict[str, Any] = {"n_hombres": len(m), "n_mujeres": len(f), "n_otros_o_nd": len(rs) - len(m) - len(f)}
            if len(m) < k or len(f) < k:
                out["estado"] = f"celda insuficiente (< {k}); no se publican métricas por sexo"
                return out
            antes_m = [r["salario_actual"] for r in m]
            antes_f = [r["salario_actual"] for r in f]
            desp_m = [prop[r["id_seudonimo"]]["salario_propuesto"] for r in m]
            desp_f = [prop[r["id_seudonimo"]]["salario_propuesto"] for r in f]
            out.update({
                "estado": "ok",
                "brecha_media_antes_pct": _brecha(antes_m, antes_f),
                "brecha_media_despues_pct": _brecha(desp_m, desp_f),
                "brecha_mediana_antes_pct": round(100 * (statistics.median(antes_m) - statistics.median(antes_f)) / statistics.median(antes_m), 2),
                "brecha_mediana_despues_pct": round(100 * (statistics.median(desp_m) - statistics.median(desp_f)) / statistics.median(desp_m), 2),
                "incremento_medio_hombres_pct": round(statistics.fmean(prop[r["id_seudonimo"]]["incremento_pct"] for r in m), 2),
                "incremento_medio_mujeres_pct": round(statistics.fmean(prop[r["id_seudonimo"]]["incremento_pct"] for r in f), 2),
                "desempeno_medio_hombres": round(statistics.fmean(r["desempeno"] for r in m), 2),
                "desempeno_medio_mujeres": round(statistics.fmean(r["desempeno"] for r in f), 2),
            })
            alertas = []
            if abs(out["brecha_media_despues_pct"]) >= umbral:
                alertas.append(f"brecha media tras la propuesta ≥ {umbral} %")
            if abs(out["brecha_media_despues_pct"]) - abs(out["brecha_media_antes_pct"]) >= eq["umbral_ampliacion_brecha_pp"]:
                alertas.append("la propuesta amplía la brecha existente")
            if abs(out["desempeno_medio_hombres"] - out["desempeno_medio_mujeres"]) >= eq["umbral_diferencia_desempeno"]:
                alertas.append("diferencia de valoración del desempeño entre sexos: posible sesgo en el dato de origen")
            out["alertas"] = alertas
            return out

        por_grupo = {g: bloque(filas(g)) for g in sorted({r["grupo"] for r in registros})}
        global_ = bloque(filas(None))

        # Paradoja de Simpson: el agregado oculta brechas por grupo o las invierte
        simpson = []
        gb = global_.get("brecha_media_despues_pct")
        for g, b in por_grupo.items():
            bg = b.get("brecha_media_despues_pct")
            if bg is None or gb is None:
                continue
            if abs(bg) >= umbral and abs(gb) < umbral:
                simpson.append(f"{g}: brecha {bg} % oculta por un agregado de {gb} %")
            elif bg * gb < 0 and abs(bg) >= 1:
                simpson.append(f"{g}: signo de la brecha opuesto al agregado")

        # Detección de variables proxy (Mittelstadt et al., 2016)
        es_f = [1.0 if prot[r["id_seudonimo"]]["sexo"] == "F" else 0.0 for r in registros]
        edad = [float(prot[r["id_seudonimo"]]["edad"]) for r in registros]
        usadas = {"desempeno", "competencias_acreditadas", "salario_actual"}
        proxies = []
        for var in ["desempeno", "competencias_acreditadas", "antiguedad_anios", "jornada_parcial", "salario_actual"]:
            x = [float(r[var]) for r in registros]
            for nombre_p, y in (("sexo(F)", es_f), ("edad", edad)):
                c = _corr(x, y)
                if c is not None and abs(c) >= eq["umbral_correlacion_proxy"]:
                    proxies.append({"variable": var, "atributo": nombre_p, "r": round(c, 3),
                                    "usada_en_decision": var in usadas})

        grupos_alerta = sorted(g for g, b in por_grupo.items() if b.get("alertas"))
        informe = {
            "metodo": "Brecha = (media H - media M) / media H * 100. Umbrales de alerta configurables; no constituyen juicio jurídico.",
            "global": global_, "por_grupo": por_grupo, "simpson": simpson,
            "proxies": proxies, "grupos_con_alerta": grupos_alerta,
        }
        self.log("auditoria_equidad", grupos_con_alerta=grupos_alerta, simpson=len(simpson),
                 proxies=[f"{p['variable']}~{p['atributo']}" for p in proxies])
        return self.emitir("informe_equidad", informe)


# ---------------------------------------------------------------------------
# A4. Guardián de cumplimiento (AUT acotada / AUD)
# ---------------------------------------------------------------------------

class GuardianCumplimiento(Agente):
    nombre = "guardian_cumplimiento"

    def revisar(self, registros: list[dict[str, Any]], propuestas: list[dict[str, Any]],
                equidad: dict[str, Any], notas: dict[str, Any]) -> Mensaje:
        pol = self.ctx.politica
        inc, sup = pol["incremento"], pol["supervision"]
        fuente = {r["id_seudonimo"]: r for r in registros}
        permitidos = set(pol["factores_permitidos"])
        resultado = []
        for p in propuestas:
            violaciones, motivos = [], []
            r = fuente.get(p["id_seudonimo"])
            if r is None:
                violaciones.append("propuesta sin registro de origen")
            else:
                if abs(r["salario_actual"] - p["salario_actual"]) > 0.005:
                    violaciones.append("salario actual alterado respecto al origen")
                if r.get("alerta_inyeccion"):
                    motivos.append("comentario del responsable con posible inyección de instrucciones")
            if p["hash_politica"] != self.ctx.hash_politica:
                violaciones.append("política distinta de la aprobada")
            usados = {f["factor"] for f in p["factores"]}
            if not usados <= permitidos:
                violaciones.append(f"factores no permitidos: {sorted(usados - permitidos)}")
            if abs(sum(f["pct"] for f in p["factores"]) - p["incremento_pct"]) > 0.011:
                violaciones.append("desglose de factores no cuadra con el incremento")
            if abs(p["salario_actual"] * (1 + p["incremento_pct"] / 100) - p["salario_propuesto"]) > 0.02:
                violaciones.append("salario propuesto no cuadra con el incremento")
            minimo = pol["grupos_profesionales"][p["grupo"]]["minimo_convenio"]
            if p["salario_propuesto"] < minimo:
                violaciones.append("propuesta por debajo del mínimo de convenio")
            if p["incremento_pct"] < 0:
                violaciones.append("reducción salarial no admitida por esta política")
            if p["incremento_pct"] > inc["tope_individual_pct"] and "minimo_convenio" not in usados:
                violaciones.append("supera el tope individual")
            if p["grupo"] in equidad.get("grupos_con_alerta", []):
                motivos.append(f"grupo {p['grupo']} con alerta de equidad")
            if p["incremento_pct"] >= sup["pct_riesgo_alto"]:
                motivos.append("incremento elevado")
            if "minimo_convenio" in usados:
                motivos.append("ajuste por mínimo de convenio")

            if violaciones:
                estado, riesgo = "bloqueada", "alto"
            else:
                estado = "pendiente_revision"
                riesgo = "alto" if motivos else ("medio" if "posicion_banda" in usados else "bajo")
            resultado.append({"id_seudonimo": p["id_seudonimo"], "estado": estado, "riesgo": riesgo,
                              "violaciones": violaciones, "motivos_revision": motivos})

        # Control global de presupuesto (el mínimo de convenio puede excederlo: obligación legal)
        masa = sum(p["salario_actual"] for p in propuestas)
        presupuesto = masa * inc["presupuesto_masa_salarial_pct"] / 100
        coste = sum(p["salario_propuesto"] - p["salario_actual"] for p in propuestas)
        coste_minimos = sum(p["salario_propuesto"] - p["salario_actual"] for p in propuestas
                            if any(f["factor"] == "minimo_convenio" for f in p["factores"]))
        presupuesto_ok = coste <= presupuesto + 0.01 * len(propuestas) or coste - coste_minimos <= presupuesto
        if not presupuesto_ok:
            for x in resultado:
                x["estado"], x["riesgo"] = "bloqueada", "alto"
                x["violaciones"].append("el lote supera el presupuesto aprobado")

        conteo = {e: sum(1 for x in resultado if x["estado"] == e) for e in ("pendiente_revision", "bloqueada")}
        riesgos = {n: sum(1 for x in resultado if x["riesgo"] == n) for n in ("alto", "medio", "bajo")}
        self.log("control_cumplimiento", **conteo, riesgos=riesgos,
                 nota="Ninguna propuesta se ejecuta sin decisión humana (art. 14 AI Act; art. 22 RGPD).")
        return self.emitir("dictamen_cumplimiento", {"dictamenes": resultado, "conteo": conteo, "riesgos": riesgos,
                                                      "presupuesto": {"limite": round(presupuesto, 2), "coste": round(coste, 2),
                                                                      "dentro_de_limite": presupuesto_ok}})


# ---------------------------------------------------------------------------
# A5. Explicador (XAI)
# ---------------------------------------------------------------------------

_TERMINOS_VETADOS = re.compile(
    r"\b(sexo|g[eé]nero|mujer(es)?|hombre(s)?|femenin\w*|masculin\w*|edad|embaraz\w*|maternidad|paternidad|"
    r"nacionalidad|sindica\w*|baja\s+m[eé]dica|salud|discapacidad|religi[oó]n|etnia|origen)\b",
    re.IGNORECASE,
)
_URL = re.compile(r"https?://|www\.", re.IGNORECASE)

SISTEMA_EXPLICADOR = (
    "Redactas explicaciones retributivas en español claro para una persona trabajadora. "
    "Usa EXCLUSIVAMENTE los hechos del bloque <hechos>. No añadas factores, cifras ni valoraciones. "
    "No menciones características personales ni atributos protegidos. No incluyas enlaces. "
    "Escribe un solo párrafo de 80 a 140 palabras e incluye literalmente el porcentaje y el salario propuesto con dos decimales."
)

AVISO_DERECHOS = (
    "Esta propuesta se ha elaborado con apoyo de un sistema automatizado y no es definitiva hasta que la revise "
    "y decida una persona responsable. Puedes pedir una explicación adicional, aportar tu punto de vista y "
    "solicitar la revisión humana de la decisión a través del canal indicado por la empresa."
)


class Explicador(Agente):
    nombre = "explicador"

    def __init__(self, ctx: Contexto, llm: BackendLLM):
        super().__init__(ctx)
        self.llm = llm

    def _plantilla(self, h: dict[str, Any]) -> str:
        partes = "; ".join(f"{ETIQUETAS_FACTOR.get(f['factor'], f['factor'])}: {f['pct']:+.2f} %" for f in h["factores"])
        return (f"Se propone una revisión salarial del {h['incremento_pct']:.2f} %, de {h['salario_actual']:.2f} "
                f"a {h['salario_propuesto']:.2f} {h['moneda']}. Factores aplicados según la política "
                f"{h['version_politica']}: {partes}. Compa-ratio en la banda del grupo {h['grupo']}: {h['compa_ratio']:.2f}.")

    @staticmethod
    def verificar_salida(texto: str, h: dict[str, Any]) -> list[str]:
        fallos = []
        if f"{h['incremento_pct']:.2f}" not in texto.replace(",", "."):
            fallos.append("no contiene el porcentaje exacto")
        if f"{h['salario_propuesto']:.2f}" not in texto.replace(",", "."):
            fallos.append("no contiene el salario propuesto exacto")
        if _TERMINOS_VETADOS.search(texto):
            fallos.append("menciona atributos protegidos")
        if _URL.search(texto):
            fallos.append("contiene enlaces")
        if len(texto) > 1500:
            fallos.append("excede la longitud máxima")
        return fallos

    def explicar(self, propuestas: list[dict[str, Any]], dictamenes: dict[str, dict[str, Any]]) -> Mensaje:
        self.ctx.capacidades.exigir_herramienta(self.nombre, "llm_generar")
        moneda = self.ctx.politica["moneda"]
        explicaciones, rechazadas = {}, 0
        for p in propuestas:
            if dictamenes[p["id_seudonimo"]]["estado"] == "bloqueada":
                continue
            # Solo hechos estructurados: el texto libre del responsable NUNCA llega al modelo.
            h = {k: p[k] for k in ("grupo", "salario_actual", "incremento_pct", "salario_propuesto",
                                   "compa_ratio", "factores", "version_politica")}
            h["moneda"] = moneda
            usuario = f"<hechos>{json.dumps(h, ensure_ascii=False)}</hechos>"
            origen = self.llm.nombre
            try:
                texto = self.llm.generar(self.nombre, SISTEMA_EXPLICADOR, usuario).strip()
                fallos = self.verificar_salida(texto, h)
            except ErrorSeguridad:
                raise
            except Exception as e:  # fallo del proveedor: degradación segura
                texto, fallos = "", [f"error del backend: {type(e).__name__}"]
            if fallos:
                rechazadas += 1
                self.log("salida_llm_rechazada", id_seudonimo=p["id_seudonimo"], fallos=fallos)
                texto, origen = self._plantilla(h), "plantilla"
            explicaciones[p["id_seudonimo"]] = {"texto": texto, "aviso_derechos": AVISO_DERECHOS, "origen": origen}
        self.log("explicaciones_generadas", n=len(explicaciones), salidas_llm_rechazadas=rechazadas, backend=self.llm.nombre)
        return self.emitir("explicaciones", explicaciones)
