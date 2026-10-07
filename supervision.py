"""Supervisión humana significativa (HITL) y exportación.

Reglas (art. 14 y 26.2 AI Act; art. 22 RGPD; constructo AUD):
- Ninguna propuesta sale del sistema sin una decisión humana registrada.
- Cada decisión exige persona revisora identificada y justificación mínima.
- Las propuestas bloqueadas por el guardián no pueden aprobarse tal cual:
  solo modificarse o rechazarse.
- La aprobación en bloque solo se admite para riesgo bajo (contra el sesgo de
  automatización); las de riesgo alto o medio se deciden una a una.
- El sistema no escribe en nómina: exporta un fichero que una persona carga.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from .registro import RegistroAuditoria
from .seguridad import ErrorSeguridad, Seudonimizador, derivar_clave, hash_fichero, neutralizar_celda_csv

ACCIONES = {"aprobar", "modificar", "rechazar"}


def _cargar(dir_ejecucion: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    expediente = json.loads((dir_ejecucion / "expediente.json").read_text(encoding="utf-8"))
    politica_sup = json.loads((dir_ejecucion / "politica_snapshot.json").read_text(encoding="utf-8"))
    return expediente, politica_sup


def aplicar_decisiones(dir_ejecucion: Path, decisiones: list[dict[str, Any]], clave_maestra: bytes) -> dict[str, Any]:
    expediente, politica = _cargar(dir_ejecucion)
    sup, tope = politica["supervision"], politica["incremento"]["tope_individual_pct"]
    minimos = {g: v["minimo_convenio"] for g, v in politica["grupos_profesionales"].items()}
    registro = RegistroAuditoria(dir_ejecucion / "registro_auditoria.jsonl", clave_maestra)
    indice = {p["id_seudonimo"]: p for p in expediente["propuestas"]}
    conteo: dict[str, Any] = {"aplicadas": 0, "rechazadas_por_validacion": 0, "detalle_rechazos": []}

    for d in decisiones:
        errores: list[str] = []
        revisor = str(d.get("revisor", "")).strip()
        just = str(d.get("justificacion", "")).strip()
        accion = d.get("accion")
        ids = d.get("ids") if d.get("en_bloque") else [d.get("id_seudonimo")]
        if not revisor:
            errores.append("falta persona revisora")
        if len(just) < sup["longitud_minima_justificacion"]:
            errores.append(f"justificación < {sup['longitud_minima_justificacion']} caracteres")
        if accion not in ACCIONES:
            errores.append("acción no válida")
        if not ids:
            errores.append("sin propuestas")
        objetivos = []
        for i in ids or []:
            p = indice.get(i)
            if p is None:
                errores.append(f"{i}: no existe")
                continue
            if p["decision_humana"] is not None:
                errores.append(f"{i}: ya decidida")
            if d.get("en_bloque") and p["riesgo"] not in sup["aprobacion_en_bloque_permitida_para"]:
                errores.append(f"{i}: riesgo {p['riesgo']} no admite decisión en bloque")
            if accion == "aprobar" and p["estado"] == "bloqueada":
                errores.append(f"{i}: bloqueada por el guardián; solo puede modificarse o rechazarse")
            objetivos.append(p)
        nuevo_pct = None
        if accion == "modificar":
            try:
                nuevo_pct = round(float(d.get("nuevo_pct")), 2)
            except (TypeError, ValueError):
                errores.append("modificar exige nuevo_pct numérico")
            else:
                if not 0 <= nuevo_pct <= tope:
                    errores.append(f"nuevo_pct fuera de [0, {tope}]")
                for p in objetivos:
                    if round(p["salario_actual"] * (1 + nuevo_pct / 100), 2) < minimos[p["grupo"]]:
                        errores.append(f"{p['id_seudonimo']}: quedaría por debajo del mínimo de convenio")

        if errores:
            conteo["rechazadas_por_validacion"] += 1
            conteo["detalle_rechazos"].append({"ids": ids, "errores": errores})
            registro.registrar("supervision_humana", "decision_rechazada", {"revisor": revisor or None, "ids": ids, "errores": errores})
            continue
        for p in objetivos:
            final_pct = p["incremento_pct"] if accion == "aprobar" else (nuevo_pct if accion == "modificar" else 0.0)
            p["decision_humana"] = {
                "accion": accion, "revisor": revisor, "justificacion": just,
                "incremento_final_pct": final_pct,
                "salario_final": round(p["salario_actual"] * (1 + final_pct / 100), 2) if accion != "rechazar" else p["salario_actual"],
                "en_bloque": bool(d.get("en_bloque")),
            }
            registro.registrar("supervision_humana", f"decision_{accion}", {
                "id_seudonimo": p["id_seudonimo"], "revisor": revisor, "riesgo": p["riesgo"],
                "pct_propuesto": p["incremento_pct"], "pct_final": final_pct, "justificacion": just,
            })
            conteo["aplicadas"] += 1
    (dir_ejecucion / "expediente.json").write_text(json.dumps(expediente, ensure_ascii=False, indent=2), encoding="utf-8")
    return conteo


def exportar(dir_ejecucion: Path, entrada_original: Path, salida: Path, clave_maestra: bytes) -> dict[str, int]:
    """Reidentifica recalculando el HMAC sobre el fichero de origen: no se guarda tabla de correspondencias."""
    expediente, _ = _cargar(dir_ejecucion)
    manifiesto = json.loads((dir_ejecucion / "manifiesto.json").read_text(encoding="utf-8"))
    if hash_fichero(entrada_original) != manifiesto["hash_entrada"]:
        raise ErrorSeguridad("El fichero de origen ha cambiado desde la ejecución (hash distinto).")
    seud = Seudonimizador(derivar_clave(clave_maestra, "seudonimizacion"))
    with entrada_original.open(encoding="utf-8", newline="") as f:
        mapa = {seud.seudonimo(r["id_empleado"]): r["id_empleado"].strip() for r in csv.DictReader(f)}
    pendientes = [p["id_seudonimo"] for p in expediente["propuestas"] if p["decision_humana"] is None]
    filas = []
    for p in expediente["propuestas"]:
        d = p["decision_humana"]
        if d is None or d["accion"] == "rechazar":
            continue
        if p["id_seudonimo"] not in mapa:
            raise ErrorSeguridad("El fichero de origen no corresponde a esta ejecución.")
        filas.append({"id_empleado": mapa[p["id_seudonimo"]], "grupo": p["grupo"],
                      "salario_actual": p["salario_actual"], "incremento_pct": d["incremento_final_pct"],
                      "salario_final": d["salario_final"], "decision": d["accion"], "revisor": d["revisor"]})
    with salida.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(filas[0].keys()) if filas else ["id_empleado"])
        w.writeheader()
        for fila in filas:
            w.writerow({k: neutralizar_celda_csv(v) for k, v in fila.items()})
    registro = RegistroAuditoria(dir_ejecucion / "registro_auditoria.jsonl", clave_maestra)
    registro.registrar("supervision_humana", "exportacion", {"filas": len(filas), "pendientes": len(pendientes)})
    return {"exportadas": len(filas), "pendientes": len(pendientes)}
