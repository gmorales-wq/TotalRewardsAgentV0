"""Interfaz de línea de órdenes.

  python -m agfts_swarm generar-datos  --salida datos/plantilla_ficticia.csv
  python -m agfts_swarm ejecutar       --entrada datos/plantilla_ficticia.csv --salida ejecuciones/demo --demo
  python -m agfts_swarm revisar        --ejecucion ejecuciones/demo [--decisiones decisiones.json] --demo
  python -m agfts_swarm exportar       --ejecucion ejecuciones/demo --entrada datos/plantilla_ficticia.csv --salida nomina.csv --demo
  python -m agfts_swarm verificar-registro --ejecucion ejecuciones/demo --demo
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path

from . import __version__
from .datos_sinteticos import generar
from .orquestador import ParadaSolicitada, ejecutar
from .registro import RegistroAuditoria
from .seguridad import ErrorSeguridad, cargar_clave_maestra
from .supervision import aplicar_decisiones, exportar

RAIZ = Path(__file__).resolve().parents[2]


def _clave(args) -> bytes:
    return cargar_clave_maestra(args.demo, RAIZ / ".clave_demo")


def _resumen(r: dict) -> str:
    exp, eq = r["expediente"], r["equidad"]
    lineas = [
        f"Registros válidos: {r['calidad']['filas_validas']}/{r['calidad']['filas_leidas']}  "
        f"(rechazados: {r['calidad']['filas_rechazadas']}, requieren corrección y reproceso: no reciben propuesta; "
        f"comentarios sospechosos: {r['calidad']['comentarios_con_sospecha_inyeccion']})",
        f"Presupuesto: {r['presupuesto']['presupuesto']:.2f}  coste final: {r['presupuesto']['coste_final']:.2f}  "
        f"prorrateo: {r['presupuesto']['factor_prorrateo']}",
        f"Riesgo: {r['dictamen']['riesgos']}  Estados: {r['dictamen']['conteo']}",
        f"Grupos con alerta de equidad: {eq['grupos_con_alerta'] or 'ninguno'}",
    ]
    for g, b in eq["por_grupo"].items():
        if b.get("estado") == "ok":
            lineas.append(f"  {g}: brecha media {b['brecha_media_antes_pct']} % -> {b['brecha_media_despues_pct']} %"
                          + (f"  ALERTAS: {'; '.join(b['alertas'])}" if b["alertas"] else ""))
        else:
            lineas.append(f"  {g}: {b.get('estado')}")
    for p in eq["proxies"]:
        lineas.append(f"  Proxy: {p['variable']} ~ {p['atributo']} r={p['r']} (usada en decisión: {p['usada_en_decision']})")
    for s in eq["simpson"]:
        lineas.append(f"  Simpson: {s}")
    lineas.append(f"Llamadas al modelo: {r['consumo']['llamadas']}  tokens: {r['consumo']['tokens_entrada'] + r['consumo']['tokens_salida']}")
    lineas.append(f"Pendientes de decisión humana: {sum(1 for p in exp if p['decision_humana'] is None)}")
    return "\n".join(lineas)


def _revisar_interactivo(dir_ej: Path) -> list[dict]:
    exp = json.loads((dir_ej / "expediente.json").read_text(encoding="utf-8"))
    revisor = input("Persona revisora (nombre o identificador): ").strip()
    decisiones = []
    for p in sorted(exp["propuestas"], key=lambda x: {"alto": 0, "medio": 1, "bajo": 2}[x["riesgo"]]):
        if p["decision_humana"] is not None:
            continue
        print("\n" + "=" * 72)
        print(f"{p['id_seudonimo']}  grupo {p['grupo']}  riesgo {p['riesgo'].upper()}  estado {p['estado']}")
        print(f"  {p['salario_actual']:.2f} -> {p['salario_propuesto']:.2f}  ({p['incremento_pct']:+.2f} %)")
        for f in p["factores"]:
            print(f"    · {f['factor']}: {f['pct']:+.2f} %")
        for v in p["violaciones"]:
            print(f"  [BLOQUEO] {v}")
        for m in p["motivos_revision"]:
            print(f"  [REVISAR] {m}")
        if p.get("nota_responsable"):
            # Se muestra como dato, entre comillas y con repr: nunca se interpreta.
            print(f"  Nota del responsable (texto no verificado): {p['nota_responsable']['comentario']!r}")
        acc = input("  [a]probar / [m]odificar / [r]echazar / [s]altar / [q] salir: ").strip().lower()
        if acc == "q":
            break
        if acc not in {"a", "m", "r"}:
            continue
        d = {"id_seudonimo": p["id_seudonimo"], "revisor": revisor,
             "accion": {"a": "aprobar", "m": "modificar", "r": "rechazar"}[acc]}
        if acc == "m":
            d["nuevo_pct"] = input("  Nuevo incremento %: ").strip()
        d["justificacion"] = input("  Justificación: ").strip()
        decisiones.append(d)
    return decisiones


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="agfts_swarm", description=f"Enjambre retributivo gobernado v{__version__}")
    sub = ap.add_subparsers(dest="orden", required=True)

    g = sub.add_parser("generar-datos")
    g.add_argument("--salida", type=Path, required=True)
    g.add_argument("--semilla", type=int, default=2026)

    e = sub.add_parser("ejecutar")
    e.add_argument("--entrada", type=Path, required=True)
    e.add_argument("--config", type=Path, default=RAIZ / "config")
    e.add_argument("--salida", type=Path, required=True)
    e.add_argument("--backend", choices=["mock", "claude"], default="mock")
    e.add_argument("--fecha-ref", type=date.fromisoformat, default=None)
    e.add_argument("--hash-politica", default=None, help="Hash SHA-256 aprobado de la política (bloquea si no coincide)")

    r = sub.add_parser("revisar")
    r.add_argument("--ejecucion", type=Path, required=True)
    r.add_argument("--decisiones", type=Path)

    x = sub.add_parser("exportar")
    x.add_argument("--ejecucion", type=Path, required=True)
    x.add_argument("--entrada", type=Path, required=True)
    x.add_argument("--salida", type=Path, required=True)

    v = sub.add_parser("verificar-registro")
    v.add_argument("--ejecucion", type=Path, required=True)

    for p in (e, r, x, v):
        p.add_argument("--demo", action="store_true", help="Permite clave maestra efímera local (solo pruebas)")

    a = ap.parse_args(argv)
    try:
        if a.orden == "generar-datos":
            print(f"Generado: {generar(a.salida, a.semilla)}")
        elif a.orden == "ejecutar":
            res = ejecutar(a.entrada, a.config, a.salida, _clave(a), a.backend, a.fecha_ref, a.hash_politica)
            texto = _resumen(res)
            (a.salida / "resumen.txt").write_text(texto + "\n", encoding="utf-8")
            print(texto)
        elif a.orden == "revisar":
            decisiones = (json.loads(a.decisiones.read_text(encoding="utf-8")) if a.decisiones
                          else _revisar_interactivo(a.ejecucion))
            print(aplicar_decisiones(a.ejecucion, decisiones, _clave(a)))
        elif a.orden == "exportar":
            print(exportar(a.ejecucion, a.entrada, a.salida, _clave(a)))
        elif a.orden == "verificar-registro":
            res = RegistroAuditoria.verificar(a.ejecucion / "registro_auditoria.jsonl", _clave(a))
            print(f"Íntegro: {res.integro}  eventos: {res.eventos}" + (f"  error: {res.error}" if res.error else ""))
            return 0 if res.integro else 2
    except ParadaSolicitada as ex:
        print(f"PARADA: {ex}", file=sys.stderr)
        return 3
    except ErrorSeguridad as ex:
        print(f"ERROR DE SEGURIDAD: {ex}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
