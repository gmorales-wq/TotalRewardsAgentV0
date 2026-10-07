"""Orquestador determinista del enjambre.

No es un LLM: es una máquina de estados con traspasos explícitos entre agentes.
Así la secuencia de control no puede ser secuestrada por contenido de entrada
(OWASP ASI01 Agent Goal Hijack) y cada traspaso es verificable.

En cada traspaso: (1) comprueba el interruptor de parada (art. 14.4.e AI Act),
(2) verifica la firma y la identidad del emisor, (3) proyecta los datos según la
matriz de capacidades, (4) registra el evento en el registro encadenado.
"""
from __future__ import annotations

import csv
import json
import os
from datetime import date
from pathlib import Path
from typing import Any

from .agentes import (AnalistaRetributivo, AuditorEquidad, Boveda, Contexto, CustodioDato, Explicador,
                      GuardianCumplimiento)
from .capacidades import Capacidades
from .llm import MedidorConsumo, crear_backend
from .registro import RegistroAuditoria
from .seguridad import ErrorSeguridad, Firmante, Seudonimizador, derivar_clave, hash_fichero, sha256_hex, canonico


class ParadaSolicitada(Exception):
    pass


def comprobar_parada(dir_ejecucion: Path) -> None:
    if os.environ.get("AGFTS_PARADA") == "1" or (dir_ejecucion / "PARADA").exists():
        raise ParadaSolicitada("Interruptor de parada activado por una persona supervisora.")


def ejecutar(entrada: Path, dir_config: Path, dir_ejecucion: Path, clave_maestra: bytes,
             backend: str = "mock", fecha_referencia: date | None = None,
             hash_politica_esperado: str | None = None) -> dict[str, Any]:
    dir_ejecucion.mkdir(parents=True, exist_ok=True)
    ruta_politica = dir_config / "politica_retributiva.json"
    hash_politica = hash_fichero(ruta_politica)
    if hash_politica_esperado and hash_politica != hash_politica_esperado:
        raise ErrorSeguridad("La política en disco no coincide con el hash aprobado (posible manipulación).")
    politica = json.loads(ruta_politica.read_text(encoding="utf-8"))
    capacidades = Capacidades(dir_config / "capacidades.json")
    firmante = Firmante(clave_maestra)
    registro = RegistroAuditoria(dir_ejecucion / "registro_auditoria.jsonl", clave_maestra)
    ctx = Contexto(capacidades, firmante, registro, politica, hash_politica)
    medidor = MedidorConsumo()
    llm = crear_backend(backend, medidor)
    fecha_referencia = fecha_referencia or date.today()

    hash_origen = hash_fichero(entrada)
    registro.registrar("orquestador", "inicio_ejecucion", {
        "hash_entrada": hash_origen, "hash_politica": hash_politica, "version_politica": politica["version"],
        "hash_capacidades": hash_fichero(dir_config / "capacidades.json"), "backend_llm": llm.nombre,
    })

    try:
        # 1. Custodio del dato
        comprobar_parada(dir_ejecucion)
        with entrada.open(encoding="utf-8", newline="") as f:
            filas = list(csv.DictReader(f))
        filas = capacidades.proyectar("custodio_dato", filas)
        boveda = Boveda(capacidades)
        seud = Seudonimizador(derivar_clave(clave_maestra, "seudonimizacion"))
        m1 = CustodioDato(ctx).procesar(filas, seud, boveda, fecha_referencia, hash_origen)
        m1.verificar(firmante, "custodio_dato")
        registros = m1.contenido["registros"]
        if not registros:
            raise ErrorSeguridad("Ningún registro supera el contrato de datos.")

        # 2. Analista retributivo
        comprobar_parada(dir_ejecucion)
        m2 = AnalistaRetributivo(ctx).proponer(capacidades.proyectar("analista_retributivo", registros))
        m2.verificar(firmante, "analista_retributivo")
        propuestas = m2.contenido["propuestas"]

        # 3. Auditor de equidad
        comprobar_parada(dir_ejecucion)
        m3 = AuditorEquidad(ctx).auditar(capacidades.proyectar("auditor_equidad", registros), propuestas, boveda)
        m3.verificar(firmante, "auditor_equidad")

        # 4. Guardián de cumplimiento
        comprobar_parada(dir_ejecucion)
        m4 = GuardianCumplimiento(ctx).revisar(capacidades.proyectar("guardian_cumplimiento", registros),
                                               propuestas, m3.contenido, m1.contenido["notas_revisor"])
        m4.verificar(firmante, "guardian_cumplimiento")
        dictamenes = {d["id_seudonimo"]: d for d in m4.contenido["dictamenes"]}

        # 5. Explicador
        comprobar_parada(dir_ejecucion)
        m5 = Explicador(ctx, llm).explicar(propuestas, dictamenes)
        m5.verificar(firmante, "explicador")
    except ParadaSolicitada as e:
        registro.registrar("orquestador", "parada", {"motivo": str(e)})
        raise
    except ErrorSeguridad as e:
        registro.registrar("orquestador", "error_seguridad", {"detalle": str(e)})
        raise

    # Expediente para la supervisión humana
    expediente = []
    for p in propuestas:
        d = dictamenes[p["id_seudonimo"]]
        nota = m1.contenido["notas_revisor"].get(p["id_seudonimo"])
        expediente.append({**p, **{k: d[k] for k in ("estado", "riesgo", "violaciones", "motivos_revision")},
                           "explicacion": m5.contenido.get(p["id_seudonimo"]),
                           "nota_responsable": nota, "decision_humana": None})

    salidas = {
        "informe_calidad.json": m1.contenido["informe"],
        "expediente.json": {"version_politica": politica["version"], "hash_politica": hash_politica,
                            "resumen_presupuesto": m2.contenido["resumen"], "propuestas": expediente},
        "informe_equidad.json": m3.contenido,
        "consumo_modelo.json": medidor.resumen(),
    }
    salidas["politica_snapshot.json"] = politica
    for nombre, contenido in salidas.items():
        (dir_ejecucion / nombre).write_text(json.dumps(contenido, ensure_ascii=False, indent=2), encoding="utf-8")

    manifiesto = {
        "hash_entrada": hash_origen, "hash_politica": hash_politica,
        "salidas": {n: sha256_hex(canonico(c)) for n, c in salidas.items()},
        "ultimo_hash_registro": registro.ultimo_hash,
    }
    registro.registrar("orquestador", "fin_ejecucion", manifiesto)
    (dir_ejecucion / "manifiesto.json").write_text(json.dumps(manifiesto, indent=2), encoding="utf-8")
    return {"expediente": expediente, "equidad": m3.contenido, "calidad": m1.contenido["informe"],
            "presupuesto": m2.contenido["resumen"], "consumo": medidor.resumen(),
            "dictamen": m4.contenido}
