"""Registro de auditoría encadenado (art. 12 y 26.6 AI Act; constructo AUD).

Cada evento incluye el hash del anterior y un HMAC con clave propia del registro:
- La cadena de hashes detecta borrados, inserciones o reordenaciones.
- El HMAC impide que quien no tenga la clave recalcule una cadena falsa completa.

Limitación conocida: un fichero local no es almacenamiento WORM. En producción,
el registro debe enviarse a almacenamiento inmutable (p. ej. object lock) y
anclar periódicamente el último hash en un sistema externo.
Retención mínima a configurar: 6 meses (art. 26.6 AI Act), salvo norma que exija más.

Nunca se registran datos identificativos en claro: solo seudónimos y agregados.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .seguridad import canonico, derivar_clave, sha256_hex

GENESIS = "0" * 64


@dataclass
class ResultadoVerificacion:
    integro: bool
    eventos: int
    error: str | None = None


class RegistroAuditoria:
    def __init__(self, ruta: Path, clave_maestra: bytes):
        self.ruta = Path(ruta)
        self._clave = derivar_clave(clave_maestra, "registro")
        self._ultimo_hash = GENESIS
        self._seq = 0
        if self.ruta.exists():
            for linea in self.ruta.read_text(encoding="utf-8").splitlines():
                if linea.strip():
                    ev = json.loads(linea)
                    self._ultimo_hash, self._seq = ev["hash"], ev["seq"]

    def registrar(self, agente: str, evento: str, datos: dict[str, Any] | None = None) -> dict[str, Any]:
        self._seq += 1
        cuerpo = {
            "seq": self._seq,
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "agente": agente,
            "evento": evento,
            "datos": datos or {},
            "hash_prev": self._ultimo_hash,
        }
        h = sha256_hex(canonico(cuerpo))
        cuerpo["hash"] = h
        cuerpo["mac"] = hmac.new(self._clave, h.encode(), hashlib.sha256).hexdigest()
        with self.ruta.open("a", encoding="utf-8") as f:
            f.write(json.dumps(cuerpo, ensure_ascii=False) + "\n")
        self._ultimo_hash = h
        return cuerpo

    @property
    def ultimo_hash(self) -> str:
        return self._ultimo_hash

    @staticmethod
    def verificar(ruta: Path, clave_maestra: bytes) -> ResultadoVerificacion:
        clave = derivar_clave(clave_maestra, "registro")
        previo, n = GENESIS, 0
        for i, linea in enumerate(Path(ruta).read_text(encoding="utf-8").splitlines(), start=1):
            if not linea.strip():
                continue
            ev = json.loads(linea)
            mac, h = ev.pop("mac", None), ev.pop("hash", None)
            if ev.get("seq") != i:
                return ResultadoVerificacion(False, n, f"secuencia rota en línea {i}")
            if ev.get("hash_prev") != previo:
                return ResultadoVerificacion(False, n, f"encadenamiento roto en seq {i}")
            if sha256_hex(canonico(ev)) != h:
                return ResultadoVerificacion(False, n, f"contenido alterado en seq {i}")
            esperado = hmac.new(clave, (h or "").encode(), hashlib.sha256).hexdigest()
            if not mac or not hmac.compare_digest(esperado, mac):
                return ResultadoVerificacion(False, n, f"MAC inválido en seq {i}")
            previo, n = h, n + 1
        return ResultadoVerificacion(True, n)
