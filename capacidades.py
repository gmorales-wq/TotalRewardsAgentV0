"""Mínimo privilegio y mensajería firmada entre agentes.

- `Capacidades`: carga la matriz config/capacidades.json y proyecta los datos
  para que cada agente reciba SOLO los campos autorizados (art. 5.1.c RGPD,
  minimización; OWASP LLM06 / ASI02-ASI03).
- `Mensaje`: sobre firmado con la identidad del agente emisor (identificadores
  de agente y trazabilidad; Chan et al., 2024; ASI07).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .seguridad import ErrorSeguridad, Firmante


class Capacidades:
    def __init__(self, ruta: Path):
        datos = json.loads(Path(ruta).read_text(encoding="utf-8"))
        self._matriz = {k: v for k, v in datos.items() if not k.startswith("_")}

    def campos(self, agente: str) -> set[str]:
        if agente not in self._matriz:
            raise ErrorSeguridad(f"Agente no registrado: {agente}")
        return set(self._matriz[agente]["campos"])

    def exigir_herramienta(self, agente: str, herramienta: str) -> None:
        if herramienta not in self._matriz.get(agente, {}).get("herramientas", []):
            raise ErrorSeguridad(f"{agente} no está autorizado a usar '{herramienta}'")

    def proyectar(self, agente: str, filas: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
        """Devuelve copias con solo los campos permitidos (lo no permitido no viaja)."""
        permitidos = self.campos(agente)
        return [{k: v for k, v in f.items() if k in permitidos} for f in filas]


@dataclass
class Mensaje:
    emisor: str
    tipo: str
    contenido: Any
    firma: str = ""
    metadatos: dict[str, Any] = field(default_factory=dict)

    def _firmable(self) -> dict[str, Any]:
        return {"emisor": self.emisor, "tipo": self.tipo, "contenido": self.contenido}

    def firmar(self, firmante: Firmante) -> "Mensaje":
        self.firma = firmante.firmar(self.emisor, self._firmable())
        return self

    def verificar(self, firmante: Firmante, emisor_esperado: str) -> None:
        if self.emisor != emisor_esperado:
            raise ErrorSeguridad(f"Emisor inesperado: {self.emisor} (se esperaba {emisor_esperado})")
        if not self.firma or not firmante.verificar(self.emisor, self._firmable(), self.firma):
            raise ErrorSeguridad(f"Firma inválida en mensaje '{self.tipo}' de {self.emisor}")
