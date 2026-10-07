"""Backends de modelo de lenguaje y medidor de consumo.

Principio de diseño: el LLM NUNCA calcula importes ni decide. Solo redacta
explicaciones a partir de hechos estructurados ya calculados y verificados, y
su salida pasa por un verificador antes de usarse (OWASP LLM05, LLM09).

- `MockLLM`: determinista, sin red; permite ejecutar y auditar todo en local.
- `ClaudeLLM`: opcional, vía SDK oficial `anthropic` (pip install anthropic) y
  ANTHROPIC_API_KEY. Modelo configurable con AGFTS_MODELO.
- `MedidorConsumo`: límites de llamadas y tokens (LLM10 Unbounded Consumption)
  y base para la huella computacional (apartado 7.1.10 del TFM). No convierte
  tokens en kWh ni CO2: no hay un factor fiable y público por modelo, y dar una
  cifra sería inventarla.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from .seguridad import ErrorSeguridad

ETIQUETAS_FACTOR = {
    "general": "incremento general",
    "desempeno": "desempeño",
    "competencias": "competencias acreditadas",
    "posicion_banda": "posición en banda",
    "ajuste_presupuestario": "ajuste presupuestario",
    "minimo_convenio": "ajuste a mínimo de convenio",
}


@dataclass
class MedidorConsumo:
    max_llamadas: int = 200
    max_tokens: int = 200_000
    llamadas: int = 0
    tokens_entrada: int = 0
    tokens_salida: int = 0
    segundos: float = 0.0
    por_agente: dict[str, int] = field(default_factory=dict)

    def antes(self) -> None:
        if self.llamadas >= self.max_llamadas:
            raise ErrorSeguridad(f"Límite de llamadas al modelo alcanzado ({self.max_llamadas})")
        if self.tokens_entrada + self.tokens_salida >= self.max_tokens:
            raise ErrorSeguridad(f"Límite de tokens alcanzado ({self.max_tokens})")

    def despues(self, agente: str, t_in: int, t_out: int, seg: float) -> None:
        self.llamadas += 1
        self.tokens_entrada += t_in
        self.tokens_salida += t_out
        self.segundos += seg
        self.por_agente[agente] = self.por_agente.get(agente, 0) + 1

    def resumen(self) -> dict[str, Any]:
        return {
            "llamadas": self.llamadas,
            "tokens_entrada": self.tokens_entrada,
            "tokens_salida": self.tokens_salida,
            "segundos_modelo": round(self.segundos, 3),
            "llamadas_por_agente": self.por_agente,
            "nota": "Sin conversión a energía/CO2: no se dispone de factores verificables por modelo.",
        }


class BackendLLM(Protocol):
    nombre: str

    def generar(self, agente: str, sistema: str, usuario: str, max_tokens: int = 600) -> str: ...


class MockLLM:
    """Redacta a partir del bloque JSON de hechos. Sin red, determinista."""

    nombre = "mock"

    def __init__(self, medidor: MedidorConsumo):
        self.medidor = medidor

    def generar(self, agente: str, sistema: str, usuario: str, max_tokens: int = 600) -> str:
        self.medidor.antes()
        t0 = time.perf_counter()
        inicio = usuario.index("<hechos>") + len("<hechos>")
        hechos = json.loads(usuario[inicio:usuario.index("</hechos>")])
        partes = "; ".join(f"{ETIQUETAS_FACTOR.get(f['factor'], f['factor'])}: {f['pct']:+.2f} %" for f in hechos["factores"])
        texto = (
            f"Se propone una revisión salarial del {hechos['incremento_pct']:.2f} %, "
            f"de {hechos['salario_actual']:.2f} {hechos['moneda']} a {hechos['salario_propuesto']:.2f} {hechos['moneda']}. "
            f"Desglose según la política {hechos['version_politica']}: {partes}. "
            f"Posición en la banda del grupo {hechos['grupo']}: compa-ratio {hechos['compa_ratio']:.2f}."
        )
        self.medidor.despues(agente, len(usuario) // 4, len(texto) // 4, time.perf_counter() - t0)
        return texto


class ClaudeLLM:
    nombre = "claude"

    def __init__(self, medidor: MedidorConsumo, modelo: str | None = None):
        try:
            import anthropic  # dependencia opcional
        except ImportError as e:  # pragma: no cover
            raise ErrorSeguridad("Instala el SDK: pip install anthropic") from e
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise ErrorSeguridad("Falta ANTHROPIC_API_KEY")
        self._cliente = anthropic.Anthropic()
        self.modelo = modelo or os.environ.get("AGFTS_MODELO", "claude-sonnet-5-5")
        self.medidor = medidor

    def generar(self, agente: str, sistema: str, usuario: str, max_tokens: int = 600) -> str:  # pragma: no cover - red
        self.medidor.antes()
        t0 = time.perf_counter()
        resp = self._cliente.messages.create(
            model=self.modelo,
            max_tokens=max_tokens,
            system=sistema,
            messages=[{"role": "user", "content": usuario}],
        )
        texto = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
        self.medidor.despues(agente, resp.usage.input_tokens, resp.usage.output_tokens, time.perf_counter() - t0)
        return texto


def crear_backend(nombre: str, medidor: MedidorConsumo) -> BackendLLM:
    if nombre == "mock":
        return MockLLM(medidor)
    if nombre == "claude":
        return ClaudeLLM(medidor)
    raise ValueError(f"Backend desconocido: {nombre}")
