"""Primitivas de seguridad del enjambre.

Solo biblioteca estándar (hmac, hashlib, secrets) para reducir la superficie de
cadena de suministro (OWASP LLM03 / ASI04).

Contenido:
- Gestión de claves: clave maestra desde variable de entorno; claves derivadas
  por propósito (seudonimización, firma de cada agente, registro).
- Seudonimización con HMAC-SHA256 (art. 4.5 y 32 RGPD). OJO: un seudónimo sigue
  siendo dato personal (considerando 26 RGPD); no es anonimización.
- Firma y verificación de mensajes entre agentes (ASI07).
- Detección heurística de inyección de instrucciones en texto libre (LLM01 / ASI01).
- Neutralización de inyección de fórmulas al exportar CSV (CWE-1236).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import sys
import unicodedata
from pathlib import Path
from typing import Any

VAR_CLAVE = "AGFTS_CLAVE_MAESTRA"


class ErrorSeguridad(Exception):
    """Fallo de un control de seguridad. Nunca debe silenciarse."""


# ---------------------------------------------------------------------------
# Claves
# ---------------------------------------------------------------------------

def cargar_clave_maestra(modo_demo: bool, ruta_demo: Path | None = None) -> bytes:
    """Obtiene la clave maestra.

    Producción: debe venir de la variable de entorno (inyectada por un gestor de
    secretos/KMS). Demo: si no existe, genera una y la guarda con permisos 0600,
    avisando por stderr. Nunca se registra en logs.
    """
    valor = os.environ.get(VAR_CLAVE)
    if valor:
        clave = bytes.fromhex(valor) if re.fullmatch(r"[0-9a-fA-F]{64,}", valor) else valor.encode()
        if len(clave) < 32:
            raise ErrorSeguridad(f"{VAR_CLAVE} debe tener al menos 32 bytes de entropía.")
        return clave
    if not modo_demo:
        raise ErrorSeguridad(f"Falta {VAR_CLAVE}. En producción la clave la aporta el gestor de secretos.")
    ruta = ruta_demo or Path(".clave_demo")
    if ruta.exists():
        return bytes.fromhex(ruta.read_text().strip())
    clave = secrets.token_bytes(32)
    ruta.write_text(clave.hex())
    try:
        os.chmod(ruta, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:  # pragma: no cover - sistemas sin permisos POSIX
        pass
    print(f"[AVISO] Modo demo: clave maestra efímera creada en {ruta}. No usar en producción.", file=sys.stderr)
    return clave


def derivar_clave(maestra: bytes, proposito: str) -> bytes:
    """Derivación simple tipo HKDF-expand (un bloque) para separar usos de clave."""
    return hmac.new(maestra, b"agfts-v1|" + proposito.encode(), hashlib.sha256).digest()


# ---------------------------------------------------------------------------
# Serialización canónica y hashes
# ---------------------------------------------------------------------------

def canonico(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def sha256_hex(datos: bytes) -> str:
    return hashlib.sha256(datos).hexdigest()


def hash_fichero(ruta: Path) -> str:
    return sha256_hex(Path(ruta).read_bytes())


# ---------------------------------------------------------------------------
# Seudonimización
# ---------------------------------------------------------------------------

class Seudonimizador:
    def __init__(self, clave: bytes):
        self._clave = clave

    def seudonimo(self, identificador: str) -> str:
        mac = hmac.new(self._clave, identificador.strip().encode("utf-8"), hashlib.sha256).hexdigest()
        return "P-" + mac[:16]


# ---------------------------------------------------------------------------
# Firma de mensajes entre agentes
# ---------------------------------------------------------------------------

class Firmante:
    """Cada agente firma con su clave derivada; el orquestador verifica."""

    def __init__(self, maestra: bytes):
        self._maestra = maestra

    def _clave(self, agente: str) -> bytes:
        return derivar_clave(self._maestra, f"firma:{agente}")

    def firmar(self, agente: str, contenido: Any) -> str:
        return hmac.new(self._clave(agente), canonico(contenido), hashlib.sha256).hexdigest()

    def verificar(self, agente: str, contenido: Any, firma: str) -> bool:
        return hmac.compare_digest(self.firmar(agente, contenido), firma)


# ---------------------------------------------------------------------------
# Detección de inyección de instrucciones (heurística, NO garantía)
# ---------------------------------------------------------------------------

_PATRONES_INYECCION = [
    r"ignora(r)?\s+(todas?\s+)?(las\s+)?(instrucciones|reglas|normas)",
    r"olvida\s+(las\s+)?(instrucciones|reglas)",
    r"ignore\s+(all\s+)?(previous\s+)?(instructions|rules)",
    r"disregard\s+(the\s+)?(above|previous)",
    r"(system|sistema)\s*prompt",
    r"act[uú]a\s+como",
    r"you\s+are\s+now",
    r"(asigna|aplica|sube|pon)\w*\s+(un\s+)?\d{1,3}\s*%",
    r"(aprueba|approve)\w*\s+(autom[aá]ticamente|sin\s+revis)",
    r"<\s*/?\s*(system|instructions?|tool)\s*>",
    r"\{\{.*\}\}",
]
_RE_INYECCION = re.compile("|".join(_PATRONES_INYECCION), re.IGNORECASE)


def normalizar_texto(texto: str) -> str:
    """NFKC + eliminación de caracteres de control/invisibles usados para ofuscar."""
    t = unicodedata.normalize("NFKC", texto or "")
    return "".join(c for c in t if unicodedata.category(c) not in {"Cf", "Cc"} or c in "\n\t")


def detectar_inyeccion(texto: str) -> list[str]:
    """Devuelve los fragmentos sospechosos. Lista vacía = nada detectado (no = seguro)."""
    t = normalizar_texto(texto)
    return [m.group(0) for m in _RE_INYECCION.finditer(t)]


# ---------------------------------------------------------------------------
# Exportación segura a CSV
# ---------------------------------------------------------------------------

def neutralizar_celda_csv(valor: Any) -> Any:
    """Evita inyección de fórmulas en hojas de cálculo (CWE-1236)."""
    if isinstance(valor, str) and valor and valor[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + valor
    return valor
