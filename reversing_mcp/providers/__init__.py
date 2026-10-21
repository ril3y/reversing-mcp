"""Built-in analysis provider adapters."""

from __future__ import annotations

from ..backends import AnalysisBackend
from .binary_ninja import BinaryNinjaBackend
from .frida import FridaBackend
from .ilspy import IlspyBackend
from .local_bridges import GhidraBackend, IdaBackend, JadxBackend
from .radare2 import Radare2Backend


def builtin_backends() -> tuple[AnalysisBackend, ...]:
    """Return built-ins; optional native SDKs are imported only when opened."""
    return (
        BinaryNinjaBackend(),
        FridaBackend(),
        GhidraBackend(),
        IdaBackend(),
        IlspyBackend(),
        JadxBackend(),
        Radare2Backend(),
    )
