"""Provider-neutral reversing MCP protocol and session runtime."""

from .backends import AnalysisBackend, AnalysisSession
from .manager import ServerPolicy, SessionManager
from .models import (
    PROTOCOL_VERSION,
    BackendDescriptor,
    Capability,
    CommonOperation,
    ErrorDetail,
    LifecycleAction,
    OperationResult,
    OperationSpec,
    SessionDescriptor,
    SessionMode,
    SessionRequest,
)
from .registry import ProviderRegistry

__all__ = [
    "PROTOCOL_VERSION",
    "AnalysisBackend",
    "AnalysisSession",
    "BackendDescriptor",
    "Capability",
    "CommonOperation",
    "ErrorDetail",
    "LifecycleAction",
    "OperationResult",
    "OperationSpec",
    "ProviderRegistry",
    "SessionDescriptor",
    "SessionManager",
    "SessionMode",
    "SessionRequest",
    "ServerPolicy",
]
