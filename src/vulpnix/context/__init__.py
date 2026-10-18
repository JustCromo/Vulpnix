"""Facts about where and how Vulpnix itself is running."""

from vulpnix.context.observations import Observation, ObservationCache
from vulpnix.context.execution import (
    Environment,
    ExecutionContext,
    current_execution_context,
    detect_environment,
)

__all__ = [
    "Environment",
    "ExecutionContext",
    "Observation",
    "ObservationCache",
    "current_execution_context",
    "detect_environment",
]
