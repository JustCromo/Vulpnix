"""Facts about where and how Vulpnix itself is running."""

from vulpnix.context.execution import (
    Environment,
    ExecutionContext,
    current_execution_context,
    detect_environment,
)

__all__ = [
    "Environment",
    "ExecutionContext",
    "current_execution_context",
    "detect_environment",
]
