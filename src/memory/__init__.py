"""AgentCore Memory integration module."""

from .memory_client import (
    MemoryClient,
    MemoryError,
    MemoryServiceUnavailableError,
    SessionNotFoundError,
    StorageQuotaExceededError
)
from .error_handlers import (
    handle_memory_error,
    should_degrade_gracefully,
    get_recovery_action,
    format_user_message
)

__all__ = [
    'MemoryClient',
    'MemoryError',
    'MemoryServiceUnavailableError',
    'SessionNotFoundError',
    'StorageQuotaExceededError',
    'handle_memory_error',
    'should_degrade_gracefully',
    'get_recovery_action',
    'format_user_message',
]
