"""Error handling utilities for memory operations."""

from typing import Dict, Any, Optional
from .memory_client import (
    MemoryError,
    MemoryServiceUnavailableError,
    SessionNotFoundError,
    StorageQuotaExceededError
)


def handle_memory_error(
    error: Exception,
    operation: str,
    session_id: Optional[str] = None
) -> Dict[str, Any]:
    """Handle memory errors with graceful degradation.
    
    Provides consistent error responses for memory operations with
    appropriate status codes and user-friendly messages.
    
    Args:
        error: The exception that occurred
        operation: The operation being performed (e.g., "create_session", "store_message")
        session_id: Optional session identifier for context
        
    Returns:
        Dictionary containing error information and recovery guidance
    """
    error_response = {
        'operation': operation,
        'session_id': session_id
    }
    
    if isinstance(error, MemoryServiceUnavailableError):
        # Degrade gracefully - continue without memory
        error_response.update({
            'error_type': 'memory_unavailable',
            'warning': 'memory_unavailable',
            'message': 'Conversation history temporarily unavailable.',
            'degraded_mode': True,
            'user_message': 'Your conversation will continue without history. Previous context may not be available.',
            'recovery_action': 'continue_without_memory'
        })
        
    elif isinstance(error, SessionNotFoundError):
        # Session doesn't exist - can create new one
        error_response.update({
            'error_type': 'session_not_found',
            'info': 'new_session_required',
            'message': 'Session not found or expired.',
            'user_message': 'Starting a new conversation.',
            'recovery_action': 'create_new_session'
        })
        
    elif isinstance(error, StorageQuotaExceededError):
        # Storage limit reached - need to trim messages
        error_response.update({
            'error_type': 'storage_quota_exceeded',
            'warning': 'storage_limit_reached',
            'message': 'Conversation history storage limit reached.',
            'user_message': 'Older messages will be removed to stay within limits.',
            'recovery_action': 'trim_old_messages'
        })
        
    elif isinstance(error, MemoryError):
        # Generic memory error
        error_response.update({
            'error_type': 'memory_error',
            'error': 'memory_error',
            'message': f'Memory operation failed: {str(error)}',
            'user_message': 'Unable to access conversation history. Continuing without context.',
            'degraded_mode': True,
            'recovery_action': 'continue_without_memory'
        })
        
    else:
        # Unexpected error
        error_response.update({
            'error_type': 'unexpected_error',
            'error': 'unexpected_error',
            'message': f'Unexpected error during {operation}: {str(error)}',
            'user_message': 'An unexpected error occurred. Please try again.',
            'degraded_mode': True,
            'recovery_action': 'retry_or_continue'
        })
    
    return error_response


def should_degrade_gracefully(error: Exception) -> bool:
    """Determine if an error should trigger graceful degradation.
    
    Some memory errors should allow the system to continue operating
    without memory, while others should fail the request.
    
    Args:
        error: The exception to evaluate
        
    Returns:
        True if system should continue without memory, False if request should fail
    """
    # These errors allow graceful degradation
    degradable_errors = (
        MemoryServiceUnavailableError,
        SessionNotFoundError,
    )
    
    return isinstance(error, degradable_errors)


def get_recovery_action(error: Exception) -> str:
    """Get the recommended recovery action for an error.
    
    Args:
        error: The exception that occurred
        
    Returns:
        Recovery action string
    """
    if isinstance(error, MemoryServiceUnavailableError):
        return 'continue_without_memory'
    elif isinstance(error, SessionNotFoundError):
        return 'create_new_session'
    elif isinstance(error, StorageQuotaExceededError):
        return 'trim_old_messages'
    else:
        return 'retry_or_continue'


def format_user_message(error: Exception, operation: str) -> str:
    """Format a user-friendly error message.
    
    Args:
        error: The exception that occurred
        operation: The operation being performed
        
    Returns:
        User-friendly error message
    """
    if isinstance(error, MemoryServiceUnavailableError):
        return "Your conversation will continue, but previous context may not be available."
    elif isinstance(error, SessionNotFoundError):
        return "Starting a new conversation."
    elif isinstance(error, StorageQuotaExceededError):
        return "Conversation history has been trimmed to stay within storage limits."
    elif isinstance(error, MemoryError):
        return "Unable to access conversation history. Continuing without context."
    else:
        return "An error occurred. Please try again."
