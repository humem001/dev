"""Error handling utilities for the Agent.

This module provides error handling functions that convert exceptions
into user-friendly error responses without exposing sensitive information.
"""

from typing import Dict, Any
from memory.memory_client import (
    MemoryServiceUnavailableError,
    MemoryTimeoutError
)
from gateway.gateway_client import (
    GatewayError,
    GatewayTimeoutError,
    GatewayAuthenticationError,
    GatewayServiceUnavailableError
)
from .exceptions import (
    BedrockError,
    BedrockThrottlingError,
    BedrockModelUnavailableError,
    BedrockTimeoutError
)


def handle_agent_error(error: Exception) -> Dict[str, Any]:
    """Handle agent processing errors with user-friendly messages.
    
    Args:
        error: Exception that occurred during agent processing
        
    Returns:
        Dictionary with error information formatted for user response
    """
    # Bedrock throttling errors
    if isinstance(error, BedrockThrottlingError):
        return {
            'error': 'rate_limit_exceeded',
            'message': 'The system is experiencing high load. Please try again in a moment.',
            'status_code': 429,
            'retry_after': 5
        }
    
    # Bedrock timeout errors
    if isinstance(error, BedrockTimeoutError):
        return {
            'error': 'request_timeout',
            'message': 'AI processing timed out. Please try again with a simpler request.',
            'status_code': 504
        }
    
    # Bedrock model unavailable
    if isinstance(error, BedrockModelUnavailableError):
        return {
            'error': 'service_unavailable',
            'message': 'AI service temporarily unavailable. Please try again later.',
            'status_code': 503
        }
    
    # Generic Bedrock errors
    if isinstance(error, BedrockError):
        return {
            'error': 'processing_failed',
            'message': 'Unable to process your request. Please try again or rephrase your question.',
            'status_code': 500
        }
    
    # Memory service errors - degrade gracefully
    if isinstance(error, MemoryServiceUnavailableError):
        return {
            'warning': 'context_unavailable',
            'message': 'Processing your request without conversation history.',
            'status_code': 200,
            'degraded_mode': True
        }
    
    # Memory timeout errors - degrade gracefully
    if isinstance(error, MemoryTimeoutError):
        return {
            'warning': 'context_timeout',
            'message': 'Conversation history retrieval timed out. Processing without context.',
            'status_code': 200,
            'degraded_mode': True
        }
    
    # Gateway authentication errors
    if isinstance(error, GatewayAuthenticationError):
        return {
            'error': 'authentication_failed',
            'message': 'Authentication failed. Please check your credentials.',
            'status_code': 401
        }
    
    # Gateway timeout errors
    if isinstance(error, GatewayTimeoutError):
        return {
            'error': 'gateway_timeout',
            'message': 'Tool execution timed out. Please try again.',
            'status_code': 504
        }
    
    # Gateway service unavailable
    if isinstance(error, GatewayServiceUnavailableError):
        return {
            'error': 'service_unavailable',
            'message': 'Tool service temporarily unavailable. Please try again.',
            'status_code': 503
        }
    
    # Generic Gateway errors
    if isinstance(error, GatewayError):
        return {
            'error': 'tool_execution_failed',
            'message': 'Unable to execute the requested operation. Please try again.',
            'status_code': 500
        }
    
    # Generic errors
    return {
        'error': 'internal_error',
        'message': 'An unexpected error occurred. Please try again.',
        'status_code': 500
    }


def format_error_response(
    error_dict: Dict[str, Any],
    request_id: str
) -> Dict[str, Any]:
    """Format error dictionary into complete error response.
    
    Args:
        error_dict: Error information from handle_agent_error
        request_id: Request identifier for tracing
        
    Returns:
        Complete error response dictionary
    """
    from datetime import datetime
    
    response = {
        **error_dict,
        'request_id': request_id,
        'timestamp': datetime.utcnow().isoformat()
    }
    
    return response
