"""Error handling for MCP tools.

This module defines custom exceptions and error handling utilities for MCP tool execution.
"""

from typing import Dict, Optional


class ToolExecutionError(Exception):
    """Base exception for tool execution errors."""
    
    def __init__(self, message: str, status_code: int = 500, error_code: str = 'tool_execution_failed'):
        self.message = message
        self.status_code = status_code
        self.error_code = error_code
        super().__init__(self.message)
    
    def to_dict(self) -> dict:
        """Convert error to dictionary format."""
        return {
            'error': self.error_code,
            'message': self.message,
            'status_code': self.status_code
        }


class S3AccessDeniedError(ToolExecutionError):
    """Exception for S3 access denied errors."""
    
    def __init__(self, message: str = 'You do not have permission to access the requested AWS resource.'):
        super().__init__(
            message=message,
            status_code=403,
            error_code='permission_denied'
        )


class S3ServiceUnavailableError(ToolExecutionError):
    """Exception for S3 service unavailable errors."""
    
    def __init__(self, message: str = 'AWS S3 service temporarily unavailable. Please try again.'):
        super().__init__(
            message=message,
            status_code=503,
            error_code='service_unavailable'
        )


class ToolTimeoutError(ToolExecutionError):
    """Exception for tool execution timeout errors."""
    
    def __init__(self, message: str = 'Tool execution timed out. Please try again.'):
        super().__init__(
            message=message,
            status_code=504,
            error_code='gateway_timeout'
        )


class MCPProtocolError(ToolExecutionError):
    """Exception for MCP protocol errors."""
    
    def __init__(self, message: str = 'Tool communication error. Please contact support.'):
        super().__init__(
            message=message,
            status_code=500,
            error_code='protocol_error'
        )


def handle_s3_error(error: Exception) -> ToolExecutionError:
    """Handle S3-specific errors and convert to appropriate ToolExecutionError.
    
    Args:
        error: The original exception from S3 operation
        
    Returns:
        ToolExecutionError with appropriate error code and message
    """
    error_str = str(error)
    error_code = getattr(error, 'response', {}).get('Error', {}).get('Code', '')
    
    # Handle access denied errors
    if error_code == 'AccessDenied' or 'AccessDenied' in error_str:
        return S3AccessDeniedError()
    
    # Handle service unavailable errors
    if error_code in ['ServiceUnavailable', 'SlowDown'] or 'ServiceUnavailable' in error_str:
        return S3ServiceUnavailableError()
    
    # Handle timeout errors
    if 'timeout' in error_str.lower() or 'timed out' in error_str.lower():
        return ToolTimeoutError()
    
    # Generic S3 error
    return ToolExecutionError(
        message=f'S3 operation failed: {error_str}',
        status_code=500,
        error_code='s3_operation_failed'
    )


def create_error_response(
    error: Exception,
    tool_name: str,
    user_context: Dict[str, str],
    execution_time_ms: int
) -> Dict[str, any]:
    """Create a structured error response for tool execution failures.
    
    Args:
        error: The exception that occurred
        tool_name: Name of the tool that failed
        user_context: User identity information
        execution_time_ms: Time taken before failure
        
    Returns:
        Dictionary containing structured error response
    """
    # Convert to ToolExecutionError if not already
    if isinstance(error, ToolExecutionError):
        tool_error = error
    else:
        # Try to handle as S3 error
        tool_error = handle_s3_error(error)
    
    return {
        'result': {},
        'user_attribution': {
            'user_id': user_context.get('user_id', 'unknown'),
            'operation': tool_name,
            'timestamp': None  # Will be set by caller
        },
        'execution_time_ms': execution_time_ms,
        'status': 'error',
        'error_message': tool_error.message,
        'error_code': tool_error.error_code,
        'status_code': tool_error.status_code
    }
