"""Structured audit logging module for CloudWatch.

This module provides comprehensive audit logging capabilities with:
- Structured JSON formatting for CloudWatch
- Component-specific logging helpers
- Sensitive data sanitization
- User context propagation
"""

import json
import logging
import re
from datetime import datetime
from typing import Any, Dict, Optional

from models.audit_log import AuditLogEntry
from models.user_context import UserContext


# Configure logger
logger = logging.getLogger(__name__)


# Sensitive data patterns to sanitize
SENSITIVE_PATTERNS = [
    (re.compile(r'Bearer\s+[A-Za-z0-9\-._~+/]+=*', re.IGNORECASE), 'Bearer [REDACTED]'),
    (re.compile(r'"jwt_token"\s*:\s*"[^"]*"'), '"jwt_token": "[REDACTED]"'),
    (re.compile(r'"password"\s*:\s*"[^"]*"'), '"password": "[REDACTED]"'),
    (re.compile(r'"secret"\s*:\s*"[^"]*"'), '"secret": "[REDACTED]"'),
    (re.compile(r'"api_key"\s*:\s*"[^"]*"'), '"api_key": "[REDACTED]"'),
    (re.compile(r'"access_token"\s*:\s*"[^"]*"'), '"access_token": "[REDACTED]"'),
]


def sanitize_sensitive_data(data: Any) -> Any:
    """Sanitize sensitive information from data.
    
    Removes or masks:
    - JWT tokens
    - Passwords
    - API keys
    - Access tokens
    - Other secrets
    
    Args:
        data: Data to sanitize (string, dict, list, or other)
        
    Returns:
        Sanitized copy of the data
    """
    if isinstance(data, str):
        # Apply regex patterns to sanitize strings
        sanitized = data
        for pattern, replacement in SENSITIVE_PATTERNS:
            sanitized = pattern.sub(replacement, sanitized)
        return sanitized
    
    elif isinstance(data, dict):
        # Recursively sanitize dictionary values
        sanitized = {}
        for key, value in data.items():
            # Mask entire value for sensitive keys
            if key.lower() in ['jwt_token', 'password', 'secret', 'api_key', 'access_token', 'authorization']:
                sanitized[key] = '[REDACTED]'
            else:
                sanitized[key] = sanitize_sensitive_data(value)
        return sanitized
    
    elif isinstance(data, list):
        # Recursively sanitize list items
        return [sanitize_sensitive_data(item) for item in data]
    
    else:
        # Return other types as-is
        return data


class AuditLogger:
    """Structured audit logger for CloudWatch.
    
    Provides methods for logging audit events with:
    - Consistent structure
    - User context propagation
    - Sensitive data sanitization
    - CloudWatch-compatible JSON formatting
    """
    
    def __init__(self, component: str):
        """Initialize audit logger for a specific component.
        
        Args:
            component: Component name ("agent", "gateway", "tool", "auth")
        """
        self.component = component
        self.logger = logging.getLogger(f"audit.{component}")
    
    def log_event(
        self,
        operation: str,
        status: str,
        request_id: str,
        user_context: Optional[UserContext] = None,
        duration_ms: Optional[int] = None,
        error_message: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        level: str = 'INFO'
    ) -> None:
        """Log an audit event.
        
        Args:
            operation: Operation being performed
            status: Status of the operation ("success", "failure", "warning")
            request_id: Unique request identifier
            user_context: User identity information (optional)
            duration_ms: Operation duration in milliseconds (optional)
            error_message: Error message if status is failure (optional)
            metadata: Additional metadata (optional)
            level: Log level (INFO, WARNING, ERROR)
        """
        # Create audit log entry
        if user_context:
            audit_entry = AuditLogEntry(
                timestamp=datetime.utcnow(),
                request_id=request_id,
                component=self.component,
                operation=operation,
                user_context=user_context,
                status=status,
                duration_ms=duration_ms,
                error_message=error_message,
                metadata=metadata
            )
            
            # Format for CloudWatch
            log_data = audit_entry.to_cloudwatch_format()
        else:
            # Log without user context (e.g., authentication failures)
            log_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'request_id': request_id,
                'component': self.component,
                'operation': operation,
                'status': status,
                'duration_ms': duration_ms,
                'error_message': error_message,
                'metadata': metadata or {}
            }
        
        # Sanitize sensitive data
        sanitized_log_data = sanitize_sensitive_data(log_data)
        
        # Log as JSON
        log_message = json.dumps(sanitized_log_data)
        
        # Log at appropriate level
        if level == 'ERROR':
            self.logger.error(log_message)
        elif level == 'WARNING':
            self.logger.warning(log_message)
        else:
            self.logger.info(log_message)


# Component-specific logging helpers

def log_authentication_event(
    success: bool,
    request_id: str,
    user_context: Optional[UserContext] = None,
    error_message: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> None:
    """Log authentication event.
    
    Args:
        success: Whether authentication succeeded
        request_id: Request identifier
        user_context: User context if authentication succeeded
        error_message: Error message if authentication failed
        metadata: Additional metadata
    """
    logger_instance = AuditLogger('auth')
    
    status = 'success' if success else 'failure'
    level = 'INFO' if success else 'WARNING'
    
    logger_instance.log_event(
        operation='authentication',
        status=status,
        request_id=request_id,
        user_context=user_context,
        error_message=error_message,
        metadata=metadata,
        level=level
    )


def log_agent_processing(
    operation: str,
    status: str,
    request_id: str,
    user_context: UserContext,
    duration_ms: Optional[int] = None,
    error_message: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> None:
    """Log agent processing event.
    
    Args:
        operation: Agent operation ("process_prompt", "tool_selection", "response_generation")
        status: Operation status
        request_id: Request identifier
        user_context: User identity
        duration_ms: Operation duration
        error_message: Error message if failed
        metadata: Additional metadata (e.g., session_id, tool_executions)
    """
    logger_instance = AuditLogger('agent')
    
    level = 'ERROR' if status == 'failure' else 'INFO'
    
    logger_instance.log_event(
        operation=operation,
        status=status,
        request_id=request_id,
        user_context=user_context,
        duration_ms=duration_ms,
        error_message=error_message,
        metadata=metadata,
        level=level
    )


def log_gateway_invocation(
    operation: str,
    status: str,
    request_id: str,
    user_context: UserContext,
    tool_name: Optional[str] = None,
    duration_ms: Optional[int] = None,
    error_message: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> None:
    """Log gateway invocation event.
    
    Args:
        operation: Gateway operation ("invoke_tool", "validate_jwt", "extract_user_context")
        status: Operation status
        request_id: Request identifier
        user_context: User identity
        tool_name: Name of tool being invoked
        duration_ms: Operation duration
        error_message: Error message if failed
        metadata: Additional metadata
    """
    logger_instance = AuditLogger('gateway')
    
    level = 'ERROR' if status == 'failure' else 'INFO'
    
    # Add tool_name to metadata if provided
    if tool_name:
        metadata = metadata or {}
        metadata['tool_name'] = tool_name
    
    logger_instance.log_event(
        operation=operation,
        status=status,
        request_id=request_id,
        user_context=user_context,
        duration_ms=duration_ms,
        error_message=error_message,
        metadata=metadata,
        level=level
    )


def log_tool_execution(
    tool_name: str,
    status: str,
    request_id: str,
    user_context: UserContext,
    duration_ms: Optional[int] = None,
    error_message: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> None:
    """Log tool execution event.
    
    Args:
        tool_name: Name of the tool executed
        status: Execution status
        request_id: Request identifier
        user_context: User identity
        duration_ms: Execution duration
        error_message: Error message if failed
        metadata: Additional metadata (e.g., aws_service, operation_type)
    """
    logger_instance = AuditLogger('tool')
    
    level = 'ERROR' if status == 'failure' else 'INFO'
    
    # Add tool_name to metadata
    metadata = metadata or {}
    metadata['tool_name'] = tool_name
    
    logger_instance.log_event(
        operation='tool_execution',
        status=status,
        request_id=request_id,
        user_context=user_context,
        duration_ms=duration_ms,
        error_message=error_message,
        metadata=metadata,
        level=level
    )
