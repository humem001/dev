"""Audit log data model."""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict, Any

from .user_context import UserContext


@dataclass
class AuditLogEntry:
    """Structured audit log entry."""
    
    timestamp: datetime
    request_id: str
    component: str  # "agent", "gateway", "tool"
    operation: str
    user_context: UserContext
    status: str
    duration_ms: Optional[int] = None
    error_message: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    
    def to_cloudwatch_format(self) -> Dict[str, Any]:
        """Format for CloudWatch structured logging.
        
        Returns:
            Dictionary formatted for CloudWatch logs
        """
        return {
            'timestamp': self.timestamp.isoformat(),
            'request_id': self.request_id,
            'component': self.component,
            'operation': self.operation,
            'user_id': self.user_context.user_id,
            'username': self.user_context.username,
            'client_id': self.user_context.client_id,
            'status': self.status,
            'duration_ms': self.duration_ms,
            'error_message': self.error_message,
            'metadata': self.metadata or {}
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage/transmission.
        
        Returns:
            Dictionary representation of the audit log entry
        """
        return {
            'timestamp': self.timestamp.isoformat(),
            'request_id': self.request_id,
            'component': self.component,
            'operation': self.operation,
            'user_context': self.user_context.to_dict(),
            'status': self.status,
            'duration_ms': self.duration_ms,
            'error_message': self.error_message,
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AuditLogEntry':
        """Create AuditLogEntry from dictionary.
        
        Args:
            data: Dictionary containing audit log fields
            
        Returns:
            AuditLogEntry instance
        """
        return cls(
            timestamp=datetime.fromisoformat(data['timestamp']),
            request_id=data['request_id'],
            component=data['component'],
            operation=data['operation'],
            user_context=UserContext.from_dict(data['user_context']),
            status=data['status'],
            duration_ms=data.get('duration_ms'),
            error_message=data.get('error_message'),
            metadata=data.get('metadata')
        )
