"""Agent response data models."""

from dataclasses import dataclass
from typing import List, Dict, Any

from .user_context import UserContext


@dataclass
class ToolExecution:
    """Record of tool execution."""
    
    tool_name: str
    timestamp: str
    status: str
    duration_ms: int
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for transmission.
        
        Returns:
            Dictionary representation of tool execution
        """
        return {
            'tool_name': self.tool_name,
            'timestamp': self.timestamp,
            'status': self.status,
            'duration_ms': self.duration_ms
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ToolExecution':
        """Create ToolExecution from dictionary.
        
        Args:
            data: Dictionary containing tool execution fields
            
        Returns:
            ToolExecution instance
        """
        return cls(
            tool_name=data['tool_name'],
            timestamp=data['timestamp'],
            status=data['status'],
            duration_ms=data['duration_ms']
        )


@dataclass
class AgentResponse:
    """Complete agent response."""
    
    response: str
    session_id: str
    user_context: UserContext
    tool_executions: List[ToolExecution]
    request_id: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for transmission.
        
        Returns:
            Dictionary representation of the response
        """
        return {
            'response': self.response,
            'session_id': self.session_id,
            'user_context': self.user_context.to_dict(),
            'tool_executions': [te.to_dict() for te in self.tool_executions],
            'request_id': self.request_id
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AgentResponse':
        """Create AgentResponse from dictionary.
        
        Args:
            data: Dictionary containing response fields
            
        Returns:
            AgentResponse instance
        """
        return cls(
            response=data['response'],
            session_id=data['session_id'],
            user_context=UserContext.from_dict(data['user_context']),
            tool_executions=[
                ToolExecution.from_dict(te) 
                for te in data['tool_executions']
            ],
            request_id=data['request_id']
        )
