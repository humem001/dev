"""MCP tool request and response data models."""

from dataclasses import dataclass
from typing import Any, Dict, Optional

from .user_context import UserContext


@dataclass
class MCPToolRequest:
    """Request to execute MCP tool."""
    
    tool_name: str
    parameters: Dict[str, Any]
    user_context: UserContext
    request_id: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for transmission.
        
        Returns:
            Dictionary representation of the request
        """
        return {
            'tool_name': self.tool_name,
            'parameters': self.parameters,
            'user_context': self.user_context.to_dict(),
            'request_id': self.request_id
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MCPToolRequest':
        """Create MCPToolRequest from dictionary.
        
        Args:
            data: Dictionary containing request fields
            
        Returns:
            MCPToolRequest instance
        """
        return cls(
            tool_name=data['tool_name'],
            parameters=data['parameters'],
            user_context=UserContext.from_dict(data['user_context']),
            request_id=data['request_id']
        )


@dataclass
class MCPToolResponse:
    """Response from MCP tool execution."""
    
    result: Dict[str, Any]
    user_attribution: Dict[str, str]
    execution_time_ms: int
    status: str  # "success" or "error"
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for transmission.
        
        Returns:
            Dictionary representation of the response
        """
        return {
            'result': self.result,
            'user_attribution': self.user_attribution,
            'execution_time_ms': self.execution_time_ms,
            'status': self.status,
            'error_message': self.error_message
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MCPToolResponse':
        """Create MCPToolResponse from dictionary.
        
        Args:
            data: Dictionary containing response fields
            
        Returns:
            MCPToolResponse instance
        """
        return cls(
            result=data['result'],
            user_attribution=data['user_attribution'],
            execution_time_ms=data['execution_time_ms'],
            status=data['status'],
            error_message=data.get('error_message')
        )
