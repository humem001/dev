"""MCP Tool Protocol Interface.

This module defines the standard interface that all MCP tools must implement
following the Model Context Protocol specification.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional


@dataclass
class MCPToolDefinition:
    """MCP tool definition following protocol specification."""
    name: str
    description: str
    input_schema: Dict[str, Any]
    
    def to_dict(self) -> dict:
        """Convert to dictionary format."""
        return {
            'name': self.name,
            'description': self.description,
            'input_schema': self.input_schema
        }


@dataclass
class MCPToolRequest:
    """Request to execute an MCP tool."""
    tool_name: str
    parameters: Dict[str, Any]
    user_context: Dict[str, str]  # Contains user_id, username, client_id
    request_id: str
    
    def to_dict(self) -> dict:
        """Convert to dictionary format."""
        return {
            'tool_name': self.tool_name,
            'parameters': self.parameters,
            'user_context': self.user_context,
            'request_id': self.request_id
        }


@dataclass
class MCPToolResponse:
    """Response from MCP tool execution."""
    result: Dict[str, Any]
    user_attribution: Dict[str, str]
    execution_time_ms: int
    status: str  # "success" or "error"
    error_message: Optional[str] = None
    
    def to_dict(self) -> dict:
        """Convert to dictionary format."""
        return {
            'result': self.result,
            'user_attribution': self.user_attribution,
            'execution_time_ms': self.execution_time_ms,
            'status': self.status,
            'error_message': self.error_message
        }


class MCPTool(ABC):
    """Abstract base class for MCP tools.
    
    All MCP tools must inherit from this class and implement the required methods.
    """
    
    @abstractmethod
    def get_definition(self) -> MCPToolDefinition:
        """Return the tool definition following MCP protocol.
        
        Returns:
            MCPToolDefinition with name, description, and input schema
        """
        pass
    
    @abstractmethod
    def execute(self, parameters: Dict[str, Any], user_context: Dict[str, str]) -> Dict[str, Any]:
        """Execute the tool operation.
        
        Args:
            parameters: Tool-specific parameters
            user_context: User identity information (user_id, username, client_id)
            
        Returns:
            Dictionary containing operation results
            
        Raises:
            Exception: If tool execution fails
        """
        pass
    
    def invoke(self, request: MCPToolRequest) -> MCPToolResponse:
        """Invoke the tool with timing and attribution.
        
        Args:
            request: MCPToolRequest containing tool parameters and user context
            
        Returns:
            MCPToolResponse with results, attribution, and execution metadata
        """
        start_time = datetime.utcnow()
        
        try:
            # Execute the tool
            result = self.execute(request.parameters, request.user_context)
            
            # Calculate execution time
            end_time = datetime.utcnow()
            execution_time_ms = int((end_time - start_time).total_seconds() * 1000)
            
            # Create user attribution
            user_attribution = {
                'user_id': request.user_context.get('user_id', 'unknown'),
                'operation': self.get_definition().name,
                'timestamp': end_time.isoformat()
            }
            
            return MCPToolResponse(
                result=result,
                user_attribution=user_attribution,
                execution_time_ms=execution_time_ms,
                status='success'
            )
            
        except Exception as e:
            # Calculate execution time even for errors
            end_time = datetime.utcnow()
            execution_time_ms = int((end_time - start_time).total_seconds() * 1000)
            
            # Create error response with attribution
            user_attribution = {
                'user_id': request.user_context.get('user_id', 'unknown'),
                'operation': self.get_definition().name,
                'timestamp': end_time.isoformat()
            }
            
            return MCPToolResponse(
                result={},
                user_attribution=user_attribution,
                execution_time_ms=execution_time_ms,
                status='error',
                error_message=str(e)
            )
