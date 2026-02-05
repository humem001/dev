"""AgentCore Gateway client for agent-to-gateway communication.

This module provides the client interface for communicating with AgentCore Gateway,
handling MCP protocol formatting, JWT authentication, and response parsing.
"""

import json
import time
from typing import Any, Dict, Optional, List
from dataclasses import dataclass
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from models.user_context import UserContext
from models.mcp_tool import MCPToolRequest, MCPToolResponse
from audit_logging.audit_logger import log_gateway_invocation
from config.timeout_config import TIMEOUT_CONFIG


class GatewayError(Exception):
    """Base exception for Gateway-related errors."""
    pass


class GatewayTimeoutError(GatewayError):
    """Exception raised when Gateway request times out."""
    pass


class GatewayAuthenticationError(GatewayError):
    """Exception raised when Gateway authentication fails."""
    pass


class GatewayServiceUnavailableError(GatewayError):
    """Exception raised when Gateway service is unavailable."""
    pass


class MCPProtocolError(GatewayError):
    """Exception raised when MCP protocol formatting or parsing fails."""
    pass


@dataclass
class GatewayConfig:
    """Configuration for Gateway client."""
    gateway_url: str
    timeout_seconds: Optional[int] = None  # Defaults to TIMEOUT_CONFIG.gateway_invocation
    max_retries: int = 3
    retry_delay_ms: int = 100
    backoff_multiplier: float = 2.0
    
    def __post_init__(self):
        """Set default timeout from TIMEOUT_CONFIG if not provided."""
        if self.timeout_seconds is None:
            self.timeout_seconds = TIMEOUT_CONFIG.gateway_invocation


class GatewayClient:
    """Client for communicating with AgentCore Gateway.
    
    Handles:
    - MCP protocol request formatting
    - JWT token authentication
    - Response parsing
    - Error handling and retries
    """
    
    def __init__(self, config: GatewayConfig):
        """Initialize Gateway client.
        
        Args:
            config: Gateway configuration
        """
        self.config = config
        self.session = self._create_session()
    
    def _create_session(self) -> requests.Session:
        """Create requests session with retry configuration.
        
        Returns:
            Configured requests session
        """
        session = requests.Session()
        
        # Configure retry strategy for transient failures
        # Note: Actual retry logic is handled separately with exponential backoff
        retry_strategy = Retry(
            total=0,  # We handle retries manually
            status_forcelist=[],
            allowed_methods=["POST"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        
        return session
    
    def invoke_tool(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        user_context: UserContext,
        jwt_token: str,
        request_id: str
    ) -> MCPToolResponse:
        """Invoke MCP tool through AgentCore Gateway.
        
        Args:
            tool_name: Name of the MCP tool to invoke
            parameters: Tool-specific parameters
            user_context: User identity information
            jwt_token: JWT access token for authentication
            request_id: Unique request identifier for tracing
            
        Returns:
            MCPToolResponse with tool execution results
            
        Raises:
            GatewayAuthenticationError: If JWT authentication fails
            GatewayTimeoutError: If request times out
            GatewayServiceUnavailableError: If Gateway is unavailable
            MCPProtocolError: If request/response formatting fails
            GatewayError: For other Gateway-related errors
        """
        start_time = time.time()
        
        try:
            # Log gateway invocation start
            log_gateway_invocation(
                operation='invoke_tool',
                status='started',
                request_id=request_id,
                user_context=user_context,
                tool_name=tool_name,
                metadata={'parameters_count': len(parameters)}
            )
            
            # Format MCP request
            mcp_request = self._format_mcp_request(
                tool_name=tool_name,
                parameters=parameters,
                user_context=user_context,
                request_id=request_id
            )
            
            # Invoke Gateway with retry logic
            response_data = self._invoke_with_retry(
                mcp_request=mcp_request,
                jwt_token=jwt_token
            )
            
            # Parse response
            result = self._parse_response(response_data)
            
            # Calculate duration
            duration_ms = int((time.time() - start_time) * 1000)
            
            # Log successful invocation
            log_gateway_invocation(
                operation='invoke_tool',
                status='success',
                request_id=request_id,
                user_context=user_context,
                tool_name=tool_name,
                duration_ms=duration_ms,
                metadata={
                    'result_status': result.status,
                    'execution_time_ms': result.execution_time_ms
                }
            )
            
            return result
        
        except Exception as e:
            # Calculate duration
            duration_ms = int((time.time() - start_time) * 1000)
            
            # Log failed invocation
            log_gateway_invocation(
                operation='invoke_tool',
                status='failure',
                request_id=request_id,
                user_context=user_context,
                tool_name=tool_name,
                duration_ms=duration_ms,
                error_message=str(e),
                metadata={'error_type': type(e).__name__}
            )
            
            raise
    
    def list_tools(
        self,
        jwt_token: str,
        request_id: str
    ) -> List[Dict[str, Any]]:
        """List available tools from AgentCore Gateway.
        
        Args:
            jwt_token: JWT access token for authentication
            request_id: Unique request identifier for tracing
            
        Returns:
            List of tool definitions with name, description, and inputSchema
            
        Raises:
            GatewayAuthenticationError: If JWT authentication fails
            GatewayTimeoutError: If request times out
            GatewayServiceUnavailableError: If Gateway is unavailable
            MCPProtocolError: If request/response formatting fails
            GatewayError: For other Gateway-related errors
        """
        try:
            # Format MCP tools/list request
            mcp_request = {
                'jsonrpc': '2.0',
                'method': 'tools/list',
                'params': {},
                'id': request_id
            }
            
            # Invoke Gateway
            response_data = self._invoke_gateway(
                mcp_request=mcp_request,
                jwt_token=jwt_token
            )
            
            # Parse response
            if 'result' not in response_data:
                raise MCPProtocolError("Missing 'result' in tools/list response")
            
            result = response_data['result']
            if 'tools' not in result:
                raise MCPProtocolError("Missing 'tools' in tools/list result")
            
            tools = result['tools']
            if not isinstance(tools, list):
                raise MCPProtocolError("'tools' must be an array")
            
            return tools
            
        except Exception as e:
            if isinstance(e, (GatewayError, MCPProtocolError)):
                raise
            raise GatewayError(f"Failed to list tools: {str(e)}")
    
    def _format_mcp_request(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        user_context: UserContext,
        request_id: str
    ) -> Dict[str, Any]:
        """Format request according to MCP JSON-RPC 2.0 protocol.
        
        Args:
            tool_name: Name of the tool
            parameters: Tool parameters
            user_context: User identity
            request_id: Request ID
            
        Returns:
            MCP JSON-RPC formatted request dictionary
            
        Raises:
            MCPProtocolError: If formatting fails
        """
        try:
            # Include user_context in the arguments so it gets passed through to the tool
            arguments_with_context = {
                **parameters,
                'user_context': {
                    'user_id': user_context.user_id,
                    'username': user_context.username,
                    'client_id': user_context.client_id
                }
            }
            
            # MCP JSON-RPC 2.0 format for tools/call
            return {
                'jsonrpc': '2.0',
                'method': 'tools/call',
                'params': {
                    'name': tool_name,
                    'arguments': arguments_with_context
                },
                'id': request_id
            }
        except Exception as e:
            raise MCPProtocolError(f"Failed to format MCP request: {str(e)}")
    
    def _invoke_with_retry(
        self,
        mcp_request: Dict[str, Any],
        jwt_token: str
    ) -> Dict[str, Any]:
        """Invoke Gateway with exponential backoff retry logic.
        
        Args:
            mcp_request: MCP-formatted request
            jwt_token: JWT token for authentication
            
        Returns:
            Response data dictionary
            
        Raises:
            GatewayAuthenticationError: If authentication fails
            GatewayTimeoutError: If all retries timeout
            GatewayServiceUnavailableError: If service is unavailable
            GatewayError: For other errors
        """
        last_error = None
        retry_delay_ms = self.config.retry_delay_ms
        
        for attempt in range(self.config.max_retries):
            try:
                return self._invoke_gateway(mcp_request, jwt_token)
            
            except GatewayAuthenticationError:
                # Don't retry authentication errors
                raise
            
            except (GatewayTimeoutError, GatewayServiceUnavailableError) as e:
                last_error = e
                
                # Don't retry on last attempt
                if attempt < self.config.max_retries - 1:
                    # Exponential backoff
                    time.sleep(retry_delay_ms / 1000.0)
                    retry_delay_ms = int(retry_delay_ms * self.config.backoff_multiplier)
                    continue
                else:
                    raise
            
            except GatewayError:
                # Don't retry other Gateway errors
                raise
        
        # Should not reach here, but raise last error if we do
        if last_error:
            raise last_error
        raise GatewayError("Gateway invocation failed after retries")
    
    def _invoke_gateway(
        self,
        mcp_request: Dict[str, Any],
        jwt_token: str
    ) -> Dict[str, Any]:
        """Invoke Gateway API endpoint.
        
        Args:
            mcp_request: MCP-formatted request
            jwt_token: JWT token for authentication
            
        Returns:
            Response data dictionary
            
        Raises:
            GatewayAuthenticationError: If authentication fails
            GatewayTimeoutError: If request times out
            GatewayServiceUnavailableError: If service is unavailable
            GatewayError: For other errors
        """
        headers = {
            'Authorization': f'Bearer {jwt_token}',
            'Content-Type': 'application/json'
        }
        
        try:
            response = self.session.post(
                self.config.gateway_url,
                json=mcp_request,
                headers=headers,
                timeout=self.config.timeout_seconds
            )
            
            # Handle different status codes
            if response.status_code == 401 or response.status_code == 403:
                raise GatewayAuthenticationError(
                    f"Gateway authentication failed: {response.status_code}"
                )
            
            if response.status_code == 503:
                raise GatewayServiceUnavailableError(
                    "Gateway service temporarily unavailable"
                )
            
            if response.status_code == 504:
                raise GatewayTimeoutError("Gateway request timed out")
            
            if response.status_code >= 400:
                error_msg = f"Gateway request failed with status {response.status_code}"
                try:
                    error_data = response.json()
                    if 'message' in error_data:
                        error_msg = f"{error_msg}: {error_data['message']}"
                except:
                    pass
                raise GatewayError(error_msg)
            
            # Parse successful response
            return response.json()
        
        except requests.exceptions.Timeout:
            raise GatewayTimeoutError(
                f"Gateway request timed out after {self.config.timeout_seconds}s"
            )
        
        except requests.exceptions.ConnectionError as e:
            raise GatewayServiceUnavailableError(
                f"Failed to connect to Gateway: {str(e)}"
            )
        
        except requests.exceptions.RequestException as e:
            raise GatewayError(f"Gateway request failed: {str(e)}")
    
    def _parse_response(self, response_data: Dict[str, Any]) -> MCPToolResponse:
        """Parse Gateway response into MCPToolResponse.
        
        Args:
            response_data: Raw response data from Gateway (MCP JSON-RPC format)
            
        Returns:
            Parsed MCPToolResponse
            
        Raises:
            MCPProtocolError: If response parsing fails
        """
        try:
            # MCP JSON-RPC 2.0 response format
            # Success: {"jsonrpc": "2.0", "result": {...}, "id": "..."}
            # Error: {"jsonrpc": "2.0", "error": {...}, "id": "..."}
            
            if 'error' in response_data:
                error = response_data['error']
                raise MCPProtocolError(
                    f"MCP tool execution failed: {error.get('message', 'Unknown error')}"
                )
            
            if 'result' not in response_data:
                raise ValueError("Missing 'result' field in MCP JSON-RPC response")
            
            result = response_data['result']
            
            # MCP tools/call result format:
            # {
            #   "content": [{"type": "text", "text": "..."}],
            #   "isError": false
            # }
            
            # Extract content
            content = result.get('content', [])
            is_error = result.get('isError', False)
            
            # Parse content into result dict
            tool_result = {}
            error_message = None
            
            if content:
                # Combine all text content
                text_parts = []
                for item in content:
                    if item.get('type') == 'text':
                        text_parts.append(item.get('text', ''))
                
                if text_parts:
                    combined_text = '\n'.join(text_parts)
                    # Try to parse as JSON if possible
                    try:
                        import json
                        tool_result = json.loads(combined_text)
                    except:
                        # If not JSON, store as text
                        tool_result = {'result': combined_text}
            
            if is_error:
                error_message = tool_result.get('error', 'Tool execution failed')
            
            # Create MCPToolResponse
            return MCPToolResponse(
                result=tool_result,
                user_attribution={},  # MCP doesn't provide user attribution
                execution_time_ms=0,  # MCP doesn't provide execution time
                status='error' if is_error else 'success',
                error_message=error_message
            )
        
        except Exception as e:
            raise MCPProtocolError(f"Failed to parse Gateway response: {str(e)}")
    
    def close(self):
        """Close the Gateway client session."""
        if self.session:
            self.session.close()
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
