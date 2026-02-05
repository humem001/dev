"""Gateway client for MCP tool discovery.

This module provides a client for querying AgentCore Gateway to discover
available tools using the MCP (Model Context Protocol) tools/list method.
"""

import json
import logging
from typing import Dict, Any, List, Optional
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .discovery_models import ToolListResponse


logger = logging.getLogger(__name__)


class GatewayDiscoveryError(Exception):
    """Base exception for Gateway discovery errors."""
    pass


class GatewayConnectionError(GatewayDiscoveryError):
    """Exception raised when Gateway is unreachable."""
    pass


class GatewayAuthError(GatewayDiscoveryError):
    """Exception raised when Gateway authentication fails."""
    pass


class MCPProtocolError(GatewayDiscoveryError):
    """Exception raised when MCP protocol formatting or parsing fails."""
    pass


class TokenManager:
    """Manages OAuth tokens for Gateway authentication.
    
    This is a placeholder for token management logic. In production,
    this would handle token refresh, caching, and retrieval from
    secure storage (e.g., AWS Secrets Manager).
    """
    
    def __init__(self, token: Optional[str] = None):
        """Initialize token manager.
        
        Args:
            token: Initial OAuth token (optional)
        """
        self._token = token
    
    def get_token(self) -> str:
        """Get current OAuth token.
        
        Returns:
            OAuth access token
            
        Raises:
            GatewayAuthError: If no token is available
        """
        if not self._token:
            raise GatewayAuthError("No OAuth token available")
        return self._token
    
    async def refresh_token(self) -> None:
        """Refresh the OAuth token.
        
        This is a placeholder for token refresh logic.
        In production, this would call the OAuth token endpoint.
        """
        logger.info("Token refresh requested (placeholder)")
        # TODO: Implement actual token refresh logic


class GatewayDiscoveryClient:
    """Client for discovering tools from AgentCore Gateway using MCP protocol.
    
    This client communicates with the Gateway's MCP endpoint to retrieve
    tool definitions using the tools/list JSON-RPC method.
    """
    
    def __init__(
        self,
        gateway_url: str,
        token_manager: TokenManager,
        timeout: int = 30
    ):
        """Initialize Gateway discovery client.
        
        Args:
            gateway_url: Base URL of the Gateway MCP endpoint
            token_manager: Manager for OAuth token handling
            timeout: Request timeout in seconds (default: 30)
        """
        self.gateway_url = gateway_url
        self.token_manager = token_manager
        self.timeout = timeout
        self.session = self._create_session()
        self._request_id = 0
    
    def _create_session(self) -> requests.Session:
        """Create requests session with retry configuration.
        
        Returns:
            Configured requests session with retry strategy
        """
        session = requests.Session()
        
        # Configure retry strategy for transient failures
        retry_strategy = Retry(
            total=0,  # We handle retries at a higher level
            status_forcelist=[],
            allowed_methods=["POST"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        
        return session
    
    def _get_next_request_id(self) -> int:
        """Get next JSON-RPC request ID.
        
        Returns:
            Monotonically increasing request ID
        """
        self._request_id += 1
        return self._request_id
    
    def close(self) -> None:
        """Close the Gateway client session."""
        if self.session:
            self.session.close()
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
    
    def list_tools(self, cursor: Optional[str] = None) -> ToolListResponse:
        """Query Gateway for available tools using MCP tools/list.
        
        Sends a JSON-RPC request to the Gateway's MCP endpoint to retrieve
        tool definitions. Supports pagination via cursor parameter.
        
        Args:
            cursor: Optional pagination cursor for retrieving next page
            
        Returns:
            ToolListResponse containing tools and optional next cursor
            
        Raises:
            GatewayConnectionError: If Gateway is unreachable
            GatewayAuthError: If authentication fails
            MCPProtocolError: If response doesn't match MCP protocol
        """
        # Build MCP tools/list JSON-RPC request
        request_payload = {
            "jsonrpc": "2.0",
            "id": self._get_next_request_id(),
            "method": "tools/list",
            "params": {}
        }
        
        # Add cursor if provided for pagination
        if cursor:
            request_payload["params"]["cursor"] = cursor
        
        # Get OAuth token
        try:
            token = self.token_manager.get_token()
        except GatewayAuthError as e:
            logger.error(f"Failed to get OAuth token: {e}")
            raise
        
        # Prepare headers
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        
        # Send request to Gateway
        try:
            logger.debug(f"Sending MCP tools/list request to {self.gateway_url}")
            response = self.session.post(
                self.gateway_url,
                json=request_payload,
                headers=headers,
                timeout=self.timeout
            )
            
            # Handle HTTP errors
            if response.status_code == 401 or response.status_code == 403:
                raise GatewayAuthError(
                    f"Gateway authentication failed: {response.status_code}"
                )
            
            if response.status_code >= 500:
                raise GatewayConnectionError(
                    f"Gateway server error: {response.status_code}"
                )
            
            if response.status_code >= 400:
                error_msg = f"Gateway request failed with status {response.status_code}"
                try:
                    error_data = response.json()
                    if 'error' in error_data:
                        error_msg = f"{error_msg}: {error_data['error']}"
                except:
                    pass
                raise MCPProtocolError(error_msg)
            
            # Parse JSON-RPC response
            response_data = response.json()
            
        except requests.exceptions.Timeout:
            raise GatewayConnectionError(
                f"Gateway request timed out after {self.timeout}s"
            )
        except requests.exceptions.ConnectionError as e:
            raise GatewayConnectionError(
                f"Failed to connect to Gateway: {str(e)}"
            )
        except requests.exceptions.RequestException as e:
            raise GatewayConnectionError(f"Gateway request failed: {str(e)}")
        except json.JSONDecodeError as e:
            raise MCPProtocolError(f"Invalid JSON response from Gateway: {str(e)}")
        
        # Validate JSON-RPC response structure
        if "jsonrpc" not in response_data or response_data["jsonrpc"] != "2.0":
            raise MCPProtocolError("Invalid JSON-RPC response: missing or invalid jsonrpc field")
        
        if "id" not in response_data:
            raise MCPProtocolError("Invalid JSON-RPC response: missing id field")
        
        # Check for JSON-RPC error
        if "error" in response_data:
            error = response_data["error"]
            error_msg = error.get("message", "Unknown error")
            raise MCPProtocolError(f"MCP protocol error: {error_msg}")
        
        # Extract result
        if "result" not in response_data:
            raise MCPProtocolError("Invalid JSON-RPC response: missing result field")
        
        result = response_data["result"]
        
        # Validate result structure
        if "tools" not in result:
            raise MCPProtocolError("Invalid MCP response: missing tools field in result")
        
        if not isinstance(result["tools"], list):
            raise MCPProtocolError("Invalid MCP response: tools field must be an array")
        
        # Extract tools and pagination cursor
        tools = result["tools"]
        next_cursor = result.get("nextCursor")
        
        logger.info(f"Retrieved {len(tools)} tools from Gateway")
        if next_cursor:
            logger.debug(f"More pages available (cursor: {next_cursor})")
        
        return ToolListResponse(tools=tools, next_cursor=next_cursor)
    
    def list_all_tools(self) -> List[Dict[str, Any]]:
        """Query Gateway for all available tools, handling pagination.
        
        Automatically handles pagination by following nextCursor values
        until all tools have been retrieved.
        
        Returns:
            Complete list of tool definitions from Gateway
            
        Raises:
            GatewayConnectionError: If Gateway is unreachable
            GatewayAuthError: If authentication fails
            MCPProtocolError: If response doesn't match MCP protocol
        """
        all_tools: List[Dict[str, Any]] = []
        cursor: Optional[str] = None
        page_count = 0
        
        logger.debug("Starting paginated tool discovery from Gateway")
        
        while True:
            page_count += 1
            logger.debug(f"Fetching page {page_count}" + (f" (cursor: {cursor})" if cursor else ""))
            
            # Get next page of tools
            response = self.list_tools(cursor=cursor)
            
            # Add tools from this page
            all_tools.extend(response.tools)
            
            # Check if more pages exist
            if not response.has_more():
                break
            
            # Get cursor for next page
            cursor = response.next_cursor
        
        logger.info(f"Retrieved total of {len(all_tools)} tools across {page_count} page(s)")
        return all_tools
