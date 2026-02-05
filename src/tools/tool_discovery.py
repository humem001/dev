"""Tool discovery interface for agent integration.

This module provides interfaces for the agent to discover available tools
dynamically without requiring code changes. Supports both local registry
and Gateway-based discovery with feature flag control.
"""

import os
import logging
from typing import List, Dict, Any, Optional
from .tool_registry import get_global_registry
from .mcp_tool_interface import MCPToolDefinition

logger = logging.getLogger(__name__)


class LocalToolDiscoveryService:
    """Service for discovering available MCP tools from local registry.
    
    This is the legacy discovery service that uses the hardcoded tool registry.
    Provides methods for the agent to:
    - List all available tools
    - Get tool definitions
    - Query tool metadata
    - Filter tools by criteria
    """
    
    def __init__(self):
        """Initialize tool discovery service."""
        self.registry = get_global_registry()
    
    def list_available_tools(self) -> List[str]:
        """List names of all available tools.
        
        Returns:
            List of tool names
        """
        return self.registry.list_tools()
    
    def get_tool_definitions(self) -> List[MCPToolDefinition]:
        """Get definitions for all available tools.
        
        Returns:
            List of MCPToolDefinition objects
        """
        return self.registry.discover_tools()
    
    def get_tool_definition(self, tool_name: str) -> Optional[MCPToolDefinition]:
        """Get definition for a specific tool.
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            MCPToolDefinition or None if not found
        """
        return self.registry.get_tool_definition(tool_name)
    
    def get_tools_metadata(self) -> List[Dict[str, Any]]:
        """Get metadata for all tools.
        
        Returns:
            List of tool metadata dictionaries
        """
        return self.registry.list_tools_with_metadata()
    
    def get_tool_metadata(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Get metadata for a specific tool.
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            Tool metadata dictionary or None if not found
        """
        return self.registry.get_tool_metadata(tool_name)
    
    def is_tool_available(self, tool_name: str) -> bool:
        """Check if a tool is available.
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            True if tool is available
        """
        return self.registry.is_tool_registered(tool_name)
    
    def filter_tools_by_tag(self, tag: str) -> List[Dict[str, Any]]:
        """Filter tools by metadata tag.
        
        Args:
            tag: Tag to filter by
            
        Returns:
            List of tool metadata for tools with the specified tag
        """
        all_tools = self.registry.list_tools_with_metadata()
        return [
            tool for tool in all_tools
            if tag in tool.get('tags', [])
        ]
    
    def filter_tools_by_category(self, category: str) -> List[Dict[str, Any]]:
        """Filter tools by category.
        
        Args:
            category: Category to filter by
            
        Returns:
            List of tool metadata for tools in the specified category
        """
        all_tools = self.registry.list_tools_with_metadata()
        return [
            tool for tool in all_tools
            if tool.get('category') == category
        ]
    
    def search_tools(self, query: str) -> List[Dict[str, Any]]:
        """Search tools by name or description.
        
        Args:
            query: Search query (case-insensitive)
            
        Returns:
            List of tool metadata for matching tools
        """
        query_lower = query.lower()
        all_tools = self.registry.list_tools_with_metadata()
        
        return [
            tool for tool in all_tools
            if query_lower in tool.get('name', '').lower()
            or query_lower in tool.get('description', '').lower()
        ]
    
    def get_tools_for_bedrock(self) -> List[Dict[str, Any]]:
        """Get tool definitions formatted for Bedrock tool use.
        
        Returns tool definitions in the format expected by Bedrock's
        tool use feature (Converse API format).
        
        Returns:
            List of tool definitions for Bedrock
        """
        definitions = self.get_tool_definitions()
        
        bedrock_tools = []
        for definition in definitions:
            bedrock_tools.append({
                'name': definition.name,
                'description': definition.description,
                'input_schema': definition.input_schema
            })
        
        return bedrock_tools


class ToolDiscoveryService:
    """Unified tool discovery service with feature flag support.
    
    Provides a single interface for tool discovery that can use either:
    - Gateway-based discovery (new, dynamic)
    - Local registry discovery (legacy, hardcoded)
    
    The mode is controlled by the ENABLE_GATEWAY_DISCOVERY environment variable.
    """
    
    def __init__(self):
        """Initialize tool discovery service based on configuration."""
        self.enable_gateway_discovery = os.environ.get(
            "ENABLE_GATEWAY_DISCOVERY", "false"
        ).lower() == "true"
        
        if self.enable_gateway_discovery:
            logger.info("Gateway-based tool discovery enabled")
            # Gateway discovery will be initialized lazily when needed
            self._gateway_service = None
            self._local_service = None  # Keep as fallback
        else:
            logger.info("Using local registry for tool discovery")
            self._local_service = LocalToolDiscoveryService()
            self._gateway_service = None
    
    def _get_gateway_service(self):
        """Lazy initialization of Gateway discovery service.
        
        Returns:
            Gateway-based discovery service instance
        """
        if self._gateway_service is None:
            try:
                from .tool_discovery_service import (
                    ToolDiscoveryService as GatewayDiscoveryService
                )
                from .gateway_discovery_client import (
                    GatewayDiscoveryClient,
                    TokenManager
                )
                from .tool_cache import ToolCache
                from .tool_validator import ToolValidator
                from .discovery_config import DiscoveryConfig
                
                # Load configuration from environment
                config = DiscoveryConfig.from_environment()
                
                # Initialize components
                token = os.environ.get("GATEWAY_OAUTH_TOKEN")
                token_manager = TokenManager(token=token)
                gateway_client = GatewayDiscoveryClient(
                    gateway_url=config.gateway_url,
                    token_manager=token_manager,
                    timeout=config.gateway_timeout
                )
                cache = ToolCache(ttl_seconds=config.cache_ttl_seconds)
                validator = ToolValidator()
                
                # Create discovery service
                self._gateway_service = GatewayDiscoveryService(
                    gateway_client=gateway_client,
                    cache=cache,
                    validator=validator,
                    config=config
                )
                
                logger.info("Gateway discovery service initialized")
                
            except Exception as e:
                logger.error(f"Failed to initialize Gateway discovery: {e}")
                logger.warning("Falling back to local registry")
                self.enable_gateway_discovery = False
                if self._local_service is None:
                    self._local_service = LocalToolDiscoveryService()
        
        return self._gateway_service
    
    def _get_local_service(self):
        """Get local registry service, initializing if needed."""
        if self._local_service is None:
            self._local_service = LocalToolDiscoveryService()
        return self._local_service
    
    def get_tools_for_bedrock(self) -> List[Dict[str, Any]]:
        """Get tool definitions formatted for Bedrock tool use.
        
        Returns tool definitions in the format expected by Bedrock's
        tool use feature. Uses Gateway discovery if enabled, otherwise
        falls back to local registry.
        
        Returns:
            List of tool definitions for Bedrock
        """
        if self.enable_gateway_discovery:
            try:
                gateway_service = self._get_gateway_service()
                if gateway_service:
                    # Discover tools from Gateway
                    from .discovery_models import ToolDefinition
                    tools = gateway_service.discover_tools()
                    
                    # Convert to Bedrock format
                    return [tool.to_bedrock_format() for tool in tools]
            except Exception as e:
                logger.error(f"Gateway discovery failed: {e}")
                logger.warning("Falling back to local registry")
        
        # Use local registry (either by configuration or as fallback)
        local_service = self._get_local_service()
        return local_service.get_tools_for_bedrock()
    
    def list_available_tools(self) -> List[str]:
        """List names of all available tools.
        
        Returns:
            List of tool names
        """
        if self.enable_gateway_discovery:
            try:
                gateway_service = self._get_gateway_service()
                if gateway_service:
                    tools = gateway_service.discover_tools()
                    return [tool.name for tool in tools]
            except Exception as e:
                logger.error(f"Gateway discovery failed: {e}")
        
        local_service = self._get_local_service()
        return local_service.list_available_tools()
    
    def get_tool_definitions(self) -> List[MCPToolDefinition]:
        """Get definitions for all available tools.
        
        Note: This returns MCPToolDefinition objects for backward compatibility
        with the local registry interface.
        
        Returns:
            List of MCPToolDefinition objects
        """
        local_service = self._get_local_service()
        return local_service.get_tool_definitions()


# Global discovery service instance
_global_discovery_service: Optional[ToolDiscoveryService] = None


def get_discovery_service() -> ToolDiscoveryService:
    """Get the global tool discovery service instance.
    
    The service automatically selects between Gateway-based and local
    registry discovery based on the ENABLE_GATEWAY_DISCOVERY environment variable.
    
    Returns:
        Global ToolDiscoveryService instance
    """
    global _global_discovery_service
    if _global_discovery_service is None:
        _global_discovery_service = ToolDiscoveryService()
    return _global_discovery_service
