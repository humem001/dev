"""Tool Registry for dynamic MCP tool registration and discovery.

This module provides configuration-driven tool registration and discovery,
allowing new tools to be added without modifying core agent code.
"""

import json
import os
from typing import Dict, List, Optional, Type
from dataclasses import dataclass

from .mcp_tool_interface import MCPTool, MCPToolDefinition


@dataclass
class ToolRegistryConfig:
    """Configuration for tool registry.
    
    Can be loaded from environment variables or configuration file.
    """
    config_file: Optional[str] = None  # Path to JSON config file
    
    def __post_init__(self):
        """Set default config file from environment if not provided."""
        if self.config_file is None:
            self.config_file = os.environ.get('TOOL_REGISTRY_CONFIG', None)


class ToolRegistry:
    """Registry for MCP tools with dynamic discovery.
    
    Supports:
    - Configuration-driven tool registration
    - Dynamic tool discovery
    - Tool addition without code changes
    - Tool metadata retrieval
    """
    
    def __init__(self, config: Optional[ToolRegistryConfig] = None):
        """Initialize tool registry.
        
        Args:
            config: Optional registry configuration
        """
        self.config = config or ToolRegistryConfig()
        self._tools: Dict[str, Type[MCPTool]] = {}
        self._tool_metadata: Dict[str, dict] = {}
        
        # Load tools from configuration if available
        if self.config.config_file and os.path.exists(self.config.config_file):
            self._load_from_config()
    
    def register_tool(
        self,
        tool_class: Type[MCPTool],
        metadata: Optional[dict] = None
    ) -> None:
        """Register a tool class.
        
        Args:
            tool_class: MCP tool class to register
            metadata: Optional metadata (tags, version, etc.)
        """
        # Create instance to get definition
        tool_instance = tool_class()
        definition = tool_instance.get_definition()
        
        # Register tool
        self._tools[definition.name] = tool_class
        
        # Store metadata
        self._tool_metadata[definition.name] = {
            'name': definition.name,
            'description': definition.description,
            'input_schema': definition.input_schema,
            'class_name': tool_class.__name__,
            'module': tool_class.__module__,
            **(metadata or {})
        }
    
    def get_tool(self, tool_name: str) -> Optional[MCPTool]:
        """Get tool instance by name.
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            MCPTool instance or None if not found
        """
        tool_class = self._tools.get(tool_name)
        if tool_class:
            return tool_class()
        return None
    
    def get_tool_definition(self, tool_name: str) -> Optional[MCPToolDefinition]:
        """Get tool definition by name.
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            MCPToolDefinition or None if not found
        """
        tool = self.get_tool(tool_name)
        if tool:
            return tool.get_definition()
        return None
    
    def list_tools(self) -> List[str]:
        """List all registered tool names.
        
        Returns:
            List of tool names
        """
        return list(self._tools.keys())
    
    def discover_tools(self) -> List[MCPToolDefinition]:
        """Discover all available tools.
        
        Returns:
            List of tool definitions for all registered tools
        """
        definitions = []
        for tool_name in self._tools:
            tool = self.get_tool(tool_name)
            if tool:
                definitions.append(tool.get_definition())
        return definitions
    
    def get_tool_metadata(self, tool_name: str) -> Optional[dict]:
        """Get tool metadata.
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            Tool metadata dictionary or None if not found
        """
        return self._tool_metadata.get(tool_name)
    
    def list_tools_with_metadata(self) -> List[dict]:
        """List all tools with their metadata.
        
        Returns:
            List of tool metadata dictionaries
        """
        return list(self._tool_metadata.values())
    
    def is_tool_registered(self, tool_name: str) -> bool:
        """Check if a tool is registered.
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            True if tool is registered
        """
        return tool_name in self._tools
    
    def unregister_tool(self, tool_name: str) -> bool:
        """Unregister a tool.
        
        Args:
            tool_name: Name of the tool to unregister
            
        Returns:
            True if tool was unregistered, False if not found
        """
        if tool_name in self._tools:
            del self._tools[tool_name]
            if tool_name in self._tool_metadata:
                del self._tool_metadata[tool_name]
            return True
        return False
    
    def _load_from_config(self) -> None:
        """Load tool registrations from configuration file.
        
        Configuration file format (JSON):
        {
            "tools": [
                {
                    "module": "src.tools.s3_list_buckets_tool",
                    "class": "S3ListBucketsTool",
                    "metadata": {
                        "tags": ["aws", "s3"],
                        "version": "1.0.0"
                    }
                }
            ]
        }
        """
        try:
            with open(self.config.config_file, 'r') as f:
                config_data = json.load(f)
            
            tools_config = config_data.get('tools', [])
            
            for tool_config in tools_config:
                module_name = tool_config.get('module')
                class_name = tool_config.get('class')
                metadata = tool_config.get('metadata', {})
                
                if not module_name or not class_name:
                    continue
                
                # Dynamically import tool class
                try:
                    module = __import__(module_name, fromlist=[class_name])
                    tool_class = getattr(module, class_name)
                    
                    # Register tool
                    self.register_tool(tool_class, metadata)
                except (ImportError, AttributeError) as e:
                    # Log error but continue loading other tools
                    print(f"Warning: Failed to load tool {class_name} from {module_name}: {e}")
                    continue
        
        except Exception as e:
            # Log error but don't fail initialization
            print(f"Warning: Failed to load tool registry config from {self.config.config_file}: {e}")


# Global registry instance
_global_registry: Optional[ToolRegistry] = None


def get_global_registry() -> ToolRegistry:
    """Get the global tool registry instance.
    
    Creates the registry on first access.
    
    Returns:
        Global ToolRegistry instance
    """
    global _global_registry
    if _global_registry is None:
        _global_registry = ToolRegistry()
    return _global_registry


def register_tool(tool_class: Type[MCPTool], metadata: Optional[dict] = None) -> None:
    """Register a tool in the global registry.
    
    Convenience function for registering tools.
    
    Args:
        tool_class: MCP tool class to register
        metadata: Optional metadata
    """
    registry = get_global_registry()
    registry.register_tool(tool_class, metadata)


def discover_tools() -> List[MCPToolDefinition]:
    """Discover all available tools from global registry.
    
    Convenience function for tool discovery.
    
    Returns:
        List of tool definitions
    """
    registry = get_global_registry()
    return registry.discover_tools()
