"""Tests for tool registry and discovery functionality.

This module tests the configuration-driven tool registration and discovery
mechanism, ensuring tools can be added dynamically without code changes.
"""

import json
import os
import tempfile
import pytest
from typing import Dict, Any

from src.tools.tool_registry import (
    ToolRegistry,
    ToolRegistryConfig,
    get_global_registry,
    register_tool,
    discover_tools
)
from src.tools.tool_discovery import (
    ToolDiscoveryService,
    get_discovery_service
)
from src.tools.mcp_tool_interface import (
    MCPTool,
    MCPToolDefinition
)
from src.tools.s3_list_buckets_tool import S3ListBucketsTool


# Mock tool for testing
class MockEC2Tool(MCPTool):
    """Mock EC2 tool for testing."""
    
    def get_definition(self) -> MCPToolDefinition:
        return MCPToolDefinition(
            name='describe_ec2_instances',
            description='Describe EC2 instances in the account',
            input_schema={
                'type': 'object',
                'properties': {
                    'region': {'type': 'string'}
                },
                'required': []
            }
        )
    
    def execute(self, parameters: Dict[str, Any], user_context: Dict[str, str]) -> Dict[str, Any]:
        return {
            'instances': [],
            'count': 0,
            'user_id': user_context.get('user_id', 'unknown')
        }


class TestToolRegistry:
    """Test suite for ToolRegistry."""
    
    def test_register_tool(self):
        """Test registering a tool."""
        registry = ToolRegistry()
        
        # Register tool
        registry.register_tool(S3ListBucketsTool, metadata={
            'tags': ['aws', 's3'],
            'version': '1.0.0'
        })
        
        # Verify registration
        assert registry.is_tool_registered('list_s3_buckets')
        assert 'list_s3_buckets' in registry.list_tools()
    
    def test_get_tool(self):
        """Test retrieving a tool instance."""
        registry = ToolRegistry()
        registry.register_tool(S3ListBucketsTool)
        
        # Get tool
        tool = registry.get_tool('list_s3_buckets')
        
        # Verify tool instance
        assert tool is not None
        assert isinstance(tool, S3ListBucketsTool)
    
    def test_get_tool_not_found(self):
        """Test retrieving non-existent tool."""
        registry = ToolRegistry()
        
        # Get non-existent tool
        tool = registry.get_tool('nonexistent_tool')
        
        # Verify None returned
        assert tool is None
    
    def test_get_tool_definition(self):
        """Test retrieving tool definition."""
        registry = ToolRegistry()
        registry.register_tool(S3ListBucketsTool)
        
        # Get definition
        definition = registry.get_tool_definition('list_s3_buckets')
        
        # Verify definition
        assert definition is not None
        assert definition.name == 'list_s3_buckets'
        assert 'S3 buckets' in definition.description
        assert definition.input_schema is not None
    
    def test_list_tools(self):
        """Test listing all registered tools."""
        registry = ToolRegistry()
        registry.register_tool(S3ListBucketsTool)
        registry.register_tool(MockEC2Tool)
        
        # List tools
        tools = registry.list_tools()
        
        # Verify list
        assert len(tools) == 2
        assert 'list_s3_buckets' in tools
        assert 'describe_ec2_instances' in tools
    
    def test_discover_tools(self):
        """Test discovering all tool definitions."""
        registry = ToolRegistry()
        registry.register_tool(S3ListBucketsTool)
        registry.register_tool(MockEC2Tool)
        
        # Discover tools
        definitions = registry.discover_tools()
        
        # Verify definitions
        assert len(definitions) == 2
        tool_names = [d.name for d in definitions]
        assert 'list_s3_buckets' in tool_names
        assert 'describe_ec2_instances' in tool_names
    
    def test_get_tool_metadata(self):
        """Test retrieving tool metadata."""
        registry = ToolRegistry()
        metadata = {
            'tags': ['aws', 's3'],
            'version': '1.0.0',
            'category': 'storage'
        }
        registry.register_tool(S3ListBucketsTool, metadata=metadata)
        
        # Get metadata
        retrieved_metadata = registry.get_tool_metadata('list_s3_buckets')
        
        # Verify metadata
        assert retrieved_metadata is not None
        assert retrieved_metadata['tags'] == ['aws', 's3']
        assert retrieved_metadata['version'] == '1.0.0'
        assert retrieved_metadata['category'] == 'storage'
    
    def test_list_tools_with_metadata(self):
        """Test listing tools with metadata."""
        registry = ToolRegistry()
        registry.register_tool(S3ListBucketsTool, metadata={'tags': ['aws']})
        registry.register_tool(MockEC2Tool, metadata={'tags': ['ec2']})
        
        # List with metadata
        tools_metadata = registry.list_tools_with_metadata()
        
        # Verify metadata list
        assert len(tools_metadata) == 2
        assert all('name' in tm for tm in tools_metadata)
        assert all('description' in tm for tm in tools_metadata)
    
    def test_unregister_tool(self):
        """Test unregistering a tool."""
        registry = ToolRegistry()
        registry.register_tool(S3ListBucketsTool)
        
        # Verify registered
        assert registry.is_tool_registered('list_s3_buckets')
        
        # Unregister
        result = registry.unregister_tool('list_s3_buckets')
        
        # Verify unregistered
        assert result is True
        assert not registry.is_tool_registered('list_s3_buckets')
    
    def test_unregister_nonexistent_tool(self):
        """Test unregistering non-existent tool."""
        registry = ToolRegistry()
        
        # Unregister non-existent tool
        result = registry.unregister_tool('nonexistent_tool')
        
        # Verify False returned
        assert result is False
    
    def test_load_from_config_file(self):
        """Test loading tools from configuration file."""
        # Create temporary config file
        config_data = {
            'tools': [
                {
                    'module': 'src.tools.s3_list_buckets_tool',
                    'class': 'S3ListBucketsTool',
                    'metadata': {
                        'tags': ['aws', 's3'],
                        'version': '1.0.0'
                    }
                }
            ]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_data, f)
            config_file = f.name
        
        try:
            # Create registry with config
            config = ToolRegistryConfig(config_file=config_file)
            registry = ToolRegistry(config)
            
            # Verify tool loaded
            assert registry.is_tool_registered('list_s3_buckets')
            metadata = registry.get_tool_metadata('list_s3_buckets')
            assert metadata['tags'] == ['aws', 's3']
        finally:
            # Clean up
            os.unlink(config_file)
    
    def test_load_from_config_file_invalid_tool(self):
        """Test loading config with invalid tool reference."""
        # Create config with invalid tool
        config_data = {
            'tools': [
                {
                    'module': 'nonexistent.module',
                    'class': 'NonexistentTool',
                    'metadata': {}
                }
            ]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_data, f)
            config_file = f.name
        
        try:
            # Create registry with config (should not fail)
            config = ToolRegistryConfig(config_file=config_file)
            registry = ToolRegistry(config)
            
            # Verify no tools loaded
            assert len(registry.list_tools()) == 0
        finally:
            # Clean up
            os.unlink(config_file)
    
    def test_global_registry(self):
        """Test global registry instance."""
        # Get global registry
        registry1 = get_global_registry()
        registry2 = get_global_registry()
        
        # Verify same instance
        assert registry1 is registry2
    
    def test_register_tool_convenience_function(self):
        """Test convenience function for registering tools."""
        # Clear global registry for test
        registry = get_global_registry()
        if registry.is_tool_registered('describe_ec2_instances'):
            registry.unregister_tool('describe_ec2_instances')
        
        # Register using convenience function
        register_tool(MockEC2Tool, metadata={'tags': ['ec2']})
        
        # Verify registration
        assert registry.is_tool_registered('describe_ec2_instances')
    
    def test_discover_tools_convenience_function(self):
        """Test convenience function for discovering tools."""
        # Register a tool
        registry = get_global_registry()
        if not registry.is_tool_registered('list_s3_buckets'):
            register_tool(S3ListBucketsTool)
        
        # Discover using convenience function
        definitions = discover_tools()
        
        # Verify discovery
        assert len(definitions) > 0
        tool_names = [d.name for d in definitions]
        assert 'list_s3_buckets' in tool_names


class TestToolDiscoveryService:
    """Test suite for ToolDiscoveryService."""
    
    def test_list_available_tools(self):
        """Test listing available tools."""
        # Setup registry
        registry = ToolRegistry()
        registry.register_tool(S3ListBucketsTool)
        
        # Create discovery service
        discovery = ToolDiscoveryService()
        discovery.registry = registry
        
        # List tools
        tools = discovery.list_available_tools()
        
        # Verify list
        assert 'list_s3_buckets' in tools
    
    def test_get_tool_definitions(self):
        """Test getting tool definitions."""
        # Setup registry
        registry = ToolRegistry()
        registry.register_tool(S3ListBucketsTool)
        
        # Create discovery service
        discovery = ToolDiscoveryService()
        discovery.registry = registry
        
        # Get definitions
        definitions = discovery.get_tool_definitions()
        
        # Verify definitions
        assert len(definitions) > 0
        assert any(d.name == 'list_s3_buckets' for d in definitions)
    
    def test_get_tool_definition(self):
        """Test getting single tool definition."""
        # Setup registry
        registry = ToolRegistry()
        registry.register_tool(S3ListBucketsTool)
        
        # Create discovery service
        discovery = ToolDiscoveryService()
        discovery.registry = registry
        
        # Get definition
        definition = discovery.get_tool_definition('list_s3_buckets')
        
        # Verify definition
        assert definition is not None
        assert definition.name == 'list_s3_buckets'
    
    def test_is_tool_available(self):
        """Test checking tool availability."""
        # Setup registry
        registry = ToolRegistry()
        registry.register_tool(S3ListBucketsTool)
        
        # Create discovery service
        discovery = ToolDiscoveryService()
        discovery.registry = registry
        
        # Check availability
        assert discovery.is_tool_available('list_s3_buckets')
        assert not discovery.is_tool_available('nonexistent_tool')
    
    def test_filter_tools_by_tag(self):
        """Test filtering tools by tag."""
        # Setup registry
        registry = ToolRegistry()
        registry.register_tool(S3ListBucketsTool, metadata={'tags': ['aws', 's3']})
        registry.register_tool(MockEC2Tool, metadata={'tags': ['aws', 'ec2']})
        
        # Create discovery service
        discovery = ToolDiscoveryService()
        discovery.registry = registry
        
        # Filter by tag
        aws_tools = discovery.filter_tools_by_tag('aws')
        s3_tools = discovery.filter_tools_by_tag('s3')
        
        # Verify filtering
        assert len(aws_tools) == 2
        assert len(s3_tools) == 1
        assert s3_tools[0]['name'] == 'list_s3_buckets'
    
    def test_filter_tools_by_category(self):
        """Test filtering tools by category."""
        # Setup registry
        registry = ToolRegistry()
        registry.register_tool(S3ListBucketsTool, metadata={'category': 'storage'})
        registry.register_tool(MockEC2Tool, metadata={'category': 'compute'})
        
        # Create discovery service
        discovery = ToolDiscoveryService()
        discovery.registry = registry
        
        # Filter by category
        storage_tools = discovery.filter_tools_by_category('storage')
        
        # Verify filtering
        assert len(storage_tools) == 1
        assert storage_tools[0]['name'] == 'list_s3_buckets'
    
    def test_search_tools(self):
        """Test searching tools by name or description."""
        # Setup registry
        registry = ToolRegistry()
        registry.register_tool(S3ListBucketsTool)
        registry.register_tool(MockEC2Tool)
        
        # Create discovery service
        discovery = ToolDiscoveryService()
        discovery.registry = registry
        
        # Search tools
        s3_results = discovery.search_tools('s3')
        ec2_results = discovery.search_tools('ec2')
        bucket_results = discovery.search_tools('bucket')
        
        # Verify search
        assert len(s3_results) == 1
        assert s3_results[0]['name'] == 'list_s3_buckets'
        assert len(ec2_results) == 1
        assert len(bucket_results) == 1
    
    def test_get_tools_for_bedrock(self):
        """Test getting tools formatted for Bedrock."""
        # Setup registry
        registry = ToolRegistry()
        registry.register_tool(S3ListBucketsTool)
        
        # Create discovery service
        discovery = ToolDiscoveryService()
        discovery.registry = registry
        
        # Get Bedrock format
        bedrock_tools = discovery.get_tools_for_bedrock()
        
        # Verify format
        assert len(bedrock_tools) > 0
        assert 'toolSpec' in bedrock_tools[0]
        assert 'name' in bedrock_tools[0]['toolSpec']
        assert 'description' in bedrock_tools[0]['toolSpec']
        assert 'inputSchema' in bedrock_tools[0]['toolSpec']
    
    def test_global_discovery_service(self):
        """Test global discovery service instance."""
        # Get global service
        service1 = get_discovery_service()
        service2 = get_discovery_service()
        
        # Verify same instance
        assert service1 is service2


class TestToolRegistryIntegration:
    """Integration tests for tool registry with agent."""
    
    def test_agent_can_discover_tools(self):
        """Test that agent can discover available tools."""
        from src.agent.agent_core import Agent, AgentConfig
        
        # Create agent config
        config = AgentConfig(
            bedrock_model_id='anthropic.claude-3-sonnet-20240229-v1:0',
            agentcore_gateway_url='https://gateway.example.com',
            agentcore_memory_id='memory-123'
        )
        
        # Create agent
        agent = Agent(config)
        
        # Discover tools
        tools = agent.list_available_tools()
        
        # Verify discovery works
        assert isinstance(tools, list)
    
    def test_new_tool_discoverable_without_agent_changes(self):
        """Test that new tools are discoverable without modifying agent code.
        
        This validates Requirement 10.1: Support adding new MCP tools without
        modifying the Agent code.
        """
        # Register new tool
        registry = get_global_registry()
        registry.register_tool(MockEC2Tool, metadata={
            'tags': ['aws', 'ec2'],
            'version': '1.0.0'
        })
        
        # Create discovery service
        discovery = get_discovery_service()
        
        # Verify new tool is discoverable
        assert discovery.is_tool_available('describe_ec2_instances')
        
        # Verify tool definition is accessible
        definition = discovery.get_tool_definition('describe_ec2_instances')
        assert definition is not None
        assert definition.name == 'describe_ec2_instances'
        
        # Clean up
        registry.unregister_tool('describe_ec2_instances')
