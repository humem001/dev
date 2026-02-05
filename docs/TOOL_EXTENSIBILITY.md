# Tool Extensibility Guide

This guide explains how to add new MCP tools to the serverless AI agent system without modifying core agent code.

## Overview

The system uses a configuration-driven tool registry that allows dynamic tool registration and discovery. This enables:

- Adding new AWS service tools without changing agent code
- Configuration-based tool management
- Dynamic tool discovery by the agent
- Metadata-driven tool organization

## Architecture

### Components

1. **ToolRegistry**: Central registry for managing tool registrations
2. **ToolDiscoveryService**: Interface for discovering available tools
3. **MCPTool Interface**: Standard interface all tools must implement
4. **Configuration File**: JSON file for declarative tool registration

### Tool Registration Flow

```
Configuration File → ToolRegistry → ToolDiscoveryService → Agent
```

## Adding a New Tool

### Step 1: Implement the MCPTool Interface

Create a new tool class that inherits from `MCPTool`:

```python
from src.tools.mcp_tool_interface import MCPTool, MCPToolDefinition
from typing import Dict, Any

class MyNewTool(MCPTool):
    """Description of what this tool does."""
    
    def get_definition(self) -> MCPToolDefinition:
        """Return the tool definition following MCP protocol."""
        return MCPToolDefinition(
            name='my_new_tool',
            description='Description for the AI agent',
            input_schema={
                'type': 'object',
                'properties': {
                    'param1': {'type': 'string', 'description': 'Parameter description'},
                    'param2': {'type': 'integer', 'description': 'Another parameter'}
                },
                'required': ['param1']
            }
        )
    
    def execute(self, parameters: Dict[str, Any], user_context: Dict[str, str]) -> Dict[str, Any]:
        """Execute the tool operation.
        
        Args:
            parameters: Tool-specific parameters from the agent
            user_context: User identity (user_id, username, client_id)
            
        Returns:
            Dictionary containing operation results
        """
        # Implement your tool logic here
        result = {
            'data': 'your result data',
            'user_id': user_context.get('user_id', 'unknown')
        }
        return result
```

### Step 2: Register the Tool

#### Option A: Programmatic Registration

In `src/tools/lambda_handler.py`, add your tool to the initialization:

```python
def _initialize_tool_registry():
    """Initialize the global tool registry with available tools."""
    # Register built-in tools
    register_tool(S3ListBucketsTool, metadata={
        'tags': ['aws', 's3', 'storage'],
        'version': '1.0.0',
        'category': 'aws_services'
    })
    
    # Register your new tool
    register_tool(MyNewTool, metadata={
        'tags': ['aws', 'your-service'],
        'version': '1.0.0',
        'category': 'aws_services'
    })
```

#### Option B: Configuration File Registration

Create or update `tool_registry_config.json`:

```json
{
  "tools": [
    {
      "module": "src.tools.s3_list_buckets_tool",
      "class": "S3ListBucketsTool",
      "metadata": {
        "tags": ["aws", "s3", "storage"],
        "version": "1.0.0",
        "category": "aws_services"
      }
    },
    {
      "module": "src.tools.my_new_tool",
      "class": "MyNewTool",
      "metadata": {
        "tags": ["aws", "your-service"],
        "version": "1.0.0",
        "category": "aws_services"
      }
    }
  ]
}
```

Set the environment variable:
```bash
export TOOL_REGISTRY_CONFIG=/path/to/tool_registry_config.json
```

### Step 3: Test Your Tool

Create tests for your new tool:

```python
import pytest
from src.tools.my_new_tool import MyNewTool
from src.tools.tool_registry import get_global_registry

def test_my_new_tool_registration():
    """Test that new tool is registered."""
    registry = get_global_registry()
    assert registry.is_tool_registered('my_new_tool')

def test_my_new_tool_execution():
    """Test tool execution."""
    tool = MyNewTool()
    
    parameters = {'param1': 'test_value'}
    user_context = {
        'user_id': 'test-user-123',
        'username': 'testuser',
        'client_id': 'test-client'
    }
    
    result = tool.execute(parameters, user_context)
    
    assert 'data' in result
    assert result['user_id'] == 'test-user-123'
```

### Step 4: Deploy

No changes to the agent code are required! The agent will automatically discover your new tool through the registry.

## Tool Discovery

### From the Agent

The agent can discover tools dynamically:

```python
# List all available tools
tools = agent.list_available_tools()
# Returns: ['list_s3_buckets', 'my_new_tool', ...]

# Get tool definitions
definitions = agent.get_tool_definitions()
# Returns: [MCPToolDefinition(...), ...]
```

### From the Discovery Service

For more advanced queries:

```python
from src.tools.tool_discovery import get_discovery_service

discovery = get_discovery_service()

# Search tools
results = discovery.search_tools('s3')

# Filter by tag
aws_tools = discovery.filter_tools_by_tag('aws')

# Filter by category
storage_tools = discovery.filter_tools_by_category('storage')

# Get Bedrock-formatted tools
bedrock_tools = discovery.get_tools_for_bedrock()
```

## Tool Metadata

Tools can include metadata for organization and discovery:

```python
metadata = {
    'tags': ['aws', 's3', 'storage'],      # Tags for filtering
    'version': '1.0.0',                     # Tool version
    'category': 'aws_services',             # Category grouping
    'author': 'Your Team',                  # Optional: author info
    'documentation_url': 'https://...'      # Optional: docs link
}
```

## Best Practices

### 1. Tool Naming

- Use descriptive, action-oriented names: `list_s3_buckets`, `describe_ec2_instances`
- Use snake_case for tool names
- Keep names concise but clear

### 2. Input Schema

- Define clear, well-documented input schemas
- Use JSON Schema format
- Mark required parameters explicitly
- Provide descriptions for all parameters

### 3. Error Handling

- Use the tool error handling framework:

```python
from src.tools.tool_errors import ToolExecutionError

def execute(self, parameters, user_context):
    try:
        # Your logic here
        pass
    except SomeAWSError as e:
        raise ToolExecutionError(
            message='User-friendly error message',
            error_code='service_error',
            status_code=503
        )
```

### 4. User Attribution

- Always include user_id in results
- Log operations with user context
- Follow the attribution pattern:

```python
return {
    'result_data': {...},
    'user_id': user_context.get('user_id', 'unknown')
}
```

### 5. Testing

- Write unit tests for tool logic
- Test with various parameter combinations
- Test error conditions
- Verify user attribution

## Example: Adding an EC2 Tool

Here's a complete example of adding an EC2 describe instances tool:

```python
# src/tools/ec2_describe_instances_tool.py

import boto3
from botocore.config import Config
from typing import Dict, Any, Optional
from .mcp_tool_interface import MCPTool, MCPToolDefinition
from .tool_errors import ToolExecutionError
from ..config.timeout_config import TIMEOUT_CONFIG


class EC2DescribeInstancesTool(MCPTool):
    """MCP tool for describing EC2 instances."""
    
    def __init__(self, ec2_client=None, timeout: Optional[int] = None):
        """Initialize the EC2 tool."""
        if ec2_client is None:
            timeout_seconds = timeout or TIMEOUT_CONFIG.aws_operation
            boto_config = Config(
                connect_timeout=timeout_seconds,
                read_timeout=timeout_seconds,
                retries={'max_attempts': 0}
            )
            self.ec2_client = boto3.client('ec2', config=boto_config)
        else:
            self.ec2_client = ec2_client
    
    def get_definition(self) -> MCPToolDefinition:
        """Return the tool definition."""
        return MCPToolDefinition(
            name='describe_ec2_instances',
            description='Describe EC2 instances in the account',
            input_schema={
                'type': 'object',
                'properties': {
                    'region': {
                        'type': 'string',
                        'description': 'AWS region (optional)'
                    },
                    'instance_ids': {
                        'type': 'array',
                        'items': {'type': 'string'},
                        'description': 'Specific instance IDs to describe (optional)'
                    }
                },
                'required': []
            }
        )
    
    def execute(self, parameters: Dict[str, Any], user_context: Dict[str, str]) -> Dict[str, Any]:
        """Execute the EC2 DescribeInstances operation."""
        try:
            # Build request parameters
            request_params = {}
            if 'instance_ids' in parameters:
                request_params['InstanceIds'] = parameters['instance_ids']
            
            # Execute EC2 operation
            response = self.ec2_client.describe_instances(**request_params)
            
            # Format instance information
            instances = []
            for reservation in response.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instances.append({
                        'instance_id': instance['InstanceId'],
                        'instance_type': instance['InstanceType'],
                        'state': instance['State']['Name'],
                        'launch_time': instance['LaunchTime'].isoformat()
                    })
            
            # Return results with user attribution
            return {
                'instances': instances,
                'count': len(instances),
                'user_id': user_context.get('user_id', 'unknown')
            }
        except Exception as e:
            raise ToolExecutionError(
                message=f'Failed to describe EC2 instances: {str(e)}',
                error_code='ec2_error',
                status_code=500
            )
```

Register in `lambda_handler.py`:

```python
from .ec2_describe_instances_tool import EC2DescribeInstancesTool

def _initialize_tool_registry():
    register_tool(S3ListBucketsTool, metadata={
        'tags': ['aws', 's3', 'storage'],
        'version': '1.0.0',
        'category': 'aws_services'
    })
    
    register_tool(EC2DescribeInstancesTool, metadata={
        'tags': ['aws', 'ec2', 'compute'],
        'version': '1.0.0',
        'category': 'aws_services'
    })
```

That's it! The agent will automatically discover and use the new EC2 tool without any code changes.

## Troubleshooting

### Tool Not Discovered

1. Check tool is registered in `_initialize_tool_registry()`
2. Verify tool class inherits from `MCPTool`
3. Check `get_definition()` returns valid `MCPToolDefinition`
4. Ensure tool name is unique

### Configuration File Not Loading

1. Verify `TOOL_REGISTRY_CONFIG` environment variable is set
2. Check JSON syntax is valid
3. Verify module and class names are correct
4. Check file permissions

### Tool Execution Fails

1. Check input schema matches parameters
2. Verify AWS permissions for the tool's operations
3. Check timeout configuration
4. Review CloudWatch logs for detailed errors

## Requirements Validation

This implementation satisfies:

- **Requirement 10.1**: Support adding new MCP tools without modifying Agent code ✓
- **Requirement 10.2**: MCP tool implementation follows standard interface pattern ✓
- **Requirement 10.3**: Configuration-driven tool registration ✓
- **Requirement 10.4**: Agent dynamically discovers available tools ✓
