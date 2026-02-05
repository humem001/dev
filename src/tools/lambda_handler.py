"""Lambda handler for MCP Tool execution.

This module provides the AWS Lambda handler function for executing MCP tools
through AgentCore Gateway with user context propagation and structured logging.
"""

import json
import logging
import os
import time
from datetime import datetime
from typing import Any, Dict

from .s3_list_buckets_tool import S3ListBucketsTool
from .mcp_tool_interface import MCPToolRequest
from .tool_errors import ToolExecutionError, MCPProtocolError
from .tool_registry import get_global_registry, register_tool
from models.user_context import UserContext

# Try to import audit logger, but make it optional for Tool Lambda
try:
    from audit_logging.audit_logger import log_tool_execution
except ImportError:
    # Fallback if audit logger not available
    def log_tool_execution(*args, **kwargs):
        pass


# Configure structured logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)


# Initialize tool registry on module load
def _initialize_tool_registry():
    """Initialize the global tool registry with available tools.
    
    This function is called once when the module is loaded.
    Tools can be registered here or loaded from configuration.
    """
    # Register built-in tools
    register_tool(S3ListBucketsTool, metadata={
        'tags': ['aws', 's3', 'storage'],
        'version': '1.0.0',
        'category': 'aws_services'
    })
    
    # Additional tools can be registered here or loaded from config
    # The registry will also auto-load from TOOL_REGISTRY_CONFIG env var


# Initialize registry on module load
_initialize_tool_registry()


def log_structured(
    level: str,
    message: str,
    component: str = 'mcp_tool',
    **kwargs
):
    """Log structured JSON for CloudWatch.
    
    Args:
        level: Log level (INFO, ERROR, WARNING)
        message: Log message
        component: Component name
        **kwargs: Additional fields to include in log
    """
    log_entry = {
        'timestamp': datetime.utcnow().isoformat(),
        'level': level,
        'component': component,
        'message': message,
        **kwargs
    }
    
    log_func = getattr(logger, level.lower(), logger.info)
    log_func(json.dumps(log_entry))


def parse_event(event: Dict[str, Any]) -> MCPToolRequest:
    """Parse incoming event from AgentCore Gateway.
    
    Args:
        event: Lambda event from AgentCore Gateway
        
    Returns:
        MCPToolRequest with parsed parameters and user context
        
    Raises:
        MCPProtocolError: If event format is invalid
    """
    try:
        # Extract required fields from event
        tool_name = event.get('tool_name')
        parameters = event.get('parameters', {})
        user_context = event.get('user_context', {})
        request_id = event.get('request_id', 'unknown')
        
        # Validate required fields
        if not tool_name:
            raise MCPProtocolError('Missing required field: tool_name')
        
        if not user_context or 'user_id' not in user_context:
            raise MCPProtocolError('Missing required field: user_context.user_id')
        
        return MCPToolRequest(
            tool_name=tool_name,
            parameters=parameters,
            user_context=user_context,
            request_id=request_id
        )
    except MCPProtocolError:
        raise
    except Exception as e:
        raise MCPProtocolError(f'Invalid event format: {str(e)}')


def get_tool(tool_name: str):
    """Get tool instance by name from registry.
    
    Args:
        tool_name: Name of the tool to retrieve
        
    Returns:
        MCPTool instance
        
    Raises:
        MCPProtocolError: If tool not found
    """
    registry = get_global_registry()
    tool = registry.get_tool(tool_name)
    
    if not tool:
        raise MCPProtocolError(f'Unknown tool: {tool_name}')
    
    return tool


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """AWS Lambda handler for MCP protocol requests.
    
    Supports two invocation modes:
    1. MCP JSON-RPC 2.0 (for tools/list and direct testing)
    2. Gateway direct invocation (for tool execution from AgentCore Gateway)
    
    Args:
        event: Event data (MCP JSON-RPC 2.0 or Gateway format)
        context: Lambda context object
        
    Returns:
        Response in appropriate format
    """
    request_id = event.get('id', context.aws_request_id if context else 'unknown')
    start_time = time.time()
    
    try:
        # Check if this is an MCP JSON-RPC request
        if 'jsonrpc' in event:
            # MCP JSON-RPC 2.0 format
            return handle_mcp_request(event, context, request_id, start_time)
        else:
            # Gateway direct invocation format
            return handle_gateway_request(event, context, request_id, start_time)
    
    except Exception as e:
        log_structured(
            level='ERROR',
            message='Unexpected error in handler',
            error=str(e),
            error_type=type(e).__name__,
            request_id=request_id
        )
        
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': 'Internal error'
            })
        }


def handle_mcp_request(event: Dict[str, Any], context: Any, request_id: str, start_time: float) -> Dict[str, Any]:
    """Handle MCP JSON-RPC 2.0 requests.
    
    Supports MCP JSON-RPC 2.0 methods:
    - tools/list: Returns list of available tools
    - tools/call: Executes a specific tool
    
    Args:
        event: MCP JSON-RPC 2.0 formatted event
        context: Lambda context object
        request_id: Request ID
        start_time: Request start time
        
    Returns:
        MCP JSON-RPC 2.0 formatted response
    """
    try:
        # Parse MCP JSON-RPC request
        jsonrpc = event.get('jsonrpc')
        method = event.get('method')
        params = event.get('params', {})
        
        if jsonrpc != '2.0':
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'jsonrpc': '2.0',
                    'error': {
                        'code': -32600,
                        'message': 'Invalid Request: jsonrpc must be "2.0"'
                    },
                    'id': request_id
                })
            }
        
        # Handle tools/list method
        if method == 'tools/list':
            return handle_tools_list(request_id)
        
        # Handle tools/call method
        elif method == 'tools/call':
            return handle_tools_call(params, request_id, context, start_time)
        
        else:
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'jsonrpc': '2.0',
                    'error': {
                        'code': -32601,
                        'message': f'Method not found: {method}'
                    },
                    'id': request_id
                })
            }
    
    except Exception as e:
        log_structured(
            level='ERROR',
            message='Unexpected error in MCP handler',
            error=str(e),
            error_type=type(e).__name__,
            request_id=request_id
        )
        
        return {
            'statusCode': 500,
            'body': json.dumps({
                'jsonrpc': '2.0',
                'error': {
                    'code': -32603,
                    'message': 'Internal error'
                },
                'id': request_id
            })
        }


def handle_gateway_request(event: Dict[str, Any], context: Any, request_id: str, start_time: float) -> Dict[str, Any]:
    """Handle Gateway direct invocation requests.
    
    Gateway sends tool execution requests in a simplified format without MCP wrapping.
    
    Args:
        event: Gateway formatted event
        context: Lambda context object
        request_id: Request ID
        start_time: Request start time
        
    Returns:
        Tool execution result
    """
    try:
        # Gateway sends tool name and parameters directly
        # The tool name is in the Gateway configuration, parameters are in the event
        # For now, we'll assume it's calling list_s3_buckets
        
        # Extract parameters (Gateway may send them in various formats)
        parameters = event.get('arguments', event.get('parameters', {}))
        
        # Extract user_context from parameters (it's included in arguments by Gateway client)
        user_context_dict = parameters.pop('user_context', {}) if isinstance(parameters, dict) else {}
        
        # Default to list_s3_buckets tool
        tool_name = 'list_s3_buckets'
        
        # Create MCPToolRequest
        tool_request = MCPToolRequest(
            tool_name=tool_name,
            parameters=parameters,
            user_context=user_context_dict,
            request_id=request_id
        )
        
        # Get tool instance
        tool = get_tool(tool_name)
        
        # Execute tool
        response = tool.invoke(tool_request)
        
        # Return result directly (not wrapped in MCP format)
        return {
            'statusCode': 200 if response.status == 'success' else 500,
            'body': json.dumps(response.result)
        }
        
    except Exception as e:
        log_structured(
            level='ERROR',
            message='Error in Gateway request handler',
            error=str(e),
            error_type=type(e).__name__,
            request_id=request_id
        )
        
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e)
            })
        }


def handle_tools_list(request_id: str) -> Dict[str, Any]:
    """Handle MCP tools/list request.
    
    Returns list of available tools in MCP format.
    
    Args:
        request_id: Request ID
        
    Returns:
        MCP JSON-RPC response with tools list
    """
    try:
        registry = get_global_registry()
        tools = []
        
        for tool_name in registry.list_tools():
            tool = registry.get_tool(tool_name)
            if tool:
                definition = tool.get_definition()
                tools.append({
                    'name': definition.name,
                    'description': definition.description,
                    'inputSchema': definition.input_schema
                })
        
        log_structured(
            level='INFO',
            message='MCP tools/list request completed',
            operation='tools_list',
            tools_count=len(tools),
            request_id=request_id
        )
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'jsonrpc': '2.0',
                'result': {
                    'tools': tools
                },
                'id': request_id
            })
        }
    
    except Exception as e:
        log_structured(
            level='ERROR',
            message='Error handling tools/list',
            error=str(e),
            request_id=request_id
        )
        
        return {
            'statusCode': 500,
            'body': json.dumps({
                'jsonrpc': '2.0',
                'error': {
                    'code': -32603,
                    'message': f'Failed to list tools: {str(e)}'
                },
                'id': request_id
            })
        }


def handle_tools_call(params: Dict[str, Any], request_id: str, context: Any, start_time: float) -> Dict[str, Any]:
    """Handle MCP tools/call request.
    
    Args:
        params: Tool call parameters (name, arguments)
        request_id: Request ID
        context: Lambda context
        start_time: Request start time
        
    Returns:
        MCP JSON-RPC response with tool result
    """
    try:
        # Extract tool name and arguments from MCP params
        tool_name = params.get('name')
        arguments = params.get('arguments', {})
        
        if not tool_name:
            return {
                'statusCode': 400,
                'body': json.dumps({
                    'jsonrpc': '2.0',
                    'error': {
                        'code': -32602,
                        'message': 'Invalid params: missing tool name'
                    },
                    'id': request_id
                })
            }
        
        # Extract user_context from arguments (it's included by Gateway client)
        # Make a copy to avoid modifying the original
        tool_arguments = dict(arguments)
        user_context_dict = tool_arguments.pop('user_context', {})
        
        # Create MCPToolRequest with user_context separated from parameters
        tool_request = MCPToolRequest(
            tool_name=tool_name,
            parameters=tool_arguments,
            user_context=user_context_dict,
            request_id=request_id
        )
        
        # Create UserContext for logging
        user_context = UserContext(
            user_id=user_context_dict.get('user_id', 'unknown'),
            username=user_context_dict.get('username', 'unknown'),
            client_id=user_context_dict.get('client_id', 'unknown')
        )
        
        # Log incoming request
        log_structured(
            level='INFO',
            message='MCP tool invocation started',
            operation='tool_invocation',
            tool_name=tool_name,
            user_id=user_context.user_id,
            username=user_context.username,
            client_id=user_context.client_id,
            request_id=request_id
        )
        
        # Get tool instance
        tool = get_tool(tool_name)
        
        # Execute tool
        response = tool.invoke(tool_request)
        
        # Calculate duration
        duration_ms = int((time.time() - start_time) * 1000)
        
        # Log successful execution
        log_tool_execution(
            tool_name=tool_name,
            status='success',
            request_id=request_id,
            user_context=user_context,
            duration_ms=duration_ms,
            metadata={
                'response_status': response.status,
                'execution_time_ms': response.execution_time_ms
            }
        )
        
        log_structured(
            level='INFO',
            message='MCP tool invocation completed',
            operation='tool_invocation',
            tool_name=tool_name,
            user_id=user_context.user_id,
            status=response.status,
            execution_time_ms=response.execution_time_ms,
            request_id=request_id
        )
        
        # Return MCP JSON-RPC response
        # Format: {"jsonrpc": "2.0", "result": {"content": [...], "isError": false}, "id": "..."}
        result_content = []
        
        if response.result:
            # Convert result to text content
            result_text = json.dumps(response.result)
            result_content.append({
                'type': 'text',
                'text': result_text
            })
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'jsonrpc': '2.0',
                'result': {
                    'content': result_content,
                    'isError': response.status == 'error'
                },
                'id': request_id
            })
        }
        
    except MCPProtocolError as e:
        duration_ms = int((time.time() - start_time) * 1000)
        
        log_structured(
            level='ERROR',
            message='MCP protocol error',
            operation='tool_invocation',
            error=str(e),
            error_code=e.error_code,
            request_id=request_id
        )
        
        return {
            'statusCode': 400,
            'body': json.dumps({
                'jsonrpc': '2.0',
                'error': {
                    'code': -32602,
                    'message': str(e)
                },
                'id': request_id
            })
        }
        
    except ToolExecutionError as e:
        duration_ms = int((time.time() - start_time) * 1000)
        
        log_structured(
            level='ERROR',
            message='Tool execution error',
            operation='tool_invocation',
            tool_name=params.get('name'),
            error=str(e),
            error_code=e.error_code,
            request_id=request_id
        )
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'jsonrpc': '2.0',
                'result': {
                    'content': [{
                        'type': 'text',
                        'text': json.dumps({'error': str(e)})
                    }],
                    'isError': True
                },
                'id': request_id
            })
        }
        
    except Exception as e:
        duration_ms = int((time.time() - start_time) * 1000)
        
        log_structured(
            level='ERROR',
            message='Unexpected error in tool execution',
            operation='tool_invocation',
            error=str(e),
            error_type=type(e).__name__,
            request_id=request_id
        )
        
        return {
            'statusCode': 500,
            'body': json.dumps({
                'jsonrpc': '2.0',
                'error': {
                    'code': -32603,
                    'message': 'Internal error during tool execution'
                },
                'id': request_id
            })
        }
