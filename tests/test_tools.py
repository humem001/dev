"""Unit tests for MCP tools."""

import json
import pytest
from datetime import datetime
from unittest.mock import Mock, MagicMock
from botocore.exceptions import ClientError

from src.tools.mcp_tool_interface import (
    MCPToolDefinition,
    MCPToolRequest,
    MCPToolResponse,
    MCPTool
)
from src.tools.s3_list_buckets_tool import S3ListBucketsTool
from src.tools.tool_errors import (
    S3AccessDeniedError,
    S3ServiceUnavailableError,
    ToolTimeoutError,
    MCPProtocolError,
    handle_s3_error
)
from src.tools.lambda_handler import lambda_handler, parse_event, get_tool


class TestMCPToolInterface:
    """Test MCP tool interface and base classes."""
    
    def test_mcp_tool_definition_to_dict(self):
        """Test MCPToolDefinition serialization."""
        definition = MCPToolDefinition(
            name='test_tool',
            description='Test tool description',
            input_schema={'type': 'object', 'properties': {}}
        )
        
        result = definition.to_dict()
        
        assert result['name'] == 'test_tool'
        assert result['description'] == 'Test tool description'
        assert result['input_schema']['type'] == 'object'
    
    def test_mcp_tool_request_to_dict(self):
        """Test MCPToolRequest serialization."""
        request = MCPToolRequest(
            tool_name='test_tool',
            parameters={'key': 'value'},
            user_context={'user_id': 'user-123'},
            request_id='req-123'
        )
        
        result = request.to_dict()
        
        assert result['tool_name'] == 'test_tool'
        assert result['parameters']['key'] == 'value'
        assert result['user_context']['user_id'] == 'user-123'
        assert result['request_id'] == 'req-123'
    
    def test_mcp_tool_response_to_dict(self):
        """Test MCPToolResponse serialization."""
        response = MCPToolResponse(
            result={'data': 'test'},
            user_attribution={'user_id': 'user-123'},
            execution_time_ms=100,
            status='success'
        )
        
        result = response.to_dict()
        
        assert result['result']['data'] == 'test'
        assert result['user_attribution']['user_id'] == 'user-123'
        assert result['execution_time_ms'] == 100
        assert result['status'] == 'success'
        assert result['error_message'] is None


class TestS3ListBucketsTool:
    """Test S3 ListBuckets tool implementation."""
    
    def test_get_definition(self):
        """Test tool definition follows MCP protocol."""
        tool = S3ListBucketsTool()
        definition = tool.get_definition()
        
        assert definition.name == 'list_s3_buckets'
        assert 'S3 buckets' in definition.description
        assert definition.input_schema['type'] == 'object'
        assert definition.input_schema['required'] == []
    
    def test_execute_success(self):
        """Test successful S3 bucket listing."""
        # Mock S3 client
        mock_s3 = Mock()
        mock_s3.list_buckets.return_value = {
            'Buckets': [
                {'Name': 'bucket-1', 'CreationDate': datetime(2024, 1, 1)},
                {'Name': 'bucket-2', 'CreationDate': datetime(2024, 1, 2)}
            ]
        }
        
        tool = S3ListBucketsTool(s3_client=mock_s3)
        user_context = {'user_id': 'user-123', 'username': 'testuser'}
        
        result = tool.execute({}, user_context)
        
        assert result['count'] == 2
        assert len(result['buckets']) == 2
        assert result['buckets'][0]['name'] == 'bucket-1'
        assert result['buckets'][1]['name'] == 'bucket-2'
        assert result['user_id'] == 'user-123'
        assert '2024-01-01' in result['buckets'][0]['creation_date']
    
    def test_execute_access_denied(self):
        """Test S3 access denied error handling."""
        # Mock S3 client with access denied error
        mock_s3 = Mock()
        mock_s3.list_buckets.side_effect = ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'Access Denied'}},
            'ListBuckets'
        )
        
        tool = S3ListBucketsTool(s3_client=mock_s3)
        user_context = {'user_id': 'user-123'}
        
        with pytest.raises(S3AccessDeniedError) as exc_info:
            tool.execute({}, user_context)
        
        assert exc_info.value.status_code == 403
        assert 'permission' in exc_info.value.message.lower()
    
    def test_execute_service_unavailable(self):
        """Test S3 service unavailable error handling."""
        # Mock S3 client with service unavailable error
        mock_s3 = Mock()
        mock_s3.list_buckets.side_effect = ClientError(
            {'Error': {'Code': 'ServiceUnavailable', 'Message': 'Service Unavailable'}},
            'ListBuckets'
        )
        
        tool = S3ListBucketsTool(s3_client=mock_s3)
        user_context = {'user_id': 'user-123'}
        
        with pytest.raises(S3ServiceUnavailableError) as exc_info:
            tool.execute({}, user_context)
        
        assert exc_info.value.status_code == 503
        assert 'unavailable' in exc_info.value.message.lower()
    
    def test_invoke_with_attribution(self):
        """Test tool invocation includes user attribution."""
        # Mock S3 client
        mock_s3 = Mock()
        mock_s3.list_buckets.return_value = {
            'Buckets': [
                {'Name': 'test-bucket', 'CreationDate': datetime(2024, 1, 1)}
            ]
        }
        
        tool = S3ListBucketsTool(s3_client=mock_s3)
        request = MCPToolRequest(
            tool_name='list_s3_buckets',
            parameters={},
            user_context={'user_id': 'user-123', 'username': 'testuser'},
            request_id='req-123'
        )
        
        response = tool.invoke(request)
        
        assert response.status == 'success'
        assert response.user_attribution['user_id'] == 'user-123'
        assert response.user_attribution['operation'] == 'list_s3_buckets'
        assert response.execution_time_ms >= 0
        assert response.result['count'] == 1


class TestToolErrors:
    """Test tool error handling."""
    
    def test_s3_access_denied_error(self):
        """Test S3AccessDeniedError properties."""
        error = S3AccessDeniedError()
        
        assert error.status_code == 403
        assert error.error_code == 'permission_denied'
        assert 'permission' in error.message.lower()
    
    def test_s3_service_unavailable_error(self):
        """Test S3ServiceUnavailableError properties."""
        error = S3ServiceUnavailableError()
        
        assert error.status_code == 503
        assert error.error_code == 'service_unavailable'
        assert 'unavailable' in error.message.lower()
    
    def test_tool_timeout_error(self):
        """Test ToolTimeoutError properties."""
        error = ToolTimeoutError()
        
        assert error.status_code == 504
        assert error.error_code == 'gateway_timeout'
        assert 'timed out' in error.message.lower()
    
    def test_handle_s3_error_access_denied(self):
        """Test handle_s3_error converts AccessDenied correctly."""
        client_error = ClientError(
            {'Error': {'Code': 'AccessDenied', 'Message': 'Access Denied'}},
            'ListBuckets'
        )
        
        result = handle_s3_error(client_error)
        
        assert isinstance(result, S3AccessDeniedError)
        assert result.status_code == 403
    
    def test_handle_s3_error_service_unavailable(self):
        """Test handle_s3_error converts ServiceUnavailable correctly."""
        client_error = ClientError(
            {'Error': {'Code': 'ServiceUnavailable', 'Message': 'Service Unavailable'}},
            'ListBuckets'
        )
        
        result = handle_s3_error(client_error)
        
        assert isinstance(result, S3ServiceUnavailableError)
        assert result.status_code == 503


class TestLambdaHandler:
    """Test Lambda handler for MCP tool."""
    
    def test_parse_event_success(self):
        """Test successful event parsing."""
        event = {
            'tool_name': 'list_s3_buckets',
            'parameters': {},
            'user_context': {'user_id': 'user-123', 'username': 'testuser'},
            'request_id': 'req-123'
        }
        
        request = parse_event(event)
        
        assert request.tool_name == 'list_s3_buckets'
        assert request.user_context['user_id'] == 'user-123'
        assert request.request_id == 'req-123'
    
    def test_parse_event_missing_tool_name(self):
        """Test event parsing with missing tool_name."""
        event = {
            'parameters': {},
            'user_context': {'user_id': 'user-123'}
        }
        
        with pytest.raises(MCPProtocolError) as exc_info:
            parse_event(event)
        
        assert 'tool_name' in str(exc_info.value)
    
    def test_parse_event_missing_user_context(self):
        """Test event parsing with missing user_context."""
        event = {
            'tool_name': 'list_s3_buckets',
            'parameters': {}
        }
        
        with pytest.raises(MCPProtocolError) as exc_info:
            parse_event(event)
        
        assert 'user_context' in str(exc_info.value)
    
    def test_get_tool_success(self):
        """Test getting tool by name."""
        tool = get_tool('list_s3_buckets')
        
        assert isinstance(tool, S3ListBucketsTool)
    
    def test_get_tool_unknown(self):
        """Test getting unknown tool."""
        with pytest.raises(MCPProtocolError) as exc_info:
            get_tool('unknown_tool')
        
        assert 'Unknown tool' in str(exc_info.value)
    
    def test_lambda_handler_success(self):
        """Test successful Lambda handler execution."""
        # Mock S3 client
        mock_s3 = Mock()
        mock_s3.list_buckets.return_value = {
            'Buckets': [
                {'Name': 'test-bucket', 'CreationDate': datetime(2024, 1, 1)}
            ]
        }
        
        # Patch S3ListBucketsTool to use mock client
        import src.tools.lambda_handler as handler_module
        original_get_tool = handler_module.get_tool
        
        def mock_get_tool(tool_name):
            return S3ListBucketsTool(s3_client=mock_s3)
        
        handler_module.get_tool = mock_get_tool
        
        try:
            event = {
                'tool_name': 'list_s3_buckets',
                'parameters': {},
                'user_context': {'user_id': 'user-123', 'username': 'testuser'},
                'request_id': 'req-123'
            }
            
            response = lambda_handler(event, None)
            
            assert response['statusCode'] == 200
            body = json.loads(response['body'])
            assert body['status'] == 'success'
            assert body['result']['count'] == 1
            assert body['user_attribution']['user_id'] == 'user-123'
        finally:
            handler_module.get_tool = original_get_tool
    
    def test_lambda_handler_protocol_error(self):
        """Test Lambda handler with protocol error."""
        event = {
            'parameters': {},
            'user_context': {'user_id': 'user-123'}
        }
        
        response = lambda_handler(event, None)
        
        assert response['statusCode'] == 500
        body = json.loads(response['body'])
        assert body['error'] == 'protocol_error'
