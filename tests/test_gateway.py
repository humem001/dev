"""Unit tests for AgentCore Gateway client."""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
import requests

from src.gateway.gateway_client import (
    GatewayClient,
    GatewayConfig,
    GatewayError,
    GatewayTimeoutError,
    GatewayAuthenticationError,
    GatewayServiceUnavailableError,
    MCPProtocolError
)
from src.models.user_context import UserContext
from src.models.mcp_tool import MCPToolResponse


@pytest.fixture
def gateway_config():
    """Create test Gateway configuration."""
    return GatewayConfig(
        gateway_url="https://test-gateway.example.com/invoke",
        timeout_seconds=15,
        max_retries=3,
        retry_delay_ms=100,
        backoff_multiplier=2.0
    )


@pytest.fixture
def user_context():
    """Create test user context."""
    return UserContext(
        user_id="test-user-123",
        username="testuser",
        client_id="test-client-456"
    )


@pytest.fixture
def jwt_token():
    """Create test JWT token."""
    return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.token"


class TestGatewayClient:
    """Test suite for GatewayClient."""
    
    def test_format_mcp_request(self, gateway_config, user_context):
        """Test MCP request formatting."""
        client = GatewayClient(gateway_config)
        
        mcp_request = client._format_mcp_request(
            tool_name="list_s3_buckets",
            parameters={"region": "us-east-1"},
            user_context=user_context,
            request_id="req-123"
        )
        
        assert mcp_request['tool_name'] == "list_s3_buckets"
        assert mcp_request['tool_input'] == {"region": "us-east-1"}
        assert mcp_request['user_context'] == user_context.to_dict()
        assert mcp_request['request_id'] == "req-123"
    
    def test_format_mcp_request_error(self, gateway_config):
        """Test MCP request formatting with invalid data."""
        client = GatewayClient(gateway_config)
        
        # Create invalid user context that will fail to_dict()
        invalid_context = Mock()
        invalid_context.to_dict.side_effect = Exception("Serialization error")
        
        with pytest.raises(MCPProtocolError) as exc_info:
            client._format_mcp_request(
                tool_name="test_tool",
                parameters={},
                user_context=invalid_context,
                request_id="req-123"
            )
        
        assert "Failed to format MCP request" in str(exc_info.value)
    
    @patch('src.gateway.gateway_client.requests.Session')
    def test_invoke_tool_success(self, mock_session_class, gateway_config, user_context, jwt_token):
        """Test successful tool invocation through Gateway."""
        # Setup mock response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'tool_output': {
                'result': {'buckets': ['bucket1', 'bucket2']},
                'user_attribution': {
                    'user_id': 'test-user-123',
                    'operation': 'list_s3_buckets',
                    'timestamp': '2024-01-01T00:00:00'
                },
                'error_message': None
            },
            'execution_metadata': {
                'duration_ms': 150,
                'status': 'success'
            }
        }
        
        mock_session = Mock()
        mock_session.post.return_value = mock_response
        mock_session_class.return_value = mock_session
        
        # Create client and invoke tool
        client = GatewayClient(gateway_config)
        response = client.invoke_tool(
            tool_name="list_s3_buckets",
            parameters={},
            user_context=user_context,
            jwt_token=jwt_token,
            request_id="req-123"
        )
        
        # Verify response
        assert isinstance(response, MCPToolResponse)
        assert response.status == 'success'
        assert response.result == {'buckets': ['bucket1', 'bucket2']}
        assert response.execution_time_ms == 150
        assert response.user_attribution['user_id'] == 'test-user-123'
        
        # Verify request was made correctly
        mock_session.post.assert_called_once()
        call_args = mock_session.post.call_args
        assert call_args[0][0] == gateway_config.gateway_url
        assert call_args[1]['headers']['Authorization'] == f'Bearer {jwt_token}'
        assert call_args[1]['headers']['Content-Type'] == 'application/json'
    
    @patch('src.gateway.gateway_client.requests.Session')
    def test_invoke_tool_authentication_error(self, mock_session_class, gateway_config, user_context, jwt_token):
        """Test Gateway authentication error handling."""
        mock_response = Mock()
        mock_response.status_code = 401
        
        mock_session = Mock()
        mock_session.post.return_value = mock_response
        mock_session_class.return_value = mock_session
        
        client = GatewayClient(gateway_config)
        
        with pytest.raises(GatewayAuthenticationError) as exc_info:
            client.invoke_tool(
                tool_name="list_s3_buckets",
                parameters={},
                user_context=user_context,
                jwt_token=jwt_token,
                request_id="req-123"
            )
        
        assert "authentication failed" in str(exc_info.value).lower()
    
    @patch('src.gateway.gateway_client.requests.Session')
    def test_invoke_tool_timeout(self, mock_session_class, gateway_config, user_context, jwt_token):
        """Test Gateway timeout handling."""
        mock_session = Mock()
        mock_session.post.side_effect = requests.exceptions.Timeout()
        mock_session_class.return_value = mock_session
        
        client = GatewayClient(gateway_config)
        
        with pytest.raises(GatewayTimeoutError) as exc_info:
            client.invoke_tool(
                tool_name="list_s3_buckets",
                parameters={},
                user_context=user_context,
                jwt_token=jwt_token,
                request_id="req-123"
            )
        
        assert "timed out" in str(exc_info.value).lower()
    
    @patch('src.gateway.gateway_client.requests.Session')
    def test_invoke_tool_service_unavailable(self, mock_session_class, gateway_config, user_context, jwt_token):
        """Test Gateway service unavailable handling."""
        mock_response = Mock()
        mock_response.status_code = 503
        
        mock_session = Mock()
        mock_session.post.return_value = mock_response
        mock_session_class.return_value = mock_session
        
        client = GatewayClient(gateway_config)
        
        with pytest.raises(GatewayServiceUnavailableError) as exc_info:
            client.invoke_tool(
                tool_name="list_s3_buckets",
                parameters={},
                user_context=user_context,
                jwt_token=jwt_token,
                request_id="req-123"
            )
        
        assert "unavailable" in str(exc_info.value).lower()
    
    @patch('src.gateway.gateway_client.requests.Session')
    def test_invoke_tool_connection_error(self, mock_session_class, gateway_config, user_context, jwt_token):
        """Test Gateway connection error handling."""
        mock_session = Mock()
        mock_session.post.side_effect = requests.exceptions.ConnectionError("Connection refused")
        mock_session_class.return_value = mock_session
        
        client = GatewayClient(gateway_config)
        
        with pytest.raises(GatewayServiceUnavailableError) as exc_info:
            client.invoke_tool(
                tool_name="list_s3_buckets",
                parameters={},
                user_context=user_context,
                jwt_token=jwt_token,
                request_id="req-123"
            )
        
        assert "Failed to connect" in str(exc_info.value)
    
    @patch('src.gateway.gateway_client.requests.Session')
    @patch('src.gateway.gateway_client.time.sleep')
    def test_retry_logic_with_exponential_backoff(
        self, mock_sleep, mock_session_class, gateway_config, user_context, jwt_token
    ):
        """Test retry logic with exponential backoff for transient failures."""
        # First two attempts fail with timeout, third succeeds
        mock_response_success = Mock()
        mock_response_success.status_code = 200
        mock_response_success.json.return_value = {
            'tool_output': {
                'result': {'success': True},
                'user_attribution': {'user_id': 'test-user-123'},
                'error_message': None
            },
            'execution_metadata': {
                'duration_ms': 100,
                'status': 'success'
            }
        }
        
        mock_session = Mock()
        mock_session.post.side_effect = [
            requests.exceptions.Timeout(),  # First attempt fails
            requests.exceptions.Timeout(),  # Second attempt fails
            mock_response_success            # Third attempt succeeds
        ]
        mock_session_class.return_value = mock_session
        
        client = GatewayClient(gateway_config)
        response = client.invoke_tool(
            tool_name="list_s3_buckets",
            parameters={},
            user_context=user_context,
            jwt_token=jwt_token,
            request_id="req-123"
        )
        
        # Verify success after retries
        assert response.status == 'success'
        
        # Verify exponential backoff delays
        assert mock_sleep.call_count == 2
        # First retry: 100ms
        assert mock_sleep.call_args_list[0][0][0] == 0.1
        # Second retry: 200ms (100 * 2.0)
        assert mock_sleep.call_args_list[1][0][0] == 0.2
    
    @patch('src.gateway.gateway_client.requests.Session')
    def test_retry_exhausted(self, mock_session_class, gateway_config, user_context, jwt_token):
        """Test that retries are exhausted and error is raised."""
        mock_session = Mock()
        mock_session.post.side_effect = requests.exceptions.Timeout()
        mock_session_class.return_value = mock_session
        
        client = GatewayClient(gateway_config)
        
        with pytest.raises(GatewayTimeoutError):
            client.invoke_tool(
                tool_name="list_s3_buckets",
                parameters={},
                user_context=user_context,
                jwt_token=jwt_token,
                request_id="req-123"
            )
        
        # Verify all retries were attempted
        assert mock_session.post.call_count == gateway_config.max_retries
    
    @patch('src.gateway.gateway_client.requests.Session')
    def test_no_retry_on_authentication_error(self, mock_session_class, gateway_config, user_context, jwt_token):
        """Test that authentication errors are not retried."""
        mock_response = Mock()
        mock_response.status_code = 401
        
        mock_session = Mock()
        mock_session.post.return_value = mock_response
        mock_session_class.return_value = mock_session
        
        client = GatewayClient(gateway_config)
        
        with pytest.raises(GatewayAuthenticationError):
            client.invoke_tool(
                tool_name="list_s3_buckets",
                parameters={},
                user_context=user_context,
                jwt_token=jwt_token,
                request_id="req-123"
            )
        
        # Verify only one attempt was made (no retries)
        assert mock_session.post.call_count == 1
    
    def test_parse_response_success(self, gateway_config):
        """Test parsing successful Gateway response."""
        client = GatewayClient(gateway_config)
        
        response_data = {
            'tool_output': {
                'result': {'data': 'test'},
                'user_attribution': {'user_id': 'user-123'},
                'error_message': None
            },
            'execution_metadata': {
                'duration_ms': 200,
                'status': 'success'
            }
        }
        
        parsed = client._parse_response(response_data)
        
        assert parsed.result == {'data': 'test'}
        assert parsed.user_attribution == {'user_id': 'user-123'}
        assert parsed.execution_time_ms == 200
        assert parsed.status == 'success'
        assert parsed.error_message is None
    
    def test_parse_response_with_error(self, gateway_config):
        """Test parsing Gateway response with error."""
        client = GatewayClient(gateway_config)
        
        response_data = {
            'tool_output': {
                'result': {},
                'user_attribution': {'user_id': 'user-123'},
                'error_message': 'Tool execution failed'
            },
            'execution_metadata': {
                'duration_ms': 50,
                'status': 'error'
            }
        }
        
        parsed = client._parse_response(response_data)
        
        assert parsed.status == 'error'
        assert parsed.error_message == 'Tool execution failed'
    
    def test_parse_response_invalid_format(self, gateway_config):
        """Test parsing invalid Gateway response."""
        client = GatewayClient(gateway_config)
        
        # Missing required fields
        invalid_response = {'invalid': 'data'}
        
        with pytest.raises(MCPProtocolError) as exc_info:
            client._parse_response(invalid_response)
        
        assert "Failed to parse Gateway response" in str(exc_info.value)
    
    def test_context_manager(self, gateway_config):
        """Test Gateway client as context manager."""
        with GatewayClient(gateway_config) as client:
            assert client.session is not None
        
        # Session should be closed after context exit
        # Note: We can't easily verify this without accessing internal state
    
    def test_close(self, gateway_config):
        """Test explicit close of Gateway client."""
        client = GatewayClient(gateway_config)
        assert client.session is not None
        
        client.close()
        # Session close should have been called
    
    @patch('src.gateway.gateway_client.requests.Session')
    def test_retry_on_503_service_unavailable(self, mock_session_class, gateway_config, user_context, jwt_token):
        """Test retry logic for 503 Service Unavailable responses."""
        # First attempt returns 503, second succeeds
        mock_response_503 = Mock()
        mock_response_503.status_code = 503
        
        mock_response_success = Mock()
        mock_response_success.status_code = 200
        mock_response_success.json.return_value = {
            'tool_output': {
                'result': {'success': True},
                'user_attribution': {'user_id': 'test-user-123'},
                'error_message': None
            },
            'execution_metadata': {
                'duration_ms': 100,
                'status': 'success'
            }
        }
        
        mock_session = Mock()
        mock_session.post.side_effect = [mock_response_503, mock_response_success]
        mock_session_class.return_value = mock_session
        
        client = GatewayClient(gateway_config)
        response = client.invoke_tool(
            tool_name="list_s3_buckets",
            parameters={},
            user_context=user_context,
            jwt_token=jwt_token,
            request_id="req-123"
        )
        
        # Verify success after retry
        assert response.status == 'success'
        assert mock_session.post.call_count == 2
    
    @patch('src.gateway.gateway_client.requests.Session')
    def test_retry_on_504_gateway_timeout(self, mock_session_class, gateway_config, user_context, jwt_token):
        """Test retry logic for 504 Gateway Timeout responses."""
        # First attempt returns 504, second succeeds
        mock_response_504 = Mock()
        mock_response_504.status_code = 504
        
        mock_response_success = Mock()
        mock_response_success.status_code = 200
        mock_response_success.json.return_value = {
            'tool_output': {
                'result': {'success': True},
                'user_attribution': {'user_id': 'test-user-123'},
                'error_message': None
            },
            'execution_metadata': {
                'duration_ms': 100,
                'status': 'success'
            }
        }
        
        mock_session = Mock()
        mock_session.post.side_effect = [mock_response_504, mock_response_success]
        mock_session_class.return_value = mock_session
        
        client = GatewayClient(gateway_config)
        response = client.invoke_tool(
            tool_name="list_s3_buckets",
            parameters={},
            user_context=user_context,
            jwt_token=jwt_token,
            request_id="req-123"
        )
        
        # Verify success after retry
        assert response.status == 'success'
        assert mock_session.post.call_count == 2
    
    @patch('src.gateway.gateway_client.requests.Session')
    def test_no_retry_on_400_bad_request(self, mock_session_class, gateway_config, user_context, jwt_token):
        """Test that 400 Bad Request errors are not retried."""
        mock_response = Mock()
        mock_response.status_code = 400
        mock_response.json.return_value = {'message': 'Bad request'}
        
        mock_session = Mock()
        mock_session.post.return_value = mock_response
        mock_session_class.return_value = mock_session
        
        client = GatewayClient(gateway_config)
        
        with pytest.raises(GatewayError) as exc_info:
            client.invoke_tool(
                tool_name="list_s3_buckets",
                parameters={},
                user_context=user_context,
                jwt_token=jwt_token,
                request_id="req-123"
            )
        
        # Verify only one attempt was made (no retries)
        assert mock_session.post.call_count == 1
        assert "400" in str(exc_info.value)
    
    @patch('src.gateway.gateway_client.requests.Session')
    @patch('src.gateway.gateway_client.time.sleep')
    def test_exponential_backoff_calculation(
        self, mock_sleep, mock_session_class, gateway_config, user_context, jwt_token
    ):
        """Test that exponential backoff delays are calculated correctly."""
        # Configure custom backoff settings
        custom_config = GatewayConfig(
            gateway_url="https://test-gateway.example.com/invoke",
            timeout_seconds=15,
            max_retries=4,
            retry_delay_ms=50,
            backoff_multiplier=3.0
        )
        
        # All attempts fail with timeout
        mock_session = Mock()
        mock_session.post.side_effect = requests.exceptions.Timeout()
        mock_session_class.return_value = mock_session
        
        client = GatewayClient(custom_config)
        
        with pytest.raises(GatewayTimeoutError):
            client.invoke_tool(
                tool_name="list_s3_buckets",
                parameters={},
                user_context=user_context,
                jwt_token=jwt_token,
                request_id="req-123"
            )
        
        # Verify exponential backoff delays
        assert mock_sleep.call_count == 3  # max_retries - 1
        # First retry: 50ms
        assert mock_sleep.call_args_list[0][0][0] == 0.05
        # Second retry: 150ms (50 * 3.0)
        assert mock_sleep.call_args_list[1][0][0] == 0.15
        # Third retry: 450ms (150 * 3.0)
        assert mock_sleep.call_args_list[2][0][0] == 0.45
