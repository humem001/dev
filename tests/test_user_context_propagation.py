"""Property-based and integration tests for user context propagation.

This module tests that user context is correctly preserved and propagated
through all service layers (Agent → Gateway → Tool).
"""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
from hypothesis import given, strategies as st, settings

from src.models.user_context import UserContext
from src.models.mcp_tool import MCPToolRequest, MCPToolResponse
from src.agent.agent_core import Agent, AgentConfig
from src.gateway.gateway_client import GatewayClient, GatewayConfig
from src.tools.s3_list_buckets_tool import S3ListBucketsTool
from src.tools.mcp_tool_interface import MCPToolRequest as ToolRequest


# ============================================================================
# Property-Based Tests
# ============================================================================

# Feature: serverless-ai-agent-system, Property 4: User Context Preservation
@given(
    user_id=st.text(min_size=1, max_size=100),
    username=st.text(min_size=1, max_size=100),
    client_id=st.text(min_size=1, max_size=100)
)
@settings(max_examples=100)
@pytest.mark.property_test
def test_property_user_context_preservation(user_id, username, client_id):
    """
    Property 4: User Context Preservation
    
    For any user context extracted from a JWT token, the context should remain
    identical (invariant) as it flows through Agent → Gateway → Tool layers.
    
    Validates: Requirements 3.2, 3.5
    """
    # Create original user context
    original_context = UserContext(
        user_id=user_id,
        username=username,
        client_id=client_id
    )
    
    # Test 1: UserContext serialization and deserialization preserves data
    context_dict = original_context.to_dict()
    restored_context = UserContext.from_dict(context_dict)
    
    assert restored_context.user_id == original_context.user_id
    assert restored_context.username == original_context.username
    assert restored_context.client_id == original_context.client_id
    
    # Test 2: MCPToolRequest preserves user context
    tool_request = MCPToolRequest(
        tool_name='test_tool',
        parameters={},
        user_context=original_context,
        request_id='test-req'
    )
    
    request_dict = tool_request.to_dict()
    restored_request = MCPToolRequest.from_dict(request_dict)
    
    assert restored_request.user_context.user_id == original_context.user_id
    assert restored_request.user_context.username == original_context.username
    assert restored_request.user_context.client_id == original_context.client_id
    
    # Test 3: Tool request format preserves user context
    tool_req = ToolRequest(
        tool_name='test_tool',
        parameters={},
        user_context=original_context.to_dict(),
        request_id='test-req'
    )
    
    assert tool_req.user_context['user_id'] == original_context.user_id
    assert tool_req.user_context['username'] == original_context.username
    assert tool_req.user_context['client_id'] == original_context.client_id


# ============================================================================
# Integration Tests
# ============================================================================

class TestEndToEndContextPropagation:
    """Integration tests for end-to-end user context propagation.
    
    Tests that user context flows correctly from Agent → Gateway → Tool
    and that the context is identical at all layers.
    
    Validates: Requirements 3.2, 3.3, 3.4, 3.5
    """
    
    @pytest.fixture
    def user_context(self):
        """Create test user context."""
        return UserContext(
            user_id='test-user-123',
            username='testuser',
            client_id='test-client-456'
        )
    
    @pytest.fixture
    def jwt_token(self):
        """Create test JWT token."""
        return 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.token'
    
    @pytest.fixture
    def agent_config(self):
        """Create test agent configuration."""
        return AgentConfig(
            bedrock_model_id='anthropic.claude-3-sonnet-20240229-v1:0',
            agentcore_gateway_url='https://test-gateway.example.com',
            agentcore_memory_id='test-memory-id',
            session_timeout_minutes=60,
            max_context_messages=10,
            max_context_tokens=4000,
            region_name='us-east-1'
        )
    
    @pytest.fixture
    def gateway_config(self):
        """Create test gateway configuration."""
        return GatewayConfig(
            gateway_url='https://test-gateway.example.com/invoke',
            timeout_seconds=15,
            max_retries=3,
            retry_delay_ms=100,
            backoff_multiplier=2.0
        )
    
    def test_context_flows_through_gateway_client(self, user_context, jwt_token, gateway_config):
        """Test that user context is correctly included in Gateway requests."""
        with patch('src.gateway.gateway_client.requests.Session') as mock_session_class:
            # Setup mock response
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                'tool_output': {
                    'result': {'test': 'data'},
                    'user_attribution': {
                        'user_id': user_context.user_id,
                        'operation': 'test_tool',
                        'timestamp': '2024-01-01T00:00:00'
                    },
                    'error_message': None
                },
                'execution_metadata': {
                    'duration_ms': 100,
                    'status': 'success'
                }
            }
            
            mock_session = Mock()
            mock_session.post.return_value = mock_response
            mock_session_class.return_value = mock_session
            
            # Create gateway client and invoke tool
            gateway = GatewayClient(gateway_config)
            response = gateway.invoke_tool(
                tool_name='test_tool',
                parameters={},
                user_context=user_context,
                jwt_token=jwt_token,
                request_id='test-req-123'
            )
            
            # Verify request was made with correct user context
            mock_session.post.assert_called_once()
            call_args = mock_session.post.call_args
            request_body = call_args[1]['json']  # Gateway uses json= parameter
            
            # Verify user context is in the request
            assert 'user_context' in request_body
            assert request_body['user_context']['user_id'] == user_context.user_id
            assert request_body['user_context']['username'] == user_context.username
            assert request_body['user_context']['client_id'] == user_context.client_id
            
            # Verify user context is in the response attribution
            assert response.user_attribution['user_id'] == user_context.user_id
    
    def test_context_flows_through_tool_execution(self, user_context):
        """Test that user context is correctly received and used by tools."""
        # Mock S3 client
        mock_s3 = Mock()
        mock_s3.list_buckets.return_value = {
            'Buckets': [
                {'Name': 'test-bucket', 'CreationDate': datetime(2024, 1, 1)}
            ]
        }
        
        # Create tool and execute with user context
        tool = S3ListBucketsTool(s3_client=mock_s3)
        tool_request = ToolRequest(
            tool_name='list_s3_buckets',
            parameters={},
            user_context=user_context.to_dict(),
            request_id='test-req-123'
        )
        
        response = tool.invoke(tool_request)
        
        # Verify user context is in the response attribution
        assert response.user_attribution['user_id'] == user_context.user_id
        assert response.user_attribution['operation'] == 'list_s3_buckets'
        
        # Verify result includes user_id
        assert response.result['user_id'] == user_context.user_id
    
    def test_context_identical_across_all_layers(self, user_context, jwt_token, gateway_config):
        """Test that user context remains identical across Agent → Gateway → Tool."""
        captured_contexts = []
        
        with patch('src.gateway.gateway_client.requests.Session') as mock_session_class:
            # Setup mock to capture the request
            def capture_request(*args, **kwargs):
                request_body = kwargs['json']  # Gateway uses json= parameter
                captured_contexts.append({
                    'layer': 'gateway_request',
                    'user_context': request_body['user_context']
                })
                
                # Return mock response
                mock_response = Mock()
                mock_response.status_code = 200
                mock_response.json.return_value = {
                    'tool_output': {
                        'result': {'user_id': user_context.user_id},
                        'user_attribution': {
                            'user_id': user_context.user_id,
                            'operation': 'test_tool',
                            'timestamp': '2024-01-01T00:00:00'
                        },
                        'error_message': None
                    },
                    'execution_metadata': {
                        'duration_ms': 100,
                        'status': 'success'
                    }
                }
                return mock_response
            
            mock_session = Mock()
            mock_session.post.side_effect = capture_request
            mock_session_class.return_value = mock_session
            
            # Invoke through gateway
            gateway = GatewayClient(gateway_config)
            response = gateway.invoke_tool(
                tool_name='test_tool',
                parameters={},
                user_context=user_context,
                jwt_token=jwt_token,
                request_id='test-req-123'
            )
            
            # Verify context was captured
            assert len(captured_contexts) == 1
            gateway_context = captured_contexts[0]['user_context']
            
            # Verify context is identical at gateway layer
            assert gateway_context['user_id'] == user_context.user_id
            assert gateway_context['username'] == user_context.username
            assert gateway_context['client_id'] == user_context.client_id
            
            # Verify context is identical in response
            assert response.user_attribution['user_id'] == user_context.user_id
    
    def test_context_preserved_through_serialization_cycles(self, user_context):
        """Test that user context survives multiple serialization/deserialization cycles."""
        # Cycle 1: UserContext → dict → UserContext
        dict1 = user_context.to_dict()
        context1 = UserContext.from_dict(dict1)
        
        assert context1.user_id == user_context.user_id
        assert context1.username == user_context.username
        assert context1.client_id == user_context.client_id
        
        # Cycle 2: UserContext → MCPToolRequest → dict → MCPToolRequest
        request1 = MCPToolRequest(
            tool_name='test_tool',
            parameters={},
            user_context=context1,
            request_id='test-req'
        )
        request_dict = request1.to_dict()
        request2 = MCPToolRequest.from_dict(request_dict)
        
        assert request2.user_context.user_id == user_context.user_id
        assert request2.user_context.username == user_context.username
        assert request2.user_context.client_id == user_context.client_id
        
        # Cycle 3: JSON serialization
        json_str = json.dumps(request_dict)
        parsed_dict = json.loads(json_str)
        request3 = MCPToolRequest.from_dict(parsed_dict)
        
        assert request3.user_context.user_id == user_context.user_id
        assert request3.user_context.username == user_context.username
        assert request3.user_context.client_id == user_context.client_id
    
    def test_context_not_modified_by_gateway(self, user_context, jwt_token, gateway_config):
        """Test that Gateway does not modify user context during processing."""
        original_dict = user_context.to_dict()
        
        with patch('src.gateway.gateway_client.requests.Session') as mock_session_class:
            # Setup mock response
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                'tool_output': {
                    'result': {},
                    'user_attribution': {'user_id': user_context.user_id},
                    'error_message': None
                },
                'execution_metadata': {
                    'duration_ms': 100,
                    'status': 'success'
                }
            }
            
            mock_session = Mock()
            mock_session.post.return_value = mock_response
            mock_session_class.return_value = mock_session
            
            # Invoke through gateway
            gateway = GatewayClient(gateway_config)
            gateway.invoke_tool(
                tool_name='test_tool',
                parameters={},
                user_context=user_context,
                jwt_token=jwt_token,
                request_id='test-req-123'
            )
            
            # Verify original context is unchanged
            assert user_context.to_dict() == original_dict
    
    def test_context_not_modified_by_tool(self, user_context):
        """Test that Tool does not modify user context during execution."""
        original_dict = user_context.to_dict()
        
        # Mock S3 client
        mock_s3 = Mock()
        mock_s3.list_buckets.return_value = {'Buckets': []}
        
        # Execute tool
        tool = S3ListBucketsTool(s3_client=mock_s3)
        tool_request = ToolRequest(
            tool_name='list_s3_buckets',
            parameters={},
            user_context=user_context.to_dict(),
            request_id='test-req-123'
        )
        
        tool.invoke(tool_request)
        
        # Verify original context is unchanged
        assert user_context.to_dict() == original_dict
    
    def test_multiple_tools_preserve_same_context(self, user_context):
        """Test that multiple tool invocations preserve the same user context."""
        # Mock S3 client
        mock_s3 = Mock()
        mock_s3.list_buckets.return_value = {'Buckets': []}
        
        # Execute tool multiple times
        tool = S3ListBucketsTool(s3_client=mock_s3)
        
        responses = []
        for i in range(3):
            tool_request = ToolRequest(
                tool_name='list_s3_buckets',
                parameters={},
                user_context=user_context.to_dict(),
                request_id=f'test-req-{i}'
            )
            response = tool.invoke(tool_request)
            responses.append(response)
        
        # Verify all responses have the same user context
        for response in responses:
            assert response.user_attribution['user_id'] == user_context.user_id
            assert response.result['user_id'] == user_context.user_id
    
    def test_context_with_special_characters(self):
        """Test that user context with special characters is preserved."""
        special_context = UserContext(
            user_id='user-123-!@#$%',
            username='test.user+tag@example.com',
            client_id='client-456-{special}'
        )
        
        # Serialize and deserialize
        context_dict = special_context.to_dict()
        json_str = json.dumps(context_dict)
        parsed_dict = json.loads(json_str)
        restored_context = UserContext.from_dict(parsed_dict)
        
        # Verify special characters are preserved
        assert restored_context.user_id == special_context.user_id
        assert restored_context.username == special_context.username
        assert restored_context.client_id == special_context.client_id
    
    def test_context_with_unicode_characters(self):
        """Test that user context with unicode characters is preserved."""
        unicode_context = UserContext(
            user_id='user-123-日本語',
            username='用户名-测试',
            client_id='client-456-العربية'
        )
        
        # Serialize and deserialize
        context_dict = unicode_context.to_dict()
        json_str = json.dumps(context_dict, ensure_ascii=False)
        parsed_dict = json.loads(json_str)
        restored_context = UserContext.from_dict(parsed_dict)
        
        # Verify unicode characters are preserved
        assert restored_context.user_id == unicode_context.user_id
        assert restored_context.username == unicode_context.username
        assert restored_context.client_id == unicode_context.client_id


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
