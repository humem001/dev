"""Unit tests for Agent implementation."""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from src.agent.agent_core import Agent, AgentConfig
from src.agent.exceptions import (
    AgentError,
    BedrockError,
    BedrockThrottlingError,
    BedrockModelUnavailableError
)
from src.agent.error_handlers import handle_agent_error, format_error_response
from src.agent.lambda_handler import lambda_handler, _parse_event
from src.models.user_context import UserContext
from src.models.conversation import ConversationMessage
from src.models.agent_response import AgentResponse, ToolExecution


@pytest.fixture
def agent_config():
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
def user_context():
    """Create test user context."""
    return UserContext(
        user_id='test-user-123',
        username='testuser',
        client_id='test-client-id'
    )


@pytest.fixture
def mock_bedrock_client():
    """Create mock Bedrock client."""
    mock_client = Mock()
    mock_response = {
        'body': Mock(read=lambda: json.dumps({
            'content': [{'type': 'text', 'text': 'Test response'}]
        }).encode())
    }
    mock_client.invoke_model.return_value = mock_response
    return mock_client


@pytest.fixture
def mock_memory_client():
    """Create mock Memory client."""
    mock_client = Mock()
    mock_client.create_session.return_value = 'test-session-123'
    mock_client.retrieve_context.return_value = []
    mock_client.store_message.return_value = None
    return mock_client


@pytest.fixture
def mock_gateway_client():
    """Create mock Gateway client."""
    mock_client = Mock()
    return mock_client


class TestAgentCore:
    """Tests for Agent core functionality."""
    
    def test_agent_initialization(self, agent_config):
        """Test agent initializes correctly."""
        with patch('boto3.client'):
            agent = Agent(agent_config)
            assert agent.config == agent_config
    
    def test_process_prompt_simple_response(
        self,
        agent_config,
        user_context,
        mock_bedrock_client,
        mock_memory_client,
        mock_gateway_client
    ):
        """Test processing prompt with simple response (no tools)."""
        with patch('boto3.client', return_value=mock_bedrock_client):
            agent = Agent(agent_config)
            agent.memory_client = mock_memory_client
            agent.gateway_client = mock_gateway_client
            
            response = agent.process_prompt(
                prompt='Hello, how are you?',
                user_context=user_context,
                jwt_token='test-token',
                request_id='test-request-123'
            )
            
            assert isinstance(response, AgentResponse)
            assert response.response == 'Test response'
            assert response.user_context == user_context
            assert response.request_id == 'test-request-123'
            assert len(response.tool_executions) == 0
    
    def test_create_session(self, agent_config, user_context, mock_memory_client):
        """Test session creation."""
        with patch('boto3.client'):
            agent = Agent(agent_config)
            agent.memory_client = mock_memory_client
            
            session_id = agent._create_session(user_context)
            
            assert session_id == 'test-session-123'
            mock_memory_client.create_session.assert_called_once_with(user_context.user_id)
    
    def test_retrieve_context(self, agent_config, mock_memory_client):
        """Test context retrieval."""
        with patch('boto3.client'):
            agent = Agent(agent_config)
            agent.memory_client = mock_memory_client
            
            messages = agent._retrieve_context('test-session-123')
            
            assert messages == []
            mock_memory_client.retrieve_context.assert_called_once_with('test-session-123')
    
    def test_build_bedrock_messages(self, agent_config):
        """Test building Bedrock messages."""
        with patch('boto3.client'):
            agent = Agent(agent_config)
            
            context_messages = [
                ConversationMessage(
                    role='user',
                    content='Previous message',
                    timestamp=datetime.utcnow()
                )
            ]
            
            messages = agent._build_bedrock_messages('Current prompt', context_messages)
            
            assert len(messages) == 2
            assert messages[0]['role'] == 'user'
            assert messages[0]['content'][0]['text'] == 'Previous message'
            assert messages[1]['role'] == 'user'
            assert messages[1]['content'][0]['text'] == 'Current prompt'
    
    def test_extract_response_text(self, agent_config):
        """Test extracting response text from Bedrock response."""
        with patch('boto3.client'):
            agent = Agent(agent_config)
            
            bedrock_response = {
                'content': [
                    {'type': 'text', 'text': 'Test response text'}
                ]
            }
            
            text = agent._extract_response_text(bedrock_response)
            
            assert text == 'Test response text'
    
    def test_format_tool_result_fallback(self, agent_config):
        """Test formatting tool result as fallback."""
        with patch('boto3.client'):
            agent = Agent(agent_config)
            
            tool_result = {'buckets': ['bucket1', 'bucket2']}
            
            response = agent._format_tool_result_fallback('list_s3_buckets', tool_result)
            
            assert 'list_s3_buckets' in response
            assert 'bucket1' in response


class TestErrorHandlers:
    """Tests for error handling."""
    
    def test_handle_bedrock_throttling_error(self):
        """Test handling Bedrock throttling error."""
        error = BedrockThrottlingError("Rate limit exceeded")
        
        result = handle_agent_error(error)
        
        assert result['error'] == 'rate_limit_exceeded'
        assert result['status_code'] == 429
        assert 'retry_after' in result
    
    def test_handle_bedrock_model_unavailable_error(self):
        """Test handling Bedrock model unavailable error."""
        error = BedrockModelUnavailableError("Model unavailable")
        
        result = handle_agent_error(error)
        
        assert result['error'] == 'service_unavailable'
        assert result['status_code'] == 503
    
    def test_handle_generic_bedrock_error(self):
        """Test handling generic Bedrock error."""
        error = BedrockError("Processing failed")
        
        result = handle_agent_error(error)
        
        assert result['error'] == 'processing_failed'
        assert result['status_code'] == 500
    
    def test_format_error_response(self):
        """Test formatting error response."""
        error_dict = {
            'error': 'test_error',
            'message': 'Test error message',
            'status_code': 500
        }
        
        response = format_error_response(error_dict, 'test-request-123')
        
        assert response['error'] == 'test_error'
        assert response['message'] == 'Test error message'
        assert response['request_id'] == 'test-request-123'
        assert 'timestamp' in response


class TestLambdaHandler:
    """Tests for Lambda handler."""
    
    def test_parse_event_valid(self):
        """Test parsing valid event."""
        event = {
            'prompt': 'Test prompt',
            'jwt_token': 'test-token',
            'session_id': 'test-session'
        }
        
        prompt, jwt_token, session_id = _parse_event(event)
        
        assert prompt == 'Test prompt'
        assert jwt_token == 'test-token'
        assert session_id == 'test-session'
    
    def test_parse_event_missing_prompt(self):
        """Test parsing event with missing prompt."""
        event = {
            'jwt_token': 'test-token'
        }
        
        with pytest.raises(ValueError, match="Missing or invalid 'prompt' field"):
            _parse_event(event)
    
    def test_parse_event_missing_jwt_token(self):
        """Test parsing event with missing JWT token."""
        event = {
            'prompt': 'Test prompt'
        }
        
        with pytest.raises(ValueError, match="Missing or invalid 'jwt_token' field"):
            _parse_event(event)
    
    def test_parse_event_optional_session_id(self):
        """Test parsing event with optional session_id."""
        event = {
            'prompt': 'Test prompt',
            'jwt_token': 'test-token'
        }
        
        prompt, jwt_token, session_id = _parse_event(event)
        
        assert prompt == 'Test prompt'
        assert jwt_token == 'test-token'
        assert session_id is None
    
    @patch.dict('os.environ', {
        'COGNITO_JWKS_URL': 'https://test-jwks.example.com',
        'BEDROCK_MODEL_ID': 'test-model',
        'AGENTCORE_GATEWAY_URL': 'https://test-gateway.example.com',
        'AGENTCORE_MEMORY_ID': 'test-memory-id'
    })
    def test_lambda_handler_missing_configuration(self):
        """Test Lambda handler with missing configuration."""
        event = {
            'prompt': 'Test prompt',
            'jwt_token': 'test-token'
        }
        context = Mock(request_id='test-request-123')
        
        # Clear global variables to simulate missing config
        import src.agent.lambda_handler as handler_module
        handler_module.jwt_validator = None
        handler_module.agent = None
        
        response = lambda_handler(event, context)
        
        assert response['statusCode'] == 500
        body = json.loads(response['body'])
        assert body['error'] == 'configuration_error'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
