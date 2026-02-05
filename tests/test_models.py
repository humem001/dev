"""Unit tests for core data models."""

from datetime import datetime
import pytest

from src.models import (
    UserContext,
    ConversationMessage,
    ConversationSession,
    MCPToolRequest,
    MCPToolResponse,
    AgentResponse,
    ToolExecution,
    AuditLogEntry,
)


class TestUserContext:
    """Tests for UserContext model."""
    
    def test_from_jwt_claims(self):
        """Test creating UserContext from JWT claims."""
        claims = {
            'sub': 'user-123',
            'cognito:username': 'john.doe',
            'client_id': 'client-456'
        }
        
        context = UserContext.from_jwt_claims(claims)
        
        assert context.user_id == 'user-123'
        assert context.username == 'john.doe'
        assert context.client_id == 'client-456'
    
    def test_to_dict(self):
        """Test converting UserContext to dictionary."""
        context = UserContext(
            user_id='user-123',
            username='john.doe',
            client_id='client-456'
        )
        
        result = context.to_dict()
        
        assert result == {
            'user_id': 'user-123',
            'username': 'john.doe',
            'client_id': 'client-456'
        }
    
    def test_from_dict(self):
        """Test creating UserContext from dictionary."""
        data = {
            'user_id': 'user-123',
            'username': 'john.doe',
            'client_id': 'client-456'
        }
        
        context = UserContext.from_dict(data)
        
        assert context.user_id == 'user-123'
        assert context.username == 'john.doe'
        assert context.client_id == 'client-456'


class TestConversationMessage:
    """Tests for ConversationMessage model."""
    
    def test_to_dict(self):
        """Test converting ConversationMessage to dictionary."""
        timestamp = datetime(2024, 1, 1, 12, 0, 0)
        message = ConversationMessage(
            role='user',
            content='Hello',
            timestamp=timestamp,
            tool_calls=None
        )
        
        result = message.to_dict()
        
        assert result['role'] == 'user'
        assert result['content'] == 'Hello'
        assert result['timestamp'] == timestamp.isoformat()
        assert result['tool_calls'] is None
    
    def test_from_dict(self):
        """Test creating ConversationMessage from dictionary."""
        data = {
            'role': 'assistant',
            'content': 'Hi there',
            'timestamp': '2024-01-01T12:00:00',
            'tool_calls': [{'tool': 'test'}]
        }
        
        message = ConversationMessage.from_dict(data)
        
        assert message.role == 'assistant'
        assert message.content == 'Hi there'
        assert message.timestamp == datetime(2024, 1, 1, 12, 0, 0)
        assert message.tool_calls == [{'tool': 'test'}]


class TestConversationSession:
    """Tests for ConversationSession model."""
    
    def test_add_message(self):
        """Test adding message to session."""
        session = ConversationSession(
            session_id='session-123',
            user_id='user-456'
        )
        
        session.add_message('user', 'Hello')
        
        assert len(session.messages) == 1
        assert session.messages[0].role == 'user'
        assert session.messages[0].content == 'Hello'
    
    def test_get_recent_messages(self):
        """Test retrieving recent messages."""
        session = ConversationSession(
            session_id='session-123',
            user_id='user-456'
        )
        
        for i in range(15):
            session.add_message('user', f'Message {i}')
        
        recent = session.get_recent_messages(count=5)
        
        assert len(recent) == 5
        assert recent[-1].content == 'Message 14'
    
    def test_to_dict(self):
        """Test converting ConversationSession to dictionary."""
        session = ConversationSession(
            session_id='session-123',
            user_id='user-456'
        )
        session.add_message('user', 'Hello')
        
        result = session.to_dict()
        
        assert result['session_id'] == 'session-123'
        assert result['user_id'] == 'user-456'
        assert result['message_count'] == 1
        assert len(result['messages']) == 1
    
    def test_from_dict(self):
        """Test creating ConversationSession from dictionary."""
        data = {
            'session_id': 'session-123',
            'user_id': 'user-456',
            'created_at': '2024-01-01T12:00:00',
            'last_updated': '2024-01-01T12:30:00',
            'messages': [
                {
                    'role': 'user',
                    'content': 'Hello',
                    'timestamp': '2024-01-01T12:00:00',
                    'tool_calls': None
                }
            ]
        }
        
        session = ConversationSession.from_dict(data)
        
        assert session.session_id == 'session-123'
        assert session.user_id == 'user-456'
        assert len(session.messages) == 1


class TestMCPToolRequest:
    """Tests for MCPToolRequest model."""
    
    def test_to_dict(self):
        """Test converting MCPToolRequest to dictionary."""
        user_context = UserContext('user-123', 'john.doe', 'client-456')
        request = MCPToolRequest(
            tool_name='list_s3_buckets',
            parameters={'region': 'us-east-1'},
            user_context=user_context,
            request_id='req-789'
        )
        
        result = request.to_dict()
        
        assert result['tool_name'] == 'list_s3_buckets'
        assert result['parameters'] == {'region': 'us-east-1'}
        assert result['request_id'] == 'req-789'
        assert result['user_context']['user_id'] == 'user-123'
    
    def test_from_dict(self):
        """Test creating MCPToolRequest from dictionary."""
        data = {
            'tool_name': 'list_s3_buckets',
            'parameters': {'region': 'us-east-1'},
            'user_context': {
                'user_id': 'user-123',
                'username': 'john.doe',
                'client_id': 'client-456'
            },
            'request_id': 'req-789'
        }
        
        request = MCPToolRequest.from_dict(data)
        
        assert request.tool_name == 'list_s3_buckets'
        assert request.parameters == {'region': 'us-east-1'}
        assert request.user_context.user_id == 'user-123'


class TestMCPToolResponse:
    """Tests for MCPToolResponse model."""
    
    def test_to_dict(self):
        """Test converting MCPToolResponse to dictionary."""
        response = MCPToolResponse(
            result={'buckets': ['bucket1', 'bucket2']},
            user_attribution={'user_id': 'user-123'},
            execution_time_ms=150,
            status='success',
            error_message=None
        )
        
        result = response.to_dict()
        
        assert result['status'] == 'success'
        assert result['execution_time_ms'] == 150
        assert result['error_message'] is None
    
    def test_from_dict(self):
        """Test creating MCPToolResponse from dictionary."""
        data = {
            'result': {'buckets': ['bucket1']},
            'user_attribution': {'user_id': 'user-123'},
            'execution_time_ms': 150,
            'status': 'success',
            'error_message': None
        }
        
        response = MCPToolResponse.from_dict(data)
        
        assert response.status == 'success'
        assert response.execution_time_ms == 150


class TestAgentResponse:
    """Tests for AgentResponse model."""
    
    def test_to_dict(self):
        """Test converting AgentResponse to dictionary."""
        user_context = UserContext('user-123', 'john.doe', 'client-456')
        tool_exec = ToolExecution(
            tool_name='list_s3_buckets',
            timestamp='2024-01-01T12:00:00',
            status='success',
            duration_ms=150
        )
        
        response = AgentResponse(
            response='Here are your buckets',
            session_id='session-123',
            user_context=user_context,
            tool_executions=[tool_exec],
            request_id='req-789'
        )
        
        result = response.to_dict()
        
        assert result['response'] == 'Here are your buckets'
        assert result['session_id'] == 'session-123'
        assert len(result['tool_executions']) == 1
    
    def test_from_dict(self):
        """Test creating AgentResponse from dictionary."""
        data = {
            'response': 'Here are your buckets',
            'session_id': 'session-123',
            'user_context': {
                'user_id': 'user-123',
                'username': 'john.doe',
                'client_id': 'client-456'
            },
            'tool_executions': [
                {
                    'tool_name': 'list_s3_buckets',
                    'timestamp': '2024-01-01T12:00:00',
                    'status': 'success',
                    'duration_ms': 150
                }
            ],
            'request_id': 'req-789'
        }
        
        response = AgentResponse.from_dict(data)
        
        assert response.response == 'Here are your buckets'
        assert len(response.tool_executions) == 1


class TestAuditLogEntry:
    """Tests for AuditLogEntry model."""
    
    def test_to_cloudwatch_format(self):
        """Test converting AuditLogEntry to CloudWatch format."""
        user_context = UserContext('user-123', 'john.doe', 'client-456')
        timestamp = datetime(2024, 1, 1, 12, 0, 0)
        
        log_entry = AuditLogEntry(
            timestamp=timestamp,
            request_id='req-789',
            component='agent',
            operation='process_prompt',
            user_context=user_context,
            status='success',
            duration_ms=200,
            error_message=None,
            metadata={'model': 'claude-3-sonnet'}
        )
        
        result = log_entry.to_cloudwatch_format()
        
        assert result['component'] == 'agent'
        assert result['user_id'] == 'user-123'
        assert result['username'] == 'john.doe'
        assert result['status'] == 'success'
        assert result['metadata']['model'] == 'claude-3-sonnet'
    
    def test_to_dict(self):
        """Test converting AuditLogEntry to dictionary."""
        user_context = UserContext('user-123', 'john.doe', 'client-456')
        timestamp = datetime(2024, 1, 1, 12, 0, 0)
        
        log_entry = AuditLogEntry(
            timestamp=timestamp,
            request_id='req-789',
            component='tool',
            operation='list_buckets',
            user_context=user_context,
            status='success'
        )
        
        result = log_entry.to_dict()
        
        assert result['component'] == 'tool'
        assert result['operation'] == 'list_buckets'
        assert 'user_context' in result
    
    def test_from_dict(self):
        """Test creating AuditLogEntry from dictionary."""
        data = {
            'timestamp': '2024-01-01T12:00:00',
            'request_id': 'req-789',
            'component': 'gateway',
            'operation': 'invoke_tool',
            'user_context': {
                'user_id': 'user-123',
                'username': 'john.doe',
                'client_id': 'client-456'
            },
            'status': 'success',
            'duration_ms': 100,
            'error_message': None,
            'metadata': None
        }
        
        log_entry = AuditLogEntry.from_dict(data)
        
        assert log_entry.component == 'gateway'
        assert log_entry.user_context.user_id == 'user-123'
