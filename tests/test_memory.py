"""Unit tests for AgentCore Memory integration."""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, patch
from botocore.exceptions import ClientError

from src.memory import (
    MemoryClient,
    MemoryError,
    MemoryServiceUnavailableError,
    SessionNotFoundError,
    StorageQuotaExceededError,
    handle_memory_error,
    should_degrade_gracefully,
    get_recovery_action,
    format_user_message
)
from src.models.conversation import ConversationMessage


class TestMemoryClient:
    """Test suite for MemoryClient."""
    
    @pytest.fixture
    def memory_client(self):
        """Create a MemoryClient instance for testing."""
        return MemoryClient(
            memory_id="test-memory-id",
            session_timeout_minutes=60,
            max_context_messages=10
        )
    
    def test_create_session_success(self, memory_client):
        """Test successful session creation."""
        user_id = "test-user-123"
        session_id = memory_client.create_session(user_id)
        
        assert session_id is not None
        assert isinstance(session_id, str)
        assert len(session_id) > 0
    
    def test_create_session_unique_ids(self, memory_client):
        """Test that session IDs are unique."""
        user_id = "test-user-123"
        session_id_1 = memory_client.create_session(user_id)
        session_id_2 = memory_client.create_session(user_id)
        
        assert session_id_1 != session_id_2
    
    def test_store_message_success(self, memory_client):
        """Test successful message storage."""
        user_id = "test-user-123"
        session_id = memory_client.create_session(user_id)
        
        # Store a user message
        memory_client.store_message(
            session_id=session_id,
            role="user",
            content="Hello, agent!"
        )
        
        # Retrieve and verify
        messages = memory_client.retrieve_context(session_id)
        assert len(messages) == 1
        assert messages[0].role == "user"
        assert messages[0].content == "Hello, agent!"
    
    def test_store_message_with_tool_calls(self, memory_client):
        """Test storing message with tool call information."""
        user_id = "test-user-123"
        session_id = memory_client.create_session(user_id)
        
        tool_calls = [
            {"tool_name": "list_s3_buckets", "status": "success"}
        ]
        
        memory_client.store_message(
            session_id=session_id,
            role="assistant",
            content="Here are your S3 buckets",
            tool_calls=tool_calls
        )
        
        messages = memory_client.retrieve_context(session_id)
        assert len(messages) == 1
        assert messages[0].tool_calls == tool_calls
    
    def test_store_message_session_not_found(self, memory_client):
        """Test storing message to non-existent session."""
        with pytest.raises(SessionNotFoundError):
            memory_client.store_message(
                session_id="non-existent-session",
                role="user",
                content="Test message"
            )
    
    def test_retrieve_context_success(self, memory_client):
        """Test successful context retrieval."""
        user_id = "test-user-123"
        session_id = memory_client.create_session(user_id)
        
        # Store multiple messages
        memory_client.store_message(session_id, "user", "Message 1")
        memory_client.store_message(session_id, "assistant", "Response 1")
        memory_client.store_message(session_id, "user", "Message 2")
        
        # Retrieve context
        messages = memory_client.retrieve_context(session_id)
        assert len(messages) == 3
        assert messages[0].content == "Message 1"
        assert messages[1].content == "Response 1"
        assert messages[2].content == "Message 2"
    
    def test_retrieve_context_with_limit(self, memory_client):
        """Test context retrieval with message limit."""
        user_id = "test-user-123"
        session_id = memory_client.create_session(user_id)
        
        # Store 5 messages
        for i in range(5):
            memory_client.store_message(session_id, "user", f"Message {i}")
        
        # Retrieve only 3 most recent
        messages = memory_client.retrieve_context(session_id, max_messages=3)
        assert len(messages) == 3
        assert messages[0].content == "Message 2"
        assert messages[2].content == "Message 4"
    
    def test_retrieve_context_session_not_found(self, memory_client):
        """Test retrieving context from non-existent session."""
        with pytest.raises(SessionNotFoundError):
            memory_client.retrieve_context("non-existent-session")
    
    def test_retrieve_context_expired_session(self, memory_client):
        """Test retrieving context from expired session."""
        # Create client with very short timeout
        short_timeout_client = MemoryClient(
            memory_id="test-memory-id",
            session_timeout_minutes=0  # Immediate expiration
        )
        
        user_id = "test-user-123"
        session_id = short_timeout_client.create_session(user_id)
        
        # Session should be expired immediately
        with pytest.raises(SessionNotFoundError, match="expired"):
            short_timeout_client.retrieve_context(session_id)
    
    def test_expire_session_success(self, memory_client):
        """Test successful session expiration."""
        user_id = "test-user-123"
        session_id = memory_client.create_session(user_id)
        
        # Expire the session
        memory_client.expire_session(session_id)
        
        # Session should no longer exist
        with pytest.raises(SessionNotFoundError):
            memory_client.retrieve_context(session_id)
    
    def test_expire_session_not_found(self, memory_client):
        """Test expiring non-existent session."""
        with pytest.raises(SessionNotFoundError):
            memory_client.expire_session("non-existent-session")
    
    def test_multi_tenant_isolation(self, memory_client):
        """Test that different users have isolated sessions."""
        user1_id = "user-1"
        user2_id = "user-2"
        
        session1 = memory_client.create_session(user1_id)
        session2 = memory_client.create_session(user2_id)
        
        # Store different messages in each session
        memory_client.store_message(session1, "user", "User 1 message")
        memory_client.store_message(session2, "user", "User 2 message")
        
        # Verify isolation
        messages1 = memory_client.retrieve_context(session1)
        messages2 = memory_client.retrieve_context(session2)
        
        assert len(messages1) == 1
        assert len(messages2) == 1
        assert messages1[0].content == "User 1 message"
        assert messages2[0].content == "User 2 message"


class TestErrorHandlers:
    """Test suite for error handling utilities."""
    
    def test_handle_memory_service_unavailable(self):
        """Test handling of service unavailable error."""
        error = MemoryServiceUnavailableError("Service down")
        result = handle_memory_error(error, "create_session")
        
        assert result['error_type'] == 'memory_unavailable'
        assert result['degraded_mode'] is True
        assert result['recovery_action'] == 'continue_without_memory'
        assert 'temporarily unavailable' in result['message'].lower()
    
    def test_handle_session_not_found(self):
        """Test handling of session not found error."""
        error = SessionNotFoundError("Session missing")
        result = handle_memory_error(error, "retrieve_context", "session-123")
        
        assert result['error_type'] == 'session_not_found'
        assert result['recovery_action'] == 'create_new_session'
        assert result['session_id'] == "session-123"
    
    def test_handle_storage_quota_exceeded(self):
        """Test handling of storage quota exceeded error."""
        error = StorageQuotaExceededError("Quota exceeded")
        result = handle_memory_error(error, "store_message")
        
        assert result['error_type'] == 'storage_quota_exceeded'
        assert result['recovery_action'] == 'trim_old_messages'
        assert 'storage limit' in result['message'].lower()
    
    def test_handle_generic_memory_error(self):
        """Test handling of generic memory error."""
        error = MemoryError("Generic error")
        result = handle_memory_error(error, "store_message")
        
        assert result['error_type'] == 'memory_error'
        assert result['degraded_mode'] is True
    
    def test_handle_unexpected_error(self):
        """Test handling of unexpected error."""
        error = ValueError("Unexpected error")
        result = handle_memory_error(error, "store_message")
        
        assert result['error_type'] == 'unexpected_error'
        assert result['degraded_mode'] is True
    
    def test_should_degrade_gracefully_true(self):
        """Test graceful degradation for appropriate errors."""
        assert should_degrade_gracefully(MemoryServiceUnavailableError())
        assert should_degrade_gracefully(SessionNotFoundError())
    
    def test_should_degrade_gracefully_false(self):
        """Test no graceful degradation for critical errors."""
        assert not should_degrade_gracefully(StorageQuotaExceededError())
        assert not should_degrade_gracefully(ValueError())
    
    def test_get_recovery_action(self):
        """Test recovery action determination."""
        assert get_recovery_action(MemoryServiceUnavailableError()) == 'continue_without_memory'
        assert get_recovery_action(SessionNotFoundError()) == 'create_new_session'
        assert get_recovery_action(StorageQuotaExceededError()) == 'trim_old_messages'
        assert get_recovery_action(ValueError()) == 'retry_or_continue'
    
    def test_format_user_message(self):
        """Test user-friendly message formatting."""
        msg1 = format_user_message(MemoryServiceUnavailableError(), "create_session")
        assert "continue" in msg1.lower()
        
        msg2 = format_user_message(SessionNotFoundError(), "retrieve_context")
        assert "new conversation" in msg2.lower()
        
        msg3 = format_user_message(StorageQuotaExceededError(), "store_message")
        assert "trimmed" in msg3.lower()
