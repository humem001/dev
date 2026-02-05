"""AgentCore Memory service client wrapper."""

import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any
import boto3
from botocore.exceptions import ClientError, BotoCoreError
from botocore.config import Config

from models.conversation import ConversationMessage, ConversationSession
from config.timeout_config import TIMEOUT_CONFIG


# Custom exceptions for memory operations
class MemoryError(Exception):
    """Base exception for memory operations."""
    pass


class MemoryServiceUnavailableError(MemoryError):
    """Raised when AgentCore Memory service is unavailable."""
    pass


class SessionNotFoundError(MemoryError):
    """Raised when a session is not found."""
    pass


class StorageQuotaExceededError(MemoryError):
    """Raised when storage quota is exceeded."""
    pass


class MemoryTimeoutError(MemoryError):
    """Raised when a memory operation times out."""
    pass


class MemoryClient:
    """Client wrapper for AgentCore Memory service.
    
    Provides session management, message storage, and context retrieval
    with proper error handling and graceful degradation.
    """
    
    def __init__(
        self,
        memory_id: str,
        session_timeout_minutes: int = 60,
        max_context_messages: int = 10,
        max_context_tokens: int = 4000,
        region_name: Optional[str] = None,
        timeout_seconds: Optional[int] = None
    ):
        """Initialize Memory client.
        
        Args:
            memory_id: AgentCore Memory resource identifier
            session_timeout_minutes: Session expiration timeout in minutes
            max_context_messages: Maximum number of messages to retrieve
            max_context_tokens: Maximum token count for context
            region_name: AWS region name (defaults to environment default)
            timeout_seconds: Timeout for memory operations (defaults to TIMEOUT_CONFIG)
        """
        self.memory_id = memory_id
        self.session_timeout_minutes = session_timeout_minutes
        self.max_context_messages = max_context_messages
        self.max_context_tokens = max_context_tokens
        self.timeout_seconds = timeout_seconds or TIMEOUT_CONFIG.memory_operation
        
        # Initialize boto3 client for AgentCore Memory with timeout configuration
        # Note: Using bedrock-agent-runtime as AgentCore Memory is part of Bedrock
        try:
            # Configure boto3 client with timeout settings
            boto_config = Config(
                connect_timeout=self.timeout_seconds,
                read_timeout=self.timeout_seconds,
                retries={'max_attempts': 0}  # We handle retries at a higher level
            )
            
            self.client = boto3.client(
                'bedrock-agent-runtime',
                region_name=region_name,
                config=boto_config
            )
        except Exception as e:
            raise MemoryError(f"Failed to initialize Memory client: {str(e)}")
        
        # In-memory cache for sessions (for local testing/development)
        # In production, this would be replaced with actual AgentCore Memory API calls
        self._session_cache: Dict[str, ConversationSession] = {}
    
    def create_session(self, user_id: str) -> str:
        """Create a new conversation session with unique ID.
        
        Args:
            user_id: User identifier for session isolation
            
        Returns:
            Unique session identifier
            
        Raises:
            MemoryServiceUnavailableError: If service is unavailable
            StorageQuotaExceededError: If storage quota is exceeded
        """
        try:
            # Generate unique session ID
            session_id = str(uuid.uuid4())
            
            # Create new session
            session = ConversationSession(
                session_id=session_id,
                user_id=user_id
            )
            
            # Store in cache (in production, this would call AgentCore Memory API)
            self._session_cache[session_id] = session
            
            return session_id
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            
            if error_code == 'ServiceUnavailable':
                raise MemoryServiceUnavailableError(
                    "AgentCore Memory service is temporarily unavailable"
                )
            elif error_code == 'QuotaExceeded':
                raise StorageQuotaExceededError(
                    "Storage quota exceeded for user"
                )
            elif error_code == 'RequestTimeout':
                raise MemoryTimeoutError(
                    f"Memory operation timed out after {self.timeout_seconds}s"
                )
            else:
                raise MemoryError(f"Failed to create session: {str(e)}")
                
        except BotoCoreError as e:
            # Check if it's a timeout error
            if 'timed out' in str(e).lower() or 'timeout' in str(e).lower():
                raise MemoryTimeoutError(
                    f"Memory operation timed out after {self.timeout_seconds}s"
                )
            raise MemoryServiceUnavailableError(
                f"Network error connecting to Memory service: {str(e)}"
            )
        except Exception as e:
            raise MemoryError(f"Unexpected error creating session: {str(e)}")
    
    def store_message(
        self,
        session_id: str,
        role: str,
        content: str,
        tool_calls: Optional[List[Dict[str, Any]]] = None
    ) -> None:
        """Store a message in the conversation session.
        
        Args:
            session_id: Session identifier
            role: Message role ("user" or "assistant")
            content: Message content
            tool_calls: Optional list of tool call details
            
        Raises:
            SessionNotFoundError: If session doesn't exist
            MemoryServiceUnavailableError: If service is unavailable
            StorageQuotaExceededError: If storage quota is exceeded
        """
        try:
            # Retrieve session
            session = self._get_session(session_id)
            
            # Add message to session
            session.add_message(role, content, tool_calls)
            
            # Update session in cache (in production, this would call AgentCore Memory API)
            self._session_cache[session_id] = session
            
        except SessionNotFoundError:
            raise
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            
            if error_code == 'ServiceUnavailable':
                raise MemoryServiceUnavailableError(
                    "AgentCore Memory service is temporarily unavailable"
                )
            elif error_code == 'QuotaExceeded':
                raise StorageQuotaExceededError(
                    "Storage quota exceeded for session"
                )
            elif error_code == 'RequestTimeout':
                raise MemoryTimeoutError(
                    f"Memory operation timed out after {self.timeout_seconds}s"
                )
            else:
                raise MemoryError(f"Failed to store message: {str(e)}")
                
        except BotoCoreError as e:
            # Check if it's a timeout error
            if 'timed out' in str(e).lower() or 'timeout' in str(e).lower():
                raise MemoryTimeoutError(
                    f"Memory operation timed out after {self.timeout_seconds}s"
                )
            raise MemoryServiceUnavailableError(
                f"Network error connecting to Memory service: {str(e)}"
            )
        except Exception as e:
            raise MemoryError(f"Unexpected error storing message: {str(e)}")
    
    def retrieve_context(
        self,
        session_id: str,
        max_messages: Optional[int] = None
    ) -> List[ConversationMessage]:
        """Retrieve conversation context from session.
        
        Args:
            session_id: Session identifier
            max_messages: Maximum number of messages to retrieve (defaults to configured max)
            
        Returns:
            List of recent conversation messages
            
        Raises:
            SessionNotFoundError: If session doesn't exist
            MemoryServiceUnavailableError: If service is unavailable
        """
        try:
            # Retrieve session
            session = self._get_session(session_id)
            
            # Check if session is expired
            if self._is_session_expired(session):
                raise SessionNotFoundError(f"Session {session_id} has expired")
            
            # Get recent messages
            message_count = max_messages or self.max_context_messages
            messages = session.get_recent_messages(message_count)
            
            return messages
            
        except SessionNotFoundError:
            raise
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            
            if error_code == 'ServiceUnavailable':
                raise MemoryServiceUnavailableError(
                    "AgentCore Memory service is temporarily unavailable"
                )
            elif error_code == 'RequestTimeout':
                raise MemoryTimeoutError(
                    f"Memory operation timed out after {self.timeout_seconds}s"
                )
            else:
                raise MemoryError(f"Failed to retrieve context: {str(e)}")
                
        except BotoCoreError as e:
            # Check if it's a timeout error
            if 'timed out' in str(e).lower() or 'timeout' in str(e).lower():
                raise MemoryTimeoutError(
                    f"Memory operation timed out after {self.timeout_seconds}s"
                )
            raise MemoryServiceUnavailableError(
                f"Network error connecting to Memory service: {str(e)}"
            )
        except Exception as e:
            raise MemoryError(f"Unexpected error retrieving context: {str(e)}")
    
    def expire_session(self, session_id: str) -> None:
        """Mark a session as expired and remove from storage.
        
        Args:
            session_id: Session identifier
            
        Raises:
            SessionNotFoundError: If session doesn't exist
            MemoryServiceUnavailableError: If service is unavailable
        """
        try:
            # Check if session exists
            if session_id not in self._session_cache:
                raise SessionNotFoundError(f"Session {session_id} not found")
            
            # Remove session from cache (in production, this would call AgentCore Memory API)
            del self._session_cache[session_id]
            
        except SessionNotFoundError:
            raise
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            
            if error_code == 'ServiceUnavailable':
                raise MemoryServiceUnavailableError(
                    "AgentCore Memory service is temporarily unavailable"
                )
            elif error_code == 'RequestTimeout':
                raise MemoryTimeoutError(
                    f"Memory operation timed out after {self.timeout_seconds}s"
                )
            else:
                raise MemoryError(f"Failed to expire session: {str(e)}")
                
        except BotoCoreError as e:
            # Check if it's a timeout error
            if 'timed out' in str(e).lower() or 'timeout' in str(e).lower():
                raise MemoryTimeoutError(
                    f"Memory operation timed out after {self.timeout_seconds}s"
                )
            raise MemoryServiceUnavailableError(
                f"Network error connecting to Memory service: {str(e)}"
            )
        except Exception as e:
            raise MemoryError(f"Unexpected error expiring session: {str(e)}")
    
    def _get_session(self, session_id: str) -> ConversationSession:
        """Retrieve session from storage.
        
        Args:
            session_id: Session identifier
            
        Returns:
            ConversationSession object
            
        Raises:
            SessionNotFoundError: If session doesn't exist
        """
        if session_id not in self._session_cache:
            raise SessionNotFoundError(f"Session {session_id} not found")
        
        return self._session_cache[session_id]
    
    def _is_session_expired(self, session: ConversationSession) -> bool:
        """Check if a session has expired.
        
        Args:
            session: ConversationSession to check
            
        Returns:
            True if session is expired, False otherwise
        """
        now = datetime.now(timezone.utc)
        expiration_time = session.last_updated + timedelta(
            minutes=self.session_timeout_minutes
        )
        return now > expiration_time
