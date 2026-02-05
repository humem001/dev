"""Conversation data models."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any


@dataclass
class ConversationMessage:
    """Single message in a conversation."""
    
    role: str           # "user" or "assistant"
    content: str        # Message content
    timestamp: datetime
    tool_calls: Optional[List[Dict[str, Any]]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage/transmission.
        
        Returns:
            Dictionary representation of the message
        """
        return {
            'role': self.role,
            'content': self.content,
            'timestamp': self.timestamp.isoformat(),
            'tool_calls': self.tool_calls
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ConversationMessage':
        """Create ConversationMessage from dictionary.
        
        Args:
            data: Dictionary containing message fields
            
        Returns:
            ConversationMessage instance
        """
        return cls(
            role=data['role'],
            content=data['content'],
            timestamp=datetime.fromisoformat(data['timestamp']),
            tool_calls=data.get('tool_calls')
        )


@dataclass
class ConversationSession:
    """Conversation session with history."""
    
    session_id: str
    user_id: str
    messages: List[ConversationMessage] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def add_message(
        self, 
        role: str, 
        content: str, 
        tool_calls: Optional[List[Dict[str, Any]]] = None
    ) -> None:
        """Add message to conversation.
        
        Args:
            role: Message role ("user" or "assistant")
            content: Message content
            tool_calls: Optional list of tool call details
        """
        message = ConversationMessage(
            role=role,
            content=content,
            timestamp=datetime.now(timezone.utc),
            tool_calls=tool_calls
        )
        self.messages.append(message)
        self.last_updated = datetime.now(timezone.utc)
    
    def get_recent_messages(self, count: int = 10) -> List[ConversationMessage]:
        """Get most recent messages.
        
        Args:
            count: Number of recent messages to retrieve
            
        Returns:
            List of recent ConversationMessage objects
        """
        return self.messages[-count:]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage/transmission.
        
        Returns:
            Dictionary representation of the session
        """
        return {
            'session_id': self.session_id,
            'user_id': self.user_id,
            'messages': [m.to_dict() for m in self.messages],
            'created_at': self.created_at.isoformat(),
            'last_updated': self.last_updated.isoformat(),
            'message_count': len(self.messages)
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ConversationSession':
        """Create ConversationSession from dictionary.
        
        Args:
            data: Dictionary containing session fields
            
        Returns:
            ConversationSession instance
        """
        session = cls(
            session_id=data['session_id'],
            user_id=data['user_id'],
            created_at=datetime.fromisoformat(data['created_at']),
            last_updated=datetime.fromisoformat(data['last_updated'])
        )
        session.messages = [
            ConversationMessage.from_dict(msg) 
            for msg in data.get('messages', [])
        ]
        return session
