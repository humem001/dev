"""User context data model."""

from dataclasses import dataclass
from typing import Dict


@dataclass
class UserContext:
    """Complete user identity information extracted from JWT claims."""
    
    user_id: str        # Cognito sub claim (UUID)
    username: str       # Cognito username claim
    client_id: str      # Cognito client_id claim
    
    @classmethod
    def from_jwt_claims(cls, claims: Dict[str, str]) -> 'UserContext':
        """Extract user context from JWT claims.
        
        Handles missing or malformed claims gracefully by raising descriptive errors.
        
        Args:
            claims: Dictionary of JWT claims
            
        Returns:
            UserContext instance with extracted user information
            
        Raises:
            ValueError: If required claims are missing or malformed
        """
        # Validate claims is a dictionary
        if not isinstance(claims, dict):
            raise ValueError("Claims must be a dictionary")
        
        # Check for required claims
        # Note: Access tokens use 'username', ID tokens use 'cognito:username'
        required_claims = ['sub', 'client_id']
        missing_claims = [claim for claim in required_claims if claim not in claims]
        
        # Check for either 'username' or 'cognito:username'
        if 'username' not in claims and 'cognito:username' not in claims:
            missing_claims.append('cognito:username')
        
        if missing_claims:
            raise ValueError(
                f"Missing required JWT claims: {', '.join(missing_claims)}"
            )
        
        # Extract and validate claim values
        user_id = claims['sub']
        # Try 'cognito:username' first (ID token), fall back to 'username' (access token)
        username = claims.get('cognito:username') or claims.get('username')
        client_id = claims['client_id']
        
        # Validate claim values are non-empty strings
        if not isinstance(user_id, str) or not user_id.strip():
            raise ValueError("JWT claim 'sub' must be a non-empty string")
        
        if not isinstance(username, str) or not username.strip():
            raise ValueError("JWT claim 'username' or 'cognito:username' must be a non-empty string")
        
        if not isinstance(client_id, str) or not client_id.strip():
            raise ValueError("JWT claim 'client_id' must be a non-empty string")
        
        return cls(
            user_id=user_id.strip(),
            username=username.strip(),
            client_id=client_id.strip()
        )
    
    def to_dict(self) -> Dict[str, str]:
        """Convert to dictionary for logging/transmission.
        
        Returns:
            Dictionary representation of user context
        """
        return {
            'user_id': self.user_id,
            'username': self.username,
            'client_id': self.client_id
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> 'UserContext':
        """Create UserContext from dictionary.
        
        Args:
            data: Dictionary containing user context fields
            
        Returns:
            UserContext instance
        """
        return cls(
            user_id=data['user_id'],
            username=data['username'],
            client_id=data['client_id']
        )
