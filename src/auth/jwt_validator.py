"""JWT validation module with JWKS retrieval and token verification."""

import time
from typing import Dict, Optional
from urllib.request import urlopen
import json
import socket

from jose import jwt, JWTError
from jose.exceptions import JWTClaimsError, ExpiredSignatureError

from config.timeout_config import TIMEOUT_CONFIG


class JWTValidationError(Exception):
    """Base exception for JWT validation errors."""
    pass


class JWTValidator:
    """Validates JWT tokens using JWKS from Cognito.
    
    This class handles:
    - JWKS endpoint fetching from Cognito discovery URL
    - JWT signature validation using JWKS
    - Token expiration checking
    - Claim extraction (sub, cognito:username, client_id)
    """
    
    def __init__(self, jwks_url: str, cache_ttl: int = 3600, timeout: Optional[int] = None):
        """Initialize JWT validator.
        
        Args:
            jwks_url: Cognito JWKS discovery URL
            cache_ttl: Time to live for JWKS cache in seconds (default: 1 hour)
            timeout: Timeout for JWKS retrieval in seconds (default: from TIMEOUT_CONFIG)
        """
        self.jwks_url = jwks_url
        self.cache_ttl = cache_ttl
        self.timeout = timeout or TIMEOUT_CONFIG.jwt_validation
        self._jwks_cache: Optional[Dict] = None
        self._cache_timestamp: float = 0
    
    def _fetch_jwks(self) -> Dict:
        """Fetch JWKS from Cognito discovery URL.
        
        Returns:
            Dictionary containing JWKS keys
            
        Raises:
            JWTValidationError: If JWKS retrieval fails or times out
        """
        try:
            # Set socket timeout for the request
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(self.timeout)
            
            try:
                with urlopen(self.jwks_url, timeout=self.timeout) as response:
                    jwks_data = json.loads(response.read().decode('utf-8'))
                    return jwks_data
            finally:
                # Restore original timeout
                socket.setdefaulttimeout(old_timeout)
                
        except socket.timeout:
            raise JWTValidationError(
                f"JWKS retrieval timed out after {self.timeout} seconds"
            )
        except Exception as e:
            raise JWTValidationError(f"Failed to retrieve JWKS: {str(e)}")
    
    def _get_jwks(self) -> Dict:
        """Get JWKS with caching.
        
        Returns:
            Dictionary containing JWKS keys
        """
        current_time = time.time()
        
        # Check if cache is valid
        if self._jwks_cache and (current_time - self._cache_timestamp) < self.cache_ttl:
            return self._jwks_cache
        
        # Fetch new JWKS
        self._jwks_cache = self._fetch_jwks()
        self._cache_timestamp = current_time
        
        return self._jwks_cache
    
    def validate_token(self, token: str) -> Dict[str, str]:
        """Validate JWT token and extract claims.
        
        This method:
        1. Retrieves JWKS from Cognito
        2. Validates JWT signature using JWKS
        3. Checks token expiration
        4. Extracts and validates required claims
        
        Args:
            token: JWT access token string
            
        Returns:
            Dictionary of JWT claims including sub, cognito:username, client_id
            
        Raises:
            JWTValidationError: If token is invalid, expired, or missing required claims
        """
        try:
            # Get JWKS
            jwks = self._get_jwks()
            
            # Decode and validate token
            # python-jose will automatically:
            # - Verify signature using JWKS
            # - Check expiration
            # - Validate token structure
            claims = jwt.decode(
                token,
                jwks,
                options={
                    'verify_signature': True,
                    'verify_exp': True,
                    'verify_aud': False  # Cognito access tokens don't have aud claim
                }
            )
            
            # Validate required claims are present
            # Note: Access tokens use 'username', ID tokens use 'cognito:username'
            required_claims = ['sub', 'client_id']
            missing_claims = [claim for claim in required_claims if claim not in claims]
            
            # Check for either 'username' or 'cognito:username'
            if 'username' not in claims and 'cognito:username' not in claims:
                missing_claims.append('username or cognito:username')
            
            if missing_claims:
                raise JWTValidationError(
                    f"Token missing required claims: {', '.join(missing_claims)}"
                )
            
            return claims
            
        except ExpiredSignatureError:
            raise JWTValidationError("Token has expired")
        except JWTClaimsError as e:
            raise JWTValidationError(f"Invalid token claims: {str(e)}")
        except JWTError as e:
            raise JWTValidationError(f"Invalid token: {str(e)}")
        except Exception as e:
            raise JWTValidationError(f"Token validation failed: {str(e)}")
    
    def extract_claims(self, token: str) -> Dict[str, str]:
        """Extract claims from JWT token without full validation.
        
        This is useful for extracting claims when you've already validated
        the token or need to inspect claims for logging purposes.
        
        Args:
            token: JWT access token string
            
        Returns:
            Dictionary of JWT claims
            
        Raises:
            JWTValidationError: If token cannot be decoded
        """
        try:
            # Decode without verification (just extract claims)
            claims = jwt.get_unverified_claims(token)
            return claims
        except Exception as e:
            raise JWTValidationError(f"Failed to extract claims: {str(e)}")
