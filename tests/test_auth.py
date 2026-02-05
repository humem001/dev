"""Unit tests for authentication module."""

import json
import time
from unittest.mock import Mock, patch, MagicMock
from urllib.error import URLError
import pytest

from jose import jwt
from jose.exceptions import ExpiredSignatureError, JWTError

from src.auth import JWTValidator, JWTValidationError
from src.models import UserContext


class TestJWTValidator:
    """Tests for JWTValidator class."""
    
    @pytest.fixture
    def mock_jwks(self):
        """Mock JWKS response."""
        return {
            'keys': [
                {
                    'kid': 'test-key-id',
                    'kty': 'RSA',
                    'use': 'sig',
                    'n': 'test-modulus',
                    'e': 'AQAB'
                }
            ]
        }
    
    @pytest.fixture
    def validator(self):
        """Create JWTValidator instance."""
        return JWTValidator(
            jwks_url='https://cognito-idp.us-east-1.amazonaws.com/test-pool/.well-known/jwks.json',
            cache_ttl=3600
        )
    
    def test_init(self, validator):
        """Test JWTValidator initialization."""
        assert validator.jwks_url.endswith('jwks.json')
        assert validator.cache_ttl == 3600
        assert validator._jwks_cache is None
        assert validator._cache_timestamp == 0
    
    @patch('src.auth.jwt_validator.urlopen')
    def test_fetch_jwks_success(self, mock_urlopen, validator, mock_jwks):
        """Test successful JWKS fetching."""
        # Mock response
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(mock_jwks).encode('utf-8')
        mock_response.__enter__.return_value = mock_response
        mock_response.__exit__.return_value = None
        mock_urlopen.return_value = mock_response
        
        result = validator._fetch_jwks()
        
        assert result == mock_jwks
        mock_urlopen.assert_called_once()
    
    @patch('src.auth.jwt_validator.urlopen')
    def test_fetch_jwks_failure(self, mock_urlopen, validator):
        """Test JWKS fetching failure."""
        mock_urlopen.side_effect = URLError('Connection failed')
        
        with pytest.raises(JWTValidationError) as exc_info:
            validator._fetch_jwks()
        
        assert 'Failed to retrieve JWKS' in str(exc_info.value)
    
    @patch('src.auth.jwt_validator.urlopen')
    def test_get_jwks_caching(self, mock_urlopen, validator, mock_jwks):
        """Test JWKS caching mechanism."""
        # Mock response
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(mock_jwks).encode('utf-8')
        mock_response.__enter__.return_value = mock_response
        mock_response.__exit__.return_value = None
        mock_urlopen.return_value = mock_response
        
        # First call should fetch
        result1 = validator._get_jwks()
        assert result1 == mock_jwks
        assert mock_urlopen.call_count == 1
        
        # Second call should use cache
        result2 = validator._get_jwks()
        assert result2 == mock_jwks
        assert mock_urlopen.call_count == 1  # Still 1, not 2
    
    @patch('src.auth.jwt_validator.urlopen')
    def test_get_jwks_cache_expiration(self, mock_urlopen, validator, mock_jwks):
        """Test JWKS cache expiration."""
        # Mock response
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps(mock_jwks).encode('utf-8')
        mock_response.__enter__.return_value = mock_response
        mock_response.__exit__.return_value = None
        mock_urlopen.return_value = mock_response
        
        # First call
        validator._get_jwks()
        assert mock_urlopen.call_count == 1
        
        # Expire cache
        validator._cache_timestamp = time.time() - 4000  # Older than TTL
        
        # Second call should fetch again
        validator._get_jwks()
        assert mock_urlopen.call_count == 2
    
    @patch('src.auth.jwt_validator.JWTValidator._get_jwks')
    @patch('jose.jwt.decode')
    def test_validate_token_success(self, mock_decode, mock_get_jwks, validator, mock_jwks):
        """Test successful token validation."""
        mock_get_jwks.return_value = mock_jwks
        
        expected_claims = {
            'sub': 'user-123',
            'cognito:username': 'john.doe',
            'client_id': 'client-456',
            'exp': int(time.time()) + 3600,
            'iat': int(time.time())
        }
        mock_decode.return_value = expected_claims
        
        result = validator.validate_token('valid.jwt.token')
        
        assert result == expected_claims
        mock_decode.assert_called_once()
    
    @patch('src.auth.jwt_validator.JWTValidator._get_jwks')
    @patch('jose.jwt.decode')
    def test_validate_token_missing_claims(self, mock_decode, mock_get_jwks, validator, mock_jwks):
        """Test token validation with missing required claims."""
        mock_get_jwks.return_value = mock_jwks
        
        # Missing cognito:username
        incomplete_claims = {
            'sub': 'user-123',
            'client_id': 'client-456'
        }
        mock_decode.return_value = incomplete_claims
        
        with pytest.raises(JWTValidationError) as exc_info:
            validator.validate_token('incomplete.jwt.token')
        
        assert 'missing required claims' in str(exc_info.value).lower()
        assert 'cognito:username' in str(exc_info.value)
    
    @patch('src.auth.jwt_validator.JWTValidator._get_jwks')
    @patch('jose.jwt.decode')
    def test_validate_token_expired(self, mock_decode, mock_get_jwks, validator, mock_jwks):
        """Test validation of expired token."""
        mock_get_jwks.return_value = mock_jwks
        mock_decode.side_effect = ExpiredSignatureError('Token expired')
        
        with pytest.raises(JWTValidationError) as exc_info:
            validator.validate_token('expired.jwt.token')
        
        assert 'expired' in str(exc_info.value).lower()
    
    @patch('src.auth.jwt_validator.JWTValidator._get_jwks')
    @patch('jose.jwt.decode')
    def test_validate_token_invalid_signature(self, mock_decode, mock_get_jwks, validator, mock_jwks):
        """Test validation of token with invalid signature."""
        mock_get_jwks.return_value = mock_jwks
        mock_decode.side_effect = JWTError('Invalid signature')
        
        with pytest.raises(JWTValidationError) as exc_info:
            validator.validate_token('invalid.jwt.token')
        
        assert 'invalid token' in str(exc_info.value).lower()
    
    @patch('jose.jwt.get_unverified_claims')
    def test_extract_claims_success(self, mock_get_claims, validator):
        """Test successful claim extraction without validation."""
        expected_claims = {
            'sub': 'user-123',
            'cognito:username': 'john.doe',
            'client_id': 'client-456'
        }
        mock_get_claims.return_value = expected_claims
        
        result = validator.extract_claims('any.jwt.token')
        
        assert result == expected_claims
        mock_get_claims.assert_called_once_with('any.jwt.token')
    
    @patch('jose.jwt.get_unverified_claims')
    def test_extract_claims_failure(self, mock_get_claims, validator):
        """Test claim extraction failure."""
        mock_get_claims.side_effect = Exception('Malformed token')
        
        with pytest.raises(JWTValidationError) as exc_info:
            validator.extract_claims('malformed.token')
        
        assert 'failed to extract claims' in str(exc_info.value).lower()


class TestUserContextFromJWTClaims:
    """Tests for UserContext.from_jwt_claims() method."""
    
    def test_from_jwt_claims_success(self):
        """Test successful UserContext extraction from valid claims."""
        claims = {
            'sub': 'user-123',
            'cognito:username': 'john.doe',
            'client_id': 'client-456'
        }
        
        context = UserContext.from_jwt_claims(claims)
        
        assert context.user_id == 'user-123'
        assert context.username == 'john.doe'
        assert context.client_id == 'client-456'
    
    def test_from_jwt_claims_with_whitespace(self):
        """Test UserContext extraction strips whitespace."""
        claims = {
            'sub': '  user-123  ',
            'cognito:username': '  john.doe  ',
            'client_id': '  client-456  '
        }
        
        context = UserContext.from_jwt_claims(claims)
        
        assert context.user_id == 'user-123'
        assert context.username == 'john.doe'
        assert context.client_id == 'client-456'
    
    def test_from_jwt_claims_not_dict(self):
        """Test UserContext extraction with non-dictionary input."""
        with pytest.raises(ValueError) as exc_info:
            UserContext.from_jwt_claims("not a dict")
        
        assert 'must be a dictionary' in str(exc_info.value).lower()
    
    def test_from_jwt_claims_missing_sub(self):
        """Test UserContext extraction with missing 'sub' claim."""
        claims = {
            'cognito:username': 'john.doe',
            'client_id': 'client-456'
        }
        
        with pytest.raises(ValueError) as exc_info:
            UserContext.from_jwt_claims(claims)
        
        assert 'missing required jwt claims' in str(exc_info.value).lower()
        assert 'sub' in str(exc_info.value)
    
    def test_from_jwt_claims_missing_username(self):
        """Test UserContext extraction with missing 'cognito:username' claim."""
        claims = {
            'sub': 'user-123',
            'client_id': 'client-456'
        }
        
        with pytest.raises(ValueError) as exc_info:
            UserContext.from_jwt_claims(claims)
        
        assert 'missing required jwt claims' in str(exc_info.value).lower()
        assert 'cognito:username' in str(exc_info.value)
    
    def test_from_jwt_claims_missing_client_id(self):
        """Test UserContext extraction with missing 'client_id' claim."""
        claims = {
            'sub': 'user-123',
            'cognito:username': 'john.doe'
        }
        
        with pytest.raises(ValueError) as exc_info:
            UserContext.from_jwt_claims(claims)
        
        assert 'missing required jwt claims' in str(exc_info.value).lower()
        assert 'client_id' in str(exc_info.value)
    
    def test_from_jwt_claims_empty_sub(self):
        """Test UserContext extraction with empty 'sub' claim."""
        claims = {
            'sub': '',
            'cognito:username': 'john.doe',
            'client_id': 'client-456'
        }
        
        with pytest.raises(ValueError) as exc_info:
            UserContext.from_jwt_claims(claims)
        
        assert 'sub' in str(exc_info.value)
        assert 'non-empty string' in str(exc_info.value).lower()
    
    def test_from_jwt_claims_empty_username(self):
        """Test UserContext extraction with empty 'cognito:username' claim."""
        claims = {
            'sub': 'user-123',
            'cognito:username': '   ',
            'client_id': 'client-456'
        }
        
        with pytest.raises(ValueError) as exc_info:
            UserContext.from_jwt_claims(claims)
        
        assert 'cognito:username' in str(exc_info.value)
        assert 'non-empty string' in str(exc_info.value).lower()
    
    def test_from_jwt_claims_non_string_values(self):
        """Test UserContext extraction with non-string claim values."""
        claims = {
            'sub': 123,  # Should be string
            'cognito:username': 'john.doe',
            'client_id': 'client-456'
        }
        
        with pytest.raises(ValueError) as exc_info:
            UserContext.from_jwt_claims(claims)
        
        assert 'sub' in str(exc_info.value)
        assert 'non-empty string' in str(exc_info.value).lower()
    
    def test_from_jwt_claims_multiple_missing(self):
        """Test UserContext extraction with multiple missing claims."""
        claims = {
            'sub': 'user-123'
        }
        
        with pytest.raises(ValueError) as exc_info:
            UserContext.from_jwt_claims(claims)
        
        error_msg = str(exc_info.value).lower()
        assert 'missing required jwt claims' in error_msg
        # Should mention both missing claims
        assert 'cognito:username' in str(exc_info.value)
        assert 'client_id' in str(exc_info.value)


class TestAuthenticationErrorHandling:
    """Tests for authentication error handling scenarios."""
    
    @pytest.fixture
    def validator(self):
        """Create JWTValidator instance."""
        return JWTValidator(
            jwks_url='https://cognito-idp.us-east-1.amazonaws.com/test-pool/.well-known/jwks.json'
        )
    
    @patch('src.auth.jwt_validator.urlopen')
    def test_jwks_retrieval_timeout(self, mock_urlopen, validator):
        """Test JWKS retrieval timeout handling."""
        mock_urlopen.side_effect = TimeoutError('Request timed out')
        
        with pytest.raises(JWTValidationError) as exc_info:
            validator._fetch_jwks()
        
        # Updated assertion to match the new timeout-specific error message
        assert 'timed out' in str(exc_info.value).lower()
    
    @patch('src.auth.jwt_validator.urlopen')
    def test_jwks_invalid_json(self, mock_urlopen, validator):
        """Test JWKS retrieval with invalid JSON response."""
        mock_response = MagicMock()
        mock_response.read.return_value = b'not valid json'
        mock_response.__enter__.return_value = mock_response
        mock_response.__exit__.return_value = None
        mock_urlopen.return_value = mock_response
        
        with pytest.raises(JWTValidationError) as exc_info:
            validator._fetch_jwks()
        
        assert 'failed to retrieve jwks' in str(exc_info.value).lower()
    
    @patch('src.auth.jwt_validator.JWTValidator._get_jwks')
    def test_validate_token_jwks_failure(self, mock_get_jwks, validator):
        """Test token validation when JWKS retrieval fails."""
        mock_get_jwks.side_effect = JWTValidationError('JWKS unavailable')
        
        with pytest.raises(JWTValidationError) as exc_info:
            validator.validate_token('any.token')
        
        assert 'jwks unavailable' in str(exc_info.value).lower()
