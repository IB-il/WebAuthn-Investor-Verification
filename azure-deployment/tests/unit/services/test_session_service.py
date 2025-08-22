"""
Unit tests for SessionService - Clean Architecture Phase 5

Tests JWT token management and session lifecycle operations.
"""

import pytest
import jwt
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, patch

from lib.services.session_service import SessionService


@pytest.mark.unit
@pytest.mark.session
class TestSessionService:
    """Test cases for SessionService."""
    
    def test_initialization(self, mock_storage_service):
        """Test SessionService initialization."""
        service = SessionService(
            storage_service=mock_storage_service,
            jwt_secret="test_secret",
            jwt_ttl_seconds=3600
        )
        
        assert service.storage == mock_storage_service
        assert service.jwt_secret == "test_secret"
        assert service.jwt_ttl_seconds == 3600
    
    def test_generate_jwt_token(self, session_service):
        """Test JWT token generation."""
        user_id = "test_user_123"
        token = session_service.generate_jwt_token(user_id)
        
        # Verify token format
        assert isinstance(token, str)
        assert len(token.split('.')) == 3  # JWT has 3 parts
        
        # Decode and verify payload
        payload = jwt.decode(
            token, 
            session_service.jwt_secret, 
            algorithms=["HS256"]
        )
        assert payload["user_id"] == user_id
        assert "exp" in payload
        assert "iat" in payload
    
    def test_verify_jwt_token_valid(self, session_service):
        """Test JWT token verification with valid token."""
        user_id = "test_user_123"
        token = session_service.generate_jwt_token(user_id)
        
        verified_user_id = session_service.verify_jwt_token(token)
        assert verified_user_id == user_id
    
    def test_verify_jwt_token_invalid(self, session_service):
        """Test JWT token verification with invalid token."""
        invalid_token = "invalid.jwt.token"
        
        verified_user_id = session_service.verify_jwt_token(invalid_token)
        assert verified_user_id is None
    
    def test_verify_jwt_token_expired(self, session_service):
        """Test JWT token verification with expired token."""
        # Create expired token
        payload = {
            "user_id": "test_user",
            "exp": datetime.now(timezone.utc) - timedelta(hours=1),
            "iat": datetime.now(timezone.utc) - timedelta(hours=2)
        }
        expired_token = jwt.encode(payload, session_service.jwt_secret, algorithm="HS256")
        
        verified_user_id = session_service.verify_jwt_token(expired_token)
        assert verified_user_id is None
    
    def test_create_session_success(self, session_service, mock_storage_service):
        """Test successful session creation."""
        mock_storage_service.save_session.return_value = True
        
        result = session_service.create_session(
            user_id="test_user",
            token="test_token", 
            challenge="test_challenge",
            username="Test User"
        )
        
        assert result is True
        mock_storage_service.save_session.assert_called_once()
        
        # Verify call arguments
        args, kwargs = mock_storage_service.save_session.call_args
        assert kwargs["token"] == "test_token"
        assert kwargs["user_id"] == "test_user"
        assert kwargs["challenge"] == "test_challenge"
        assert kwargs["username"] == "Test User"
        assert kwargs["verified"] is False
    
    def test_create_session_failure(self, session_service, mock_storage_service):
        """Test session creation failure."""
        mock_storage_service.save_session.return_value = False
        
        result = session_service.create_session(
            user_id="test_user",
            token="test_token",
            challenge="test_challenge"
        )
        
        assert result is False
    
    def test_get_session_exists(self, session_service, mock_storage_service, mock_session_with_user):
        """Test getting existing session."""
        mock_storage_service.get_session_data.return_value = mock_session_with_user
        
        session = session_service.get_session("test_token")
        
        assert session == mock_session_with_user
        mock_storage_service.get_session_data.assert_called_once_with("test_token")
    
    def test_get_session_not_found(self, session_service, mock_storage_service):
        """Test getting non-existent session."""
        mock_storage_service.get_session_data.return_value = None
        
        session = session_service.get_session("nonexistent_token")
        
        assert session is None
    
    def test_get_session_expired(self, session_service, mock_storage_service, mock_expired_session):
        """Test getting expired session."""
        mock_storage_service.get_session_data.return_value = mock_expired_session
        
        session = session_service.get_session("expired_token")
        
        # Should return None for expired session
        assert session is None
    
    def test_get_session_data_tuple(self, session_service, mock_storage_service, mock_session_with_user):
        """Test getting session data in legacy tuple format."""
        mock_storage_service.get_session_data.return_value = mock_session_with_user
        
        result = session_service.get_session_data("test_token")
        
        assert result is not None
        user_id, challenge, verified, expires_at = result
        assert user_id == mock_session_with_user["user_id"]
        assert challenge == mock_session_with_user["challenge"]
        assert verified == mock_session_with_user["verified"]
        assert expires_at == mock_session_with_user["expires_at"].isoformat()
    
    def test_mark_session_verified(self, session_service, mock_storage_service):
        """Test marking session as verified."""
        mock_storage_service.mark_session_verified.return_value = True
        
        result = session_service.mark_session_verified("test_token")
        
        assert result is True
        mock_storage_service.mark_session_verified.assert_called_once_with("test_token")
    
    def test_is_session_verified_true(self, session_service, mock_storage_service, mock_verified_session):
        """Test checking verified session."""
        mock_storage_service.get_session_data.return_value = mock_verified_session
        
        is_verified = session_service.is_session_verified("verified_token")
        
        assert is_verified is True
    
    def test_is_session_verified_false(self, session_service, mock_storage_service, mock_session_with_user):
        """Test checking unverified session."""
        mock_storage_service.get_session_data.return_value = mock_session_with_user
        
        is_verified = session_service.is_session_verified("unverified_token")
        
        assert is_verified is False
    
    def test_is_session_verified_not_found(self, session_service, mock_storage_service):
        """Test checking verification status of non-existent session."""
        mock_storage_service.get_session_data.return_value = None
        
        is_verified = session_service.is_session_verified("nonexistent_token")
        
        assert is_verified is False
    
    def test_get_session_user_id(self, session_service, mock_storage_service, mock_session_with_user):
        """Test getting user ID from session."""
        mock_storage_service.get_session_data.return_value = mock_session_with_user
        
        user_id = session_service.get_session_user_id("test_token")
        
        assert user_id == mock_session_with_user["user_id"]
    
    def test_get_session_challenge(self, session_service, mock_storage_service, mock_session_with_user):
        """Test getting challenge from session."""
        mock_storage_service.get_session_data.return_value = mock_session_with_user
        
        challenge = session_service.get_session_challenge("test_token")
        
        assert challenge == mock_session_with_user["challenge"]
    
    def test_get_token_expiry_time(self, session_service):
        """Test getting token expiry time."""
        user_id = "test_user"
        token = session_service.generate_jwt_token(user_id)
        
        expiry = session_service.get_token_expiry_time(token)
        
        assert expiry is not None
        assert isinstance(expiry, datetime)
        assert expiry.tzinfo == timezone.utc
        # Should expire in the future (within TTL)
        assert expiry > datetime.now(timezone.utc)
    
    def test_get_token_expiry_time_invalid(self, session_service):
        """Test getting expiry time of invalid token."""
        invalid_token = "invalid.jwt.token"
        
        expiry = session_service.get_token_expiry_time(invalid_token)
        
        assert expiry is None
    
    def test_is_token_expired_valid(self, session_service):
        """Test checking expiration of valid token."""
        user_id = "test_user"
        token = session_service.generate_jwt_token(user_id)
        
        is_expired = session_service.is_token_expired(token)
        
        assert is_expired is False
    
    def test_is_token_expired_expired(self, session_service):
        """Test checking expiration of expired token."""
        # Create expired token
        payload = {
            "user_id": "test_user",
            "exp": datetime.now(timezone.utc) - timedelta(hours=1),
            "iat": datetime.now(timezone.utc) - timedelta(hours=2)
        }
        expired_token = jwt.encode(payload, session_service.jwt_secret, algorithm="HS256")
        
        is_expired = session_service.is_token_expired(expired_token)
        
        assert is_expired is True
    
    def test_is_token_expired_invalid(self, session_service):
        """Test checking expiration of invalid token."""
        invalid_token = "invalid.jwt.token"
        
        is_expired = session_service.is_token_expired(invalid_token)
        
        assert is_expired is True  # Invalid tokens are considered expired
    
    def test_get_session_stats(self, session_service):
        """Test getting session statistics."""
        stats = session_service.get_session_stats()
        
        assert isinstance(stats, dict)
        assert "total_sessions" in stats
        assert "verified_sessions" in stats
        assert "expired_sessions" in stats
    
    def test_cleanup_expired_sessions(self, session_service):
        """Test expired session cleanup."""
        # This method currently returns 0 as it's not fully implemented
        count = session_service.cleanup_expired_sessions()
        
        assert count == 0
    
    def test_session_expiration_check_string_date(self, session_service):
        """Test session expiration checking with string date format."""
        # Create mock session with ISO string date
        mock_session = {
            "user_id": "test_user",
            "challenge": "test_challenge", 
            "verified": False,
            "expires_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
            "username": "Test User"
        }
        
        is_expired = session_service._is_session_expired(mock_session)
        
        assert is_expired is True
    
    def test_session_expiration_check_no_timezone(self, session_service):
        """Test session expiration checking with naive datetime."""
        # Create mock session with naive datetime that's clearly expired
        # Use UTC time for consistency since the service compares against UTC
        expired_time = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=2)  # Make it clearly expired, naive
        mock_session = {
            "user_id": "test_user",
            "challenge": "test_challenge",
            "verified": False, 
            "expires_at": expired_time,  # No timezone
            "username": "Test User"
        }
        
        is_expired = session_service._is_session_expired(mock_session)
        
        # The service converts naive datetime to UTC and compares with current UTC time
        # Since we set it 2 hours ago in UTC, it should definitely be expired
        assert is_expired is True
    
    def test_session_expiration_check_missing_expiry(self, session_service):
        """Test session expiration checking with missing expiry."""
        mock_session = {
            "user_id": "test_user",
            "challenge": "test_challenge",
            "verified": False,
            "username": "Test User"
            # No expires_at field
        }
        
        is_expired = session_service._is_session_expired(mock_session)
        
        assert is_expired is True  # Missing expiry should be considered expired
    
    @patch('logging.error')
    def test_jwt_generation_error_handling(self, mock_log, mock_storage_service):
        """Test JWT generation error handling."""
        # Test with invalid secret to trigger an error
        # Since the service has a fallback secret, we need to patch the jwt.encode method
        service = SessionService(mock_storage_service, jwt_secret="")  # Empty string to trigger potential issues
        
        with patch('jwt.encode', side_effect=Exception("JWT encoding failed")):
            with pytest.raises(Exception):
                service.generate_jwt_token("test_user")
    
    def test_create_session_with_exception(self, session_service, mock_storage_service):
        """Test session creation with storage exception."""
        mock_storage_service.save_session.side_effect = Exception("Storage error")
        
        result = session_service.create_session(
            user_id="test_user",
            token="test_token", 
            challenge="test_challenge"
        )
        
        assert result is False