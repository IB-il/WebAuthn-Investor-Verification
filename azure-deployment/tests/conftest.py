"""
Pytest configuration and fixtures for WebAuthn Investor Verification System tests.
"""

import pytest
import os
import tempfile
from unittest.mock import Mock, MagicMock
from datetime import datetime, timezone, timedelta

# Add the parent directory to Python path for imports
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.services.storage_service import AzureStorageService
from lib.services.webauthn_service import WebAuthnService
from lib.services.session_service import SessionService
from lib.services.auth_service import AuthService
from lib.services.template_service import TemplateService


@pytest.fixture
def mock_storage_service():
    """Mock storage service for testing."""
    mock = Mock(spec=AzureStorageService)
    
    # Mock basic storage operations
    mock.get_user_credentials.return_value = []
    mock.save_user_credential.return_value = True
    mock.save_session.return_value = True
    mock.get_session_data.return_value = None
    mock.mark_session_verified.return_value = True
    mock.load_credentials.return_value = {}
    mock.save_credentials.return_value = True
    mock.load_sessions.return_value = {}
    mock.save_sessions.return_value = True
    
    return mock


@pytest.fixture
def mock_session_with_user():
    """Mock session data with user information."""
    return {
        "user_id": "test_user_123",
        "challenge": "mock_challenge_base64url",
        "verified": False,
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=15)
    }


@pytest.fixture
def mock_verified_session():
    """Mock verified session data."""
    return {
        "user_id": "verified_user_123",
        "challenge": "verified_challenge_base64url",
        "verified": True,
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=10)
    }


@pytest.fixture
def mock_expired_session():
    """Mock expired session data."""
    return {
        "user_id": "expired_user_123",
        "challenge": "expired_challenge_base64url",
        "verified": False,
        "expires_at": datetime.now(timezone.utc) - timedelta(minutes=5)
    }


@pytest.fixture
def mock_user_credentials():
    """Mock user credentials for testing."""
    return [
        ("mock_credential_id_1", "mock_public_key_1", 0),
        ("mock_credential_id_2", "mock_public_key_2", 5)
    ]


@pytest.fixture
def mock_webauthn_registration_response():
    """Mock WebAuthn registration response."""
    return {
        "id": "mock_credential_id",
        "rawId": "bW9ja19jcmVkZW50aWFsX2lk",  # base64url encoded
        "type": "public-key",
        "response": {
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0",  # base64url
            "attestationObject": "mock_attestation_object_base64url"
        }
    }


@pytest.fixture  
def mock_webauthn_auth_response():
    """Mock WebAuthn authentication response."""
    return {
        "id": "mock_credential_id",
        "rawId": "bW9ja19jcmVkZW50aWFsX2lk",  # base64url encoded
        "type": "public-key",
        "response": {
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",  # base64url
            "authenticatorData": "mock_auth_data_base64url",
            "signature": "mock_signature_base64url",
            "userHandle": None
        }
    }


@pytest.fixture
def mock_http_request():
    """Mock Azure Functions HTTP request."""
    mock_req = Mock()
    mock_req.method = "GET"
    mock_req.params = {"token": "mock_jwt_token"}
    mock_req.headers = {
        "Authorization": "Bearer admin-key-d8f9e7a6b5c4d3e2f1",
        "Content-Type": "application/json",
        "X-Forwarded-For": "192.168.1.100"
    }
    mock_req.get_json.return_value = {"user_id": "test_user"}
    return mock_req


@pytest.fixture
def session_service(mock_storage_service):
    """SessionService instance with mocked storage."""
    return SessionService(
        storage_service=mock_storage_service,
        jwt_secret="test_jwt_secret_key_for_testing",
        jwt_ttl_seconds=900
    )


@pytest.fixture
def auth_service():
    """AuthService instance for testing."""
    return AuthService(admin_api_key="test-admin-api-key")


@pytest.fixture
def webauthn_service(mock_storage_service):
    """WebAuthnService instance with mocked storage."""
    return WebAuthnService(
        storage_service=mock_storage_service,
        rp_id="test.example.com",
        origin="https://test.example.com"
    )


@pytest.fixture
def template_service():
    """TemplateService instance for testing."""
    # Create temporary template directory
    temp_dir = tempfile.mkdtemp()
    
    # Create mock templates
    base_template = """<!DOCTYPE html>
<html><head><title>{% block title %}Test{% endblock %}</title></head>
<body>{% block content %}{% endblock %}</body></html>"""
    
    test_template = """{% extends "base.html" %}
{% block content %}Hello {{ name }}!{% endblock %}"""
    
    os.makedirs(os.path.join(temp_dir, "templates"))
    
    with open(os.path.join(temp_dir, "templates", "base.html"), "w") as f:
        f.write(base_template)
    
    with open(os.path.join(temp_dir, "templates", "test.html"), "w") as f:
        f.write(test_template)
    
    return TemplateService(template_dir=os.path.join(temp_dir, "templates"))


@pytest.fixture
def valid_jwt_token():
    """Valid JWT token for testing."""
    return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoidGVzdF91c2VyIiwiZXhwIjoxOTAwMDAwMDAwLCJpYXQiOjE3MDAwMDAwMDB9.test_signature"


@pytest.fixture
def expired_jwt_token():
    """Expired JWT token for testing.""" 
    return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoidGVzdF91c2VyIiwiZXhwIjoxNTAwMDAwMDAwLCJpYXQiOjE0MDAwMDAwMDB9.expired_signature"


@pytest.fixture
def invalid_jwt_token():
    """Invalid JWT token for testing."""
    return "invalid.jwt.token"


@pytest.fixture
def hebrew_test_data():
    """Hebrew text data for testing."""
    return {
        "user_id": "משתמש_בדיקה",
        "display_name": "משתמש בדיקה בעברית",
        "display_name": "משתמש לבדיקות",
        "error_message": "שגיאה במערכת",
        "success_message": "הפעולה הושלמה בהצלחה"
    }


@pytest.fixture
def malicious_input_data():
    """Malicious input data for security testing."""
    return {
        "xss_script": "<script>alert('xss')</script>",
        "sql_injection": "'; DROP TABLE users; --",
        "path_traversal": "../../../etc/passwd",
        "command_injection": "test; rm -rf /",
        "long_string": "A" * 10000,
        "null_bytes": "test\x00admin",
        "unicode_attack": "test\u202e\u202c"
    }