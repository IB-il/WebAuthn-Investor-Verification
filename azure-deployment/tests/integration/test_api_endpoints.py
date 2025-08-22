"""
Integration tests for API endpoints - Clean Architecture Phase 5

Tests end-to-end functionality of the WebAuthn verification system.
"""

import pytest
import json
from unittest.mock import Mock, patch
import azure.functions as func

# Import the main function app for testing
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


@pytest.mark.integration
class TestAPIEndpoints:
    """Integration tests for API endpoints."""
    
    def create_mock_request(self, method="GET", params=None, json_data=None, headers=None):
        """Helper to create mock HTTP requests."""
        mock_req = Mock(spec=func.HttpRequest)
        mock_req.method = method
        mock_req.params = params or {}
        mock_req.headers = headers or {}
        
        if json_data:
            mock_req.get_json.return_value = json_data
        else:
            mock_req.get_json.return_value = {}
            
        return mock_req
    
    @patch('function_app.storage_service')
    @patch('function_app.session_service')
    @patch('function_app.auth_service')
    def test_health_check_endpoint(self, mock_auth, mock_session, mock_storage):
        """Test health check endpoint integration."""
        from function_app import health_check
        
        mock_req = self.create_mock_request()
        
        response = health_check(mock_req)
        
        assert response.status_code == 200
        response_data = json.loads(response.get_body())
        assert response_data["status"] == "healthy"
        assert "service" in response_data
        assert "active_sessions" in response_data
        assert "registered_users" in response_data
    
    @patch('function_app.storage_service')
    @patch('function_app.session_service')
    @patch('function_app.auth_service')
    @patch('function_app.webauthn_service')
    def test_create_verification_link_integration(self, mock_webauthn, mock_auth, mock_session, mock_storage):
        """Test verification link creation integration."""
        from function_app import create_verification_link
        
        # Setup mocks
        mock_auth.get_client_ip.return_value = "192.168.1.100"
        mock_auth.check_rate_limit.return_value = True
        mock_auth.validate_user_input.return_value = (True, None)
        mock_session.generate_jwt_token.return_value = "mock_jwt_token"
        mock_webauthn.has_existing_credentials.return_value = False
        mock_webauthn.generate_registration_options.return_value = {
            "options": {"challenge": "mock_challenge"},
            "challenge": "mock_challenge_base64url"
        }
        mock_session.create_session.return_value = True
        
        mock_req = self.create_mock_request(
            method="POST",
            json_data={"user_id": "test_user", "username": "Test User"}
        )
        
        response = create_verification_link(mock_req)
        
        assert response.status_code == 200
        response_data = json.loads(response.get_body())
        assert "verification_url" in response_data
        assert "token" in response_data
        assert "expires_in" in response_data
    
    @patch('function_app.storage_service')
    @patch('function_app.session_service') 
    @patch('function_app.template_service')
    def test_verification_page_integration(self, mock_template, mock_session, mock_storage):
        """Test verification page rendering integration."""
        from function_app import verification_page
        
        # Setup mocks
        mock_session.verify_jwt_token.return_value = "test_user"
        mock_template.render_verification_page.return_value = "<html>Test Page</html>"
        
        mock_req = self.create_mock_request(
            params={"token": "valid_jwt_token"}
        )
        
        response = verification_page(mock_req)
        
        assert response.status_code == 200
        assert response.headers["Content-Type"] == "text/html"
        assert b"<html>Test Page</html>" in response.get_body()
    
    @patch('function_app.storage_service')
    @patch('function_app.session_service')
    @patch('function_app.template_service')
    def test_verification_page_invalid_token(self, mock_template, mock_session, mock_storage):
        """Test verification page with invalid token."""
        from function_app import verification_page
        
        # Setup mocks
        mock_session.verify_jwt_token.return_value = None  # Invalid token
        mock_template.render_error_page.return_value = "<html>Error Page</html>"
        
        mock_req = self.create_mock_request(
            params={"token": "invalid_token"}
        )
        
        response = verification_page(mock_req)
        
        assert response.status_code == 401
        assert response.headers["Content-Type"] == "text/html"
        mock_template.render_error_page.assert_called_once()
    
    @patch('function_app.storage_service')
    @patch('function_app.auth_service')
    def test_admin_api_authentication_integration(self, mock_auth, mock_storage):
        """Test admin API authentication integration."""
        from function_app import list_users
        
        # Setup mocks
        mock_auth.verify_admin_auth.return_value = True
        mock_storage.get_all_users.return_value = [
            {"user_id": "test_user", "credentials_count": 1}
        ]
        
        mock_req = self.create_mock_request(
            headers={"Authorization": "Bearer admin-key"}
        )
        
        response = list_users(mock_req)
        
        assert response.status_code == 200
        response_data = json.loads(response.get_body())
        assert "total_users" in response_data
        assert "users" in response_data
    
    @patch('function_app.storage_service')
    @patch('function_app.auth_service')
    def test_admin_api_unauthorized_integration(self, mock_auth, mock_storage):
        """Test admin API unauthorized access."""
        from function_app import list_users
        
        # Setup mocks
        mock_auth.verify_admin_auth.return_value = False
        
        mock_req = self.create_mock_request(
            headers={"Authorization": "Bearer invalid-key"}
        )
        
        response = list_users(mock_req)
        
        assert response.status_code == 401
        response_data = json.loads(response.get_body())
        assert "error" in response_data
        assert "Unauthorized" in response_data["error"]
    
    @patch('function_app.storage_service')
    @patch('function_app.session_service')
    @patch('function_app.webauthn_service')
    def test_webauthn_options_integration(self, mock_webauthn, mock_session, mock_storage):
        """Test WebAuthn options generation integration."""
        from function_app import get_webauthn_options
        
        # Setup mocks
        mock_session.verify_jwt_token.return_value = "test_user"
        mock_session.get_session.return_value = {
            "user_id": "test_user",
            "challenge": "session_challenge",
            "verified": False,
            "username": "Test User"
        }
        mock_webauthn.has_existing_credentials.return_value = False
        mock_webauthn.generate_registration_options.return_value = {
            "options": {
                "challenge": "webauthn_challenge",
                "rp": {"id": "test.example.com"},
                "user": {"id": "dGVzdF91c2Vy", "name": "Test User"}
            },
            "challenge": "webauthn_challenge_b64url"
        }
        
        mock_req = self.create_mock_request(
            params={"token": "valid_jwt_token"}
        )
        
        response = get_webauthn_options(mock_req)
        
        assert response.status_code == 200
        response_data = json.loads(response.get_body())
        assert "challenge" in response_data
        assert "rp" in response_data
        assert "user" in response_data
        assert response_data["isRegistration"] is True
    
    @patch('function_app.storage_service')
    @patch('function_app.session_service')
    @patch('function_app.auth_service')
    def test_rate_limiting_integration(self, mock_auth, mock_session, mock_storage):
        """Test rate limiting integration."""
        from function_app import create_verification_link
        
        # Setup mocks for rate limiting
        mock_auth.get_client_ip.return_value = "192.168.1.100"
        mock_auth.check_rate_limit.return_value = False  # Rate limited
        
        mock_req = self.create_mock_request(
            method="POST",
            json_data={"user_id": "test_user", "username": "Test User"}
        )
        
        response = create_verification_link(mock_req)
        
        assert response.status_code == 429
        response_data = json.loads(response.get_body())
        assert "error" in response_data
        assert "Rate limit exceeded" in response_data["error"]
    
    @patch('function_app.storage_service')
    @patch('function_app.session_service')
    @patch('function_app.auth_service')
    def test_input_validation_integration(self, mock_auth, mock_session, mock_storage):
        """Test input validation integration."""
        from function_app import create_verification_link
        
        # Setup mocks
        mock_auth.get_client_ip.return_value = "192.168.1.100" 
        mock_auth.check_rate_limit.return_value = True
        mock_auth.validate_user_input.return_value = (False, "Invalid input format")
        
        mock_req = self.create_mock_request(
            method="POST",
            json_data={"user_id": "<script>alert('xss')</script>", "username": "Test User"}
        )
        
        response = create_verification_link(mock_req)
        
        assert response.status_code == 400
        response_data = json.loads(response.get_body())
        assert "error" in response_data
        assert "Invalid input" in response_data["error"]
    
    def test_error_handling_integration(self):
        """Test general error handling integration."""
        from function_app import health_check
        
        # Create request that will cause an exception
        mock_req = Mock()
        mock_req.method = "GET"
        # Remove required attributes to cause AttributeError
        delattr(mock_req, 'params')
        
        response = health_check(mock_req)
        
        # Should still return a response, not crash
        assert hasattr(response, 'status_code')
        assert hasattr(response, 'get_body')
    
    @patch('function_app.storage_service')
    @patch('function_app.session_service')
    def test_session_expiry_handling_integration(self, mock_session, mock_storage):
        """Test session expiry handling integration.""" 
        from function_app import get_webauthn_options
        
        # Setup mocks - session exists but user verification fails (expired)
        mock_session.verify_jwt_token.return_value = None  # Expired token
        
        mock_req = self.create_mock_request(
            params={"token": "expired_jwt_token"}
        )
        
        response = get_webauthn_options(mock_req)
        
        assert response.status_code == 401
        response_data = json.loads(response.get_body())
        assert "error" in response_data
        assert "expired" in response_data["error"].lower()
    
    def test_hebrew_text_handling_integration(self, hebrew_test_data):
        """Test Hebrew text handling in API responses."""
        # Test Hebrew text handling using the AuthService's safe error response
        from lib.services.auth_service import AuthService
        
        auth_service = AuthService("test-key")
        hebrew_error = hebrew_test_data["error_message"]
        response = auth_service.create_safe_error_response(hebrew_error, 400)
        
        assert response.status_code == 400
        response_data = json.loads(response.get_body())
        # Hebrew text should be properly encoded in JSON
        assert "error" in response_data
        assert hebrew_test_data["error_message"] in response_data["error"]
        
    @patch('function_app.logging')
    def test_security_logging_integration(self, mock_logging):
        """Test security logging integration."""
        from function_app import create_verification_link
        
        # This test verifies that security events are logged
        # The actual logging is mocked, but we verify the integration
        
        mock_req = self.create_mock_request(
            method="POST",
            json_data={"user_id": "test_user", "username": "Test User"}
        )
        
        # This should trigger logging calls
        with patch('function_app.auth_service.log_security_event') as mock_log:
            with patch('function_app.auth_service.get_client_ip', return_value="192.168.1.100"):
                with patch('function_app.auth_service.check_rate_limit', return_value=True):
                    with patch('function_app.auth_service.validate_user_input', return_value=(True, None)):
                        with patch('function_app.session_service.generate_jwt_token', return_value="token"):
                            with patch('function_app.webauthn_service.has_existing_credentials', return_value=False):
                                with patch('function_app.webauthn_service.generate_registration_options', return_value={"challenge": "test"}):
                                    with patch('function_app.session_service.create_session', return_value=True):
                                        response = create_verification_link(mock_req)
                                        
                                        # Verify security event was logged
                                        mock_log.assert_called()
    
    def test_content_type_headers_integration(self):
        """Test that proper Content-Type headers are set."""
        from function_app import health_check
        
        mock_req = self.create_mock_request()
        
        response = health_check(mock_req)
        
        # JSON endpoints should have JSON content type
        assert response.headers["Content-Type"] == "application/json"
    
    def test_cors_headers_integration(self):
        """Test CORS headers if implemented."""
        from function_app import health_check
        
        mock_req = self.create_mock_request()
        
        response = health_check(mock_req)
        
        # Verify response has required headers
        assert hasattr(response, 'headers')
        assert response.headers["Content-Type"] == "application/json"