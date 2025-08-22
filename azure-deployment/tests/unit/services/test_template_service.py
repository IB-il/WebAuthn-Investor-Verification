"""
Unit tests for TemplateService - Clean Architecture Phase 5

Tests Jinja2 template rendering with Hebrew RTL support.
"""

import pytest
import tempfile
import os
from unittest.mock import patch, Mock
from jinja2 import TemplateNotFound

from lib.services.template_service import TemplateService


@pytest.mark.unit
@pytest.mark.template
class TestTemplateService:
    """Test cases for TemplateService."""
    
    def test_initialization_default_directory(self):
        """Test TemplateService initialization with default directory."""
        service = TemplateService()
        
        assert service.template_dir == "templates"
        assert service.env is not None
    
    def test_initialization_custom_directory(self):
        """Test TemplateService initialization with custom directory."""
        custom_dir = "custom_templates"
        service = TemplateService(template_dir=custom_dir)
        
        assert service.template_dir == custom_dir
    
    @patch('lib.services.template_service.Environment')
    def test_initialization_error_handling(self, mock_env):
        """Test TemplateService initialization error handling."""
        mock_env.side_effect = Exception("Jinja2 error")
        
        with pytest.raises(Exception):
            TemplateService()
    
    def test_format_hebrew_text(self, template_service):
        """Test Hebrew text formatting."""
        hebrew_text = "שלום עולם"
        formatted = template_service._format_hebrew_text(hebrew_text)
        
        assert formatted == "שלום עולם"
    
    def test_format_hebrew_text_empty(self, template_service):
        """Test Hebrew text formatting with empty string."""
        formatted = template_service._format_hebrew_text("")
        
        assert formatted == ""
    
    def test_format_hebrew_text_whitespace(self, template_service):
        """Test Hebrew text formatting with whitespace."""
        hebrew_text = "  שלום עולם  "
        formatted = template_service._format_hebrew_text(hebrew_text)
        
        assert formatted == "שלום עולם"  # Should be stripped
    
    def test_safe_default_with_value(self, template_service):
        """Test safe default filter with valid value."""
        result = template_service._safe_default("test_value", "default")
        
        assert result == "test_value"
    
    def test_safe_default_with_none(self, template_service):
        """Test safe default filter with None value."""
        result = template_service._safe_default(None, "default")
        
        assert result == "default"
    
    def test_safe_default_with_empty_string(self, template_service):
        """Test safe default filter with empty string."""
        result = template_service._safe_default("", "default")
        
        assert result == "default"
    
    def test_safe_default_with_whitespace(self, template_service):
        """Test safe default filter with whitespace."""
        result = template_service._safe_default("   ", "default")
        
        assert result == "default"
    
    def test_render_template_success(self, template_service):
        """Test successful template rendering."""
        context = {"name": "Test User"}
        
        result = template_service.render_template("test.html", context)
        
        assert "Hello Test User!" in result
        assert "<!DOCTYPE html>" in result
    
    def test_render_template_not_found(self, template_service):
        """Test template rendering with non-existent template."""
        context = {"name": "Test User"}
        
        with pytest.raises(TemplateNotFound):
            template_service.render_template("nonexistent.html", context)
    
    def test_render_template_no_environment(self):
        """Test template rendering without initialized environment."""
        service = TemplateService()
        service.env = None
        
        with pytest.raises(RuntimeError, match="Template environment not initialized"):
            service.render_template("test.html", {})
    
    def test_render_verification_page(self, template_service):
        """Test verification page rendering."""
        token = "test_jwt_token"
        
        # This will fallback to error page since verification.html doesn't exist in test setup
        result = template_service.render_verification_page(token, user_id="test_user")
        
        assert isinstance(result, str)
        assert len(result) > 0
    
    def test_render_verification_page_with_kwargs(self, template_service):
        """Test verification page rendering with additional kwargs."""
        token = "test_jwt_token"
        
        result = template_service.render_verification_page(
            token,
            user_id="test_user",
            custom_field="custom_value"
        )
        
        assert isinstance(result, str)
    
    def test_render_error_page_basic(self, template_service):
        """Test basic error page rendering."""
        result = template_service.render_error_page(
            error_message="Test error message",
            error_title="Test Error"
        )
        
        assert isinstance(result, str)
        assert len(result) > 0
    
    def test_render_error_page_with_details(self, template_service):
        """Test error page rendering with technical details."""
        result = template_service.render_error_page(
            error_message="Database connection failed",
            error_title="Connection Error",
            error_details="Connection timeout after 30 seconds"
        )
        
        assert isinstance(result, str)
        assert len(result) > 0
    
    def test_render_error_page_auto_refresh(self, template_service):
        """Test error page rendering with auto-refresh enabled."""
        result = template_service.render_error_page(
            error_message="Service temporarily unavailable",
            auto_refresh=True
        )
        
        assert isinstance(result, str)
        assert len(result) > 0
    
    def test_render_error_page_hebrew_messages(self, template_service, hebrew_test_data):
        """Test error page rendering with Hebrew messages."""
        result = template_service.render_error_page(
            error_message=hebrew_test_data["error_message"],
            error_title="שגיאה",
            error_subtitle="נסה שוב"
        )
        
        assert isinstance(result, str)
        assert hebrew_test_data["error_message"] in result
    
    def test_render_error_page_fallback(self, template_service):
        """Test error page fallback when template rendering fails."""
        # Mock template rendering to fail
        with patch.object(template_service, 'render_template', side_effect=Exception("Template error")):
            result = template_service.render_error_page("Test error")
            
            # Should return fallback HTML
            assert isinstance(result, str)
            assert "<!DOCTYPE html>" in result
            assert "Test error" in result
    
    def test_render_fallback_error_basic(self, template_service):
        """Test fallback error rendering."""
        result = template_service._render_fallback_error("Basic error")
        
        assert "<!DOCTYPE html>" in result
        assert "Basic error" in result
        assert "lang=\"he\"" in result  # Hebrew RTL
        assert "dir=\"rtl\"" in result
    
    def test_render_fallback_error_with_details(self, template_service):
        """Test fallback error rendering with details."""
        result = template_service._render_fallback_error(
            message="Error occurred",
            details="Stack trace details"
        )
        
        assert "Error occurred" in result
        assert "Stack trace details" in result
    
    def test_render_fallback_error_default_message(self, template_service):
        """Test fallback error rendering with default message."""
        result = template_service._render_fallback_error()
        
        assert "אירעה שגיאה במערכת" in result  # Hebrew default message
    
    def test_get_template_path(self, template_service):
        """Test template path resolution.""" 
        template_name = "test.html"
        
        path = template_service.get_template_path(template_name)
        
        assert isinstance(path, str)
        assert template_name in path
    
    def test_template_exists_true(self, template_service):
        """Test template existence checking for existing template."""
        exists = template_service.template_exists("test.html")
        
        assert exists is True
    
    def test_template_exists_false(self, template_service):
        """Test template existence checking for non-existent template."""
        exists = template_service.template_exists("nonexistent.html")
        
        assert exists is False
    
    def test_template_exists_no_environment(self, template_service):
        """Test template existence checking without environment."""
        template_service.env = None
        
        exists = template_service.template_exists("test.html")
        
        assert exists is False
    
    def test_template_exists_exception_handling(self, template_service):
        """Test template existence checking exception handling."""
        with patch.object(template_service.env, 'get_template', side_effect=Exception("Template error")):
            exists = template_service.template_exists("test.html")
            
            assert exists is False
    
    def test_list_templates(self, template_service):
        """Test template listing."""
        templates = template_service.list_templates()
        
        assert isinstance(templates, list)
        # Should contain our test templates
        assert "test.html" in templates or "base.html" in templates
    
    def test_list_templates_no_environment(self, template_service):
        """Test template listing without environment."""
        template_service.env = None
        
        templates = template_service.list_templates()
        
        assert templates == []
    
    def test_list_templates_no_list_method(self, template_service):
        """Test template listing without list_templates method."""
        # Mock loader without list_templates method
        mock_loader = Mock()
        del mock_loader.list_templates
        template_service.env.loader = mock_loader
        
        templates = template_service.list_templates()
        
        assert templates == []
    
    def test_list_templates_exception_handling(self, template_service):
        """Test template listing exception handling."""
        with patch.object(template_service.env.loader, 'list_templates', side_effect=Exception("List error")):
            templates = template_service.list_templates()
            
            assert templates == []
    
    @patch('logging.info')
    def test_logging_template_render_success(self, mock_log, template_service):
        """Test successful template rendering logging."""
        context = {"name": "Test User"}
        
        template_service.render_template("test.html", context)
        
        # Verify info logging was called
        mock_log.assert_called()
        log_message = mock_log.call_args[0][0]
        assert "Successfully rendered template: test.html" in log_message
    
    @patch('logging.error')
    def test_logging_template_render_error(self, mock_log, template_service):
        """Test template rendering error logging.""" 
        with pytest.raises(TemplateNotFound):
            template_service.render_template("nonexistent.html", {})
        
        # Verify error logging was called
        mock_log.assert_called()
        log_message = mock_log.call_args[0][0]
        assert "Template not found: nonexistent.html" in log_message
    
    def test_context_injection_verification_page(self, template_service):
        """Test context variable injection in verification page."""
        token = "test_token"
        user_id = "test_user"
        
        # Mock render_template to capture context
        with patch.object(template_service, 'render_template') as mock_render:
            mock_render.return_value = "rendered_content"
            
            result = template_service.render_verification_page(token, user_id=user_id)
            
            # Verify context was passed correctly
            mock_render.assert_called_once()
            call_args = mock_render.call_args
            context = call_args[0][1]
            
            assert context["token"] == token
            assert context["user_id"] == user_id
            assert context["company_name"] == "אינטרקטיב ישראל"
    
    def test_context_injection_error_page(self, template_service):
        """Test context variable injection in error page."""
        error_message = "Test error"
        error_title = "Test Error Title"
        
        # Mock render_template to capture context
        with patch.object(template_service, 'render_template') as mock_render:
            mock_render.return_value = "rendered_content"
            
            result = template_service.render_error_page(
                error_message=error_message,
                error_title=error_title
            )
            
            # Verify context was passed correctly
            mock_render.assert_called_once()
            call_args = mock_render.call_args
            context = call_args[0][1]
            
            assert context["error_message"] == error_message
            assert context["error_title"] == error_title
            assert "explanation_1" in context
            assert "explanation_2" in context
            assert "explanation_3" in context
    
    def test_hebrew_rtl_support(self, template_service):
        """Test Hebrew RTL support in templates."""
        # Test fallback error which includes Hebrew RTL
        result = template_service._render_fallback_error("בדיקה")
        
        assert "lang=\"he\"" in result
        assert "dir=\"rtl\"" in result
        assert "בדיקה" in result
    
    def test_security_auto_escaping(self, template_service, malicious_input_data):
        """Test that Jinja2 auto-escaping prevents XSS."""
        # Use the variable name that the test template expects
        context = {"name": malicious_input_data["xss_script"]}
        
        result = template_service.render_template("test.html", context)
        
        # XSS should be escaped, not executed
        assert "&lt;script&gt;" in result or "Hello &lt;script" in result
        assert "<script>alert('xss')</script>" not in result
    
    @patch('os.path.join')
    def test_template_path_construction(self, mock_join, template_service):
        """Test template path construction."""
        mock_join.return_value = "/mocked/path/templates"
        
        path = template_service.get_template_path("test.html")
        
        mock_join.assert_called()
        # Should include template directory and template name
        call_args = mock_join.call_args[0]
        assert "test.html" in call_args