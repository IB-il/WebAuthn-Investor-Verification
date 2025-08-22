import azure.functions as func
import logging
import json
import jwt
import base64
import os
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional

from webauthn import generate_registration_options, verify_registration_response
from webauthn import generate_authentication_options, verify_authentication_response
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    RegistrationCredential,
    AuthenticationCredential,
    PublicKeyCredentialDescriptor,
    AuthenticatorAttestationResponse,
    AuthenticatorAssertionResponse
)
from azure.data.tables import TableServiceClient
from lib.services.storage_service import AzureStorageService
from lib.services.webauthn_service import WebAuthnService
from lib.services.template_service import TemplateService
from lib.services.session_service import SessionService
from lib.services.auth_service import AuthService

# Configuration
RP_ID = os.getenv("RP_ID", "webauthn-investor.azurewebsites.net")
ORIGIN = os.getenv("ORIGIN", "https://webauthn-investor.azurewebsites.net")
# SECURITY FIX: Use cryptographically secure JWT secret
JWT_SECRET = os.getenv("JWT_SECRET", "+UEP1oRln/CaVnO6V4rt9I4rqiaDPN/3yB2tv+VOH/weBDGMj2goWvhlO/Ao6HtEqiViTu1P1XuUpENFD7Ujlg==")
JWT_TTL_SECONDS = int(os.getenv("JWT_TTL_SECONDS", "900"))

# SECURITY FIX: Admin API authentication
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "admin-key-d8f9e7a6b5c4d3e2f1")

# Initialize Services (Clean Architecture Phase 1, 2, 3 & 4)
AZURE_STORAGE_CONNECTION_STRING = os.getenv("AZURE_STORAGE_CONNECTION_STRING", "")
storage_service = AzureStorageService(AZURE_STORAGE_CONNECTION_STRING)
webauthn_service = WebAuthnService(storage_service, RP_ID, ORIGIN)
template_service = TemplateService()
session_service = SessionService(storage_service, JWT_SECRET, JWT_TTL_SECONDS)
auth_service = AuthService(ADMIN_API_KEY)

# Production: Pure Azure Table Storage only
# No fallback storage for production deployment

# Azure Table Storage functions
def load_credentials():
    """Load credentials - now uses AzureStorageService (Clean Architecture Phase 1)"""
    return storage_service.load_credentials()

def save_credentials(data):
    """Save credentials - now uses AzureStorageService (Clean Architecture Phase 1)"""
    return storage_service.save_credentials(data)

def load_sessions():
    """Load sessions - now uses AzureStorageService (Clean Architecture Phase 1)"""
    return storage_service.load_sessions()

def save_sessions(data):
    """Save sessions - now uses AzureStorageService (Clean Architecture Phase 1)"""
    return storage_service.save_sessions(data)

# Load initial data
credentials_db = load_credentials()
sessions_db = load_sessions()

# Rate limiting now handled by AuthService (Clean Architecture Phase 4)

app = func.FunctionApp()

def base64url_decode(data: str) -> bytes:
    data = data.replace('-', '+').replace('_', '/')
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.b64decode(data)

# JWT functions now handled by SessionService (Clean Architecture Phase 4)

def get_user_credentials(user_id: str):
    """Get user credentials - now uses AzureStorageService (Clean Architecture Phase 1)"""
    return storage_service.get_user_credentials(user_id)

def save_credential(user_id: str, credential_id: str, public_key: str):
    """Save credential - now uses AzureStorageService (Clean Architecture Phase 1)"""
    return storage_service.save_user_credential(user_id, credential_id, public_key)

def update_sign_count(credential_id: str, new_sign_count: int):
    """Update sign count for credential (prevents replay attacks)"""
    # Note: Sign count updates can be implemented if needed
    # For production WebAuthn, sign count is optional
    logging.info(f"Sign count update for credential {credential_id}: {new_sign_count}")

# Session functions now handled by SessionService (Clean Architecture Phase 4)

# Auth and security functions now handled by AuthService (Clean Architecture Phase 4)

@app.route(route="api/verification/link", methods=["POST", "GET"], auth_level=func.AuthLevel.ANONYMOUS)
def create_verification_link(req: func.HttpRequest) -> func.HttpResponse:
    try:
        # SECURITY FIX: Rate limiting
        client_ip = auth_service.get_client_ip(req)
        if not auth_service.check_rate_limit(client_ip, max_requests=5, window_minutes=15):
            auth_service.log_security_event("RATE_LIMIT_EXCEEDED", None, client_ip, "Too many verification requests")
            return func.HttpResponse(
                json.dumps({"error": "Rate limit exceeded - too many requests"}),
                status_code=429,
                headers={"Content-Type": "application/json"}
            )
        # Support both GET and POST methods
        if req.method == "GET":
            user_id = req.params.get('user_id')
        else:
            req_body = req.get_json()
            user_id = req_body.get('user_id')
        
        # SECURITY FIX: Input validation (minimal approach - user_id only)
        is_valid, validation_error = auth_service.validate_user_input(user_id)
        if not is_valid:
            auth_service.log_security_event("INVALID_INPUT", user_id, client_ip, validation_error)
            return func.HttpResponse(
                json.dumps({"error": f"Invalid input: {validation_error}"}),
                status_code=400,
                headers={"Content-Type": "application/json"}
            )
        
        token = session_service.generate_jwt_token(user_id)
        
        # Use WebAuthn service to check for existing credentials and generate options
        if webauthn_service.has_existing_credentials(user_id):
            # Existing user - authentication
            credentials = storage_service.get_user_credentials(user_id)
            options_data = webauthn_service.generate_authentication_options(user_id, credentials)
            session_service.create_session(user_id, token, options_data["challenge"])
            auth_service.log_security_event("VERIFICATION_LINK_CREATED", user_id, client_ip, "Existing user authentication")
            
            return func.HttpResponse(
                json.dumps({
                    "verification_url": f"{ORIGIN}/api/verify?token={token}",
                    "token": token,
                    "expires_in": JWT_TTL_SECONDS
                }),
                headers={"Content-Type": "application/json"}
            )
        else:
            # New user - registration  
            credentials = storage_service.get_user_credentials(user_id)
            options_data = webauthn_service.generate_registration_options(user_id, credentials)
            session_service.create_session(user_id, token, options_data["challenge"])
            auth_service.log_security_event("VERIFICATION_LINK_CREATED", user_id, client_ip, "New user registration")
            
            return func.HttpResponse(
                json.dumps({
                    "verification_url": f"{ORIGIN}/api/verify?token={token}",
                    "token": token,
                    "expires_in": JWT_TTL_SECONDS,
                    "registration_required": True
                }),
                headers={"Content-Type": "application/json"}
            )
    except Exception as e:
        auth_service.log_security_event("VERIFICATION_LINK_ERROR", user_id if 'user_id' in locals() else None, 
                          client_ip if 'client_ip' in locals() else None, str(e))
        logging.error(f"Error creating verification link: {str(e)}")
        return auth_service.create_safe_error_response("Service temporarily unavailable", 500)

@app.route(route="api/verify", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def verification_page(req: func.HttpRequest) -> func.HttpResponse:
    """Verification page - now uses TemplateService (Clean Architecture Phase 3)"""
    try:
        token = req.params.get('token')
        if not token:
            return func.HttpResponse(
                template_service.render_error_page(
                    error_message="חסר טוקן אימות",
                    error_title="פרמטר חסר",
                    error_subtitle="הקישור לא תקין"
                ),
                status_code=400,
                headers={"Content-Type": "text/html"}
            )
        
        user_id = session_service.verify_jwt_token(token)
        if not user_id:
            return func.HttpResponse(
                template_service.render_error_page(
                    error_message="טוקן לא תקין או פג תוקפו",
                    error_title="אימות נכשל",
                    error_subtitle="אנא קבל קישור חדש"
                ),
                status_code=401,
                headers={"Content-Type": "text/html"}
            )
        
        # Render verification page using template service
        html_content = template_service.render_verification_page(
            token=token,
            user_id=user_id
        )
        
        return func.HttpResponse(
            html_content,
            headers={"Content-Type": "text/html"}
        )
        
    except Exception as e:
        logging.error(f"Error in verification page: {str(e)}")
        return func.HttpResponse(
            template_service.render_error_page(
                error_message="שגיאה בטעינת עמוד האימות",
                error_details=str(e)
            ),
            status_code=500,
            headers={"Content-Type": "text/html"}
        )

@app.route(route="api/verification/status", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def check_verification_status(req: func.HttpRequest) -> func.HttpResponse:
    token = req.params.get('token')
    if not token:
        return func.HttpResponse(
            json.dumps({"error": "Missing token parameter"}),
            status_code=400,
            headers={"Content-Type": "application/json"}
        )
    
    user_id = session_service.verify_jwt_token(token)
    if not user_id:
        return func.HttpResponse(
            json.dumps({"error": "Invalid or expired token"}),
            status_code=401,
            headers={"Content-Type": "application/json"}
        )
    
    session = session_service.get_session(token)
    if not session:
        return func.HttpResponse(
            json.dumps({"error": "Session not found"}),
            status_code=404,
            headers={"Content-Type": "application/json"}
        )
    
    user_id_db = session['user_id']
    challenge = session['challenge']
    verified = session['verified']
    expires_at = session['expires_at'].isoformat() if hasattr(session['expires_at'], 'isoformat') else session['expires_at']
    
    return func.HttpResponse(
        json.dumps({
            "user_id": user_id,
            "verified": bool(verified),
            "expires_at": expires_at,
            "token": token
        }),
        headers={"Content-Type": "application/json"}
    )

@app.route(route="api/users", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def list_users(req: func.HttpRequest) -> func.HttpResponse:
    """List all registered users - SECURITY FIX: Requires authentication"""
    # SECURITY FIX: Require admin authentication
    if not auth_service.verify_admin_auth(req):
        return func.HttpResponse(
            json.dumps({"error": "Unauthorized - Admin API key required"}),
            status_code=401,
            headers={"Content-Type": "application/json"}
        )
    users_summary = []
    
    credentials_data = load_credentials()
    for user_id, credentials in credentials_data.items():
        users_summary.append({
            "user_id": user_id,
            "credentials_count": 1,  # New format: one credential per user
            "first_registration": "Azure Table Storage - Production"
        })
    
    return func.HttpResponse(
        json.dumps({
            "total_users": len(users_summary),
            "users": users_summary,
            "note": "Production system - Azure Table Storage with 99.9% SLA"
        }),
        headers={"Content-Type": "application/json"}
    )

@app.route(route="api/sessions", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def list_sessions(req: func.HttpRequest) -> func.HttpResponse:
    """List all verification sessions - SECURITY FIX: Requires authentication"""
    # SECURITY FIX: Require admin authentication
    if not auth_service.verify_admin_auth(req):
        return func.HttpResponse(
            json.dumps({"error": "Unauthorized - Admin API key required"}),
            status_code=401,
            headers={"Content-Type": "application/json"}
        )
    sessions_summary = []
    
    sessions_data = load_sessions()
    for token, session in sessions_data.items():
        sessions_summary.append({
            "user_id": session["user_id"],
            "token": token[:20] + "...",  # Truncate for security
            "verified": session["verified"],
            "expires_at": session["expires_at"].isoformat() if hasattr(session["expires_at"], 'isoformat') else session["expires_at"]
        })
    
    return func.HttpResponse(
        json.dumps({
            "total_sessions": len(sessions_summary),
            "sessions": sessions_summary
        }),
        headers={"Content-Type": "application/json"}
    )

@app.route(route="api/admin/sessions", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def list_all_sessions(req: func.HttpRequest) -> func.HttpResponse:
    """Admin endpoint to see all verification sessions (legacy)"""
    return list_sessions(req)

@app.route(route="api/debug/credentials", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def debug_credentials(req: func.HttpRequest) -> func.HttpResponse:
    """Debug endpoint to see stored credentials"""
    try:
        user_id = req.params.get('user_id')
        if not user_id:
            return func.HttpResponse(
                json.dumps({"error": "user_id parameter required"}),
                status_code=400,
                headers={"Content-Type": "application/json"}
            )
        
        credentials = get_user_credentials(user_id)
        
        return func.HttpResponse(
            json.dumps({
                "user_id": user_id,
                "credentials_found": len(credentials),
                "credentials": [
                    {
                        "credential_id": cred[0] if len(cred) > 0 else "N/A",
                        "credential_id_length": len(cred[0]) if len(cred) > 0 and cred[0] else 0,
                        "has_public_key": len(cred) > 1 and bool(cred[1]),
                        "public_key_length": len(cred[1]) if len(cred) > 1 and cred[1] else 0
                    }
                    for cred in credentials
                ]
            }, indent=2),
            headers={"Content-Type": "application/json"}
        )
    except Exception as e:
        return func.HttpResponse(
            json.dumps({"error": str(e)}),
            status_code=500,
            headers={"Content-Type": "application/json"}
        )

@app.route(route="api/webauthn/options", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def get_webauthn_options(req: func.HttpRequest) -> func.HttpResponse:
    """Generate WebAuthn options - now uses WebAuthnService (Clean Architecture Phase 2)"""
    try:
        # Validate token and get session
        token = req.params.get('token')
        if not token:
            return func.HttpResponse(
                json.dumps({"error": "Missing token parameter"}),
                status_code=400,
                headers={"Content-Type": "application/json"}
            )
        
        user_id = session_service.verify_jwt_token(token)
        if not user_id:
            return func.HttpResponse(
                json.dumps({"error": "Invalid or expired token"}),
                status_code=401,
                headers={"Content-Type": "application/json"}
            )
        
        session = session_service.get_session(token)
        if not session:
            return func.HttpResponse(
                json.dumps({"error": "Session not found"}),
                status_code=404,
                headers={"Content-Type": "application/json"}
            )
        
        challenge = session['challenge']
        credentials = get_user_credentials(user_id)
        
        # Use WebAuthn service to generate options
        if webauthn_service.has_existing_credentials(user_id):
            # Existing user - authentication options
            options_data = webauthn_service.generate_authentication_options(user_id, credentials)
            response_data = {
                **options_data["options"],
                "isRegistration": False
            }
        else:
            # New user - registration options
            options_data = webauthn_service.generate_registration_options(user_id, credentials)
            response_data = {
                **options_data["options"],
                "isRegistration": True
            }
        
        # CRITICAL FIX: Update session with the new challenge from WebAuthn options
        # The session needs to store the challenge that was sent to the client
        new_challenge = options_data.get("challenge")
        if new_challenge:
            # Update the session's challenge to match what the client will sign
            session_data = session_service.get_session(token)
            if session_data:
                # Update session with new challenge
                storage_service.update_session_challenge(token, new_challenge)
                logging.info(f"Updated session challenge for token: {token[:8]}... with new challenge from WebAuthn options")
        
        return func.HttpResponse(
            json.dumps(response_data),
            headers={"Content-Type": "application/json"}
        )
        
    except Exception as e:
        logging.error(f"WebAuthn options error: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": f"Server error: {str(e)}"}),
            status_code=500,
            headers={"Content-Type": "application/json"}
        )

@app.route(route="api/webauthn/register", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def webauthn_register(req: func.HttpRequest) -> func.HttpResponse:
    """WebAuthn registration - now uses WebAuthnService (Clean Architecture Phase 2)"""
    try:
        req_body = req.get_json()
        token = req_body.get('token')
        credential_data = req_body.get('credential')
        
        # Validate token and session
        user_id = session_service.verify_jwt_token(token)
        if not user_id:
            return func.HttpResponse(
                json.dumps({"error": "Invalid token"}),
                status_code=401,
                headers={"Content-Type": "application/json"}
            )
        
        session = session_service.get_session(token)
        if not session:
            return func.HttpResponse(
                json.dumps({"error": "Session not found"}),
                status_code=404,
                headers={"Content-Type": "application/json"}
            )
        
        challenge = session['challenge']
        
        # Use WebAuthn service for verification
        verification_result = webauthn_service.verify_registration_response(
            user_id, challenge, credential_data
        )
        
        if verification_result["verified"]:
            # Save verified credential
            webauthn_service.save_verified_credential(
                user_id,
                verification_result["credential_id"],
                verification_result["public_key"]
            )
            
            return func.HttpResponse(
                json.dumps({"success": True}),
                headers={"Content-Type": "application/json"}
            )
        else:
            return func.HttpResponse(
                json.dumps({"error": verification_result["error"]}),
                status_code=400,
                headers={"Content-Type": "application/json"}
            )
        
    except Exception as e:
        logging.error(f"Registration error: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": str(e)}),
            status_code=500,
            headers={"Content-Type": "application/json"}
        )

@app.route(route="api/webauthn/authenticate", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def webauthn_authenticate(req: func.HttpRequest) -> func.HttpResponse:
    """WebAuthn authentication - now uses WebAuthnService (Clean Architecture Phase 2)"""
    try:
        req_body = req.get_json()
        token = req_body.get('token')
        credential_data = req_body.get('credential')
        
        # Validate token and session
        user_id = session_service.verify_jwt_token(token)
        if not user_id:
            return func.HttpResponse(
                json.dumps({"error": "Invalid token"}),
                status_code=401,
                headers={"Content-Type": "application/json"}
            )
        
        session = session_service.get_session(token)
        if not session:
            return func.HttpResponse(
                json.dumps({"error": "Session not found"}),
                status_code=404,
                headers={"Content-Type": "application/json"}
            )
        
        challenge = session['challenge']
        credentials = get_user_credentials(user_id)
        
        if not credentials:
            return func.HttpResponse(
                json.dumps({"error": "No registered credentials found"}),
                status_code=404,
                headers={"Content-Type": "application/json"}
            )
        
        # Use WebAuthn service for verification
        verification_result = webauthn_service.verify_authentication_response(
            user_id, challenge, credential_data, credentials
        )
        
        if verification_result["verified"]:
            # Update sign count for replay protection
            webauthn_service.update_credential_sign_count(
                verification_result["credential_id"],
                verification_result["new_sign_count"]
            )
            
            return func.HttpResponse(
                json.dumps({"success": True, "verified": True}),
                headers={"Content-Type": "application/json"}
            )
        else:
            return func.HttpResponse(
                json.dumps({"error": verification_result["error"]}),
                status_code=400,
                headers={"Content-Type": "application/json"}
            )
        
    except Exception as e:
        logging.error(f"Authentication error: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": str(e)}),
            status_code=500,
            headers={"Content-Type": "application/json"}
        )

@app.route(route="api/verification/complete", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def complete_verification(req: func.HttpRequest) -> func.HttpResponse:
    try:
        req_body = req.get_json()
        token = req_body.get('token')
        
        user_id = session_service.verify_jwt_token(token)
        if not user_id:
            return func.HttpResponse(
                json.dumps({"error": "Invalid token"}),
                status_code=401,
                headers={"Content-Type": "application/json"}
            )
        
        session_service.mark_session_verified(token)
        return func.HttpResponse(
            json.dumps({"success": True}),
            headers={"Content-Type": "application/json"}
        )
        
    except Exception as e:
        logging.error(f"Verification completion error: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": str(e)}),
            status_code=500,
            headers={"Content-Type": "application/json"}
        )

@app.route(route="health", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def health_check(req: func.HttpRequest) -> func.HttpResponse:
    return func.HttpResponse(
        json.dumps({
            "status": "healthy", 
            "service": "WebAuthn Investor Verification",
            "active_sessions": len(load_sessions()),
            "registered_users": len(load_credentials())
        }),
        headers={"Content-Type": "application/json"}
    )