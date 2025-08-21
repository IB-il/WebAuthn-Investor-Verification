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

# Configuration
RP_ID = os.getenv("RP_ID", "webauthn-investor.azurewebsites.net")
ORIGIN = os.getenv("ORIGIN", "https://webauthn-investor.azurewebsites.net")
# SECURITY FIX: Use cryptographically secure JWT secret
JWT_SECRET = os.getenv("JWT_SECRET", "+UEP1oRln/CaVnO6V4rt9I4rqiaDPN/3yB2tv+VOH/weBDGMj2goWvhlO/Ao6HtEqiViTu1P1XuUpENFD7Ujlg==")
JWT_TTL_SECONDS = int(os.getenv("JWT_TTL_SECONDS", "900"))

# SECURITY FIX: Admin API authentication
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "admin_" + os.urandom(32).hex())

# In-memory storage (use Azure Table Storage or CosmosDB for production)
credentials_db = {}
sessions_db = {}

# SECURITY FIX: Rate limiting storage
rate_limit_db = {}  # IP -> {count, reset_time}

app = func.FunctionApp()

def base64url_decode(data: str) -> bytes:
    data = data.replace('-', '+').replace('_', '/')
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.b64decode(data)

def generate_jwt_token(user_id: str) -> str:
    payload = {
        "user_id": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(seconds=JWT_TTL_SECONDS),
        "iat": datetime.now(timezone.utc)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def verify_jwt_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload.get("user_id")
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

def get_user_credentials(user_id: str):
    return credentials_db.get(user_id, [])

def save_credential(user_id: str, credential_id: str, public_key: str):
    if user_id not in credentials_db:
        credentials_db[user_id] = []
    credentials_db[user_id].append((credential_id, public_key, 0))

def update_sign_count(credential_id: str, new_sign_count: int):
    """Update sign count for credential (prevents replay attacks)"""
    for user_id, credentials in credentials_db.items():
        for i, (cred_id, public_key, old_count) in enumerate(credentials):
            if cred_id == credential_id:
                credentials_db[user_id][i] = (cred_id, public_key, new_sign_count)
                return
    logging.warning(f"Credential {credential_id} not found for sign count update")

def create_session(user_id: str, token: str, challenge: str):
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=JWT_TTL_SECONDS)
    sessions_db[token] = {
        "user_id": user_id,
        "challenge": challenge,
        "verified": False,
        "expires_at": expires_at
    }

def get_session(token: str):
    session = sessions_db.get(token)
    if session:
        return (session["user_id"], session["challenge"], session["verified"], session["expires_at"].isoformat())
    return None

def mark_session_verified(token: str):
    if token in sessions_db:
        sessions_db[token]["verified"] = True

def verify_admin_auth(req: func.HttpRequest) -> bool:
    """SECURITY FIX: Verify admin API key authentication"""
    auth_header = req.headers.get('Authorization')
    if not auth_header:
        return False
    
    if not auth_header.startswith('Bearer '):
        return False
        
    api_key = auth_header[7:]  # Remove 'Bearer ' prefix
    return api_key == ADMIN_API_KEY

def check_rate_limit(client_ip: str, max_requests: int = 10, window_minutes: int = 15) -> bool:
    """SECURITY FIX: Rate limiting to prevent abuse"""
    import time
    
    current_time = time.time()
    window_start = current_time - (window_minutes * 60)
    
    if client_ip not in rate_limit_db:
        rate_limit_db[client_ip] = {"count": 1, "reset_time": current_time + (window_minutes * 60)}
        return True
    
    rate_data = rate_limit_db[client_ip]
    
    # Reset if window expired
    if current_time > rate_data["reset_time"]:
        rate_limit_db[client_ip] = {"count": 1, "reset_time": current_time + (window_minutes * 60)}
        return True
    
    # Check if under limit
    if rate_data["count"] < max_requests:
        rate_limit_db[client_ip]["count"] += 1
        return True
    
    return False  # Rate limited

def validate_user_input(user_id: str, username: str) -> tuple[bool, str]:
    """SECURITY FIX: Input validation and sanitization"""
    import re
    
    if not user_id or not username:
        return False, "user_id and username are required"
    
    if len(user_id) > 100 or len(username) > 100:
        return False, "user_id and username must be under 100 characters"
    
    # Allow alphanumeric, underscores, hyphens, dots, @ for email
    if not re.match(r'^[a-zA-Z0-9._@-]+$', user_id):
        return False, "user_id contains invalid characters"
        
    if not re.match(r'^[a-zA-Z0-9._@\s-]+$', username):
        return False, "username contains invalid characters"
    
    return True, ""

def log_security_event(event_type: str, user_id: str = None, client_ip: str = None, details: str = None):
    """SECURITY FIX: Enhanced security logging"""
    timestamp = datetime.now(timezone.utc).isoformat()
    
    # Hash sensitive data for privacy
    user_hash = hashlib.sha256(user_id.encode()).hexdigest()[:8] if user_id else "unknown"
    ip_hash = hashlib.sha256(client_ip.encode()).hexdigest()[:8] if client_ip else "unknown"
    
    log_entry = {
        "timestamp": timestamp,
        "event_type": event_type,
        "user_hash": user_hash,
        "ip_hash": ip_hash,
        "details": details
    }
    
    logging.warning(f"SECURITY_EVENT: {json.dumps(log_entry)}")

def safe_error_response(error_message: str, status_code: int = 400) -> func.HttpResponse:
    """SECURITY FIX: Sanitized error responses that don't leak information"""
    # Map internal errors to safe user messages
    safe_errors = {
        "WebAuthn verification failed": "Biometric verification failed. Please try again.",
        "Authentication verification failed": "Authentication failed. Please try again.",
        "Session not found": "Session expired. Please start over.",
        "Invalid token": "Session invalid or expired.",
        "Credential not registered": "Device not recognized. Please register first."
    }
    
    safe_message = safe_errors.get(error_message, "Verification failed. Please try again.")
    
    return func.HttpResponse(
        json.dumps({"error": safe_message}),
        status_code=status_code,
        headers={"Content-Type": "application/json"}
    )

@app.route(route="api/verification/link", methods=["POST", "GET"], auth_level=func.AuthLevel.ANONYMOUS)
def create_verification_link(req: func.HttpRequest) -> func.HttpResponse:
    try:
        # SECURITY FIX: Rate limiting
        client_ip = req.headers.get('X-Forwarded-For', 'unknown').split(',')[0].strip()
        if not check_rate_limit(client_ip, max_requests=5, window_minutes=15):
            log_security_event("RATE_LIMIT_EXCEEDED", None, client_ip, "Too many verification requests")
            return func.HttpResponse(
                json.dumps({"error": "Rate limit exceeded - too many requests"}),
                status_code=429,
                headers={"Content-Type": "application/json"}
            )
        # Support both GET and POST methods
        if req.method == "GET":
            user_id = req.params.get('user_id')
            username = req.params.get('username')
        else:
            req_body = req.get_json()
            user_id = req_body.get('user_id')
            username = req_body.get('username')
        
        # SECURITY FIX: Input validation
        is_valid, validation_error = validate_user_input(user_id, username)
        if not is_valid:
            log_security_event("INVALID_INPUT", user_id, client_ip, validation_error)
            return func.HttpResponse(
                json.dumps({"error": f"Invalid input: {validation_error}"}),
                status_code=400,
                headers={"Content-Type": "application/json"}
            )
        
        token = generate_jwt_token(user_id)
        credentials = get_user_credentials(user_id)
        
        if credentials:
            # Existing user - authentication
            options = generate_authentication_options(
                rp_id=RP_ID,
                allow_credentials=[
                    PublicKeyCredentialDescriptor(id=base64.b64decode(cred[0]))
                    for cred in credentials
                ],
                user_verification=UserVerificationRequirement.REQUIRED
            )
            create_session(user_id, token, base64.b64encode(options.challenge).decode())
            log_security_event("VERIFICATION_LINK_CREATED", user_id, client_ip, "Existing user authentication")
            
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
            options = generate_registration_options(
                rp_id=RP_ID,
                rp_name="Investor Verification",
                user_id=user_id.encode(),
                user_name=username,
                user_display_name=username,
                authenticator_selection=AuthenticatorSelectionCriteria(
                    user_verification=UserVerificationRequirement.REQUIRED
                )
            )
            create_session(user_id, token, base64.b64encode(options.challenge).decode())
            log_security_event("VERIFICATION_LINK_CREATED", user_id, client_ip, "New user registration")
            
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
        log_security_event("VERIFICATION_LINK_ERROR", user_id if 'user_id' in locals() else None, 
                          client_ip if 'client_ip' in locals() else None, str(e))
        logging.error(f"Error creating verification link: {str(e)}")
        return safe_error_response("Service temporarily unavailable", 500)

@app.route(route="api/verify", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def verification_page(req: func.HttpRequest) -> func.HttpResponse:
    token = req.params.get('token')
    if not token:
        return func.HttpResponse("Missing token", status_code=400)
    
    user_id = verify_jwt_token(token)
    if not user_id:
        return func.HttpResponse("Invalid or expired token", status_code=401)
    
    # Return Interactive Israel styled page with Hebrew support
    html_content = f'''
<!DOCTYPE html>
<html lang="he" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>אימות משקיע מאובטח - אינטרקטיב ישראל</title>
    <link href="https://fonts.googleapis.com/css2?family=Assistant:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Assistant', 'Heebo', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #ffffff;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            line-height: 1.6;
            direction: rtl;
        }}
        
        /* Header with logo */
        .header {{
            background: #ffffff;
            padding: 20px 0;
            border-bottom: 1px solid #e5e7eb;
            position: sticky;
            top: 0;
            z-index: 100;
        }}
        
        .header-content {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        
        .company-logo {{
            display: flex;
            align-items: center;
            gap: 16px;
        }}
        
        .logo-img {{
            height: 60px;
            width: auto;
        }}
        
        .company-name {{
            font-size: 28px;
            font-weight: 700;
            color: #303e90;
            font-family: 'Assistant', sans-serif;
        }}
        
        .security-badge {{
            display: flex;
            align-items: center;
            gap: 8px;
            background: #f0f9ff;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 14px;
            color: #0369a1;
            font-weight: 500;
        }}
        
        /* Main content */
        .main-container {{
            flex: 1;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 40px 20px;
            background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%);
        }}
        
        .verification-card {{
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.08);
            padding: 48px 40px;
            max-width: 480px;
            width: 100%;
            text-align: center;
            border: 1px solid #e5e7eb;
        }}
        
        .verification-icon {{
            margin: 0 auto 24px;
            padding: 16px 24px;
            background: linear-gradient(135deg, #303e90 0%, #4f46e5 100%);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 18px;
            font-weight: 600;
            box-shadow: 0 8px 24px rgba(48, 62, 144, 0.2);
            font-family: 'Assistant', sans-serif;
            width: fit-content;
        }}
        
        .main-heading {{
            font-size: 50px;
            font-weight: 700;
            color: #303e90;
            margin-bottom: 16px;
            font-family: 'Assistant', sans-serif;
            text-align: center;
        }}
        
        .subheading {{
            font-size: 19px;
            color: #555;
            margin-bottom: 32px;
            font-weight: 400;
            text-align: center;
        }}
        
        .status-container {{
            background: #f8fafc;
            border: 2px solid #e2e8f0;
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 32px;
            transition: all 0.3s ease;
        }}
        
        .status-container.info {{
            background: #f0f9ff;
            border-color: #7dd3fc;
            color: #0369a1;
        }}
        
        .status-container.success {{
            background: #f0fdf4;
            border-color: #86efac;
            color: #166534;
        }}
        
        .status-container.error {{
            background: #fef2f2;
            border-color: #fca5a5;
            color: #dc2626;
        }}
        
        .status-text {{
            font-size: 16px;
            font-weight: 500;
            margin-bottom: 8px;
        }}
        
        .status-subtitle {{
            font-size: 14px;
            opacity: 0.8;
        }}
        
        .biometric-icons {{
            display: flex;
            justify-content: center;
            gap: 24px;
            margin: 24px 0;
        }}
        
        .biometric-icon {{
            width: 48px;
            height: 48px;
            background: #f8fafc;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            opacity: 0.6;
            transition: all 0.3s ease;
        }}
        
        .biometric-icon.active {{
            background: linear-gradient(135deg, #303e90 0%, #db1222 100%);
            color: white;
            opacity: 1;
            transform: scale(1.1);
        }}
        
        .verify-button {{
            background: #303e90;
            color: white;
            border: none;
            padding: 20px 40px;
            border-radius: 5px;
            font-size: 19px;
            font-weight: 600;
            cursor: pointer;
            width: 100%;
            transition: all 0.3s ease;
            box-shadow: 0 2px 8px rgba(48, 62, 144, 0.2);
            position: relative;
            font-family: 'Assistant', sans-serif;
        }}
        
        .verify-button:hover:not(:disabled) {{
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(48, 62, 144, 0.3);
        }}
        
        .verify-button:active {{
            transform: translateY(0);
        }}
        
        .verify-button:disabled {{
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }}
        
        .security-notice {{
            margin-top: 32px;
            padding: 20px;
            background: #f8fafc;
            border-radius: 8px;
            font-size: 14px;
            color: #6b7280;
            text-align: left;
        }}
        
        .security-notice h4 {{
            color: #374151;
            font-weight: 600;
            margin-bottom: 8px;
        }}
        
        .security-points {{
            list-style: none;
            margin: 12px 0;
        }}
        
        .security-points li {{
            padding: 4px 0;
            position: relative;
            padding-left: 20px;
        }}
        
        .security-points li:before {{
            content: "🔒";
            position: absolute;
            left: 0;
            font-size: 12px;
        }}
        
        /* Mobile optimizations */
        @media (max-width: 640px) {{
            .header-content {{
                padding: 0 16px;
            }}
            
            .company-name {{
                font-size: 20px;
            }}
            
            .verification-card {{
                margin: 20px;
                padding: 32px 24px;
            }}
            
            .main-heading {{
                font-size: 28px;
            }}
            
            .subheading {{
                font-size: 16px;
            }}
        }}
    </style>
</head>
<body>
    <header class="header">
        <div class="header-content">
            <div class="company-logo">
                <img src="https://www.inter-il.com/wp-content/uploads/2025/03/Screenshot-2025-03-26-161501.png" 
                     alt="אינטרקטיב ישראל לוגו" class="logo-img">
            </div>
            <div class="security-badge">
                🔒 אבטחה ברמה בנקאית
            </div>
        </div>
    </header>
    
    <main class="main-container">
        <div class="verification-card">
            <div class="verification-icon">אינטרקטיב ישראל</div>
            
            <h1 class="main-heading">אימות זהות</h1>
            <p class="subheading">אבטח את חשבון ההשקעות שלך באמצעות אימות ביומטרי</p>
            
            <div id="status" class="status-container">
                <div class="status-text">מוכן לאימות הזהות שלך</div>
                <div class="status-subtitle">השתמש באימות הביומטרי של המכשיר שלך</div>
            </div>
            
            <div class="biometric-icons">
                <div class="biometric-icon">📱</div>
                <div class="biometric-icon">👆</div>
                <div class="biometric-icon">👤</div>
            </div>
            
            <button id="verifyBtn" class="verify-button" onclick="startVerification()">
                אמת את הזהות שלי
            </button>
            
            <div class="security-notice">
                <h4>האבטחה והפרטיות שלך</h4>
                <ul class="security-points">
                    <li>הנתונים הביומטריים שלך לא יוצאים מהמכשיר שלך</li>
                    <li>הצפנה ברמה בנקאית מגנה על כל התקשורת</li>
                    <li>האימות מסתיים תוך שניות, לא דקות</li>
                </ul>
            </div>
        </div>
    </main>

    <script>
        const token = "{token}";
        
        function showStatus(message, subtitle = '', type = 'info') {{
            const statusContainer = document.getElementById('status');
            const statusText = statusContainer.querySelector('.status-text') || statusContainer;
            const statusSubtitle = statusContainer.querySelector('.status-subtitle');
            
            statusText.textContent = message;
            if (statusSubtitle && subtitle) {{
                statusSubtitle.textContent = subtitle;
            }}
            
            // Remove all status classes
            statusContainer.classList.remove('info', 'success', 'error');
            // Add the appropriate class
            statusContainer.classList.add(type);
            
            // Animate biometric icons based on status
            const icons = document.querySelectorAll('.biometric-icon');
            icons.forEach((icon, index) => {{
                setTimeout(() => {{
                    if (type === 'info' && message.includes('biometric')) {{
                        icon.classList.add('active');
                    }} else {{
                        icon.classList.remove('active');
                    }}
                }}, index * 200);
            }});
        }}
        
        function showSuccess(message, subtitle = 'האימות הושלם בהצלחה') {{
            showStatus(message, subtitle, 'success');
            
            const button = document.getElementById('verifyBtn');
            button.innerHTML = '✓ הזהות אומתה';
            button.disabled = true;
            
            // Celebrate with all icons active
            document.querySelectorAll('.biometric-icon').forEach(icon => {{
                icon.classList.add('active');
            }});
        }}
        
        function showError(message, subtitle = 'אנא נסה שוב') {{
            showStatus(message, subtitle, 'error');
            document.getElementById('verifyBtn').disabled = false;
        }}
        
        async function startVerification() {{
            if (!window.PublicKeyCredential) {{
                showError('אימות ביומטרי לא נתמך', 'המכשיר הזה לא תומך באימות ביומטרי');
                return;
            }}
            
            showStatus('מכין אימות ביומטרי...', 'מתחבר לשרת מאובטח');
            document.getElementById('verifyBtn').disabled = true;
            
            try {{
                // Get WebAuthn options from server
                const optionsResponse = await fetch(`/api/webauthn/options?token={token}`);
                if (!optionsResponse.ok) {{
                    throw new Error('החיבור לשרת נכשל');
                }}
                
                const options = await optionsResponse.json();
                
                // Convert base64url to ArrayBuffer for WebAuthn
                function base64urlToBuffer(base64url) {{
                    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
                    const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
                    const binary = atob(padded);
                    const buffer = new ArrayBuffer(binary.length);
                    const view = new Uint8Array(buffer);
                    for (let i = 0; i < binary.length; i++) {{
                        view[i] = binary.charCodeAt(i);
                    }}
                    return buffer;
                }}
                
                function bufferToBase64url(buffer) {{
                    const binary = String.fromCharCode(...new Uint8Array(buffer));
                    const base64 = btoa(binary);
                    return base64.replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=/g, '');
                }}
                
                // If this is registration (new user)
                if (options.isRegistration) {{
                    const publicKeyCredentialCreationOptions = {{
                        challenge: base64urlToBuffer(options.challenge),
                        rp: options.rp,
                        user: {{
                            ...options.user,
                            id: base64urlToBuffer(options.user.id)
                        }},
                        pubKeyCredParams: options.pubKeyCredParams,
                        authenticatorSelection: options.authenticatorSelection,
                        timeout: 60000,
                        attestation: options.attestation || 'none'
                    }};
                    
                    showStatus('השלם אימות ביומטרי', 'גע בחיישן טביעת האצבע או השתמש ב-Face ID', 'info');
                    const credential = await navigator.credentials.create({{
                        publicKey: publicKeyCredentialCreationOptions
                    }});
                    
                    // Send registration result to server
                    const registrationResponse = await fetch(`/api/webauthn/register`, {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify({{
                            token: token,
                            credential: {{
                                id: credential.id,
                                rawId: bufferToBase64url(credential.rawId),
                                type: credential.type,
                                response: {{
                                    clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
                                    attestationObject: bufferToBase64url(credential.response.attestationObject)
                                }}
                            }}
                        }})
                    }});
                    
                    if (registrationResponse.ok) {{
                        showSuccess('הזהות אומתה בהצלחה!', 'הרישום הביומטרי שלך נרשם בהצלחה');
                        // Update server that verification is complete
                        await fetch(`/api/verification/complete`, {{
                            method: 'POST',
                            headers: {{ 'Content-Type': 'application/json' }},
                            body: JSON.stringify({{ token: token }})
                        }});
                    }} else {{
                        throw new Error('רישום הרישום הביומטרי נכשל');
                    }}
                }} else {{
                    // Authentication for existing user
                    const publicKeyCredentialRequestOptions = {{
                        challenge: base64urlToBuffer(options.challenge),
                        allowCredentials: options.allowCredentials ? options.allowCredentials.map(cred => ({{
                            ...cred,
                            id: base64urlToBuffer(cred.id)
                        }})) : [],
                        userVerification: options.userVerification || 'required',
                        timeout: 60000
                    }};
                    
                    showStatus('אמת בביומטריה', 'השתמש בטביעת האצבע הרשומה או ב-Face ID', 'info');
                    const credential = await navigator.credentials.get({{
                        publicKey: publicKeyCredentialRequestOptions
                    }});
                    
                    // Send authentication result to server
                    const authResponse = await fetch(`/api/webauthn/authenticate`, {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify({{
                            token: token,
                            credential: {{
                                id: credential.id,
                                rawId: bufferToBase64url(credential.rawId),
                                type: credential.type,
                                response: {{
                                    clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
                                    authenticatorData: bufferToBase64url(credential.response.authenticatorData),
                                    signature: bufferToBase64url(credential.response.signature),
                                    userHandle: credential.response.userHandle ? bufferToBase64url(credential.response.userHandle) : null
                                }}
                            }}
                        }})
                    }});
                    
                    if (authResponse.ok) {{
                        showSuccess('ברוך השב!', 'האימות הושלם בהצלחה');
                        // Update server that verification is complete
                        await fetch(`/api/verification/complete`, {{
                            method: 'POST',
                            headers: {{ 'Content-Type': 'application/json' }},
                            body: JSON.stringify({{ token: token }})
                        }});
                    }} else {{
                        throw new Error('אימות הזהות נכשל');
                    }}
                }}
                
            }} catch (error) {{
                console.error('WebAuthn error:', error);
                if (error.name === 'NotAllowedError') {{
                    showError('האימות בוטל', 'ביטלת את האימות הביומטרי');
                }} else if (error.name === 'InvalidStateError') {{
                    showError('המכשיר לא מוכן', 'אנא וודא שהאימות הביומטרי מופעל');
                }} else {{
                    showError('האימות נכשל', error.message);
                }}
                document.getElementById('verifyBtn').disabled = false;
            }}
        }}
        
        // Initialize
        showStatus('מוכן לאימות הזהות שלך', 'הקש על הכפתור למטה כדי להתחיל');
    </script>
</body>
</html>
    '''
    
    return func.HttpResponse(
        html_content,
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
    
    user_id = verify_jwt_token(token)
    if not user_id:
        return func.HttpResponse(
            json.dumps({"error": "Invalid or expired token"}),
            status_code=401,
            headers={"Content-Type": "application/json"}
        )
    
    session = get_session(token)
    if not session:
        return func.HttpResponse(
            json.dumps({"error": "Session not found"}),
            status_code=404,
            headers={"Content-Type": "application/json"}
        )
    
    user_id_db, challenge, verified, expires_at = session
    
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
    if not verify_admin_auth(req):
        return func.HttpResponse(
            json.dumps({"error": "Unauthorized - Admin API key required"}),
            status_code=401,
            headers={"Content-Type": "application/json"}
        )
    users_summary = []
    
    for user_id, credentials in credentials_db.items():
        users_summary.append({
            "user_id": user_id,
            "credentials_count": len(credentials),
            "first_registration": "stored in memory - demo only"
        })
    
    return func.HttpResponse(
        json.dumps({
            "total_users": len(users_summary),
            "users": users_summary,
            "note": "Demo system - data stored in memory only"
        }),
        headers={"Content-Type": "application/json"}
    )

@app.route(route="api/sessions", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def list_sessions(req: func.HttpRequest) -> func.HttpResponse:
    """List all verification sessions - SECURITY FIX: Requires authentication"""
    # SECURITY FIX: Require admin authentication
    if not verify_admin_auth(req):
        return func.HttpResponse(
            json.dumps({"error": "Unauthorized - Admin API key required"}),
            status_code=401,
            headers={"Content-Type": "application/json"}
        )
    sessions_summary = []
    
    for token, session in sessions_db.items():
        sessions_summary.append({
            "user_id": session["user_id"],
            "token": token[:20] + "...",  # Truncate for security
            "verified": session["verified"],
            "expires_at": session["expires_at"].isoformat()
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

@app.route(route="api/webauthn/options", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def get_webauthn_options(req: func.HttpRequest) -> func.HttpResponse:
    token = req.params.get('token')
    if not token:
        return func.HttpResponse(
            json.dumps({"error": "Missing token parameter"}),
            status_code=400,
            headers={"Content-Type": "application/json"}
        )
    
    user_id = verify_jwt_token(token)
    if not user_id:
        return func.HttpResponse(
            json.dumps({"error": "Invalid or expired token"}),
            status_code=401,
            headers={"Content-Type": "application/json"}
        )
    
    session = get_session(token)
    if not session:
        return func.HttpResponse(
            json.dumps({"error": "Session not found"}),
            status_code=404,
            headers={"Content-Type": "application/json"}
        )
    
    user_id_db, challenge, verified, expires_at = session
    credentials = get_user_credentials(user_id)
    
    if credentials:
        # Existing user - authentication
        return func.HttpResponse(
            json.dumps({
                "challenge": challenge,
                "allowCredentials": [
                    {"id": cred[0], "type": "public-key"}
                    for cred in credentials
                ],
                "userVerification": "required",
                "isRegistration": False
            }),
            headers={"Content-Type": "application/json"}
        )
    else:
        # New user - registration
        return func.HttpResponse(
            json.dumps({
                "challenge": challenge,
                "rp": {"id": RP_ID, "name": "Investor Verification"},
                "user": {
                    "id": base64.b64encode(user_id.encode()).decode(),
                    "name": user_id,
                    "displayName": user_id
                },
                "pubKeyCredParams": [{"alg": -7, "type": "public-key"}],
                "authenticatorSelection": {
                    "authenticatorAttachment": "platform",
                    "userVerification": "required"
                },
                "attestation": "none",
                "isRegistration": True
            }),
            headers={"Content-Type": "application/json"}
        )

@app.route(route="api/webauthn/register", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def webauthn_register(req: func.HttpRequest) -> func.HttpResponse:
    try:
        req_body = req.get_json()
        token = req_body.get('token')
        credential_data = req_body.get('credential')
        
        user_id = verify_jwt_token(token)
        if not user_id:
            return func.HttpResponse(
                json.dumps({"error": "Invalid token"}),
                status_code=401,
                headers={"Content-Type": "application/json"}
            )
        
        session = get_session(token)
        if not session:
            return func.HttpResponse(
                json.dumps({"error": "Session not found"}),
                status_code=404,
                headers={"Content-Type": "application/json"}
            )
        
        # REAL WebAuthn verification - SECURITY FIX
        try:
            # Get session challenge for verification
            user_id_db, challenge_b64, verified, expires_at = get_session(token)
            if not challenge_b64:
                return func.HttpResponse(
                    json.dumps({"error": "Session challenge not found"}),
                    status_code=400,
                    headers={"Content-Type": "application/json"}
                )
            
            # Convert credential data to proper WebAuthn format
            attestation_response = AuthenticatorAttestationResponse(
                client_data_json=base64url_decode(credential_data["response"]["clientDataJSON"]),
                attestation_object=base64url_decode(credential_data["response"]["attestationObject"])
            )
            
            credential = RegistrationCredential(
                id=credential_data["id"],
                raw_id=base64url_decode(credential_data["rawId"]),
                response=attestation_response,
                type=credential_data["type"]
            )
            
            # ACTUAL WebAuthn verification (not fake!)
            verification = verify_registration_response(
                credential=credential,
                expected_challenge=base64.b64decode(challenge_b64),
                expected_origin=ORIGIN,
                expected_rp_id=RP_ID,
                require_user_verification=True
            )
            
            if not verification.verified:
                return func.HttpResponse(
                    json.dumps({"error": "WebAuthn verification failed"}),
                    status_code=400,
                    headers={"Content-Type": "application/json"}
                )
            
            # Save REAL credential data
            credential_id_b64 = base64.b64encode(verification.credential_id).decode()
            public_key_b64 = base64.b64encode(verification.credential_public_key).decode()
            save_credential(user_id, credential_id_b64, public_key_b64)
            
        except Exception as verification_error:
            logging.error(f"WebAuthn verification failed: {str(verification_error)}")
            return func.HttpResponse(
                json.dumps({"error": f"Biometric verification failed: {str(verification_error)}"}),
                status_code=400,
                headers={"Content-Type": "application/json"}
            )
        
        return func.HttpResponse(
            json.dumps({"success": True}),
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
    try:
        req_body = req.get_json()
        token = req_body.get('token')
        credential_data = req_body.get('credential')
        
        user_id = verify_jwt_token(token)
        if not user_id:
            return func.HttpResponse(
                json.dumps({"error": "Invalid token"}),
                status_code=401,
                headers={"Content-Type": "application/json"}
            )
        
        # REAL WebAuthn authentication - SECURITY FIX
        try:
            # Get session challenge and user credentials
            session = get_session(token)
            if not session:
                return func.HttpResponse(
                    json.dumps({"error": "Session not found"}),
                    status_code=404,
                    headers={"Content-Type": "application/json"}
                )
            
            user_id_db, challenge_b64, verified, expires_at = session
            credentials = get_user_credentials(user_id)
            
            if not credentials:
                return func.HttpResponse(
                    json.dumps({"error": "No registered credentials found"}),
                    status_code=404,
                    headers={"Content-Type": "application/json"}
                )
            
            # Convert credential data to proper WebAuthn format
            assertion_response = AuthenticatorAssertionResponse(
                client_data_json=base64url_decode(credential_data["response"]["clientDataJSON"]),
                authenticator_data=base64url_decode(credential_data["response"]["authenticatorData"]),
                signature=base64url_decode(credential_data["response"]["signature"]),
                user_handle=base64url_decode(credential_data["response"]["userHandle"]) if credential_data["response"].get("userHandle") else None
            )
            
            credential = AuthenticationCredential(
                id=credential_data["id"],
                raw_id=base64url_decode(credential_data["rawId"]),
                response=assertion_response,
                type=credential_data["type"]
            )
            
            # Find matching credential from database
            credential_id_b64 = base64.b64encode(credential.raw_id).decode()
            matching_cred = None
            for cred in credentials:
                if cred[0] == credential_id_b64:  # credential_id, public_key, sign_count
                    matching_cred = cred
                    break
            
            if not matching_cred:
                return func.HttpResponse(
                    json.dumps({"error": "Credential not registered for this user"}),
                    status_code=404,
                    headers={"Content-Type": "application/json"}
                )
            
            _, public_key_b64, current_sign_count = matching_cred
            
            # ACTUAL WebAuthn authentication verification (not fake!)
            verification = verify_authentication_response(
                credential=credential,
                expected_challenge=base64.b64decode(challenge_b64),
                expected_origin=ORIGIN,
                expected_rp_id=RP_ID,
                credential_public_key=base64.b64decode(public_key_b64),
                credential_current_sign_count=current_sign_count,
                require_user_verification=True
            )
            
            if not verification.verified:
                return func.HttpResponse(
                    json.dumps({"error": "Authentication verification failed"}),
                    status_code=400,
                    headers={"Content-Type": "application/json"}
                )
            
            # Update sign count (prevents replay attacks)
            update_sign_count(credential_id_b64, verification.new_sign_count)
            
            return func.HttpResponse(
                json.dumps({"success": True, "verified": True}),
                headers={"Content-Type": "application/json"}
            )
            
        except Exception as auth_error:
            logging.error(f"WebAuthn authentication failed: {str(auth_error)}")
            return func.HttpResponse(
                json.dumps({"error": f"Authentication failed: {str(auth_error)}"}),
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
        
        user_id = verify_jwt_token(token)
        if not user_id:
            return func.HttpResponse(
                json.dumps({"error": "Invalid token"}),
                status_code=401,
                headers={"Content-Type": "application/json"}
            )
        
        mark_session_verified(token)
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
            "active_sessions": len(sessions_db),
            "registered_users": len(credentials_db)
        }),
        headers={"Content-Type": "application/json"}
    )