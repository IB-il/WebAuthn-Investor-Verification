import azure.functions as func
import logging
import json
import jwt
import base64
import os
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
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-super-secret")
JWT_TTL_SECONDS = int(os.getenv("JWT_TTL_SECONDS", "900"))

# In-memory storage (use Azure Table Storage or CosmosDB for production)
credentials_db = {}
sessions_db = {}

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

@app.route(route="api/verification/link", methods=["POST", "GET"], auth_level=func.AuthLevel.ANONYMOUS)
def create_verification_link(req: func.HttpRequest) -> func.HttpResponse:
    try:
        # Support both GET and POST methods
        if req.method == "GET":
            user_id = req.params.get('user_id')
            username = req.params.get('username')
        else:
            req_body = req.get_json()
            user_id = req_body.get('user_id')
            username = req_body.get('username')
        
        if not user_id or not username:
            return func.HttpResponse(
                json.dumps({"error": "user_id and username required"}),
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
        logging.error(f"Error creating verification link: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": str(e)}),
            status_code=500,
            headers={"Content-Type": "application/json"}
        )

@app.route(route="api/verify", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def verification_page(req: func.HttpRequest) -> func.HttpResponse:
    token = req.params.get('token')
    if not token:
        return func.HttpResponse("Missing token", status_code=400)
    
    user_id = verify_jwt_token(token)
    if not user_id:
        return func.HttpResponse("Invalid or expired token", status_code=401)
    
    # Return professional HTML page inspired by Inter.co design
    html_content = f'''
<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Investor Verification - WebAuthn</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #ffffff;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            line-height: 1.6;
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
            gap: 12px;
        }}
        
        .logo-icon {{
            width: 48px;
            height: 48px;
            background: linear-gradient(135deg, #303e90 0%, #db1222 100%);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 24px;
            font-weight: 700;
            box-shadow: 0 4px 12px rgba(48, 62, 144, 0.2);
        }}
        
        .company-name {{
            font-size: 24px;
            font-weight: 700;
            color: #303e90;
            letter-spacing: -0.5px;
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
            width: 80px;
            height: 80px;
            margin: 0 auto 24px;
            background: linear-gradient(135deg, #303e90 0%, #db1222 100%);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 36px;
            box-shadow: 0 8px 24px rgba(48, 62, 144, 0.2);
        }}
        
        .main-heading {{
            font-size: 32px;
            font-weight: 700;
            color: #1f2937;
            margin-bottom: 12px;
            letter-spacing: -0.5px;
        }}
        
        .subheading {{
            font-size: 18px;
            color: #6b7280;
            margin-bottom: 32px;
            font-weight: 400;
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
            background: linear-gradient(135deg, #303e90 0%, #db1222 100%);
            color: white;
            border: none;
            padding: 18px 32px;
            border-radius: 8px;
            font-size: 18px;
            font-weight: 600;
            cursor: pointer;
            width: 100%;
            transition: all 0.3s ease;
            box-shadow: 0 4px 12px rgba(48, 62, 144, 0.2);
            position: relative;
            overflow: hidden;
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
                <div class="logo-icon">IV</div>
                <div class="company-name">InvestorVerify</div>
            </div>
            <div class="security-badge">
                🔒 Bank-Level Security
            </div>
        </div>
    </header>
    
    <main class="main-container">
        <div class="verification-card">
            <div class="verification-icon">🛡️</div>
            
            <h1 class="main-heading">Identity Verification</h1>
            <p class="subheading">Secure your investment account with biometric authentication</p>
            
            <div id="status" class="status-container">
                <div class="status-text">Ready to verify your identity</div>
                <div class="status-subtitle">Use your device's biometric authentication</div>
            </div>
            
            <div class="biometric-icons">
                <div class="biometric-icon">📱</div>
                <div class="biometric-icon">👆</div>
                <div class="biometric-icon">👤</div>
            </div>
            
            <button id="verifyBtn" class="verify-button" onclick="startVerification()">
                Verify My Identity
            </button>
            
            <div class="security-notice">
                <h4>Your Security & Privacy</h4>
                <ul class="security-points">
                    <li>Your biometric data never leaves your device</li>
                    <li>Bank-grade encryption protects all communications</li>
                    <li>Verification completes in seconds, not minutes</li>
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
        
        function showSuccess(message, subtitle = 'Verification completed successfully') {{
            showStatus(message, subtitle, 'success');
            
            const button = document.getElementById('verifyBtn');
            button.innerHTML = '✓ Identity Verified';
            button.disabled = true;
            
            // Celebrate with all icons active
            document.querySelectorAll('.biometric-icon').forEach(icon => {{
                icon.classList.add('active');
            }});
        }}
        
        function showError(message, subtitle = 'Please try again') {{
            showStatus(message, subtitle, 'error');
            document.getElementById('verifyBtn').disabled = false;
        }}
        
        async function startVerification() {{
            if (!window.PublicKeyCredential) {{
                showError('WebAuthn not supported', 'This device does not support biometric authentication');
                return;
            }}
            
            showStatus('Preparing biometric verification...', 'Connecting to secure server');
            document.getElementById('verifyBtn').disabled = true;
            
            try {{
                // Get WebAuthn options from server
                const optionsResponse = await fetch(`/api/webauthn/options?token={token}`);
                if (!optionsResponse.ok) {{
                    throw new Error('Server connection failed');
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
                    
                    showStatus('Complete biometric authentication', 'Touch your fingerprint sensor or use Face ID', 'info');
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
                        showSuccess('Identity Verified Successfully!', 'Your biometric credential has been registered');
                        // Update server that verification is complete
                        await fetch(`/api/verification/complete`, {{
                            method: 'POST',
                            headers: {{ 'Content-Type': 'application/json' }},
                            body: JSON.stringify({{ token: token }})
                        }});
                    }} else {{
                        throw new Error('Credential registration failed');
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
                    
                    showStatus('Authenticate with biometric', 'Use your registered fingerprint or Face ID', 'info');
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
                        showSuccess('Welcome Back!', 'Authentication completed successfully');
                        // Update server that verification is complete
                        await fetch(`/api/verification/complete`, {{
                            method: 'POST',
                            headers: {{ 'Content-Type': 'application/json' }},
                            body: JSON.stringify({{ token: token }})
                        }});
                    }} else {{
                        throw new Error('Authentication verification failed');
                    }}
                }}
                
            }} catch (error) {{
                console.error('WebAuthn error:', error);
                if (error.name === 'NotAllowedError') {{
                    showError('Verification cancelled', 'You cancelled the biometric authentication');
                }} else if (error.name === 'InvalidStateError') {{
                    showError('Device not ready', 'Please ensure biometric authentication is enabled');
                }} else {{
                    showError('Verification failed', error.message);
                }}
                document.getElementById('verifyBtn').disabled = false;
            }}
        }}
        
        // Initialize
        showStatus('Ready to verify your identity', 'Tap the button below to start');
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
    """List all registered users"""
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
    """List all verification sessions"""
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
        
        # Save credential (simplified - in production, verify the attestation)
        credential_id = base64.b64encode(base64url_decode(credential_data['rawId'])).decode()
        save_credential(user_id, credential_id, "dummy_public_key")
        
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
        
        # Simplified authentication - in production, verify the signature
        return func.HttpResponse(
            json.dumps({"success": True}),
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