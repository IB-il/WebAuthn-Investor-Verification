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
    
    # Return simplified HTML page
    html_content = f'''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Investor Verification</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0;
            padding: 20px;
        }}
        
        .container {{
            background: white;
            padding: 40px;
            border-radius: 16px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            text-align: center;
            max-width: 400px;
            width: 100%;
        }}
        
        .logo {{
            width: 80px;
            height: 80px;
            margin: 0 auto 20px;
            background: linear-gradient(135deg, #667eea, #764ba2);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 32px;
            font-weight: bold;
        }}
        
        h1 {{
            color: #333;
            margin-bottom: 10px;
        }}
        
        .status {{
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 20px;
            background: #f0f9ff;
            color: #0369a1;
            border: 2px solid #e0f2fe;
        }}
        
        .verify-button {{
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            border: none;
            padding: 16px 32px;
            border-radius: 12px;
            font-size: 18px;
            font-weight: 600;
            cursor: pointer;
            width: 100%;
        }}
        
        .verify-button:hover {{
            transform: translateY(-2px);
        }}
        
        .verify-button:disabled {{
            opacity: 0.6;
            cursor: not-allowed;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">$</div>
        <h1>Investor Verification</h1>
        <p>Secure biometric verification for your account</p>
        
        <div id="status" class="status">
            Initializing verification...
        </div>
        
        <div style="font-size: 48px; margin-bottom: 20px;">🔒</div>
        
        <button id="verifyBtn" class="verify-button" onclick="startVerification()">
            Verify Identity
        </button>
    </div>

    <script>
        const token = "{token}";
        
        function showStatus(message, isError = false) {{
            const status = document.getElementById('status');
            status.textContent = message;
            if (isError) {{
                status.style.background = '#fef2f2';
                status.style.color = '#dc2626';
                status.style.borderColor = '#fecaca';
            }}
        }}
        
        function showSuccess(message) {{
            const status = document.getElementById('status');
            status.textContent = message;
            status.style.background = '#f0fdf4';
            status.style.color = '#166534';
            status.style.borderColor = '#dcfce7';
            
            document.getElementById('verifyBtn').textContent = '✓ Verified';
            document.getElementById('verifyBtn').disabled = true;
        }}
        
        async function startVerification() {{
            if (!window.PublicKeyCredential) {{
                showStatus('WebAuthn is not supported on this device', true);
                return;
            }}
            
            showStatus('Getting verification options...');
            document.getElementById('verifyBtn').disabled = true;
            
            try {{
                // Get WebAuthn options from server
                const optionsResponse = await fetch(`/api/webauthn/options?token={token}`);
                if (!optionsResponse.ok) {{
                    throw new Error('Failed to get authentication options');
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
                    
                    showStatus('Touch your fingerprint or use Face ID to register...');
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
                        showSuccess('Registration successful! You are now verified.');
                        // Update server that verification is complete
                        await fetch(`/api/verification/complete`, {{
                            method: 'POST',
                            headers: {{ 'Content-Type': 'application/json' }},
                            body: JSON.stringify({{ token: token }})
                        }});
                    }} else {{
                        throw new Error('Registration failed');
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
                    
                    showStatus('Touch your fingerprint or use Face ID to authenticate...');
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
                        showSuccess('Authentication successful! You are verified.');
                        // Update server that verification is complete
                        await fetch(`/api/verification/complete`, {{
                            method: 'POST',
                            headers: {{ 'Content-Type': 'application/json' }},
                            body: JSON.stringify({{ token: token }})
                        }});
                    }} else {{
                        throw new Error('Authentication failed');
                    }}
                }}
                
            }} catch (error) {{
                console.error('WebAuthn error:', error);
                showStatus('Verification failed: ' + error.message, true);
                document.getElementById('verifyBtn').disabled = false;
            }}
        }}
        
        // Initialize
        showStatus('Ready to verify your identity');
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

@app.route(route="api/admin/sessions", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def list_all_sessions(req: func.HttpRequest) -> func.HttpResponse:
    """Admin endpoint to see all verification sessions"""
    sessions_summary = []
    
    for token, session in sessions_db.items():
        sessions_summary.append({
            "token": token[:10] + "...",  # Truncate for security
            "user_id": session["user_id"],
            "verified": session["verified"],
            "expires_at": session["expires_at"].isoformat()
        })
    
    return func.HttpResponse(
        json.dumps({
            "total_sessions": len(sessions_summary),
            "sessions": sessions_summary,
            "credentials_count": len(credentials_db)
        }),
        headers={"Content-Type": "application/json"}
    )

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