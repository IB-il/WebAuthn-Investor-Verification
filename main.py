import os
import sqlite3
import json
import jwt
from datetime import datetime, timedelta, timezone
from typing import Optional
import base64

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from dotenv import load_dotenv

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

load_dotenv()

app = FastAPI(title="WebAuthn Verification Service")

# Configuration
RP_ID = os.getenv("RP_ID", "localhost")
ORIGIN = os.getenv("ORIGIN", "http://localhost:8080")
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-super-secret")
JWT_TTL_SECONDS = int(os.getenv("JWT_TTL_SECONDS", "900"))
CRM_WEBHOOK_URL = os.getenv("CRM_WEBHOOK_URL")
CRM_WEBHOOK_TOKEN = os.getenv("CRM_WEBHOOK_TOKEN")

# Database initialization
def init_db():
    conn = sqlite3.connect("verification.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            username TEXT NOT NULL,
            credential_id TEXT NOT NULL UNIQUE,
            public_key TEXT NOT NULL,
            sign_count INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS verification_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            token TEXT NOT NULL UNIQUE,
            challenge TEXT NOT NULL,
            verified BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()

# Pydantic models
class VerificationLinkRequest(BaseModel):
    user_id: str
    username: str

class RegistrationResponse(BaseModel):
    credential: dict

class AuthenticationResponse(BaseModel):
    credential: dict

# Database helpers
def get_user_credentials(user_id: str):
    conn = sqlite3.connect("verification.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT credential_id, public_key, sign_count FROM user_credentials WHERE user_id = ?",
        (user_id,)
    )
    credentials = cursor.fetchall()
    conn.close()
    return credentials

def save_credential(user_id: str, username: str, credential_id: str, public_key: str):
    conn = sqlite3.connect("verification.db")
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO user_credentials (user_id, username, credential_id, public_key) VALUES (?, ?, ?, ?)",
        (user_id, username, credential_id, public_key)
    )
    conn.commit()
    conn.close()

def update_sign_count(credential_id: str, sign_count: int):
    conn = sqlite3.connect("verification.db")
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE user_credentials SET sign_count = ? WHERE credential_id = ?",
        (sign_count, credential_id)
    )
    conn.commit()
    conn.close()

def create_session(user_id: str, token: str, challenge: str):
    conn = sqlite3.connect("verification.db")
    cursor = conn.cursor()
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=JWT_TTL_SECONDS)
    cursor.execute(
        "INSERT INTO verification_sessions (user_id, token, challenge, expires_at) VALUES (?, ?, ?, ?)",
        (user_id, token, challenge, expires_at)
    )
    conn.commit()
    conn.close()

def get_session(token: str):
    conn = sqlite3.connect("verification.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT user_id, challenge, verified, expires_at FROM verification_sessions WHERE token = ?",
        (token,)
    )
    result = cursor.fetchone()
    conn.close()
    return result

def mark_session_verified(token: str):
    conn = sqlite3.connect("verification.db")
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE verification_sessions SET verified = TRUE WHERE token = ?",
        (token,)
    )
    conn.commit()
    conn.close()

# JWT helpers
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
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# Static files
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def root():
    return {"message": "WebAuthn Verification Service"}

@app.post("/api/verification/link")
async def create_verification_link(request: VerificationLinkRequest):
    token = generate_jwt_token(request.user_id)
    
    # Check if user already has credentials
    credentials = get_user_credentials(request.user_id)
    
    if credentials:
        # Existing user - generate authentication challenge
        options = generate_authentication_options(
            rp_id=RP_ID,
            allow_credentials=[
                PublicKeyCredentialDescriptor(id=base64.b64decode(cred[0]))
                for cred in credentials
            ],
            user_verification=UserVerificationRequirement.REQUIRED
        )
        
        create_session(request.user_id, token, base64.b64encode(options.challenge).decode())
        
        return {
            "verification_url": f"{ORIGIN}/static/index.html?token={token}",
            "token": token,
            "expires_in": JWT_TTL_SECONDS
        }
    else:
        # New user - generate registration challenge
        options = generate_registration_options(
            rp_id=RP_ID,
            rp_name="Investor Verification",
            user_id=request.user_id.encode(),
            user_name=request.username,
            user_display_name=request.username,
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement.REQUIRED
            )
        )
        
        create_session(request.user_id, token, base64.b64encode(options.challenge).decode())
        
        return {
            "verification_url": f"{ORIGIN}/static/index.html?token={token}",
            "token": token,
            "expires_in": JWT_TTL_SECONDS,
            "registration_required": True
        }

@app.get("/api/verification/options")
async def get_verification_options(token: str):
    user_id = verify_jwt_token(token)
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    session = get_session(token)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    user_id_db, challenge, verified, expires_at = session
    
    if datetime.now(timezone.utc) > datetime.fromisoformat(expires_at.replace('Z', '+00:00')):
        raise HTTPException(status_code=401, detail="Session expired")
    
    if verified:
        return {"verified": True, "message": "Already verified"}
    
    credentials = get_user_credentials(user_id)
    
    if credentials:
        # Authentication flow
        options = generate_authentication_options(
            rp_id=RP_ID,
            allow_credentials=[
                PublicKeyCredentialDescriptor(id=base64.b64decode(cred[0]))
                for cred in credentials
            ],
            user_verification=UserVerificationRequirement.REQUIRED
        )
        
        return {
            "type": "authentication",
            "options": {
                "challenge": challenge,
                "timeout": options.timeout,
                "rpId": options.rp_id,
                "allowCredentials": [
                    {
                        "type": "public-key",
                        "id": cred_id,
                        "transports": ["internal"]
                    }
                    for cred_id, _, _ in credentials
                ],
                "userVerification": options.user_verification.value
            }
        }
    else:
        # Registration flow
        options = generate_registration_options(
            rp_id=RP_ID,
            rp_name="Investor Verification",
            user_id=user_id.encode(),
            user_name=user_id,
            user_display_name=user_id,
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement.REQUIRED
            )
        )
        
        return {
            "type": "registration",
            "options": {
                "challenge": challenge,
                "rp": {
                    "name": options.rp.name,
                    "id": options.rp.id
                },
                "user": {
                    "id": base64.b64encode(options.user.id).decode(),
                    "name": options.user.name,
                    "displayName": options.user.display_name
                },
                "pubKeyCredParams": [
                    {"alg": param.alg, "type": param.type}
                    for param in options.pub_key_cred_params
                ],
                "timeout": options.timeout,
                "attestation": options.attestation.value,
                "authenticatorSelection": {
                    "authenticatorAttachment": options.authenticator_selection.authenticator_attachment.value if options.authenticator_selection.authenticator_attachment else None,
                    "userVerification": options.authenticator_selection.user_verification.value
                }
            }
        }

@app.post("/api/verification/register")
async def register_credential(token: str, response: RegistrationResponse):
    user_id = verify_jwt_token(token)
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    session = get_session(token)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    user_id_db, challenge, verified, expires_at = session
    
    try:
        print(f"Received credential: {response.credential}")  # Debug log
        def base64url_decode(data: str) -> bytes:
            # Convert base64url to base64
            data = data.replace('-', '+').replace('_', '/')
            # Add padding if needed
            padding = 4 - len(data) % 4
            if padding != 4:
                data += '=' * padding
            return base64.b64decode(data)
        
        credential_data = response.credential
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
        
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=base64.b64decode(challenge),
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID
        )
        
        # If we get here without exception, verification succeeded
        credential_id_b64 = base64.b64encode(verification.credential_id).decode()
        public_key_b64 = base64.b64encode(verification.credential_public_key).decode()
        
        save_credential(user_id, user_id, credential_id_b64, public_key_b64)
        mark_session_verified(token)
        
        return {"verified": True, "message": "Registration successful"}
            
    except Exception as e:
        print(f"Registration error: {str(e)}")  # Debug log
        import traceback
        print(traceback.format_exc())  # Full stack trace
        raise HTTPException(status_code=400, detail=f"Registration error: {str(e)}")

@app.post("/api/verification/authenticate")
async def authenticate_credential(token: str, response: AuthenticationResponse):
    user_id = verify_jwt_token(token)
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    session = get_session(token)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    user_id_db, challenge, verified, expires_at = session
    
    try:
        def base64url_decode(data: str) -> bytes:
            # Convert base64url to base64
            data = data.replace('-', '+').replace('_', '/')
            # Add padding if needed
            padding = 4 - len(data) % 4
            if padding != 4:
                data += '=' * padding
            return base64.b64decode(data)
        
        credential_data = response.credential
        credential = AuthenticationCredential(
            id=credential_data["id"],
            raw_id=base64url_decode(credential_data["rawId"]),
            response=credential_data["response"],
            type=credential_data["type"]
        )
        
        # Get the credential from database
        credentials = get_user_credentials(user_id)
        credential_id_b64 = base64.b64encode(credential.raw_id).decode()
        
        matching_cred = None
        for cred in credentials:
            if cred[0] == credential_id_b64:
                matching_cred = cred
                break
        
        if not matching_cred:
            raise HTTPException(status_code=404, detail="Credential not found")
        
        _, public_key_b64, sign_count = matching_cred
        
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=base64.b64decode(challenge),
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            credential_public_key=base64.b64decode(public_key_b64),
            credential_current_sign_count=sign_count
        )
        
        if verification.verified:
            update_sign_count(credential_id_b64, verification.new_sign_count)
            mark_session_verified(token)
            
            # Optional: Send webhook to CRM
            if CRM_WEBHOOK_URL:
                # TODO: Implement webhook call
                pass
            
            return {"verified": True, "message": "Authentication successful"}
        else:
            return {"verified": False, "message": "Authentication failed"}
            
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Authentication error: {str(e)}")

@app.get("/api/verification/status")
async def check_verification_status(token: str):
    user_id = verify_jwt_token(token)
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    session = get_session(token)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    user_id_db, challenge, verified, expires_at = session
    
    return {
        "user_id": user_id,
        "verified": bool(verified),
        "expires_at": expires_at
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8080,
        reload=True
    )