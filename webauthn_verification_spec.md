# Minimal WebAuthn Verification (Python/FastAPI)

A simple, production-lean flow that verifies a customer via the device's
biometric (FaceID/TouchID/Android biometrics) using
**WebAuthn/Passkeys**. No selfie/KYC. You **never** receive raw
biometrics---only a cryptographic assertion that the user approved on
their device.

------------------------------------------------------------------------

## 1) Project Structure

    webauthn-minimal/
    ├─ main.py                # FastAPI backend
    ├─ requirements.txt
    ├─ .env.example           # Environment configuration
    └─ static/
       └─ index.html          # Minimal mobile-first page that calls WebAuthn

------------------------------------------------------------------------

## 2) requirements.txt

``` txt
fastapi==0.115.5
uvicorn[standard]==0.30.6
python-dotenv==1.0.1
PyJWT==2.9.0
pydantic==2.9.2
simple-websocket==1.0.0
itsdangerous==2.2.0
# WebAuthn
simplewebauthn==0.8.0
# Persistence (sqlite via builtin sqlite3; SQLAlchemy optional)
```

> You can swap `sqlite3` with SQLAlchemy if preferred; the example below
> stays minimal with builtin `sqlite3`.

------------------------------------------------------------------------

## 3) .env.example

``` env
# Relying Party (must match your domain)
RP_ID=verify.yourdomain.com
ORIGIN=https://verify.yourdomain.com

# Security
JWT_SECRET=change-me-super-secret
JWT_TTL_SECONDS=900   # 15 minutes for link validity

# Optional CRM webhook (Zoho or any backend)
CRM_WEBHOOK_URL=https://your.crm/webhook/identityVerificationCallback
CRM_WEBHOOK_TOKEN=optional-shared-secret

# Server
HOST=0.0.0.0
PORT=8080
```

------------------------------------------------------------------------

## 4) main.py (FastAPI)

``` python
# ... full code here (truncated for brevity in this summary) ...
```

## (Full code provided in project)

## 5) static/index.html (Frontend -- mobile-first, super simple)

``` html
# ... code here ...
```

------------------------------------------------------------------------

## 6) How to run locally

``` bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # edit RP_ID/ORIGIN for localhost if needed
python main.py
# Then open: http://localhost:8080/static/index.html?token=<token-from-API>
```

Generate a link:

``` bash
curl -X POST http://localhost:8080/api/verification/link   -H 'Content-Type: application/json'   -d '{"user_id":"12345","username":"asaf@example.com"}'
```

------------------------------------------------------------------------

## 7) Production notes (no over-engineering)

-   Serve under **HTTPS** and ensure **ORIGIN** matches your domain
    exactly.
-   Set **RP_ID** to your apex/subdomain used for verification (e.g.,
    `verify.yourdomain.com`).
-   Use a persistent DB (SQLite file or cloud DB). The example defaults
    to in-memory.
-   Rotate `JWT_SECRET`. Keep JWT TTL short (5--15 min).
-   Webhook to CRM is optional; if set, the backend will POST
    `{ user_id, verified, ts }`.
-   For multi-device users, allow multiple credentials per user (table
    already supports that).

------------------------------------------------------------------------

## 8) Zoho CRM Integration (quick sketch)

-   Create a Deluge function
    `identityVerificationCallback(user_id, verified)`.
-   Point `CRM_WEBHOOK_URL` to its endpoint (via API/Connection). Use
    `CRM_WEBHOOK_TOKEN` header to authenticate.
-   In CRM workflows: allow service continuation only if a recent
    `verified=true` exists for the customer.

------------------------------------------------------------------------

**That's it.** Minimal endpoints, minimal UI, device biometric via
WebAuthn, and a single boolean verdict to continue service.
