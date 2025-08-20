# WebAuthn Investor Verification

A minimal, production-ready WebAuthn verification system designed for stock investor identity verification. Uses biometric authentication (Face ID, Touch ID, Windows Hello) without requiring third-party services.

## Features

- 🔐 **WebAuthn/Passkeys** - Industry standard biometric authentication
- 📱 **Mobile-first** - Works on iPhone (Face ID) and Android (fingerprint)
- 🏦 **Investor-focused** - Call → Link → Biometric → Verified flow
- 🎯 **Minimal** - No over-engineering, no third-party dependencies
- 🔒 **Secure** - Cryptographic proof, no raw biometrics stored
- ⚡ **Fast** - 15-second verification process

## How It Works

1. **Investor calls service** → You generate a verification link
2. **Send link to investor** → Via SMS/email  
3. **Investor taps link** → WebAuthn prompts for biometric authentication
4. **Service gets result** → TRUE/FALSE verification status

## Quick Start

### Prerequisites

- Python 3.8+
- Modern web browser with WebAuthn support

### Local Development

```bash
# Clone and setup
git clone <your-repo>
cd UserVerification

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env for your domain (localhost for development)

# Run server
python main.py
```

### Test the Flow

1. **Generate verification link:**
```bash
curl -X POST http://localhost:8080/api/verification/link \
  -H 'Content-Type: application/json' \
  -d '{"user_id":"investor123","username":"test@example.com"}'
```

2. **Open returned URL in browser**
3. **Complete biometric verification**
4. **See "✅ Verified" result**

## Production Deployment

### HTTPS Required
WebAuthn requires HTTPS for production use. Update `.env`:

```env
RP_ID=verify.yourdomain.com
ORIGIN=https://verify.yourdomain.com
JWT_SECRET=your-production-secret-key
```

### Recommended Stack
- **Cloud**: AWS/GCP/Azure
- **SSL**: Let's Encrypt or cloud provider certificates
- **Database**: SQLite (included) or upgrade to PostgreSQL
- **Deployment**: Docker, systemd, or cloud functions

## API Endpoints

### Generate Verification Link
```bash
POST /api/verification/link
Content-Type: application/json

{
  "user_id": "investor123",
  "username": "investor@example.com"
}
```

### Check Verification Status
```bash
GET /api/verification/status?token=<jwt_token>
```

### Verification Page
```
GET /static/index.html?token=<jwt_token>
```

## Architecture

```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐
│   Service   │───▶│  Generates   │───▶│  Investor   │
│    Call     │    │     Link     │    │   Mobile    │
└─────────────┘    └──────────────┘    └─────────────┘
                                              │
┌─────────────┐    ┌──────────────┐          ▼
│   Database  │◀───│   FastAPI    │    ┌─────────────┐
│ Credentials │    │   Backend    │◀───│  WebAuthn   │
└─────────────┘    └──────────────┘    │ Biometric   │
                                       └─────────────┘
```

## File Structure

```
UserVerification/
├── main.py              # FastAPI backend
├── requirements.txt     # Python dependencies
├── .env.example         # Environment template
├── static/
│   └── index.html       # Verification frontend
├── verification.db      # SQLite database (created automatically)
└── README.md           # This file
```

## Database Schema

### user_credentials
- `user_id` - Investor identifier
- `username` - Investor email/username  
- `credential_id` - WebAuthn credential ID
- `public_key` - Cryptographic public key
- `sign_count` - Replay attack prevention

### verification_sessions
- `user_id` - Investor identifier
- `token` - JWT verification token
- `challenge` - WebAuthn challenge
- `verified` - Verification status
- `expires_at` - Session expiration

## Security Features

- **No raw biometrics stored** - Only cryptographic proofs
- **Short-lived tokens** - 15-minute expiration (configurable)
- **Replay attack prevention** - Challenge-response mechanism
- **Origin validation** - Domain-specific credential binding
- **HTTPS enforcement** - Required for production

## Browser Support

### Desktop
- Chrome 67+
- Firefox 60+
- Safari 14+
- Edge 18+

### Mobile
- iOS 14+ (Face ID/Touch ID)
- Android 7+ (Fingerprint/Face unlock)
- Chrome Mobile, Safari Mobile

## Troubleshooting

### "WebAuthn is not supported"
- Ensure HTTPS in production
- Check browser compatibility
- Verify domain configuration

### "Registration failed"
- Check server logs for detailed errors
- Verify RP_ID matches domain
- Ensure WebAuthn challenge consistency

### Mobile testing issues
- WebAuthn requires HTTPS on mobile
- Use proper domain with SSL certificate
- Test with actual device browsers

## License

MIT License - Use freely for commercial investor verification.

## Support

For issues and questions, check the troubleshooting section above or review server logs for detailed error messages.