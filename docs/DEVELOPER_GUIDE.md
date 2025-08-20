# WebAuthn Investor Verification - Developer Guide

## Architecture Overview

This system provides a minimal, production-ready WebAuthn implementation for investor identity verification. It consists of:

- **FastAPI Backend** (local development)
- **Azure Functions** (production deployment) 
- **WebAuthn Frontend** (mobile-optimized)
- **JWT-based Session Management**
- **SQLite Storage** (demo) / **Azure Storage** (production)

## Repository Structure

```
UserVerification/
├── main.py                 # FastAPI local development server
├── static/                 # Frontend assets
│   └── index.html         # WebAuthn verification page
├── azure-deployment/      # Azure Functions deployment
│   ├── function_app.py    # Azure Functions implementation
│   ├── requirements.txt   # Python dependencies
│   ├── host.json         # Azure Functions configuration
│   └── test_flow.py      # Testing utilities
├── docs/                 # Documentation
│   ├── USER_GUIDE.md     # End-user documentation
│   └── DEVELOPER_GUIDE.md # This file
├── requirements.txt      # Local development dependencies
├── .env                 # Environment configuration
└── README.md            # Project overview
```

## Quick Start

### Local Development

1. **Clone Repository**
   ```bash
   git clone https://github.com/IB-il/WebAuthn-Investor-Verification.git
   cd WebAuthn-Investor-Verification
   ```

2. **Setup Environment**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Linux/Mac
   # .venv\Scripts\activate   # Windows
   pip install -r requirements.txt
   ```

3. **Configure Environment**
   ```bash
   cp .env.example .env
   # Edit .env with your settings
   ```

4. **Run Local Server**
   ```bash
   python main.py
   ```

5. **Access Application**
   - API: http://localhost:8000
   - Docs: http://localhost:8000/docs
   - Test: http://localhost:8000/static/index.html

### Azure Deployment

1. **Install Azure CLI & Functions Core Tools**
   ```bash
   # Install Azure CLI
   curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
   
   # Install Azure Functions Core Tools
   npm install -g azure-functions-core-tools@4 --unsafe-perm true
   ```

2. **Login and Create Resources**
   ```bash
   az login
   az group create --name webauthn-rg --location eastus
   az storage account create --name webauthnstg123 --resource-group webauthn-rg
   az functionapp create --name webauthn-investor --resource-group webauthn-rg \
     --consumption-plan-location eastus --runtime python --runtime-version 3.11
   ```

3. **Deploy Functions**
   ```bash
   cd azure-deployment
   func azure functionapp publish webauthn-investor --python --build remote
   ```

## API Reference

### Core Endpoints

#### Create Verification Link
```http
POST /api/verification/link
Content-Type: application/json

{
  "user_id": "investor123",
  "username": "investor@example.com"
}

Response:
{
  "verification_url": "https://domain.com/api/verify?token=...",
  "token": "jwt_token_here",
  "expires_in": 900,
  "registration_required": true
}
```

#### Check Verification Status
```http
GET /api/verification/status?token={jwt_token}

Response:
{
  "user_id": "investor123",
  "verified": true,
  "expires_at": "2025-01-01T12:00:00Z",
  "token": "jwt_token_here"
}
```

#### Get WebAuthn Options
```http
GET /api/webauthn/options?token={jwt_token}

Response (Registration):
{
  "challenge": "base64url_challenge",
  "rp": {"id": "domain.com", "name": "Investor Verification"},
  "user": {
    "id": "base64url_user_id",
    "name": "investor123", 
    "displayName": "investor123"
  },
  "pubKeyCredParams": [{"alg": -7, "type": "public-key"}],
  "authenticatorSelection": {
    "authenticatorAttachment": "platform",
    "userVerification": "required"
  },
  "attestation": "none",
  "isRegistration": true
}
```

#### Register WebAuthn Credential
```http
POST /api/webauthn/register
Content-Type: application/json

{
  "token": "jwt_token",
  "credential": {
    "id": "credential_id",
    "rawId": "base64url_raw_id",
    "type": "public-key",
    "response": {
      "clientDataJSON": "base64url_client_data",
      "attestationObject": "base64url_attestation"
    }
  }
}
```

### Additional Endpoints

- `GET /health` - Health check
- `GET /api/verify?token={jwt}` - Verification webpage
- `POST /api/verification/complete` - Mark verification complete
- `GET /api/admin/sessions` - List all sessions (admin)

## Configuration

### Environment Variables

```bash
# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-here
JWT_TTL_SECONDS=900

# WebAuthn Configuration  
RP_ID=localhost                    # Your domain
ORIGIN=http://localhost:8000       # Your origin URL

# Database (optional)
DATABASE_URL=sqlite:///./credentials.db
```

### Azure Functions Settings

```bash
# Set application settings
az functionapp config appsettings set --name webauthn-investor --resource-group webauthn-rg \
  --settings "RP_ID=webauthn-investor.azurewebsites.net" \
             "ORIGIN=https://webauthn-investor.azurewebsites.net" \
             "JWT_SECRET=your-production-secret-here"
```

## Security Considerations

### Production Checklist

- [ ] **Strong JWT Secret**: Use 256-bit random key in production
- [ ] **HTTPS Only**: WebAuthn requires HTTPS for mobile devices
- [ ] **Proper RP_ID**: Must match your domain exactly
- [ ] **Origin Validation**: Validate origin header in all requests
- [ ] **Rate Limiting**: Implement rate limiting on all endpoints
- [ ] **Input Validation**: Validate all input parameters
- [ ] **Logging**: Log security events without sensitive data
- [ ] **Monitoring**: Set up alerts for failed verifications

### WebAuthn Security

```python
# Proper credential verification (production implementation)
verification_result = verify_registration_response(
    credential=credential,
    expected_challenge=session_challenge,
    expected_origin=ORIGIN,
    expected_rp_id=RP_ID,
    require_user_verification=True
)
```

### JWT Token Security

```python
# Production JWT configuration
JWT_ALGORITHM = "HS256"  # Use RS256 for distributed systems
JWT_ISSUER = "webauthn-investor"
JWT_AUDIENCE = "investor-verification"

# Token validation
def verify_jwt_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(
            token, 
            JWT_SECRET, 
            algorithms=[JWT_ALGORITHM],
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE
        )
        return payload.get("user_id")
    except jwt.InvalidTokenError:
        return None
```

## Database Schema

### SQLite (Development)
```sql
CREATE TABLE credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    public_key TEXT NOT NULL,
    sign_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    user_id TEXT NOT NULL,
    challenge TEXT NOT NULL,
    verified BOOLEAN DEFAULT FALSE,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Azure Table Storage (Production)
```python
# Example entity structure
{
    "PartitionKey": "credentials",
    "RowKey": f"{user_id}_{credential_id}",
    "user_id": "investor123",
    "credential_id": "base64_credential_id", 
    "public_key": "base64_public_key",
    "sign_count": 0,
    "created_at": "2025-01-01T12:00:00Z"
}
```

## Testing

### Unit Tests
```bash
# Install test dependencies
pip install pytest pytest-asyncio httpx

# Run tests
pytest tests/ -v
```

### Integration Testing
```bash
# Test complete verification flow
cd azure-deployment
python test_flow.py
```

### Manual Testing
```bash
# Create verification link
curl -X POST "http://localhost:8000/api/verification/link" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"test123","username":"test@test.com"}'

# Check verification status  
curl "http://localhost:8000/api/verification/status?token=JWT_TOKEN_HERE"
```

## Monitoring & Logging

### Application Insights (Azure)
```python
import logging
from opencensus.ext.azure.log_exporter import AzureLogHandler

# Configure Azure Application Insights
logging.getLogger().addHandler(
    AzureLogHandler(connection_string="InstrumentationKey=...")
)

# Log security events
logging.info(f"Verification attempt for user {user_id}", extra={
    "custom_dimensions": {
        "user_id": user_id,
        "verification_success": success,
        "ip_address": request.client.host
    }
})
```

### Health Checks
```python
@app.route(route="health", methods=["GET"])
def health_check(req: func.HttpRequest) -> func.HttpResponse:
    return func.HttpResponse(json.dumps({
        "status": "healthy",
        "service": "WebAuthn Investor Verification",
        "timestamp": datetime.utcnow().isoformat(),
        "active_sessions": len(sessions_db),
        "registered_users": len(credentials_db)
    }))
```

## Performance Optimization

### Caching Strategy
```python
# Cache WebAuthn options to reduce computation
import functools
from datetime import datetime, timedelta

@functools.lru_cache(maxsize=1000)
def get_cached_options(user_id: str, timestamp: int):
    # Generate options (timestamp ensures cache invalidation)
    pass
```

### Database Optimization
```sql
-- Indexes for better performance
CREATE INDEX idx_credentials_user_id ON credentials(user_id);
CREATE INDEX idx_sessions_token ON sessions(token);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
```

## Troubleshooting

### Common Issues

**WebAuthn Not Working on Mobile**
- Ensure HTTPS is used (required for mobile WebAuthn)
- Check RP_ID matches domain exactly
- Verify ORIGIN header includes protocol and port

**JWT Token Errors**
- Check token expiration times
- Verify JWT_SECRET matches between environments
- Ensure proper base64url encoding

**Azure Functions Cold Start**
- Functions may take 10-30 seconds to respond initially
- Consider using Premium plan for production
- Implement warm-up requests

### Debug Mode
```python
# Enable debug logging
import logging
logging.basicConfig(level=logging.DEBUG)

# WebAuthn debug information
print(f"Challenge: {challenge}")
print(f"RP ID: {RP_ID}")
print(f"Origin: {ORIGIN}")
```

## Contributing

### Development Workflow
1. Fork repository
2. Create feature branch: `git checkout -b feature/new-feature`
3. Make changes and test locally
4. Test Azure deployment
5. Submit pull request

### Code Style
```bash
# Install development tools
pip install black isort flake8 mypy

# Format code
black . 
isort .

# Check code quality
flake8 .
mypy .
```

## Production Deployment

### Azure Functions Production Setup
1. **Create Production Resource Group**
2. **Set up Application Insights**
3. **Configure Custom Domain with SSL**
4. **Set up Monitoring and Alerts**
5. **Implement Backup Strategy**
6. **Configure Rate Limiting**
7. **Set up CI/CD Pipeline**

### Scaling Considerations
- Azure Functions automatically scale based on demand
- Consider Azure Premium plan for consistent performance
- Implement proper database connection pooling
- Use Azure CDN for static assets
- Set up multiple regions for high availability

## Support & Maintenance

### Regular Tasks
- Monitor verification success rates
- Review security logs for anomalies
- Update dependencies regularly
- Test disaster recovery procedures
- Review and rotate JWT secrets

### Version Updates
- Test WebAuthn library updates in staging
- Monitor browser compatibility changes
- Update documentation with new features
- Maintain backwards compatibility for API clients

---

For questions or support, please create an issue in the GitHub repository or contact the development team.