# WebAuthn Investor Verification System

🔐 **Enterprise biometric authentication for investor verification using Azure Functions**

[![Azure Functions](https://img.shields.io/badge/Azure-Functions-0078d4?style=flat&logo=microsoft-azure)](https://webauthn-investor.azurewebsites.net)
[![WebAuthn](https://img.shields.io/badge/WebAuthn-2.2.0-green?style=flat)](https://webauthn.io)
[![Tests](https://img.shields.io/badge/Tests-124%20Passing-brightgreen?style=flat)]()
[![Hebrew UI](https://img.shields.io/badge/UI-Hebrew%20RTL-blue?style=flat)]()

## 🚀 **Production Ready - Live System**

**Production URL**: https://webauthn-investor.azurewebsites.net

**Status**: ✅ Active production deployment with Hebrew UI and biometric authentication

## 🎯 **Minimal Design Approach**

**Essential functionality only - no over-engineering**

### Core Features
- **🔐 Biometric Only**: Face ID, Touch ID, Windows Hello (no passwords)
- **📱 Platform Enforced**: Forces "This Device" - no external authenticators  
- **🇮🇱 Hebrew UI**: Native RTL interface with Interactive Israel branding
- **☁️ Serverless**: Azure Functions with auto-scaling
- **🗄️ Enterprise Storage**: Azure Table Storage (99.9% SLA)
- **⚡ Fast**: Sub-second verification response times

## 📋 **Quick Start**

### Create Verification Link
```bash
curl -X POST "https://webauthn-investor.azurewebsites.net/api/verification/link" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "investor_123"}'

# Response
{
  "verification_url": "https://webauthn-investor.azurewebsites.net/api/verify?token=...",
  "token": "eyJhbGc...",
  "expires_in": 900
}
```

### User Experience
1. **Send verification URL** to investor
2. **User opens link** → Hebrew UI loads
3. **Direct biometric prompt** → Face ID/Touch ID/Windows Hello  
4. **Instant verification** → No selection dialogs or complexity

## 🏗️ **Clean Architecture**

### Service Layer
```
├── AzureStorageService     # Data persistence
├── WebAuthnService         # Biometric operations  
├── SessionService          # JWT & session management
├── AuthService            # Security & validation
└── TemplateService        # Hebrew UI rendering
```

### API Endpoints
- `POST /api/verification/link` - Create verification (user_id only)
- `GET /api/verify?token=...` - Hebrew verification page
- `GET /api/webauthn/options` - WebAuthn challenge generation
- `POST /api/webauthn/register` - New credential registration
- `POST /api/webauthn/authenticate` - Existing credential verification

## 🔧 **Development**

### Prerequisites
- Python 3.11+
- Azure Functions Core Tools
- Azure Storage Account

### Local Setup
```bash
# Clone repository
git clone https://github.com/IB-il/WebAuthn-Investor-Verification.git
cd WebAuthn-Investor-Verification/azure-deployment

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp local.settings.json.example local.settings.json
# Edit with your Azure Storage connection string

# Run locally
func start --python

# Run tests
python -m pytest tests/ -v
```

### Environment Variables
```bash
# Required
AZURE_STORAGE_CONNECTION_STRING="DefaultEndpointsProtocol=https;..."

# Optional (secure defaults provided)
ADMIN_API_KEY="your-admin-key"
RP_ID="your-domain.com"
ORIGIN="https://your-domain.com"
JWT_SECRET="auto-generated"
JWT_TTL_SECONDS="900"
```

## 🧪 **Testing**

### Comprehensive Test Suite (124 Tests)
```bash
# All tests
python -m pytest tests/ -v

# By category
python -m pytest tests/unit/ -v           # Unit tests (109)
python -m pytest tests/integration/ -v    # Integration tests (15)
python -m pytest -m auth -v               # Auth tests only
python -m pytest -m webauthn -v           # WebAuthn tests only
```

### Test Coverage
- ✅ **Authentication**: Admin API, rate limiting, security validation
- ✅ **Session Management**: JWT generation, verification, expiration
- ✅ **WebAuthn**: Registration, authentication, credential management
- ✅ **Templates**: Hebrew rendering, error pages, context injection
- ✅ **Security**: XSS protection, SQL injection prevention
- ✅ **Hebrew Support**: RTL text, Unicode handling, error messages

## 🔐 **Security Model**

### Biometric Authentication
- **No Passwords**: Biometric credentials only (Face ID, Touch ID, etc.)
- **Platform Enforced**: Device authenticators required, external blocked
- **Zero Knowledge**: Server never sees biometric data
- **Cryptographic**: WebAuthn public key cryptography

### Security Features
- **Rate Limiting**: 5 requests per 15 minutes per IP
- **Input Validation**: XSS and SQL injection protection  
- **Admin Authentication**: Secure API key for admin endpoints
- **Session Security**: JWT with cryptographically secure secrets
- **Privacy Protection**: Sensitive data hashed in logs

## 🌐 **Hebrew UI**

### RTL Support
- **Native Hebrew**: Right-to-left text direction
- **Interactive Israel Branding**: Corporate colors and typography
- **Mobile Optimized**: Responsive design for Hebrew mobile devices
- **Accessibility**: Screen reader compatible

### User Experience
- **No Selection Dialog**: Direct to biometric authentication
- **Hebrew Instructions**: Native error messages and guidance
- **Progressive Enhancement**: Works without JavaScript fallback

## 📊 **Production Metrics**

### Performance
- **Response Time**: < 1 second for verification
- **Cold Start**: < 3 seconds for Azure Functions
- **Availability**: 99.9% SLA with Azure infrastructure
- **Scalability**: Auto-scaling serverless architecture

### Browser Support
- **iOS Safari**: 14+ (Face ID, Touch ID)
- **Android Chrome**: 67+ (Fingerprint, Face unlock)  
- **Desktop Chrome**: 67+ (Windows Hello, Touch ID)
- **Firefox**: 96+ (Platform authenticators)
- **Edge**: 79+ (Windows Hello)

## 🚀 **Deployment**

### Azure Functions Deployment
```bash
# Deploy to production
func azure functionapp publish webauthn-investor --python

# Verify deployment
curl https://webauthn-investor.azurewebsites.net/health
```

### Production Configuration
- **Runtime**: Python 3.11 on Azure Functions
- **Storage**: Azure Table Storage with automatic backup
- **HTTPS**: Enforced with Azure-managed certificates
- **Environment**: Secure environment variable management

## 📈 **System Evolution**

### Architecture Journey
1. **v0.1**: Basic verification system (monolithic)
2. **v0.5**: Clean Architecture Phase 1 (Storage Service)
3. **v0.6**: Clean Architecture Phase 2 (WebAuthn Service)
4. **v0.7**: Clean Architecture Phase 3 (Template System)
5. **v0.8**: Clean Architecture Phase 4 (Session & Auth Services)
6. **v0.9**: Clean Architecture Phase 5 (Comprehensive Testing)
7. **v1.0**: Minimal Approach Complete (Username Removal)

### Design Philosophy
- **Minimal Approach**: Essential functionality only
- **No Over-Engineering**: Simple, focused implementation
- **Clean Architecture**: Service-based design with single responsibility
- **Security First**: Biometric authentication with comprehensive protection
- **Hebrew Native**: RTL UI designed for Hebrew users

## 📞 **Support**

### Admin API
```bash
# List all users (requires admin key)
curl -H "Authorization: Bearer your-admin-key" \
  https://webauthn-investor.azurewebsites.net/api/users

# View active sessions
curl -H "Authorization: Bearer your-admin-key" \
  https://webauthn-investor.azurewebsites.net/api/sessions
```

### Monitoring
- **Health Check**: GET `/health` for system status
- **Logs**: Azure Application Insights integration
- **Metrics**: Request counts, response times, error rates

### Troubleshooting
- **WebAuthn Issues**: Check browser DevTools console
- **Hebrew Display**: Ensure UTF-8 encoding in browser
- **Biometric Errors**: Verify device has Face ID/Touch ID enabled
- **Network Issues**: Check HTTPS and CORS configuration

---

## 🏆 **Architecture Achievements**

✅ **Clean Architecture**: Service-based design with single responsibility  
✅ **Comprehensive Testing**: 124 tests covering all functionality  
✅ **Security Hardening**: Rate limiting, input validation, biometric only  
✅ **Hebrew UI**: Native RTL interface with Interactive Israel branding  
✅ **Platform Enforcement**: Direct biometric authentication (no selection)  
✅ **Minimal Design**: Essential functionality only - no over-engineering  
✅ **Production Ready**: Live deployment with enterprise infrastructure  

**Technical Excellence**: From monolithic 800-line file to clean service architecture with comprehensive testing and minimal design approach.