# Deployment Instructions - WebAuthn Investor Verification

## 🚀 **Production Deployment Guide**

### Prerequisites
- Azure CLI installed and configured
- Azure Functions Core Tools v4+
- Python 3.11+ with pip
- Git repository access

## 📋 **Step-by-Step Deployment**

### 1. Azure Resource Setup
```bash
# Login to Azure
az login

# Create resource group
az group create --name webauthn-rg --location "East US"

# Create storage account
az storage account create \
  --name webauthnstorageacct \
  --resource-group webauthn-rg \
  --location "East US" \
  --sku Standard_LRS

# Create Function App
az functionapp create \
  --resource-group webauthn-rg \
  --consumption-plan-location "East US" \
  --runtime python \
  --runtime-version 3.11 \
  --functions-version 4 \
  --name webauthn-investor \
  --storage-account webauthnstorageacct
```

### 2. Environment Configuration
```bash
# Get storage connection string
STORAGE_CONNECTION=$(az storage account show-connection-string \
  --name webauthnstorageacct \
  --resource-group webauthn-rg \
  --query connectionString -o tsv)

# Configure Function App settings
az functionapp config appsettings set \
  --name webauthn-investor \
  --resource-group webauthn-rg \
  --settings "AZURE_STORAGE_CONNECTION_STRING=$STORAGE_CONNECTION"

# Set admin API key (generate secure key)
ADMIN_KEY=$(openssl rand -hex 16)
az functionapp config appsettings set \
  --name webauthn-investor \
  --resource-group webauthn-rg \
  --settings "ADMIN_API_KEY=$ADMIN_KEY"

# Set JWT secret (generate secure key)
JWT_SECRET=$(openssl rand -base64 64)
az functionapp config appsettings set \
  --name webauthn-investor \
  --resource-group webauthn-rg \
  --settings "JWT_SECRET=$JWT_SECRET"

# Configure domain settings
az functionapp config appsettings set \
  --name webauthn-investor \
  --resource-group webauthn-rg \
  --settings "RP_ID=webauthn-investor.azurewebsites.net" \
             "ORIGIN=https://webauthn-investor.azurewebsites.net"
```

### 3. Code Deployment
```bash
# Clone repository
git clone https://github.com/IB-il/WebAuthn-Investor-Verification.git
cd WebAuthn-Investor-Verification/azure-deployment

# Install dependencies (optional - for local testing)
pip install -r requirements.txt

# Run tests before deployment
python -m pytest tests/ -v

# Deploy to Azure Functions
func azure functionapp publish webauthn-investor --python
```

### 4. Verification
```bash
# Health check
curl https://webauthn-investor.azurewebsites.net/health

# Create test verification
curl -X POST "https://webauthn-investor.azurewebsites.net/api/verification/link" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "test_investor"}'

# Verify admin API (replace with your admin key)
curl -H "Authorization: Bearer YOUR_ADMIN_KEY" \
  https://webauthn-investor.azurewebsites.net/api/users
```

## ⚙️ **Configuration Reference**

### Required Settings
| Variable | Description | Example |
|----------|-------------|---------|
| `AZURE_STORAGE_CONNECTION_STRING` | Azure Table Storage connection | `DefaultEndpointsProtocol=https;...` |

### Optional Settings (Secure Defaults)
| Variable | Default | Description |
|----------|---------|-------------|
| `ADMIN_API_KEY` | Auto-generated | Admin endpoints authentication |
| `JWT_SECRET` | Auto-generated | JWT token signing secret |
| `JWT_TTL_SECONDS` | `900` | Token expiration (15 minutes) |
| `RP_ID` | Function app domain | WebAuthn Relying Party ID |
| `ORIGIN` | Function app HTTPS URL | WebAuthn origin validation |

## 🔒 **Security Configuration**

### WebAuthn Settings
- **Platform Authenticator**: Enforced (Face ID, Touch ID, Windows Hello only)
- **User Verification**: Required (biometric authentication mandatory)
- **External Authenticators**: Blocked (no USB keys or external devices)

### Rate Limiting
- **Default**: 5 requests per 15 minutes per IP
- **Configurable**: Modify in `AuthService` if needed
- **Automatic**: IP-based tracking with cleanup

### Admin API Security
- **Authentication**: Bearer token required for admin endpoints
- **Key Generation**: Use cryptographically secure random keys
- **Access Control**: Admin endpoints protected behind authentication

## 📱 **Browser Compatibility**

### Supported Platforms
| Platform | Browser | Authenticator | Version |
|----------|---------|---------------|---------|
| iOS | Safari | Face ID, Touch ID | 14+ |
| Android | Chrome | Fingerprint, Face | 67+ |
| Windows | Chrome/Edge | Windows Hello | 67+/79+ |
| macOS | Chrome/Safari | Touch ID | 67+/14+ |

### WebAuthn Requirements
- **HTTPS**: Required for WebAuthn (automatically provided by Azure)
- **Secure Context**: Modern browser with WebAuthn API support
- **Platform Authenticator**: Device must have biometric capability

## 🌐 **Hebrew UI Configuration**

### RTL Support
- **Text Direction**: Automatic RTL for Hebrew content
- **Typography**: Hebrew-optimized fonts (Arial, Tahoma fallbacks)
- **Layout**: Right-to-left interface design
- **Interactive Israel**: Corporate branding and colors

### Localization
- **Error Messages**: Native Hebrew text
- **Instructions**: Hebrew user guidance
- **Accessibility**: Hebrew screen reader support

## 📊 **Monitoring & Maintenance**

### Health Monitoring
```bash
# System health
curl https://webauthn-investor.azurewebsites.net/health

# Admin statistics
curl -H "Authorization: Bearer YOUR_ADMIN_KEY" \
  https://webauthn-investor.azurewebsites.net/api/users
```

### Log Analysis
- **Azure Application Insights**: Automatic logging integration
- **Security Events**: Privacy-protected security event logging
- **Performance**: Request timing and error rate monitoring

### Maintenance Tasks
- **Dependency Updates**: Monitor for security updates
- **Certificate Renewal**: Automatic HTTPS certificate management
- **Storage Cleanup**: Expired sessions cleaned automatically
- **Testing**: Run test suite before any changes

## 🔄 **Update Deployment**

### Code Updates
```bash
# Pull latest changes
git pull origin master

# Run tests
python -m pytest tests/ -v

# Deploy updates
func azure functionapp publish webauthn-investor --python

# Verify deployment
curl https://webauthn-investor.azurewebsites.net/health
```

### Configuration Updates
```bash
# Update application settings
az functionapp config appsettings set \
  --name webauthn-investor \
  --resource-group webauthn-rg \
  --settings "SETTING_NAME=new_value"

# Restart function app (if needed)
az functionapp restart \
  --name webauthn-investor \
  --resource-group webauthn-rg
```

## 🆘 **Troubleshooting**

### Common Issues

**"ModuleNotFoundError" during deployment**
```bash
# Ensure Python 3.11 runtime
az functionapp config show \
  --name webauthn-investor \
  --resource-group webauthn-rg \
  --query "pythonVersion"
```

**WebAuthn not working on device**
- Verify HTTPS (required for WebAuthn)
- Check browser supports WebAuthn API
- Ensure device has biometric capability
- Clear browser cache and retry

**Hebrew text not displaying**
- Verify UTF-8 encoding in browser
- Check Content-Type headers include charset=utf-8
- Ensure Hebrew fonts available on device

**Rate limiting issues**
- Wait 15 minutes for rate limit reset
- Use different IP address for testing
- Configure different limits in AuthService if needed

### Debug Mode
```bash
# Enable verbose logging (local development)
export FUNCTIONS_WORKER_RUNTIME=python
export AzureWebJobsFeatureFlags=EnableWorkerIndexing
func start --python --verbose
```

## 📧 **Support**

### Production System
- **Live URL**: https://webauthn-investor.azurewebsites.net
- **Status**: Active production deployment
- **Monitoring**: 24/7 Azure infrastructure monitoring

### Technical Contact
- **Repository**: GitHub Issues for bug reports
- **Documentation**: See CLAUDE.md for technical details
- **Architecture**: See CHANGELOG.md for system evolution

---

**Deployment Status**: ✅ Production Ready  
**Last Updated**: 2025-08-22  
**Version**: v1.0.0 - Minimal Approach Complete