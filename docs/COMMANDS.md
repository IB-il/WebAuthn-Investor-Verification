# WebAuthn Investor Verification - Command Reference

## 🚀 Quick Start Commands

### Local Development Setup
```bash
# Clone repository
git clone https://github.com/IB-il/WebAuthn-Investor-Verification.git
cd WebAuthn-Investor-Verification

# Setup Python environment
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# .venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Run local server
python main.py
```

### Azure Deployment Setup
```bash
# Login to Azure
az login

# Create resource group
az group create --name webauthn-rg --location eastus

# Create storage account
az storage account create --name webauthnstg$(date +%s) --resource-group webauthn-rg --location eastus

# Create function app
az functionapp create --name webauthn-investor --resource-group webauthn-rg \
  --consumption-plan-location eastus --runtime python --runtime-version 3.11 \
  --functions-version 4

# Deploy functions
cd azure-deployment
func azure functionapp publish webauthn-investor --python --build remote
```

## 📡 API Commands

### Create Verification Link
```bash
# Local development
curl -X POST "http://localhost:8000/api/verification/link" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"investor123","username":"investor@example.com"}'

# Azure production
curl -X POST "https://webauthn-investor.azurewebsites.net/api/verification/link" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"investor123","username":"investor@example.com"}'
```

### Check Verification Status
```bash
# Replace TOKEN with actual JWT token from verification link response
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Local
curl "http://localhost:8000/api/verification/status?token=$TOKEN"

# Azure
curl "https://webauthn-investor.azurewebsites.net/api/verification/status?token=$TOKEN"
```

### Health Check
```bash
# Local
curl "http://localhost:8000/health"

# Azure
curl "https://webauthn-investor.azurewebsites.net/health"
```

### List All Sessions (Admin)
```bash
# Local
curl "http://localhost:8000/api/admin/sessions"

# Azure
curl "https://webauthn-investor.azurewebsites.net/api/admin/sessions"
```

## 🔧 Development Commands

### Testing
```bash
# Run complete verification flow test
cd azure-deployment
python -m venv test-env
source test-env/bin/activate
pip install requests
python test_flow.py
```

### Code Quality
```bash
# Install development tools
pip install black isort flake8 mypy

# Format code
black .
isort .

# Check code style
flake8 .
mypy .
```

### Database Management
```bash
# Check SQLite database (if using local storage)
sqlite3 credentials.db ".tables"
sqlite3 credentials.db "SELECT * FROM credentials;"
sqlite3 credentials.db "SELECT * FROM sessions;"
```

## ☁️ Azure Management Commands

### Resource Management
```bash
# List resource groups
az group list --output table

# List function apps
az functionapp list --resource-group webauthn-rg --output table

# Show function app details
az functionapp show --name webauthn-investor --resource-group webauthn-rg

# List functions in app
az functionapp function list --name webauthn-investor --resource-group webauthn-rg --output table
```

### Configuration
```bash
# Set application settings
az functionapp config appsettings set --name webauthn-investor --resource-group webauthn-rg \
  --settings "RP_ID=webauthn-investor.azurewebsites.net" \
             "ORIGIN=https://webauthn-investor.azurewebsites.net" \
             "JWT_SECRET=your-production-secret-here" \
             "JWT_TTL_SECONDS=900"

# List current settings
az functionapp config appsettings list --name webauthn-investor --resource-group webauthn-rg --output table
```

### Monitoring
```bash
# View function app logs
az webapp log tail --name webauthn-investor --resource-group webauthn-rg

# Show metrics
az monitor metrics list --resource /subscriptions/{subscription-id}/resourceGroups/webauthn-rg/providers/Microsoft.Web/sites/webauthn-investor \
  --metric "Requests" --interval PT1M

# List log analytics
az monitor log-analytics query --workspace {workspace-id} --analytics-query "requests | limit 10"
```

### Deployment
```bash
# Deploy from local directory
cd azure-deployment
func azure functionapp publish webauthn-investor --python --build remote

# Deploy with specific settings
func azure functionapp publish webauthn-investor --python --build remote --force

# Check deployment status
az functionapp deployment list --name webauthn-investor --resource-group webauthn-rg --output table
```

## 📊 Monitoring Commands

### Real-time Testing
```bash
# Create verification and monitor in real-time
TOKEN=$(curl -s -X POST "https://webauthn-investor.azurewebsites.net/api/verification/link" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"test123","username":"test@test.com"}' | \
  jq -r '.token')

echo "Verification URL: https://webauthn-investor.azurewebsites.net/api/verify?token=$TOKEN"

# Monitor verification status (run in loop)
while true; do
  curl -s "https://webauthn-investor.azurewebsites.net/api/verification/status?token=$TOKEN" | \
    jq '.verified' | \
    sed 's/true/✅ VERIFIED/' | \
    sed 's/false/⏳ Pending/'
  sleep 2
done
```

### Performance Testing
```bash
# Test response times
time curl -s "https://webauthn-investor.azurewebsites.net/health" > /dev/null

# Multiple concurrent requests
for i in {1..10}; do
  curl -s "https://webauthn-investor.azurewebsites.net/health" &
done
wait
```

## 🔐 Security Commands

### JWT Token Inspection
```bash
# Decode JWT token (install jq first: apt install jq)
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
echo $TOKEN | cut -d. -f2 | base64 --decode | jq .

# Validate token expiration
python3 -c "
import jwt
import json
token = '$TOKEN'
try:
    payload = jwt.decode(token, options={'verify_signature': False})
    print(json.dumps(payload, indent=2))
except Exception as e:
    print(f'Error: {e}')
"
```

### SSL Certificate Check
```bash
# Check SSL certificate
openssl s_client -connect webauthn-investor.azurewebsites.net:443 -servername webauthn-investor.azurewebsites.net

# Check certificate expiration
echo | openssl s_client -connect webauthn-investor.azurewebsites.net:443 2>/dev/null | \
  openssl x509 -noout -dates
```

## 📝 Git Commands

### Repository Management
```bash
# Check status
git status

# Add all changes
git add .

# Commit with descriptive message
git commit -m "feat: add new verification feature

- Implement biometric authentication
- Add monitoring endpoints
- Update documentation

🤖 Generated with [Claude Code](https://claude.ai/code)

Co-Authored-By: Claude <noreply@anthropic.com>"

# Push to GitHub
git push

# Create new branch
git checkout -b feature/new-feature

# Merge branch
git checkout master
git merge feature/new-feature
```

### Release Management
```bash
# Create release tag
git tag -a v1.0.0 -m "Release version 1.0.0"
git push origin v1.0.0

# List tags
git tag -l

# Create release branch
git checkout -b release/v1.0.0
```

## 🧪 Testing Commands

### Manual API Testing
```bash
# Full verification flow test
echo "1. Creating verification link..."
RESPONSE=$(curl -s -X POST "https://webauthn-investor.azurewebsites.net/api/verification/link" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"test123","username":"test@test.com"}')

TOKEN=$(echo $RESPONSE | jq -r '.token')
URL=$(echo $RESPONSE | jq -r '.verification_url')

echo "2. Verification URL: $URL"
echo "3. Token: $TOKEN"

echo "4. Initial status:"
curl -s "https://webauthn-investor.azurewebsites.net/api/verification/status?token=$TOKEN" | jq .

echo "5. Open URL in browser and complete verification, then check status again:"
echo "curl -s 'https://webauthn-investor.azurewebsites.net/api/verification/status?token=$TOKEN' | jq ."
```

### Load Testing
```bash
# Simple load test with curl
echo "Running load test..."
for i in {1..100}; do
  (curl -s "https://webauthn-investor.azurewebsites.net/health" > /dev/null && echo "✅ $i") &
  if (( i % 10 == 0 )); then wait; fi
done
wait
echo "Load test complete"
```

### Integration Testing
```bash
# Test all endpoints
ENDPOINTS=(
  "/health"
  "/api/admin/sessions"
)

BASE_URL="https://webauthn-investor.azurewebsites.net"

for endpoint in "${ENDPOINTS[@]}"; do
  echo "Testing $endpoint..."
  response=$(curl -s -w "%{http_code}" -o /dev/null "$BASE_URL$endpoint")
  if [ "$response" -eq 200 ]; then
    echo "✅ $endpoint: OK"
  else
    echo "❌ $endpoint: HTTP $response"
  fi
done
```

## 🔄 Maintenance Commands

### Cleanup Commands
```bash
# Clean Python cache
find . -type d -name "__pycache__" -delete
find . -name "*.pyc" -delete

# Clean virtual environment
rm -rf .venv
python -m venv .venv

# Clean Azure deployment artifacts
cd azure-deployment
rm -rf .azure/
```

### Backup Commands
```bash
# Backup configuration
cp .env .env.backup.$(date +%Y%m%d)

# Export Azure settings
az functionapp config appsettings list --name webauthn-investor --resource-group webauthn-rg > azure-settings-backup.json
```

### Update Commands
```bash
# Update Python dependencies
pip install --upgrade pip
pip install -r requirements.txt --upgrade

# Update Azure Functions Core Tools
npm update -g azure-functions-core-tools@4

# Update Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
```

## 📱 Mobile Testing Commands

### Generate QR Code for Easy Mobile Access
```bash
# Install qrencode: apt install qrencode (Linux) or brew install qrencode (Mac)

# Create verification link and generate QR code
RESPONSE=$(curl -s -X POST "https://webauthn-investor.azurewebsites.net/api/verification/link" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"mobile_test","username":"mobile@test.com"}')

URL=$(echo $RESPONSE | jq -r '.verification_url')
echo "Scan this QR code with your phone:"
echo $URL | qrencode -t ANSI
echo "Or open: $URL"
```

## 🆘 Troubleshooting Commands

### Debug Information
```bash
# Check Python version
python --version

# Check installed packages
pip list

# Check Azure CLI version
az --version

# Check Functions Core Tools version
func --version

# System information
uname -a
```

### Common Fixes
```bash
# Fix Azure Functions cold start
curl -s "https://webauthn-investor.azurewebsites.net/health" > /dev/null
sleep 5
curl -s "https://webauthn-investor.azurewebsites.net/health"

# Reset local environment
deactivate
rm -rf .venv
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Redeploy Azure Functions
cd azure-deployment
func azure functionapp publish webauthn-investor --python --build remote --force
```

### Log Analysis
```bash
# Parse Azure logs for errors
az webapp log tail --name webauthn-investor --resource-group webauthn-rg | grep -i error

# Check specific time range
az monitor activity-log list --resource-group webauthn-rg --start-time 2025-01-01T00:00:00Z --end-time 2025-01-01T23:59:59Z
```

## 💡 Useful Aliases

Add these to your `~/.bashrc` or `~/.zshrc`:

```bash
# WebAuthn aliases
alias wa-local="cd /path/to/WebAuthn-Investor-Verification && source .venv/bin/activate && python main.py"
alias wa-test="cd /path/to/WebAuthn-Investor-Verification/azure-deployment && python test_flow.py"
alias wa-deploy="cd /path/to/WebAuthn-Investor-Verification/azure-deployment && func azure functionapp publish webauthn-investor --python --build remote"
alias wa-logs="az webapp log tail --name webauthn-investor --resource-group webauthn-rg"
alias wa-health="curl -s https://webauthn-investor.azurewebsites.net/health | jq ."

# Azure shortcuts
alias az-login="az login"
alias az-list="az functionapp list --resource-group webauthn-rg --output table"
alias az-settings="az functionapp config appsettings list --name webauthn-investor --resource-group webauthn-rg --output table"
```

---

💡 **Tip**: Bookmark this page or keep it handy during development and deployment!

For more detailed explanations, see the [Developer Guide](DEVELOPER_GUIDE.md) or [User Guide](USER_GUIDE.md).