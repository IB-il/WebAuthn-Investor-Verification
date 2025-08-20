# WebAuthn Investor Verification - Workflow Guide

## Overview

This guide provides the exact commands and workflow for implementing investor verification using biometric authentication. This is the complete process from creating a verification link to confirming investor identity.

## 🎯 Use Case

**Investment firms and brokers** can use this system to verify investor identity instantly using biometric authentication (Face ID, Touch ID, fingerprint) instead of traditional passwords or SMS codes.

## 📋 Complete Workflow

### Step 1: Create Verification Link

When an investor requests account access or identity verification, run this command:

```bash
curl -X POST "https://webauthn-investor.azurewebsites.net/api/verification/link" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"investor123","username":"investor@example.com"}'
```

**Parameters:**
- `user_id`: Unique identifier for the investor (your internal ID)
- `username`: Email or username for display purposes

**Expected Response:**
```json
{
  "verification_url": "https://webauthn-investor.azurewebsites.net/api/verify?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 900,
  "registration_required": true
}
```

**What this means:**
- `verification_url`: Send this URL to the investor
- `token`: Keep this to check verification status
- `expires_in`: Link expires in 900 seconds (15 minutes)
- `registration_required`: `true` for new users, `false` for returning users

### Step 2: Send Link to Investor

**Send the `verification_url` to the investor via:**
- SMS message
- Email
- Secure messaging platform
- QR code (see [Mobile Testing](#mobile-testing) below)

**Example message:**
```
Please verify your identity by clicking this secure link on your mobile device:
https://webauthn-investor.azurewebsites.net/api/verify?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

This link expires in 15 minutes for your security.
```

### Step 3: Investor Completes Verification

**The investor will:**
1. Click the verification link on their phone
2. See the verification page with "Verify Identity" button
3. Tap the button
4. Complete biometric authentication (Face ID, Touch ID, fingerprint)
5. See "Registration/Authentication successful!" message

### Step 4: Check Verification Result

Use the token from Step 1 to check if verification completed:

```bash
# Replace TOKEN with actual token from Step 1
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

curl "https://webauthn-investor.azurewebsites.net/api/verification/status?token=$TOKEN"
```

**Response before verification:**
```json
{
  "user_id": "investor123",
  "verified": false,
  "expires_at": "2025-08-20T23:15:00Z",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response after successful verification:**
```json
{
  "user_id": "investor123",
  "verified": true,
  "expires_at": "2025-08-20T23:15:00Z",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

## 🤖 Automated Workflow Script

Here's a complete script that automates the entire process:

```bash
#!/bin/bash

# WebAuthn Investor Verification Workflow

USER_ID="investor123"
USERNAME="investor@example.com"
BASE_URL="https://webauthn-investor.azurewebsites.net"

echo "🔐 WebAuthn Investor Verification Workflow"
echo "==========================================="
echo ""

# Step 1: Create verification link
echo "📝 Step 1: Creating verification link for $USER_ID..."
RESPONSE=$(curl -s -X POST "$BASE_URL/api/verification/link" \
  -H "Content-Type: application/json" \
  -d "{\"user_id\":\"$USER_ID\",\"username\":\"$USERNAME\"}")

# Check if request was successful
if [ $? -ne 0 ]; then
  echo "❌ Error: Failed to create verification link"
  exit 1
fi

# Extract token and URL
TOKEN=$(echo $RESPONSE | jq -r '.token')
URL=$(echo $RESPONSE | jq -r '.verification_url')
EXPIRES_IN=$(echo $RESPONSE | jq -r '.expires_in')

if [ "$TOKEN" = "null" ] || [ "$URL" = "null" ]; then
  echo "❌ Error: Invalid response from server"
  echo "$RESPONSE"
  exit 1
fi

echo "✅ Verification link created successfully!"
echo "   Token: ${TOKEN:0:20}..."
echo "   Expires in: $EXPIRES_IN seconds"
echo ""

# Step 2: Display link for investor
echo "📧 Step 2: Send this URL to investor:"
echo "   $URL"
echo ""
echo "📱 Or scan QR code with phone (if qrencode installed):"
if command -v qrencode &> /dev/null; then
  echo "$URL" | qrencode -t ANSI
else
  echo "   (Install qrencode to display QR code)"
fi
echo ""

# Step 3: Monitor verification status
echo "⏰ Step 3: Monitoring verification status..."
echo "   Checking every 5 seconds for up to 15 minutes..."
echo "   (Investor should complete verification on their phone)"
echo ""

ATTEMPTS=0
MAX_ATTEMPTS=180  # 15 minutes with 5-second intervals

while [ $ATTEMPTS -lt $MAX_ATTEMPTS ]; do
  STATUS_RESPONSE=$(curl -s "$BASE_URL/api/verification/status?token=$TOKEN")
  VERIFIED=$(echo $STATUS_RESPONSE | jq -r '.verified')
  
  ATTEMPTS=$((ATTEMPTS + 1))
  
  if [ "$VERIFIED" = "true" ]; then
    echo "🎉 SUCCESS! Investor $USER_ID has been verified!"
    echo "   Verification completed after $((ATTEMPTS * 5)) seconds"
    echo ""
    echo "📊 Final status:"
    echo "$STATUS_RESPONSE" | jq .
    exit 0
  elif [ "$VERIFIED" = "false" ]; then
    printf "   Check %d: ⏳ Waiting for verification... (%.1f min remaining)\r" \
      $ATTEMPTS $(echo "scale=1; (($MAX_ATTEMPTS - $ATTEMPTS) * 5) / 60" | bc)
  else
    echo "❌ Error checking verification status:"
    echo "$STATUS_RESPONSE"
    exit 1
  fi
  
  sleep 5
done

echo ""
echo "⏰ Timeout: Verification not completed within 15 minutes"
echo "   Link may have expired or investor hasn't completed the process"
echo ""
echo "📊 Final status:"
curl -s "$BASE_URL/api/verification/status?token=$TOKEN" | jq .

exit 1
```

**To use this script:**

1. Save as `verify_investor.sh`
2. Make executable: `chmod +x verify_investor.sh`
3. Run: `./verify_investor.sh`

## 🔄 Real-time Monitoring

For real-time monitoring of verification status:

```bash
# Create verification link first
RESPONSE=$(curl -s -X POST "https://webauthn-investor.azurewebsites.net/api/verification/link" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"investor123","username":"investor@example.com"}')

TOKEN=$(echo $RESPONSE | jq -r '.token')
URL=$(echo $RESPONSE | jq -r '.verification_url')

echo "📧 Send to investor: $URL"
echo "⏰ Monitoring verification..."

# Monitor in real-time
while true; do
  STATUS=$(curl -s "https://webauthn-investor.azurewebsites.net/api/verification/status?token=$TOKEN")
  VERIFIED=$(echo $STATUS | jq -r '.verified')
  
  if [ "$VERIFIED" = "true" ]; then
    echo "🎉 VERIFIED! ✅"
    break
  else
    echo "⏳ Pending... ($(date +%H:%M:%S))"
    sleep 2
  fi
done
```

## 📱 Mobile Testing

### Generate QR Code for Easy Mobile Access

```bash
# Install QR code generator (one-time setup)
# Ubuntu/Debian: sudo apt install qrencode
# macOS: brew install qrencode

# Create verification link and display QR code
RESPONSE=$(curl -s -X POST "https://webauthn-investor.azurewebsites.net/api/verification/link" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"mobile_test","username":"mobile@test.com"}')

URL=$(echo $RESPONSE | jq -r '.verification_url')

echo "📱 Scan this QR code with your phone camera:"
echo "$URL" | qrencode -t ANSI

echo ""
echo "Or copy this URL to your phone:"
echo "$URL"
```

### Mobile Testing Script

```bash
#!/bin/bash

echo "📱 Mobile WebAuthn Test"
echo "====================="

# Create test verification
RESPONSE=$(curl -s -X POST "https://webauthn-investor.azurewebsites.net/api/verification/link" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"mobile_test_'$(date +%s)'","username":"mobile@test.com"}')

TOKEN=$(echo $RESPONSE | jq -r '.token')
URL=$(echo $RESPONSE | jq -r '.verification_url')

echo "1. 📧 Open this URL on your phone:"
echo "   $URL"
echo ""

if command -v qrencode &> /dev/null; then
  echo "2. 📱 Or scan this QR code:"
  echo "$URL" | qrencode -t ANSI
  echo ""
fi

echo "3. 👆 Tap 'Verify Identity' and use your biometric authentication"
echo "4. ⏰ Monitoring for completion..."
echo ""

# Monitor verification
while true; do
  STATUS=$(curl -s "https://webauthn-investor.azurewebsites.net/api/verification/status?token=$TOKEN" 2>/dev/null)
  if [ $? -eq 0 ]; then
    VERIFIED=$(echo $STATUS | jq -r '.verified' 2>/dev/null)
    if [ "$VERIFIED" = "true" ]; then
      echo "🎉 Mobile verification successful!"
      echo "📊 Result: $STATUS" | jq .
      break
    fi
  fi
  
  printf "⏳ Waiting for mobile verification... %s\r" "$(date +%H:%M:%S)"
  sleep 2
done
```

## 💼 Integration Examples

### JavaScript/Node.js Integration

```javascript
const axios = require('axios');

class WebAuthnVerification {
  constructor(baseUrl = 'https://webauthn-investor.azurewebsites.net') {
    this.baseUrl = baseUrl;
  }

  async createVerificationLink(userId, username) {
    try {
      const response = await axios.post(`${this.baseUrl}/api/verification/link`, {
        user_id: userId,
        username: username
      });
      
      return {
        success: true,
        data: response.data
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  async checkVerificationStatus(token) {
    try {
      const response = await axios.get(
        `${this.baseUrl}/api/verification/status?token=${token}`
      );
      
      return {
        success: true,
        verified: response.data.verified,
        data: response.data
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  async verifyInvestor(userId, username, timeout = 900000) {
    // Create verification link
    const linkResult = await this.createVerificationLink(userId, username);
    if (!linkResult.success) {
      throw new Error(`Failed to create verification link: ${linkResult.error}`);
    }

    const { token, verification_url } = linkResult.data;
    
    // Return promise that resolves when verification completes
    return new Promise((resolve, reject) => {
      const startTime = Date.now();
      
      const checkStatus = async () => {
        if (Date.now() - startTime > timeout) {
          reject(new Error('Verification timeout'));
          return;
        }

        const status = await this.checkVerificationStatus(token);
        if (!status.success) {
          reject(new Error(`Status check failed: ${status.error}`));
          return;
        }

        if (status.verified) {
          resolve({
            verified: true,
            verification_url,
            token,
            data: status.data
          });
        } else {
          setTimeout(checkStatus, 5000); // Check again in 5 seconds
        }
      };

      // Return verification URL immediately, start monitoring
      resolve({
        verified: false,
        verification_url,
        token,
        monitor: checkStatus
      });
    });
  }
}

// Usage example
async function main() {
  const webauthn = new WebAuthnVerification();
  
  try {
    const result = await webauthn.createVerificationLink('investor123', 'investor@example.com');
    
    if (result.success) {
      console.log('📧 Send this URL to investor:', result.data.verification_url);
      
      // Monitor verification status
      const token = result.data.token;
      let verified = false;
      
      while (!verified) {
        const status = await webauthn.checkVerificationStatus(token);
        if (status.success && status.verified) {
          console.log('🎉 Investor verified successfully!');
          verified = true;
        } else {
          console.log('⏳ Waiting for verification...');
          await new Promise(resolve => setTimeout(resolve, 5000));
        }
      }
    }
  } catch (error) {
    console.error('❌ Error:', error.message);
  }
}
```

### Python Integration

```python
import requests
import time
import json

class WebAuthnVerification:
    def __init__(self, base_url="https://webauthn-investor.azurewebsites.net"):
        self.base_url = base_url

    def create_verification_link(self, user_id, username):
        """Create a verification link for an investor."""
        try:
            response = requests.post(
                f"{self.base_url}/api/verification/link",
                json={"user_id": user_id, "username": username},
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
            return {"success": True, "data": response.json()}
        except requests.RequestException as e:
            return {"success": False, "error": str(e)}

    def check_verification_status(self, token):
        """Check if verification has been completed."""
        try:
            response = requests.get(
                f"{self.base_url}/api/verification/status",
                params={"token": token}
            )
            response.raise_for_status()
            data = response.json()
            return {
                "success": True,
                "verified": data.get("verified", False),
                "data": data
            }
        except requests.RequestException as e:
            return {"success": False, "error": str(e)}

    def verify_investor(self, user_id, username, timeout=900):
        """Complete investor verification workflow."""
        print(f"🔐 Starting verification for {user_id}...")
        
        # Step 1: Create verification link
        link_result = self.create_verification_link(user_id, username)
        if not link_result["success"]:
            raise Exception(f"Failed to create verification link: {link_result['error']}")
        
        token = link_result["data"]["token"]
        verification_url = link_result["data"]["verification_url"]
        
        print(f"📧 Send this URL to investor: {verification_url}")
        print("⏰ Waiting for verification completion...")
        
        # Step 2: Monitor verification status
        start_time = time.time()
        while time.time() - start_time < timeout:
            status = self.check_verification_status(token)
            
            if not status["success"]:
                print(f"❌ Error checking status: {status['error']}")
                time.sleep(5)
                continue
                
            if status["verified"]:
                print("🎉 Verification successful!")
                return {
                    "success": True,
                    "verified": True,
                    "token": token,
                    "data": status["data"]
                }
            
            print("⏳ Still waiting...")
            time.sleep(5)
        
        print("⏰ Verification timeout")
        return {"success": False, "error": "Timeout"}

# Usage example
if __name__ == "__main__":
    webauthn = WebAuthnVerification()
    
    try:
        result = webauthn.verify_investor("investor123", "investor@example.com")
        if result["success"]:
            print("✅ Investor verification completed successfully!")
        else:
            print(f"❌ Verification failed: {result['error']}")
    except Exception as e:
        print(f"❌ Error: {e}")
```

## 🚨 Error Handling

### Common Error Scenarios

**1. Invalid Request Format**
```bash
# Wrong: Missing Content-Type header
curl -X POST "https://webauthn-investor.azurewebsites.net/api/verification/link" \
  -d '{"user_id":"test","username":"test@test.com"}'

# Correct: Include Content-Type header
curl -X POST "https://webauthn-investor.azurewebsites.net/api/verification/link" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"test","username":"test@test.com"}'
```

**2. Token Validation Errors**
```bash
# Check if token is valid
TOKEN="invalid_token_here"
RESPONSE=$(curl -s "https://webauthn-investor.azurewebsites.net/api/verification/status?token=$TOKEN")
ERROR=$(echo $RESPONSE | jq -r '.error // empty')

if [ ! -z "$ERROR" ]; then
  echo "❌ Token error: $ERROR"
else
  echo "✅ Token is valid"
fi
```

**3. Expired Links**
```bash
# Check expiration
STATUS=$(curl -s "https://webauthn-investor.azurewebsites.net/api/verification/status?token=$TOKEN")
EXPIRES_AT=$(echo $STATUS | jq -r '.expires_at')
CURRENT_TIME=$(date -u +%Y-%m-%dT%H:%M:%S)

echo "Link expires at: $EXPIRES_AT"
echo "Current time: $CURRENT_TIME"
```

## 📊 Monitoring and Analytics

### Track Verification Success Rates

```bash
#!/bin/bash

# Verification analytics script
TOTAL_ATTEMPTS=0
SUCCESSFUL_VERIFICATIONS=0
FAILED_VERIFICATIONS=0

echo "📊 WebAuthn Verification Analytics"
echo "================================="

for i in {1..10}; do
  USER_ID="test_user_$i"
  USERNAME="test$i@example.com"
  
  echo "Testing verification $i/10..."
  
  # Create verification link
  RESPONSE=$(curl -s -X POST "https://webauthn-investor.azurewebsites.net/api/verification/link" \
    -H "Content-Type: application/json" \
    -d "{\"user_id\":\"$USER_ID\",\"username\":\"$USERNAME\"}")
  
  TOKEN=$(echo $RESPONSE | jq -r '.token')
  
  if [ "$TOKEN" != "null" ]; then
    TOTAL_ATTEMPTS=$((TOTAL_ATTEMPTS + 1))
    echo "✅ Link created successfully"
  else
    FAILED_VERIFICATIONS=$((FAILED_VERIFICATIONS + 1))
    echo "❌ Failed to create link"
  fi
  
  sleep 1
done

echo ""
echo "📈 Results:"
echo "  Total attempts: $TOTAL_ATTEMPTS"
echo "  Successful links: $TOTAL_ATTEMPTS"
echo "  Failed links: $FAILED_VERIFICATIONS"
echo "  Success rate: $(echo "scale=1; $TOTAL_ATTEMPTS * 100 / ($TOTAL_ATTEMPTS + $FAILED_VERIFICATIONS)" | bc)%"
```

## 🔗 Related Documentation

- **[User Guide](USER_GUIDE.md)** - For investors using the verification system
- **[Developer Guide](DEVELOPER_GUIDE.md)** - Technical implementation details
- **[Command Reference](COMMANDS.md)** - All available commands and utilities

---

**💡 Pro Tip**: Bookmark this workflow guide for quick reference during investor verification processes!