import requests
import json
import time

# Azure Function base URL
BASE_URL = "https://webauthn-investor.azurewebsites.net"

def test_verification_flow():
    """Test the complete verification flow"""
    
    # Step 1: Create verification link
    print("🔗 Step 1: Creating verification link...")
    response = requests.post(
        f"{BASE_URL}/api/verification/link",
        json={
            "user_id": "investor123",
            "username": "test@investor.com"
        },
        headers={"Content-Type": "application/json"}
    )
    
    if response.status_code == 200:
        data = response.json()
        token = data["token"]
        verification_url = data["verification_url"]
        
        print(f"✅ Verification link created:")
        print(f"   Token: {token}")
        print(f"   URL: {verification_url}")
        print(f"   Expires in: {data['expires_in']} seconds")
        
        # Step 2: Show how to check status
        print(f"\n📊 Step 2: Checking verification status...")
        
        # Check initial status
        status_response = requests.get(f"{BASE_URL}/api/verification/status?token={token}")
        if status_response.status_code == 200:
            status = status_response.json()
            print(f"   Initial status: {status}")
        
        # Step 3: Instructions for manual testing
        print(f"\n📱 Step 3: Manual testing instructions:")
        print(f"   1. Open this URL on your phone: {verification_url}")
        print(f"   2. Complete biometric verification")
        print(f"   3. Check status with: GET {BASE_URL}/api/verification/status?token={token}")
        
        # Step 4: Monitor for changes (polling example)
        print(f"\n⏰ Step 4: Monitoring for verification completion...")
        print("   (Polling every 5 seconds for 60 seconds...)")
        
        for i in range(12):  # Check for 1 minute
            time.sleep(5)
            status_response = requests.get(f"{BASE_URL}/api/verification/status?token={token}")
            
            if status_response.status_code == 200:
                status = status_response.json()
                print(f"   Check {i+1}: Verified = {status.get('verified', False)}")
                
                if status.get('verified'):
                    print(f"🎉 SUCCESS! User {status['user_id']} is verified!")
                    break
            else:
                print(f"   Check {i+1}: Status check failed")
                
        return token
        
    else:
        print(f"❌ Failed to create verification link: {response.text}")
        return None

def check_verification_status(token):
    """Check the verification status for a specific token"""
    response = requests.get(f"{BASE_URL}/api/verification/status?token={token}")
    
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": f"Status check failed: {response.text}"}

if __name__ == "__main__":
    print("🧪 Testing WebAuthn Verification Flow\n" + "="*50)
    token = test_verification_flow()
    
    if token:
        print(f"\n📋 Manual verification commands:")
        print(f"   Check status: curl '{BASE_URL}/api/verification/status?token={token}'")
        print(f"   Health check: curl '{BASE_URL}/health'")