# WebAuthn Data Storage and User Management

## 📊 **What Data is Stored and Where**

### **user_id and username Purpose**

The `user_id` and `username` serve different purposes in the WebAuthn verification system:

#### **user_id** (Primary Identifier)
- **Purpose**: Unique identifier for the investor/user in your system
- **Examples**: `"investor_12345"`, `"user_abc123"`, `"client_789"`
- **Usage**: Links WebAuthn credentials to your business logic
- **Requirements**: Must be unique and consistent for the same person

#### **username** (Display Name)  
- **Purpose**: Human-readable identifier shown to the user
- **Examples**: `"john@investor.com"`, `"John Smith"`, `"j.smith"`
- **Usage**: Displayed during WebAuthn registration/authentication
- **Requirements**: Should be recognizable to the user

## 🗄️ **Data Storage Locations**

### **Local Development (SQLite)**
Data is stored in `verification.db` file with two main tables:

#### **user_credentials** table:
```sql
CREATE TABLE user_credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,           -- Your system's user ID
    username TEXT NOT NULL,          -- Display name  
    credential_id TEXT NOT NULL,     -- WebAuthn credential ID
    public_key TEXT NOT NULL,        -- Cryptographic public key
    sign_count INTEGER DEFAULT 0,    -- Security counter
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
```

#### **verification_sessions** table:
```sql
CREATE TABLE verification_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,           -- Links to user_credentials
    token TEXT NOT NULL UNIQUE,      -- JWT token for this session
    challenge TEXT NOT NULL,         -- WebAuthn challenge
    verified BOOLEAN DEFAULT FALSE, -- Verification status
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL   -- Session expiration
)
```

### **Azure Production (In-Memory)**
For the demo Azure deployment, data is stored in Python dictionaries:

```python
# User credentials storage
credentials_db = {
    "investor123": [
        ("credential_id_1", "public_key_1", 0),
        ("credential_id_2", "public_key_2", 0)
    ]
}

# Active sessions storage
sessions_db = {
    "jwt_token_here": {
        "user_id": "investor123",
        "challenge": "base64_challenge", 
        "verified": True,
        "expires_at": datetime_object
    }
}
```

**⚠️ Note**: Azure demo uses in-memory storage that resets when the function restarts. For production, use Azure Table Storage or CosmosDB.

## 👥 **User Management**

### **Viewing Registered Users**

#### **Browser (GET):**
```
https://webauthn-investor.azurewebsites.net/api/users
```

#### **curl:**
```bash
curl "https://webauthn-investor.azurewebsites.net/api/users"
```

#### **Response:**
```json
{
  "total_users": 3,
  "users": [
    {
      "user_id": "investor123",
      "username": "john@investor.com",
      "credentials_count": 2,
      "first_registration": "2025-01-20T10:30:00"
    },
    {
      "user_id": "investor456", 
      "username": "jane@investor.com",
      "credentials_count": 1,
      "first_registration": "2025-01-20T09:15:00"
    }
  ]
}
```

### **Viewing Recent Sessions**

#### **Browser (GET):**
```
https://webauthn-investor.azurewebsites.net/api/sessions
```

#### **Response:**
```json
{
  "total_sessions": 12,
  "sessions": [
    {
      "user_id": "investor123",
      "token": "eyJhbGciOiJIUzI1NiIs...",
      "verified": true,
      "created_at": "2025-01-20T15:30:00",
      "expires_at": "2025-01-20T15:45:00"
    }
  ]
}
```

## 🔄 **User ID Consistency Rules**

### **Same User, Same user_id**
```bash
# First time registration
curl "https://webauthn-investor.azurewebsites.net/api/verification/link?user_id=investor123&username=john@example.com"

# Next time (same user) - MUST use same user_id
curl "https://webauthn-investor.azurewebsites.net/api/verification/link?user_id=investor123&username=john@example.com"
```

### **Different Users, Different user_id**
```bash
# User 1
curl "https://webauthn-investor.azurewebsites.net/api/verification/link?user_id=investor123&username=john@example.com"

# User 2 - MUST use different user_id
curl "https://webauthn-investor.azurewebsites.net/api/verification/link?user_id=investor456&username=jane@example.com"
```

## 📋 **What Happens During Verification**

### **First Time (Registration)**
1. **Create Link**: `user_id` + `username` → New verification link
2. **User Verifies**: Biometric auth creates WebAuthn credential
3. **Data Stored**: 
   - `user_credentials`: user_id, username, credential_id, public_key
   - `verification_sessions`: user_id, token, verified=true

### **Return User (Authentication)**
1. **Create Link**: Same `user_id` → System detects existing credentials
2. **User Verifies**: Uses existing biometric credential
3. **Data Updated**: 
   - `verification_sessions`: New session with verified=true
   - `user_credentials`: sign_count incremented

## 🔍 **Checking User Data**

### **Find if User Exists**
```bash
# Check if user_id exists in system
curl "https://webauthn-investor.azurewebsites.net/api/users" | grep "investor123"
```

### **View User's Verification History**
```bash
# See all sessions for a user
curl "https://webauthn-investor.azurewebsites.net/api/sessions" | grep "investor123"
```

## 💡 **Best Practices**

### **User ID Generation**
```bash
# Good: Consistent user IDs
user_id="investor_$(date +%s)"          # investor_1705746123
user_id="client_${company_id}_${emp_id}" # client_acme_12345
user_id="uuid_$(uuidgen)"               # uuid_550e8400-e29b-41d4-a716-446655440000

# Bad: Random IDs each time
user_id="temp_$(date +%N)"              # Changes every nanosecond!
```

### **Username Examples**
```bash
# Business Context Examples
username="john.smith@acmeinvest.com"    # Professional email
username="John Smith (Acme Invest)"     # Full name with company
username="Client #12345"                # Client number
username="Account: ACME-INV-001"        # Account identifier
```

## 🔧 **Integration Examples**

### **Investment Firm Integration**
```javascript
// Your customer database
const customer = {
  id: "INV_12345",
  email: "john@example.com", 
  name: "John Smith",
  account: "ACME-001"
};

// Create verification link
const verificationData = {
  user_id: customer.id,                    // Use your customer ID
  username: `${customer.name} (${customer.account})` // Recognizable display name
};
```

### **Multi-Device Support**
```bash
# Same user can register multiple devices
# Day 1: Register on iPhone
curl "https://webauthn-investor.azurewebsites.net/api/verification/link?user_id=investor123&username=john@example.com"

# Day 2: Register on Android (same user_id!)  
curl "https://webauthn-investor.azurewebsites.net/api/verification/link?user_id=investor123&username=john@example.com"

# Result: User has 2 credentials, can verify with either device
```

## ⚠️ **Important Notes**

### **Data Persistence**
- **Local**: Data persists in SQLite database file
- **Azure Demo**: Data resets when function restarts (every ~20 minutes of inactivity)
- **Production**: Use permanent storage (Azure Table Storage, CosmosDB, etc.)

### **Security Considerations**
- **user_id**: Can be internal ID, doesn't need to be secret
- **username**: Displayed to user, should not contain sensitive info
- **Credentials**: Cryptographic keys, automatically secured by WebAuthn
- **Tokens**: Temporary JWT tokens, expire in 15 minutes

### **GDPR/Privacy**
- **Biometric Data**: Never leaves user's device
- **Stored Data**: Only public keys and metadata
- **User Deletion**: Delete from `user_credentials` and `verification_sessions` tables

## 🎯 **Quick Reference Commands**

```bash
# List all users
curl "https://webauthn-investor.azurewebsites.net/api/users"

# List recent sessions  
curl "https://webauthn-investor.azurewebsites.net/api/sessions"

# Create verification for new user
curl "https://webauthn-investor.azurewebsites.net/api/verification/link?user_id=NEW_USER&username=new@user.com"

# Create verification for existing user (same user_id)
curl "https://webauthn-investor.azurewebsites.net/api/verification/link?user_id=EXISTING_USER&username=existing@user.com"

# Check specific verification status
curl "https://webauthn-investor.azurewebsites.net/api/verification/status?token=JWT_TOKEN"
```

---

**💡 Summary**: Use consistent `user_id` for the same person across all verifications. The `username` is just for display. Data is stored securely and can be viewed via the API endpoints.