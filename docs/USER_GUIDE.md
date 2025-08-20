# WebAuthn Investor Verification - User Guide

## Overview

The WebAuthn Investor Verification system provides secure, passwordless biometric authentication for stock investors using their mobile devices. This system eliminates the need for passwords or SMS codes by leveraging modern biometric authentication (Face ID, Touch ID, Windows Hello).

## How It Works

### For Stock Investors

1. **📞 Call Your Investment Service**
   - Contact your investment firm or broker
   - Request identity verification for account access

2. **📧 Receive Verification Link**
   - Your service provider will send you a secure verification link
   - Link expires in 15 minutes for security
   - Example: `https://webauthn-investor.azurewebsites.net/api/verify?token=...`

3. **📱 Open Link on Your Phone**
   - Click the verification link on your smartphone
   - Must be opened on a mobile device with biometric capabilities
   - Works on iOS (iPhone) and Android devices

4. **🔒 Complete Biometric Verification**
   - Tap "Verify Identity" button
   - Your phone will prompt for biometric authentication:
     - **iPhone**: Face ID or Touch ID
     - **Android**: Fingerprint or face unlock
     - **Windows**: Windows Hello (if using PC)

5. **✅ Verification Complete**
   - Screen shows "Registration/Authentication successful!"
   - Your identity is now verified with the investment service
   - Service provider receives instant confirmation

## Security Features

### 🛡️ What Makes This Secure

- **No Passwords**: Uses biometric data that cannot be stolen or forgotten
- **Device-Bound**: Credentials are stored securely on your device only
- **Encrypted**: All communications use HTTPS encryption
- **Time-Limited**: Verification links expire automatically
- **Privacy-Focused**: Your biometric data never leaves your device

### 🔐 What Gets Stored

- **On Your Device**: Encrypted biometric credential (passkey)
- **On Server**: Public key only (cannot recreate biometric data)
- **Never Stored**: Your actual fingerprints, face data, or passwords

## Device Requirements

### ✅ Compatible Devices

- **iPhone**: iOS 14+ with Face ID or Touch ID
- **Android**: Android 9+ with fingerprint or face unlock
- **Windows**: Windows 10+ with Windows Hello
- **Mac**: macOS with Touch ID

### ⚠️ Not Supported

- Older devices without biometric capabilities
- Devices with disabled biometric authentication
- Basic phones without smartphone capabilities

## Troubleshooting

### Common Issues

**🚫 "WebAuthn is not supported on this device"**
- Enable biometric authentication in device settings
- Ensure device meets minimum requirements
- Try using a newer device or browser

**❌ Verification failed**
- Ensure stable internet connection
- Try the verification process again
- Contact your investment service if issue persists

**⏰ Link expired**
- Request a new verification link from your service provider
- Complete verification within 15 minutes of receiving link

**🔄 Button not responding**
- Refresh the page
- Ensure JavaScript is enabled in your browser
- Try using a different browser

### Getting Help

1. **Contact Your Investment Service**
   - They can generate new verification links
   - Provide technical support for account-specific issues

2. **Check Device Settings**
   - Ensure biometric authentication is enabled
   - Verify internet connectivity
   - Update your browser if needed

## Privacy & Data Protection

### What We Collect
- Unique user identifier (provided by your investment service)
- Timestamp of verification
- Device public key (cannot be used to recreate biometric data)

### What We Don't Collect
- Your actual biometric data (fingerprints, face data)
- Personal information beyond what's needed for verification
- Location data or device information

### Data Retention
- Verification sessions expire automatically
- Credentials can be removed by deleting the passkey from your device
- No long-term storage of personal biometric information

## Benefits

### For Investors
- **🚀 Faster**: Instant verification with just a touch
- **🔒 More Secure**: No passwords to steal or forget  
- **📱 Convenient**: Use your existing biometric setup
- **🌍 Universal**: Works across different investment platforms

### For Investment Services
- **✅ Instant Verification**: Real-time confirmation of investor identity
- **🛡️ Reduced Fraud**: Biometric authentication is harder to fake
- **💰 Lower Costs**: No SMS or call costs for verification
- **📊 Better UX**: Smoother onboarding and account access

## Frequently Asked Questions

**Q: Is my biometric data stored on the server?**
A: No, your biometric data never leaves your device. Only a mathematical public key is stored on our servers.

**Q: What if I lose my phone?**
A: Contact your investment service to disable verification for your old device and set up verification on your new device.

**Q: Can I use this on multiple devices?**
A: Yes, you can register biometric credentials on multiple devices for the same account.

**Q: How long does verification take?**
A: Typically 2-5 seconds once you tap "Verify Identity" and complete the biometric prompt.

**Q: Is this more secure than SMS codes?**
A: Yes, biometric verification cannot be intercepted, forwarded, or stolen like SMS codes can be.

---

*For technical support or questions about this verification system, contact your investment service provider.*