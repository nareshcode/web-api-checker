# CyberSec Bot Report

**Scan Level:** 🔵 **COMPREHENSIVE** - ALL security checks

**Scanned API Endpoint:** `https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false`

**Original curl command:**

```bash
curl --location 'https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false' --header 'u-session-token: 01K0YJ2HRAQHKEBFV5DQY8BDS8' --header 'traceparent: 00-B2F2C5F047404E1A9CDA9C23DF82DD59-00000000684373b1-01' --header 'x-slice-checksum: 2f30cd7962868f8ae7a1cbcff58e4a9f36db1fd3d8a832e98482f20e07d09fcc|1753372255827|IST' --header 'Platform: ios:89376' --header 'device-id: D8CBA312-59C8-4CF3-9475-A5E9CDBA514E' --header 'modular-flow-version: v0.0' --header 'device_model: iPhone 12' --header 'app_version: 13.0.0' --header 'u-access-token: FysNCgWnZzzNFKHKCgDsHdtepraJwdx8' --header 'ssid: 123456789' --header 'x-date: 2025-07-24T21:20:55+05:30' --header 'longitude: 0.0' --header 'deviceId: D8CBA312-59C8-4CF3-9475-A5E9CDBA514E' --header 'isSavingsAccountOnboarded: true' --header 'slotId: 1' --header 'Content-Type: application/json' --header 'networkType: Wi-Fi' --header 'device_name: iPhone' --header 'latitude: 0.0' --header 'app_build: 89376' --header 'sp-device-id: D8CBA312-59C8-4CF3-9475-A5E9CDBA514E' --header 'Cookie: __cf_bm=yl1aWLbCCCGBXBvaWUCOdlIimOG4KJqzwFKpTEPGysY-1753372113-1.0.1.1-nLC3hLhfyP0Cmk6RY56F6A9F2VOwpqlknWkyuwlPIBrFTgwIhgPHe26mTFAvrZmmOec8j81YLFWQXKIxLA3pPfdDL71BmSbB6p4Pr0M53Jw'
```

**Parsed curl details:**

- Method: `GET`
- Headers: `{}`

## 🚨 Security Priority Summary

**Total Issues Found:** 13
**Security Score:** 0/100

### ✅ CRITICAL - No Critical Issues Found

### ✅ HIGH - No High Priority Issues Found

### 🟡 MEDIUM - Should Fix (Within 1 Month)
*These improvements will strengthen your security posture.*

1. **Missing security header Content-Security-Policy on https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false**
   - **Action:** Review this issue for best security practices.
   - **Timeline:** Within 1 month
   - **Risk:** Medium - Security improvement recommended

2. **Missing security header X-Frame-Options on https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false**
   - **Action:** Review this issue for best security practices.
   - **Timeline:** Within 1 month
   - **Risk:** Medium - Security improvement recommended

3. **Missing security header Referrer-Policy on https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false**
   - **Action:** Review this issue for best security practices.
   - **Timeline:** Within 1 month
   - **Risk:** Medium - Security improvement recommended

4. **Missing security header Permissions-Policy on https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false**
   - **Action:** Review this issue for best security practices.
   - **Timeline:** Within 1 month
   - **Risk:** Medium - Security improvement recommended

5. **Missing security header X-XSS-Protection on https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false**
   - **Action:** Review this issue for best security practices.
   - **Timeline:** Within 1 month
   - **Risk:** Medium - Security improvement recommended

6. **Missing security header Cache-Control on https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false**
   - **Action:** Review this issue for best security practices.
   - **Timeline:** Within 1 month
   - **Risk:** Medium - Security improvement recommended

7. **Missing security header Pragma on https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false**
   - **Action:** Review this issue for best security practices.
   - **Timeline:** Within 1 month
   - **Risk:** Medium - Security improvement recommended

8. **Missing security header Expires on https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false**
   - **Action:** Review this issue for best security practices.
   - **Timeline:** Within 1 month
   - **Risk:** Medium - Security improvement recommended

9. **Missing security header Access-Control-Allow-Origin on https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false**
   - **Action:** Review this issue for best security practices.
   - **Timeline:** Within 1 month
   - **Risk:** Medium - Security improvement recommended

10. **Missing security header Access-Control-Allow-Methods on https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false**
   - **Action:** Review this issue for best security practices.
   - **Timeline:** Within 1 month
   - **Risk:** Medium - Security improvement recommended

11. **Missing security header Access-Control-Allow-Headers on https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false**
   - **Action:** Review this issue for best security practices.
   - **Timeline:** Within 1 month
   - **Risk:** Medium - Security improvement recommended

12. **Missing security header X-Permitted-Cross-Domain-Policies on https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false**
   - **Action:** Review this issue for best security practices.
   - **Timeline:** Within 1 month
   - **Risk:** Medium - Security improvement recommended

13. **Missing security header Feature-Policy on https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false**
   - **Action:** Review this issue for best security practices.
   - **Timeline:** Within 1 month
   - **Risk:** Medium - Security improvement recommended

### ✅ LOW - No Low Priority Issues Found

## 🔍 Attack Code & Fix Code for Every Vulnerability

*This section provides developers with exact attack code to simulate vulnerabilities and fix code to resolve them.*

### 1. Security Headers Vulnerability

**🎯 Target:** `https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false`

**📝 Description:** Missing security headers expose the application to various attacks including XSS, clickjacking, and protocol downgrade attacks.

**💥 Impact:** XSS, clickjacking, protocol downgrade, MIME confusion attacks, information disclosure

**🔍 CVSS Score:** 6.5 (Medium)

**📊 CVSS Details:**
- **Attack Vector:** Network
- **Complexity:** Low
- **Privileges Required:** None
- **User Interaction:** Required
- **Scope:** Unchanged
- **Confidentiality:** Low
- **Integrity:** Low
- **Availability:** None

**🔴 Priority:** Medium - Within 1 month

**🎯 Successful Payloads:**
1. `Content-Security-Policy`

**⚔️ Attack Code (How to Simulate):**
```javascript
// Security Headers Attack Code
// 1. XSS Attack (if CSP missing)
const xssPayload = "<script>alert('XSS')</script>";
fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false?q=" + encodeURIComponent(xssPayload));

// 2. Clickjacking Attack (if X-Frame-Options missing)
const clickjackingPage = `
<!DOCTYPE html>
<html>
<head><title>Free Prize!</title></head>
<body>
    <h1>🎁 Click for free prize!</h1>
    <iframe src="https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false" style="opacity:0.1; position:absolute; top:50px; left:50px;"></iframe>
    <button onclick="triggerDelete()" style="position:absolute; top:50px; left:50px; z-index:1000;">
        🎁 CLAIM PRIZE
    </button>
    <script>
        function triggerDelete() {
            fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false", {method: "DELETE"});
        }
    </script>
</body>
</html>`;

// 3. Protocol Downgrade (if HSTS missing)
// Attacker intercepts HTTPS and forces HTTP
fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false".replace('https://', 'http://'));
```

**🛡️ Fix Code (How to Resolve):**
```javascript
// Security Headers Fix Code
// Add these headers to all API responses
response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; object-src 'none'";
response.headers['X-Frame-Options'] = 'DENY';
response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload';
response.headers['X-Content-Type-Options'] = 'nosniff';
response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin';
response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=(), payment=()';
response.headers['X-XSS-Protection'] = '1; mode=block';
response.headers['Access-Control-Allow-Origin'] = 'https://yourdomain.com';
response.headers['Access-Control-Allow-Methods'] = 'GET, POST, DELETE';
response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization';
response.headers['X-Permitted-Cross-Domain-Policies'] = 'none';
response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, proxy-revalidate';
response.headers['Pragma'] = 'no-cache';
response.headers['Expires'] = '0';
```

**🛡️ Prevention Methods:**
- Implement Content Security Policy (CSP)
- Set X-Frame-Options to prevent clickjacking
- Enable Strict-Transport-Security (HSTS)
- Set X-Content-Type-Options to nosniff
- Configure Referrer-Policy
- Set Permissions-Policy for feature control

**📋 Testing Commands:**
```bash
# Test 1: Content-Security-Policy
curl -X GET "https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false?input=Content-Security-Policy"

```

---

### 2. Security Headers Vulnerability

**🎯 Target:** `https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false`

**📝 Description:** Missing security headers expose the application to various attacks including XSS, clickjacking, and protocol downgrade attacks.

**💥 Impact:** XSS, clickjacking, protocol downgrade, MIME confusion attacks, information disclosure

**🔍 CVSS Score:** 6.5 (Medium)

**📊 CVSS Details:**
- **Attack Vector:** Network
- **Complexity:** Low
- **Privileges Required:** None
- **User Interaction:** Required
- **Scope:** Unchanged
- **Confidentiality:** Low
- **Integrity:** Low
- **Availability:** None

**🔴 Priority:** Medium - Within 1 month

**🎯 Successful Payloads:**
1. `X-Frame-Options`

**⚔️ Attack Code (How to Simulate):**
```javascript
// Security Headers Attack Code
// 1. XSS Attack (if CSP missing)
const xssPayload = "<script>alert('XSS')</script>";
fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false?q=" + encodeURIComponent(xssPayload));

// 2. Clickjacking Attack (if X-Frame-Options missing)
const clickjackingPage = `
<!DOCTYPE html>
<html>
<head><title>Free Prize!</title></head>
<body>
    <h1>🎁 Click for free prize!</h1>
    <iframe src="https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false" style="opacity:0.1; position:absolute; top:50px; left:50px;"></iframe>
    <button onclick="triggerDelete()" style="position:absolute; top:50px; left:50px; z-index:1000;">
        🎁 CLAIM PRIZE
    </button>
    <script>
        function triggerDelete() {
            fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false", {method: "DELETE"});
        }
    </script>
</body>
</html>`;

// 3. Protocol Downgrade (if HSTS missing)
// Attacker intercepts HTTPS and forces HTTP
fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false".replace('https://', 'http://'));
```

**🛡️ Fix Code (How to Resolve):**
```javascript
// Security Headers Fix Code
// Add these headers to all API responses
response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; object-src 'none'";
response.headers['X-Frame-Options'] = 'DENY';
response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload';
response.headers['X-Content-Type-Options'] = 'nosniff';
response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin';
response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=(), payment=()';
response.headers['X-XSS-Protection'] = '1; mode=block';
response.headers['Access-Control-Allow-Origin'] = 'https://yourdomain.com';
response.headers['Access-Control-Allow-Methods'] = 'GET, POST, DELETE';
response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization';
response.headers['X-Permitted-Cross-Domain-Policies'] = 'none';
response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, proxy-revalidate';
response.headers['Pragma'] = 'no-cache';
response.headers['Expires'] = '0';
```

**🛡️ Prevention Methods:**
- Implement Content Security Policy (CSP)
- Set X-Frame-Options to prevent clickjacking
- Enable Strict-Transport-Security (HSTS)
- Set X-Content-Type-Options to nosniff
- Configure Referrer-Policy
- Set Permissions-Policy for feature control

**📋 Testing Commands:**
```bash
# Test 1: X-Frame-Options
curl -X GET "https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false?input=X-Frame-Options"

```

---

### 3. Security Headers Vulnerability

**🎯 Target:** `https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false`

**📝 Description:** Missing security headers expose the application to various attacks including XSS, clickjacking, and protocol downgrade attacks.

**💥 Impact:** XSS, clickjacking, protocol downgrade, MIME confusion attacks, information disclosure

**🔍 CVSS Score:** 6.5 (Medium)

**📊 CVSS Details:**
- **Attack Vector:** Network
- **Complexity:** Low
- **Privileges Required:** None
- **User Interaction:** Required
- **Scope:** Unchanged
- **Confidentiality:** Low
- **Integrity:** Low
- **Availability:** None

**🔴 Priority:** Medium - Within 1 month

**🎯 Successful Payloads:**
1. `Referrer-Policy`

**⚔️ Attack Code (How to Simulate):**
```javascript
// Security Headers Attack Code
// 1. XSS Attack (if CSP missing)
const xssPayload = "<script>alert('XSS')</script>";
fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false?q=" + encodeURIComponent(xssPayload));

// 2. Clickjacking Attack (if X-Frame-Options missing)
const clickjackingPage = `
<!DOCTYPE html>
<html>
<head><title>Free Prize!</title></head>
<body>
    <h1>🎁 Click for free prize!</h1>
    <iframe src="https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false" style="opacity:0.1; position:absolute; top:50px; left:50px;"></iframe>
    <button onclick="triggerDelete()" style="position:absolute; top:50px; left:50px; z-index:1000;">
        🎁 CLAIM PRIZE
    </button>
    <script>
        function triggerDelete() {
            fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false", {method: "DELETE"});
        }
    </script>
</body>
</html>`;

// 3. Protocol Downgrade (if HSTS missing)
// Attacker intercepts HTTPS and forces HTTP
fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false".replace('https://', 'http://'));
```

**🛡️ Fix Code (How to Resolve):**
```javascript
// Security Headers Fix Code
// Add these headers to all API responses
response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; object-src 'none'";
response.headers['X-Frame-Options'] = 'DENY';
response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload';
response.headers['X-Content-Type-Options'] = 'nosniff';
response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin';
response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=(), payment=()';
response.headers['X-XSS-Protection'] = '1; mode=block';
response.headers['Access-Control-Allow-Origin'] = 'https://yourdomain.com';
response.headers['Access-Control-Allow-Methods'] = 'GET, POST, DELETE';
response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization';
response.headers['X-Permitted-Cross-Domain-Policies'] = 'none';
response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, proxy-revalidate';
response.headers['Pragma'] = 'no-cache';
response.headers['Expires'] = '0';
```

**🛡️ Prevention Methods:**
- Implement Content Security Policy (CSP)
- Set X-Frame-Options to prevent clickjacking
- Enable Strict-Transport-Security (HSTS)
- Set X-Content-Type-Options to nosniff
- Configure Referrer-Policy
- Set Permissions-Policy for feature control

**📋 Testing Commands:**
```bash
# Test 1: Referrer-Policy
curl -X GET "https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false?input=Referrer-Policy"

```

---

### 4. Security Headers Vulnerability

**🎯 Target:** `https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false`

**📝 Description:** Missing security headers expose the application to various attacks including XSS, clickjacking, and protocol downgrade attacks.

**💥 Impact:** XSS, clickjacking, protocol downgrade, MIME confusion attacks, information disclosure

**🔍 CVSS Score:** 6.5 (Medium)

**📊 CVSS Details:**
- **Attack Vector:** Network
- **Complexity:** Low
- **Privileges Required:** None
- **User Interaction:** Required
- **Scope:** Unchanged
- **Confidentiality:** Low
- **Integrity:** Low
- **Availability:** None

**🔴 Priority:** Medium - Within 1 month

**🎯 Successful Payloads:**
1. `Permissions-Policy`

**⚔️ Attack Code (How to Simulate):**
```javascript
// Security Headers Attack Code
// 1. XSS Attack (if CSP missing)
const xssPayload = "<script>alert('XSS')</script>";
fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false?q=" + encodeURIComponent(xssPayload));

// 2. Clickjacking Attack (if X-Frame-Options missing)
const clickjackingPage = `
<!DOCTYPE html>
<html>
<head><title>Free Prize!</title></head>
<body>
    <h1>🎁 Click for free prize!</h1>
    <iframe src="https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false" style="opacity:0.1; position:absolute; top:50px; left:50px;"></iframe>
    <button onclick="triggerDelete()" style="position:absolute; top:50px; left:50px; z-index:1000;">
        🎁 CLAIM PRIZE
    </button>
    <script>
        function triggerDelete() {
            fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false", {method: "DELETE"});
        }
    </script>
</body>
</html>`;

// 3. Protocol Downgrade (if HSTS missing)
// Attacker intercepts HTTPS and forces HTTP
fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false".replace('https://', 'http://'));
```

**🛡️ Fix Code (How to Resolve):**
```javascript
// Security Headers Fix Code
// Add these headers to all API responses
response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; object-src 'none'";
response.headers['X-Frame-Options'] = 'DENY';
response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload';
response.headers['X-Content-Type-Options'] = 'nosniff';
response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin';
response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=(), payment=()';
response.headers['X-XSS-Protection'] = '1; mode=block';
response.headers['Access-Control-Allow-Origin'] = 'https://yourdomain.com';
response.headers['Access-Control-Allow-Methods'] = 'GET, POST, DELETE';
response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization';
response.headers['X-Permitted-Cross-Domain-Policies'] = 'none';
response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, proxy-revalidate';
response.headers['Pragma'] = 'no-cache';
response.headers['Expires'] = '0';
```

**🛡️ Prevention Methods:**
- Implement Content Security Policy (CSP)
- Set X-Frame-Options to prevent clickjacking
- Enable Strict-Transport-Security (HSTS)
- Set X-Content-Type-Options to nosniff
- Configure Referrer-Policy
- Set Permissions-Policy for feature control

**📋 Testing Commands:**
```bash
# Test 1: Permissions-Policy
curl -X GET "https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false?input=Permissions-Policy"

```

---

### 5. Security Headers Vulnerability

**🎯 Target:** `https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false`

**📝 Description:** Missing security headers expose the application to various attacks including XSS, clickjacking, and protocol downgrade attacks.

**💥 Impact:** XSS, clickjacking, protocol downgrade, MIME confusion attacks, information disclosure

**🔍 CVSS Score:** 6.5 (Medium)

**📊 CVSS Details:**
- **Attack Vector:** Network
- **Complexity:** Low
- **Privileges Required:** None
- **User Interaction:** Required
- **Scope:** Unchanged
- **Confidentiality:** Low
- **Integrity:** Low
- **Availability:** None

**🔴 Priority:** Medium - Within 1 month

**🎯 Successful Payloads:**
1. `X-XSS-Protection`

**⚔️ Attack Code (How to Simulate):**
```javascript
// Security Headers Attack Code
// 1. XSS Attack (if CSP missing)
const xssPayload = "<script>alert('XSS')</script>";
fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false?q=" + encodeURIComponent(xssPayload));

// 2. Clickjacking Attack (if X-Frame-Options missing)
const clickjackingPage = `
<!DOCTYPE html>
<html>
<head><title>Free Prize!</title></head>
<body>
    <h1>🎁 Click for free prize!</h1>
    <iframe src="https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false" style="opacity:0.1; position:absolute; top:50px; left:50px;"></iframe>
    <button onclick="triggerDelete()" style="position:absolute; top:50px; left:50px; z-index:1000;">
        🎁 CLAIM PRIZE
    </button>
    <script>
        function triggerDelete() {
            fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false", {method: "DELETE"});
        }
    </script>
</body>
</html>`;

// 3. Protocol Downgrade (if HSTS missing)
// Attacker intercepts HTTPS and forces HTTP
fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false".replace('https://', 'http://'));
```

**🛡️ Fix Code (How to Resolve):**
```javascript
// Security Headers Fix Code
// Add these headers to all API responses
response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; object-src 'none'";
response.headers['X-Frame-Options'] = 'DENY';
response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload';
response.headers['X-Content-Type-Options'] = 'nosniff';
response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin';
response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=(), payment=()';
response.headers['X-XSS-Protection'] = '1; mode=block';
response.headers['Access-Control-Allow-Origin'] = 'https://yourdomain.com';
response.headers['Access-Control-Allow-Methods'] = 'GET, POST, DELETE';
response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization';
response.headers['X-Permitted-Cross-Domain-Policies'] = 'none';
response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, proxy-revalidate';
response.headers['Pragma'] = 'no-cache';
response.headers['Expires'] = '0';
```

**🛡️ Prevention Methods:**
- Implement Content Security Policy (CSP)
- Set X-Frame-Options to prevent clickjacking
- Enable Strict-Transport-Security (HSTS)
- Set X-Content-Type-Options to nosniff
- Configure Referrer-Policy
- Set Permissions-Policy for feature control

**📋 Testing Commands:**
```bash
# Test 1: X-XSS-Protection
curl -X GET "https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false?input=X-XSS-Protection"

```

---

### 6. Security Headers Vulnerability

**🎯 Target:** `https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false`

**📝 Description:** Missing security headers expose the application to various attacks including XSS, clickjacking, and protocol downgrade attacks.

**💥 Impact:** XSS, clickjacking, protocol downgrade, MIME confusion attacks, information disclosure

**🔍 CVSS Score:** 6.5 (Medium)

**📊 CVSS Details:**
- **Attack Vector:** Network
- **Complexity:** Low
- **Privileges Required:** None
- **User Interaction:** Required
- **Scope:** Unchanged
- **Confidentiality:** Low
- **Integrity:** Low
- **Availability:** None

**🔴 Priority:** Medium - Within 1 month

**🎯 Successful Payloads:**
1. `Cache-Control`

**⚔️ Attack Code (How to Simulate):**
```javascript
// Security Headers Attack Code
// 1. XSS Attack (if CSP missing)
const xssPayload = "<script>alert('XSS')</script>";
fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false?q=" + encodeURIComponent(xssPayload));

// 2. Clickjacking Attack (if X-Frame-Options missing)
const clickjackingPage = `
<!DOCTYPE html>
<html>
<head><title>Free Prize!</title></head>
<body>
    <h1>🎁 Click for free prize!</h1>
    <iframe src="https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false" style="opacity:0.1; position:absolute; top:50px; left:50px;"></iframe>
    <button onclick="triggerDelete()" style="position:absolute; top:50px; left:50px; z-index:1000;">
        🎁 CLAIM PRIZE
    </button>
    <script>
        function triggerDelete() {
            fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false", {method: "DELETE"});
        }
    </script>
</body>
</html>`;

// 3. Protocol Downgrade (if HSTS missing)
// Attacker intercepts HTTPS and forces HTTP
fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false".replace('https://', 'http://'));
```

**🛡️ Fix Code (How to Resolve):**
```javascript
// Security Headers Fix Code
// Add these headers to all API responses
response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; object-src 'none'";
response.headers['X-Frame-Options'] = 'DENY';
response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload';
response.headers['X-Content-Type-Options'] = 'nosniff';
response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin';
response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=(), payment=()';
response.headers['X-XSS-Protection'] = '1; mode=block';
response.headers['Access-Control-Allow-Origin'] = 'https://yourdomain.com';
response.headers['Access-Control-Allow-Methods'] = 'GET, POST, DELETE';
response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization';
response.headers['X-Permitted-Cross-Domain-Policies'] = 'none';
response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, proxy-revalidate';
response.headers['Pragma'] = 'no-cache';
response.headers['Expires'] = '0';
```

**🛡️ Prevention Methods:**
- Implement Content Security Policy (CSP)
- Set X-Frame-Options to prevent clickjacking
- Enable Strict-Transport-Security (HSTS)
- Set X-Content-Type-Options to nosniff
- Configure Referrer-Policy
- Set Permissions-Policy for feature control

**📋 Testing Commands:**
```bash
# Test 1: Cache-Control
curl -X GET "https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false?input=Cache-Control"

```

---

### 7. Security Headers Vulnerability

**🎯 Target:** `https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false`

**📝 Description:** Missing security headers expose the application to various attacks including XSS, clickjacking, and protocol downgrade attacks.

**💥 Impact:** XSS, clickjacking, protocol downgrade, MIME confusion attacks, information disclosure

**🔍 CVSS Score:** 6.5 (Medium)

**📊 CVSS Details:**
- **Attack Vector:** Network
- **Complexity:** Low
- **Privileges Required:** None
- **User Interaction:** Required
- **Scope:** Unchanged
- **Confidentiality:** Low
- **Integrity:** Low
- **Availability:** None

**🔴 Priority:** Medium - Within 1 month

**🎯 Successful Payloads:**
1. `Pragma`

**⚔️ Attack Code (How to Simulate):**
```javascript
// Security Headers Attack Code
// 1. XSS Attack (if CSP missing)
const xssPayload = "<script>alert('XSS')</script>";
fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false?q=" + encodeURIComponent(xssPayload));

// 2. Clickjacking Attack (if X-Frame-Options missing)
const clickjackingPage = `
<!DOCTYPE html>
<html>
<head><title>Free Prize!</title></head>
<body>
    <h1>🎁 Click for free prize!</h1>
    <iframe src="https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false" style="opacity:0.1; position:absolute; top:50px; left:50px;"></iframe>
    <button onclick="triggerDelete()" style="position:absolute; top:50px; left:50px; z-index:1000;">
        🎁 CLAIM PRIZE
    </button>
    <script>
        function triggerDelete() {
            fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false", {method: "DELETE"});
        }
    </script>
</body>
</html>`;

// 3. Protocol Downgrade (if HSTS missing)
// Attacker intercepts HTTPS and forces HTTP
fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false".replace('https://', 'http://'));
```

**🛡️ Fix Code (How to Resolve):**
```javascript
// Security Headers Fix Code
// Add these headers to all API responses
response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; object-src 'none'";
response.headers['X-Frame-Options'] = 'DENY';
response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload';
response.headers['X-Content-Type-Options'] = 'nosniff';
response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin';
response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=(), payment=()';
response.headers['X-XSS-Protection'] = '1; mode=block';
response.headers['Access-Control-Allow-Origin'] = 'https://yourdomain.com';
response.headers['Access-Control-Allow-Methods'] = 'GET, POST, DELETE';
response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization';
response.headers['X-Permitted-Cross-Domain-Policies'] = 'none';
response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, proxy-revalidate';
response.headers['Pragma'] = 'no-cache';
response.headers['Expires'] = '0';
```

**🛡️ Prevention Methods:**
- Implement Content Security Policy (CSP)
- Set X-Frame-Options to prevent clickjacking
- Enable Strict-Transport-Security (HSTS)
- Set X-Content-Type-Options to nosniff
- Configure Referrer-Policy
- Set Permissions-Policy for feature control

**📋 Testing Commands:**
```bash
# Test 1: Pragma
curl -X GET "https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false?input=Pragma"

```

---

### 8. Security Headers Vulnerability

**🎯 Target:** `https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false`

**📝 Description:** Missing security headers expose the application to various attacks including XSS, clickjacking, and protocol downgrade attacks.

**💥 Impact:** XSS, clickjacking, protocol downgrade, MIME confusion attacks, information disclosure

**🔍 CVSS Score:** 6.5 (Medium)

**📊 CVSS Details:**
- **Attack Vector:** Network
- **Complexity:** Low
- **Privileges Required:** None
- **User Interaction:** Required
- **Scope:** Unchanged
- **Confidentiality:** Low
- **Integrity:** Low
- **Availability:** None

**🔴 Priority:** Medium - Within 1 month

**🎯 Successful Payloads:**
1. `Expires`

**⚔️ Attack Code (How to Simulate):**
```javascript
// Security Headers Attack Code
// 1. XSS Attack (if CSP missing)
const xssPayload = "<script>alert('XSS')</script>";
fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false?q=" + encodeURIComponent(xssPayload));

// 2. Clickjacking Attack (if X-Frame-Options missing)
const clickjackingPage = `
<!DOCTYPE html>
<html>
<head><title>Free Prize!</title></head>
<body>
    <h1>🎁 Click for free prize!</h1>
    <iframe src="https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false" style="opacity:0.1; position:absolute; top:50px; left:50px;"></iframe>
    <button onclick="triggerDelete()" style="position:absolute; top:50px; left:50px; z-index:1000;">
        🎁 CLAIM PRIZE
    </button>
    <script>
        function triggerDelete() {
            fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false", {method: "DELETE"});
        }
    </script>
</body>
</html>`;

// 3. Protocol Downgrade (if HSTS missing)
// Attacker intercepts HTTPS and forces HTTP
fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false".replace('https://', 'http://'));
```

**🛡️ Fix Code (How to Resolve):**
```javascript
// Security Headers Fix Code
// Add these headers to all API responses
response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; object-src 'none'";
response.headers['X-Frame-Options'] = 'DENY';
response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload';
response.headers['X-Content-Type-Options'] = 'nosniff';
response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin';
response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=(), payment=()';
response.headers['X-XSS-Protection'] = '1; mode=block';
response.headers['Access-Control-Allow-Origin'] = 'https://yourdomain.com';
response.headers['Access-Control-Allow-Methods'] = 'GET, POST, DELETE';
response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization';
response.headers['X-Permitted-Cross-Domain-Policies'] = 'none';
response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, proxy-revalidate';
response.headers['Pragma'] = 'no-cache';
response.headers['Expires'] = '0';
```

**🛡️ Prevention Methods:**
- Implement Content Security Policy (CSP)
- Set X-Frame-Options to prevent clickjacking
- Enable Strict-Transport-Security (HSTS)
- Set X-Content-Type-Options to nosniff
- Configure Referrer-Policy
- Set Permissions-Policy for feature control

**📋 Testing Commands:**
```bash
# Test 1: Expires
curl -X GET "https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false?input=Expires"

```

---

### 9. Security Headers Vulnerability

**🎯 Target:** `https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false`

**📝 Description:** Missing security headers expose the application to various attacks including XSS, clickjacking, and protocol downgrade attacks.

**💥 Impact:** XSS, clickjacking, protocol downgrade, MIME confusion attacks, information disclosure

**🔍 CVSS Score:** 6.5 (Medium)

**📊 CVSS Details:**
- **Attack Vector:** Network
- **Complexity:** Low
- **Privileges Required:** None
- **User Interaction:** Required
- **Scope:** Unchanged
- **Confidentiality:** Low
- **Integrity:** Low
- **Availability:** None

**🔴 Priority:** Medium - Within 1 month

**🎯 Successful Payloads:**
1. `Access-Control-Allow-Origin`

**⚔️ Attack Code (How to Simulate):**
```javascript
// Security Headers Attack Code
// 1. XSS Attack (if CSP missing)
const xssPayload = "<script>alert('XSS')</script>";
fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false?q=" + encodeURIComponent(xssPayload));

// 2. Clickjacking Attack (if X-Frame-Options missing)
const clickjackingPage = `
<!DOCTYPE html>
<html>
<head><title>Free Prize!</title></head>
<body>
    <h1>🎁 Click for free prize!</h1>
    <iframe src="https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false" style="opacity:0.1; position:absolute; top:50px; left:50px;"></iframe>
    <button onclick="triggerDelete()" style="position:absolute; top:50px; left:50px; z-index:1000;">
        🎁 CLAIM PRIZE
    </button>
    <script>
        function triggerDelete() {
            fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false", {method: "DELETE"});
        }
    </script>
</body>
</html>`;

// 3. Protocol Downgrade (if HSTS missing)
// Attacker intercepts HTTPS and forces HTTP
fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false".replace('https://', 'http://'));
```

**🛡️ Fix Code (How to Resolve):**
```javascript
// Security Headers Fix Code
// Add these headers to all API responses
response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; object-src 'none'";
response.headers['X-Frame-Options'] = 'DENY';
response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload';
response.headers['X-Content-Type-Options'] = 'nosniff';
response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin';
response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=(), payment=()';
response.headers['X-XSS-Protection'] = '1; mode=block';
response.headers['Access-Control-Allow-Origin'] = 'https://yourdomain.com';
response.headers['Access-Control-Allow-Methods'] = 'GET, POST, DELETE';
response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization';
response.headers['X-Permitted-Cross-Domain-Policies'] = 'none';
response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, proxy-revalidate';
response.headers['Pragma'] = 'no-cache';
response.headers['Expires'] = '0';
```

**🛡️ Prevention Methods:**
- Implement Content Security Policy (CSP)
- Set X-Frame-Options to prevent clickjacking
- Enable Strict-Transport-Security (HSTS)
- Set X-Content-Type-Options to nosniff
- Configure Referrer-Policy
- Set Permissions-Policy for feature control

**📋 Testing Commands:**
```bash
# Test 1: Access-Control-Allow-Origin
curl -X GET "https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false?input=Access-Control-Allow-Origin"

```

---

### 10. Security Headers Vulnerability

**🎯 Target:** `https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false`

**📝 Description:** Missing security headers expose the application to various attacks including XSS, clickjacking, and protocol downgrade attacks.

**💥 Impact:** XSS, clickjacking, protocol downgrade, MIME confusion attacks, information disclosure

**🔍 CVSS Score:** 6.5 (Medium)

**📊 CVSS Details:**
- **Attack Vector:** Network
- **Complexity:** Low
- **Privileges Required:** None
- **User Interaction:** Required
- **Scope:** Unchanged
- **Confidentiality:** Low
- **Integrity:** Low
- **Availability:** None

**🔴 Priority:** Medium - Within 1 month

**🎯 Successful Payloads:**
1. `Access-Control-Allow-Methods`

**⚔️ Attack Code (How to Simulate):**
```javascript
// Security Headers Attack Code
// 1. XSS Attack (if CSP missing)
const xssPayload = "<script>alert('XSS')</script>";
fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false?q=" + encodeURIComponent(xssPayload));

// 2. Clickjacking Attack (if X-Frame-Options missing)
const clickjackingPage = `
<!DOCTYPE html>
<html>
<head><title>Free Prize!</title></head>
<body>
    <h1>🎁 Click for free prize!</h1>
    <iframe src="https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false" style="opacity:0.1; position:absolute; top:50px; left:50px;"></iframe>
    <button onclick="triggerDelete()" style="position:absolute; top:50px; left:50px; z-index:1000;">
        🎁 CLAIM PRIZE
    </button>
    <script>
        function triggerDelete() {
            fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false", {method: "DELETE"});
        }
    </script>
</body>
</html>`;

// 3. Protocol Downgrade (if HSTS missing)
// Attacker intercepts HTTPS and forces HTTP
fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false".replace('https://', 'http://'));
```

**🛡️ Fix Code (How to Resolve):**
```javascript
// Security Headers Fix Code
// Add these headers to all API responses
response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; object-src 'none'";
response.headers['X-Frame-Options'] = 'DENY';
response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload';
response.headers['X-Content-Type-Options'] = 'nosniff';
response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin';
response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=(), payment=()';
response.headers['X-XSS-Protection'] = '1; mode=block';
response.headers['Access-Control-Allow-Origin'] = 'https://yourdomain.com';
response.headers['Access-Control-Allow-Methods'] = 'GET, POST, DELETE';
response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization';
response.headers['X-Permitted-Cross-Domain-Policies'] = 'none';
response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, proxy-revalidate';
response.headers['Pragma'] = 'no-cache';
response.headers['Expires'] = '0';
```

**🛡️ Prevention Methods:**
- Implement Content Security Policy (CSP)
- Set X-Frame-Options to prevent clickjacking
- Enable Strict-Transport-Security (HSTS)
- Set X-Content-Type-Options to nosniff
- Configure Referrer-Policy
- Set Permissions-Policy for feature control

**📋 Testing Commands:**
```bash
# Test 1: Access-Control-Allow-Methods
curl -X GET "https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false?input=Access-Control-Allow-Methods"

```

---

### 11. Security Headers Vulnerability

**🎯 Target:** `https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false`

**📝 Description:** Missing security headers expose the application to various attacks including XSS, clickjacking, and protocol downgrade attacks.

**💥 Impact:** XSS, clickjacking, protocol downgrade, MIME confusion attacks, information disclosure

**🔍 CVSS Score:** 6.5 (Medium)

**📊 CVSS Details:**
- **Attack Vector:** Network
- **Complexity:** Low
- **Privileges Required:** None
- **User Interaction:** Required
- **Scope:** Unchanged
- **Confidentiality:** Low
- **Integrity:** Low
- **Availability:** None

**🔴 Priority:** Medium - Within 1 month

**🎯 Successful Payloads:**
1. `Access-Control-Allow-Headers`

**⚔️ Attack Code (How to Simulate):**
```javascript
// Security Headers Attack Code
// 1. XSS Attack (if CSP missing)
const xssPayload = "<script>alert('XSS')</script>";
fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false?q=" + encodeURIComponent(xssPayload));

// 2. Clickjacking Attack (if X-Frame-Options missing)
const clickjackingPage = `
<!DOCTYPE html>
<html>
<head><title>Free Prize!</title></head>
<body>
    <h1>🎁 Click for free prize!</h1>
    <iframe src="https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false" style="opacity:0.1; position:absolute; top:50px; left:50px;"></iframe>
    <button onclick="triggerDelete()" style="position:absolute; top:50px; left:50px; z-index:1000;">
        🎁 CLAIM PRIZE
    </button>
    <script>
        function triggerDelete() {
            fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false", {method: "DELETE"});
        }
    </script>
</body>
</html>`;

// 3. Protocol Downgrade (if HSTS missing)
// Attacker intercepts HTTPS and forces HTTP
fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false".replace('https://', 'http://'));
```

**🛡️ Fix Code (How to Resolve):**
```javascript
// Security Headers Fix Code
// Add these headers to all API responses
response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; object-src 'none'";
response.headers['X-Frame-Options'] = 'DENY';
response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload';
response.headers['X-Content-Type-Options'] = 'nosniff';
response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin';
response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=(), payment=()';
response.headers['X-XSS-Protection'] = '1; mode=block';
response.headers['Access-Control-Allow-Origin'] = 'https://yourdomain.com';
response.headers['Access-Control-Allow-Methods'] = 'GET, POST, DELETE';
response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization';
response.headers['X-Permitted-Cross-Domain-Policies'] = 'none';
response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, proxy-revalidate';
response.headers['Pragma'] = 'no-cache';
response.headers['Expires'] = '0';
```

**🛡️ Prevention Methods:**
- Implement Content Security Policy (CSP)
- Set X-Frame-Options to prevent clickjacking
- Enable Strict-Transport-Security (HSTS)
- Set X-Content-Type-Options to nosniff
- Configure Referrer-Policy
- Set Permissions-Policy for feature control

**📋 Testing Commands:**
```bash
# Test 1: Access-Control-Allow-Headers
curl -X GET "https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false?input=Access-Control-Allow-Headers"

```

---

### 12. Security Headers Vulnerability

**🎯 Target:** `https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false`

**📝 Description:** Missing security headers expose the application to various attacks including XSS, clickjacking, and protocol downgrade attacks.

**💥 Impact:** XSS, clickjacking, protocol downgrade, MIME confusion attacks, information disclosure

**🔍 CVSS Score:** 6.5 (Medium)

**📊 CVSS Details:**
- **Attack Vector:** Network
- **Complexity:** Low
- **Privileges Required:** None
- **User Interaction:** Required
- **Scope:** Unchanged
- **Confidentiality:** Low
- **Integrity:** Low
- **Availability:** None

**🔴 Priority:** Medium - Within 1 month

**🎯 Successful Payloads:**
1. `X-Permitted-Cross-Domain-Policies`

**⚔️ Attack Code (How to Simulate):**
```javascript
// Security Headers Attack Code
// 1. XSS Attack (if CSP missing)
const xssPayload = "<script>alert('XSS')</script>";
fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false?q=" + encodeURIComponent(xssPayload));

// 2. Clickjacking Attack (if X-Frame-Options missing)
const clickjackingPage = `
<!DOCTYPE html>
<html>
<head><title>Free Prize!</title></head>
<body>
    <h1>🎁 Click for free prize!</h1>
    <iframe src="https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false" style="opacity:0.1; position:absolute; top:50px; left:50px;"></iframe>
    <button onclick="triggerDelete()" style="position:absolute; top:50px; left:50px; z-index:1000;">
        🎁 CLAIM PRIZE
    </button>
    <script>
        function triggerDelete() {
            fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false", {method: "DELETE"});
        }
    </script>
</body>
</html>`;

// 3. Protocol Downgrade (if HSTS missing)
// Attacker intercepts HTTPS and forces HTTP
fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false".replace('https://', 'http://'));
```

**🛡️ Fix Code (How to Resolve):**
```javascript
// Security Headers Fix Code
// Add these headers to all API responses
response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; object-src 'none'";
response.headers['X-Frame-Options'] = 'DENY';
response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload';
response.headers['X-Content-Type-Options'] = 'nosniff';
response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin';
response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=(), payment=()';
response.headers['X-XSS-Protection'] = '1; mode=block';
response.headers['Access-Control-Allow-Origin'] = 'https://yourdomain.com';
response.headers['Access-Control-Allow-Methods'] = 'GET, POST, DELETE';
response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization';
response.headers['X-Permitted-Cross-Domain-Policies'] = 'none';
response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, proxy-revalidate';
response.headers['Pragma'] = 'no-cache';
response.headers['Expires'] = '0';
```

**🛡️ Prevention Methods:**
- Implement Content Security Policy (CSP)
- Set X-Frame-Options to prevent clickjacking
- Enable Strict-Transport-Security (HSTS)
- Set X-Content-Type-Options to nosniff
- Configure Referrer-Policy
- Set Permissions-Policy for feature control

**📋 Testing Commands:**
```bash
# Test 1: X-Permitted-Cross-Domain-Policies
curl -X GET "https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false?input=X-Permitted-Cross-Domain-Policies"

```

---

### 13. Security Headers Vulnerability

**🎯 Target:** `https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false`

**📝 Description:** Missing security headers expose the application to various attacks including XSS, clickjacking, and protocol downgrade attacks.

**💥 Impact:** XSS, clickjacking, protocol downgrade, MIME confusion attacks, information disclosure

**🔍 CVSS Score:** 6.5 (Medium)

**📊 CVSS Details:**
- **Attack Vector:** Network
- **Complexity:** Low
- **Privileges Required:** None
- **User Interaction:** Required
- **Scope:** Unchanged
- **Confidentiality:** Low
- **Integrity:** Low
- **Availability:** None

**🔴 Priority:** Medium - Within 1 month

**🎯 Successful Payloads:**
1. `Feature-Policy`

**⚔️ Attack Code (How to Simulate):**
```javascript
// Security Headers Attack Code
// 1. XSS Attack (if CSP missing)
const xssPayload = "<script>alert('XSS')</script>";
fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false?q=" + encodeURIComponent(xssPayload));

// 2. Clickjacking Attack (if X-Frame-Options missing)
const clickjackingPage = `
<!DOCTYPE html>
<html>
<head><title>Free Prize!</title></head>
<body>
    <h1>🎁 Click for free prize!</h1>
    <iframe src="https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false" style="opacity:0.1; position:absolute; top:50px; left:50px;"></iframe>
    <button onclick="triggerDelete()" style="position:absolute; top:50px; left:50px; z-index:1000;">
        🎁 CLAIM PRIZE
    </button>
    <script>
        function triggerDelete() {
            fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false", {method: "DELETE"});
        }
    </script>
</body>
</html>`;

// 3. Protocol Downgrade (if HSTS missing)
// Attacker intercepts HTTPS and forces HTTP
fetch("https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false".replace('https://', 'http://'));
```

**🛡️ Fix Code (How to Resolve):**
```javascript
// Security Headers Fix Code
// Add these headers to all API responses
response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; object-src 'none'";
response.headers['X-Frame-Options'] = 'DENY';
response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload';
response.headers['X-Content-Type-Options'] = 'nosniff';
response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin';
response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=(), payment=()';
response.headers['X-XSS-Protection'] = '1; mode=block';
response.headers['Access-Control-Allow-Origin'] = 'https://yourdomain.com';
response.headers['Access-Control-Allow-Methods'] = 'GET, POST, DELETE';
response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization';
response.headers['X-Permitted-Cross-Domain-Policies'] = 'none';
response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, proxy-revalidate';
response.headers['Pragma'] = 'no-cache';
response.headers['Expires'] = '0';
```

**🛡️ Prevention Methods:**
- Implement Content Security Policy (CSP)
- Set X-Frame-Options to prevent clickjacking
- Enable Strict-Transport-Security (HSTS)
- Set X-Content-Type-Options to nosniff
- Configure Referrer-Policy
- Set Permissions-Policy for feature control

**📋 Testing Commands:**
```bash
# Test 1: Feature-Policy
curl -X GET "https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false?input=Feature-Policy"

```

---

## 🔄 Dynamic Security Checks
No new dynamic checks found yet. The scraper runs every 15 minutes.

## ✅ Security Controls Working Well
The following security measures are properly implemented:

- ✅ **All endpoints require authentication**
  - No open endpoints found
- ✅ **No sql injection vulnerabilities detected**
  - All endpoints safe from sql injection
- ✅ **No xss vulnerabilities detected**
  - All endpoints safe from xss
- ✅ **No xxe vulnerabilities detected**
  - All endpoints safe from xxe
- ✅ **No nosql injection vulnerabilities detected**
  - All endpoints safe from nosql injection
- ✅ **No ldap injection vulnerabilities detected**
  - All endpoints safe from ldap injection
- ✅ **No command injection vulnerabilities detected**
  - All endpoints safe from command injection
- ✅ **No path traversal vulnerabilities detected**
  - All endpoints safe from path traversal
- ✅ **Strict-Transport-Security set on https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false**
  - max-age=31536000; includeSubDomains
- ✅ **X-Content-Type-Options set on https://api.uat-nesfb.com/non-banking/discovery/v1/collectrequest?sliceAccountActiveStatus=false&connectionFailure=false&subscriptionFailure=false**
  - nosniff
- ✅ **HTTPS enabled**
  - API uses HTTPS

## 📋 Detailed Technical Results
<details>
<summary>Click to expand detailed technical findings</summary>

### HTTPS Usage
- API uses HTTPS: ✅ PASS

### Open Endpoints (No Auth)
- All tested endpoints require authentication: ✅ PASS

### Attack Vector Tests
- **Sql Injection:** ✅ SECURE
- **Xss:** ✅ SECURE
- **Command Injection:** ✅ SECURE
- **Path Traversal:** ✅ SECURE
- **Ssrf:** ❌ VULNERABLE
  - URL: Unknown
  - Successful payloads: 0

</details>
