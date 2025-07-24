#!/usr/bin/env python3
"""
Comprehensive False Positive Validation System
This module provides robust validation to prevent false positives in security scanning
"""

import re
import time
import requests
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass

@dataclass
class ValidationResult:
    """Result of false positive validation"""
    is_false_positive: bool
    confidence: float  # 0.0 to 1.0
    reason: str
    evidence: Dict[str, any]

class FalsePositiveValidator:
    """
    Comprehensive false positive detection and validation system
    """
    
    def __init__(self):
        # WAF and security indicators
        self.waf_indicators = [
            '<!doctype', '<html', '<head', '<body', '<title>',
            'cloudflare', 'access denied', 'forbidden', 'ray id', 
            'blocked', 'security', 'firewall', 'protection',
            'captcha', 'challenge', 'rate limit', 'too many requests',
            'blocked by', 'security check', 'bot protection'
        ]
        
        # Authentication and session indicators
        self.auth_indicators = [
            'unauthorized', 'forbidden', 'access denied', 'login required',
            'authentication', 'session expired', 'token invalid', 'invalid token',
            '401', '403', '440', 'session', 'login', 'signin'
        ]
        
        # JSON and API response indicators (legitimate responses)
        self.legitimate_indicators = [
            'success', 'error', 'message', 'status', 'code',
            'data', 'result', 'response', 'api', 'json',
            'userid', 'deviceid', 'accountid', 'sessionid', 'requestid',
            'activityid', 'transactionid', 'orderid', 'paymentid'
        ]
        
        # Command injection false positive patterns
        self.cmd_false_positive_patterns = [
            r'userid', r'deviceid', r'accountid', r'sessionid', r'requestid',
            r'activityid', r'transactionid', r'orderid', r'paymentid',
            r'islitesupported', r'isslicebankaccount', r'isupis2s',
            r'myqrfunctionality', r'switchconsent', r'isavatarcached'
        ]
        
        # SQL injection false positive patterns
        self.sql_false_positive_patterns = [
            r'sequence', r'sequential', r'sequel', r'sequelize',
            r'sequenceid', r'sequencenumber', r'sequencelog'
        ]
        
        # Banking-specific false positive patterns
        self.banking_false_positive_patterns = {
            'double_spending': [
                r'idempotency', r'duplicate', r'replay', r'transaction',
                r'amount', r'account', r'payment', r'transfer'
            ],
            'race_conditions': [
                r'concurrent', r'race', r'condition', r'loan',
                r'amount', r'user', r'account', r'request'
            ],
            'bola_attacks': [
                r'userid', r'accountid', r'deviceid', r'sessionid',
                r'authorization', r'access', r'permission', r'role'
            ],
            'kyc_bypass': [
                r'kyc', r'verification', r'document', r'identity',
                r'status', r'level', r'complete', r'pending'
            ],
            'loan_abuse': [
                r'loan', r'amount', r'income', r'credit', r'score',
                r'employment', r'criteria', r'approval', r'application'
            ],
            'discount_abuse': [
                r'discount', r'code', r'promo', r'offer', r'cashback',
                r'reward', r'benefit', r'user', r'application'
            ],
            'webhook_abuse': [
                r'webhook', r'callback', r'url', r'event', r'notification',
                r'payment', r'success', r'complete', r'trigger'
            ],
            'micro_transactions': [
                r'micro', r'transaction', r'small', r'amount', r'rapid',
                r'request', r'frequency', r'limit', r'threshold'
            ]
        }

    def validate_response(self, 
                         response: requests.Response, 
                         baseline_response: Optional[requests.Response] = None,
                         payload: str = "",
                         attack_type: str = "") -> ValidationResult:
        """
        Comprehensive false positive validation
        
        Args:
            response: The response to validate
            baseline_response: The baseline response for comparison
            payload: The payload that was tested
            attack_type: Type of attack (sql_injection, xss, command_injection, etc.)
            
        Returns:
            ValidationResult with detailed analysis
        """
        
        evidence = {
            'status_code': response.status_code,
            'content_length': len(response.text),
            'response_preview': response.text[:200],
            'payload': payload,
            'attack_type': attack_type
        }
        
        # 1. WAF Block Detection
        waf_score = self._check_waf_block(response)
        if waf_score > 0.8:
            return ValidationResult(
                is_false_positive=True,
                confidence=0.95,
                reason="WAF block detected - secure, not vulnerable",
                evidence={**evidence, 'waf_score': waf_score}
            )
        
        # 2. Authentication Error Detection
        auth_score = self._check_auth_error(response)
        if auth_score > 0.8:
            return ValidationResult(
                is_false_positive=True,
                confidence=0.9,
                reason="Authentication error - not a vulnerability",
                evidence={**evidence, 'auth_score': auth_score}
            )
        
        # 3. Response Comparison with Baseline
        if baseline_response:
            comparison_score = self._compare_with_baseline(response, baseline_response)
            if comparison_score > 0.9:
                return ValidationResult(
                    is_false_positive=True,
                    confidence=0.95,
                    reason="Response identical to baseline - false positive",
                    evidence={**evidence, 'comparison_score': comparison_score}
                )
        
        # 4. Attack-Specific Validation
        attack_specific_result = self._validate_attack_specific(response, payload, attack_type)
        if attack_specific_result.is_false_positive:
            return attack_specific_result
        
        # 5. Content Analysis
        content_score = self._analyze_content(response, payload, attack_type)
        if content_score > 0.8:
            return ValidationResult(
                is_false_positive=True,
                confidence=content_score,
                reason="Content analysis indicates false positive",
                evidence={**evidence, 'content_score': content_score}
            )
        
        # 6. Timing Analysis
        timing_score = self._analyze_timing(response, payload, attack_type)
        if timing_score > 0.8:
            return ValidationResult(
                is_false_positive=True,
                confidence=timing_score,
                reason="Timing analysis indicates false positive",
                evidence={**evidence, 'timing_score': timing_score}
            )
        
        # If we reach here, it's likely a real vulnerability
        return ValidationResult(
            is_false_positive=False,
            confidence=0.7,
            reason="No false positive indicators found - potential real vulnerability",
            evidence=evidence
        )

    def _check_waf_block(self, response: requests.Response) -> float:
        """Check if response is a WAF block page"""
        score = 0.0
        text_lower = response.text.lower()
        
        # Check for WAF indicators
        for indicator in self.waf_indicators:
            if indicator in text_lower:
                score += 0.1
        
        # Check for HTML structure (WAF pages are usually HTML)
        if '<html' in text_lower and '<body' in text_lower:
            score += 0.3
        
        # Check for 403 status
        if response.status_code == 403:
            score += 0.4
        
        return min(score, 1.0)

    def _check_auth_error(self, response: requests.Response) -> float:
        """Check if response is an authentication error"""
        score = 0.0
        text_lower = response.text.lower()
        
        # Check for auth indicators
        for indicator in self.auth_indicators:
            if indicator in text_lower:
                score += 0.2
        
        # Check for auth status codes
        if response.status_code in [401, 403, 440]:
            score += 0.3
        
        return min(score, 1.0)

    def _compare_with_baseline(self, response: requests.Response, baseline: requests.Response) -> float:
        """Compare response with baseline for similarity"""
        if response.text == baseline.text:
            return 1.0  # Identical response
        
        # Check length similarity
        length_diff = abs(len(response.text) - len(baseline.text))
        length_ratio = length_diff / len(baseline.text)
        
        if length_ratio < 0.1:  # Less than 10% difference
            return 0.8
        
        return 0.0

    def _validate_attack_specific(self, response: requests.Response, payload: str, attack_type: str) -> ValidationResult:
        """Validate based on specific attack type"""
        
        if attack_type == "sql_injection":
            return self._validate_sql_injection(response, payload)
        elif attack_type == "command_injection":
            return self._validate_command_injection(response, payload)
        elif attack_type == "xss":
            return self._validate_xss(response, payload)
        elif attack_type in self.banking_false_positive_patterns:
            return self._validate_banking_attack(response, payload, attack_type)
        
        return ValidationResult(
            is_false_positive=False,
            confidence=0.5,
            reason="No attack-specific validation available",
            evidence={}
        )

    def _validate_sql_injection(self, response: requests.Response, payload: str) -> ValidationResult:
        """Validate SQL injection specific false positives"""
        text_lower = response.text.lower()
        
        # Check for SQL false positive patterns
        for pattern in self.sql_false_positive_patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return ValidationResult(
                    is_false_positive=True,
                    confidence=0.9,
                    reason=f"SQL false positive pattern detected: {pattern}",
                    evidence={'pattern': pattern}
                )
        
        # Check if "sql" appears in legitimate context
        if 'sql' in text_lower:
            # Check if it's in a legitimate JSON field
            if any(field in text_lower for field in ['userid', 'deviceid', 'accountid']):
                return ValidationResult(
                    is_false_positive=True,
                    confidence=0.85,
                    reason="SQL indicator found in legitimate JSON context",
                    evidence={'context': 'json_field'}
                )
        
        return ValidationResult(
            is_false_positive=False,
            confidence=0.6,
            reason="No SQL injection false positive patterns detected",
            evidence={}
        )

    def _validate_command_injection(self, response: requests.Response, payload: str) -> ValidationResult:
        """Validate command injection specific false positives"""
        text_lower = response.text.lower()
        
        # Check for command false positive patterns
        for pattern in self.cmd_false_positive_patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return ValidationResult(
                    is_false_positive=True,
                    confidence=0.9,
                    reason=f"Command injection false positive pattern detected: {pattern}",
                    evidence={'pattern': pattern}
                )
        
        # Check if command indicators appear in legitimate context
        cmd_indicators = ['id', 'ls', 'dir', 'cat', 'type']
        for indicator in cmd_indicators:
            if indicator in text_lower:
                # Check if it's part of a legitimate field name
                if any(field in text_lower for field in ['userid', 'deviceid', 'accountid', 'activityid']):
                    return ValidationResult(
                        is_false_positive=True,
                        confidence=0.85,
                        reason=f"Command indicator '{indicator}' found in legitimate context",
                        evidence={'indicator': indicator, 'context': 'json_field'}
                    )
        
        return ValidationResult(
            is_false_positive=False,
            confidence=0.6,
            reason="No command injection false positive patterns detected",
            evidence={}
        )

    def _validate_xss(self, response: requests.Response, payload: str) -> ValidationResult:
        """Validate XSS specific false positives"""
        text_lower = response.text.lower()
        
        # Check if payload is reflected in legitimate JSON context
        if payload in response.text:
            # Check if it's in a JSON field (not actual XSS)
            if '"' in response.text and ':' in response.text:
                return ValidationResult(
                    is_false_positive=True,
                    confidence=0.8,
                    reason="XSS payload reflected in JSON context - likely false positive",
                    evidence={'context': 'json_reflection'}
                )
        
        return ValidationResult(
            is_false_positive=False,
            confidence=0.6,
            reason="No XSS false positive patterns detected",
            evidence={}
        )
    
    def _validate_banking_attack(self, response: requests.Response, payload: str, attack_type: str) -> ValidationResult:
        """Validate banking-specific attack false positives"""
        text_lower = response.text.lower()
        
        # Get patterns for this specific banking attack type
        patterns = self.banking_false_positive_patterns.get(attack_type, [])
        
        # Check for banking false positive patterns
        for pattern in patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return ValidationResult(
                    is_false_positive=True,
                    confidence=0.9,
                    reason=f"Banking {attack_type} false positive pattern detected: {pattern}",
                    evidence={'pattern': pattern, 'attack_type': attack_type}
                )
        
        # Check if response is a legitimate API response (not vulnerable)
        if response.status_code in [200, 201, 400, 401, 403, 404, 500]:
            # Check if it's a standard API response format
            if any(indicator in text_lower for indicator in self.legitimate_indicators):
                return ValidationResult(
                    is_false_positive=True,
                    confidence=0.85,
                    reason=f"Banking {attack_type} - legitimate API response detected",
                    evidence={'status_code': response.status_code, 'context': 'api_response'}
                )
        
        # Check if payload appears in legitimate JSON context
        if payload in response.text:
            # Check if it's in a JSON structure (likely false positive)
            if '"' in response.text and ':' in response.text:
                return ValidationResult(
                    is_false_positive=True,
                    confidence=0.8,
                    reason=f"Banking {attack_type} payload reflected in JSON context",
                    evidence={'context': 'json_reflection'}
                )
        
        # Special handling for test services like httpbin.org
        if 'httpbin.org' in response.url or 'test' in response.url.lower():
            # Test services often echo back the request, which can appear vulnerable
            if payload in response.text:
                return ValidationResult(
                    is_false_positive=True,
                    confidence=0.95,
                    reason=f"Banking {attack_type} - test service echo detected",
                    evidence={'service': 'test_echo', 'url': response.url}
                )
        
        # Check for legitimate banking API responses
        banking_indicators = [
            'transaction', 'account', 'balance', 'payment', 'transfer',
            'loan', 'credit', 'debit', 'amount', 'currency', 'status',
            'success', 'error', 'message', 'code', 'id', 'reference'
        ]
        
        if any(indicator in text_lower for indicator in banking_indicators):
            # If response contains banking terminology, it's likely a legitimate response
            if response.status_code in [200, 201, 400, 401, 403]:
                return ValidationResult(
                    is_false_positive=True,
                    confidence=0.9,
                    reason=f"Banking {attack_type} - legitimate banking API response",
                    evidence={'status_code': response.status_code, 'context': 'banking_api'}
                )
        
        return ValidationResult(
            is_false_positive=False,
            confidence=0.6,
            reason=f"No {attack_type} false positive patterns detected",
            evidence={'attack_type': attack_type}
        )

    def _analyze_content(self, response: requests.Response, payload: str, attack_type: str) -> float:
        """Analyze content for false positive indicators"""
        score = 0.0
        text_lower = response.text.lower()
        
        # Check for legitimate API response indicators
        for indicator in self.legitimate_indicators:
            if indicator in text_lower:
                score += 0.05
        
        # Check for JSON structure (legitimate API responses)
        if '{' in text_lower and '}' in text_lower:
            score += 0.2
        
        # Check for small response size (likely error page)
        if len(response.text) < 100:
            score += 0.3
        
        return min(score, 1.0)

    def _analyze_timing(self, response: requests.Response, payload: str, attack_type: str) -> float:
        """Analyze timing for false positive indicators"""
        # This would be implemented based on response timing analysis
        # For now, return a low score as timing analysis is complex
        return 0.0

    def validate_multiple_responses(self, 
                                  responses: List[Tuple[requests.Response, str, str]]) -> List[ValidationResult]:
        """Validate multiple responses at once"""
        results = []
        for response, payload, attack_type in responses:
            result = self.validate_response(response, payload=payload, attack_type=attack_type)
            results.append(result)
        return results

    def get_validation_summary(self, results: List[ValidationResult]) -> Dict:
        """Get summary of validation results"""
        total = len(results)
        false_positives = sum(1 for r in results if r.is_false_positive)
        real_vulnerabilities = total - false_positives
        
        return {
            'total_tests': total,
            'false_positives': false_positives,
            'real_vulnerabilities': real_vulnerabilities,
            'false_positive_rate': false_positives / total if total > 0 else 0,
            'accuracy': real_vulnerabilities / total if total > 0 else 0
        } 