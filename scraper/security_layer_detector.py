#!/usr/bin/env python3
"""
Security Layer Detection System
Detects WAF blocks, rate limiting, and other security protection mechanisms
"""

import re
import time
import requests
from typing import Dict, List, Optional
from dataclasses import dataclass

@dataclass
class SecurityLayerResult:
    """Result of security layer detection"""
    layer_type: str  # 'waf', 'rate_limit', 'auth_block', 'captcha', 'challenge'
    confidence: float  # 0.0 to 1.0
    details: Dict[str, any]
    is_blocked: bool
    block_reason: str

class SecurityLayerDetector:
    """
    Comprehensive security layer detection system
    """
    
    def __init__(self):
        # WAF detection patterns
        self.waf_patterns = {
            'cloudflare': {
                'indicators': [
                    'cloudflare', 'ray id', 'access denied', 'forbidden',
                    'blocked by cloudflare', 'security check', 'captcha',
                    'challenge', 'please wait', 'checking your browser'
                ],
                'status_codes': [403, 429, 503],
                'headers': ['cf-ray', 'cf-cache-status', 'cf-request-id']
            },
            'aws_waf': {
                'indicators': [
                    'aws waf', 'access denied', 'forbidden', 'blocked',
                    'security check', 'captcha', 'challenge'
                ],
                'status_codes': [403, 429],
                'headers': ['x-amz-cf-id', 'x-amz-cf-pop']
            },
            'akamai': {
                'indicators': [
                    'akamai', 'access denied', 'forbidden', 'blocked',
                    'security check', 'captcha', 'challenge'
                ],
                'status_codes': [403, 429],
                'headers': ['x-akamai-transformed', 'x-akamai-origin-hop']
            },
            'fastly': {
                'indicators': [
                    'fastly', 'access denied', 'forbidden', 'blocked',
                    'security check', 'captcha', 'challenge'
                ],
                'status_codes': [403, 429],
                'headers': ['x-fastly', 'x-fastly-ssl']
            },
            'generic_waf': {
                'indicators': [
                    'access denied', 'forbidden', 'blocked', 'security',
                    'firewall', 'protection', 'captcha', 'challenge',
                    'rate limit', 'too many requests', 'blocked by'
                ],
                'status_codes': [403, 429, 503],
                'headers': []
            }
        }
        
        # Rate limiting patterns
        self.rate_limit_patterns = {
            'indicators': [
                'rate limit', 'too many requests', 'quota exceeded',
                'rate limit exceeded', 'throttled', 'slow down',
                '429', 'too many', 'limit exceeded'
            ],
            'status_codes': [429],
            'headers': ['retry-after', 'x-ratelimit-remaining', 'x-ratelimit-reset']
        }
        
        # Authentication block patterns
        self.auth_block_patterns = {
            'indicators': [
                'unauthorized', 'forbidden', 'access denied', 'login required',
                'authentication', 'session expired', 'token invalid', 'invalid token',
                '401', '403', '440', 'session', 'login', 'signin'
            ],
            'status_codes': [401, 403, 440],
            'headers': ['www-authenticate', 'x-auth-required']
        }
        
        # Captcha/Challenge patterns
        self.captcha_patterns = {
            'indicators': [
                'captcha', 'challenge', 'verify', 'human verification',
                'security check', 'please verify', 'prove you are human',
                'recaptcha', 'hcaptcha', 'turnstile'
            ],
            'status_codes': [403, 429],
            'headers': []
        }

    def detect_security_layers(self, response: requests.Response, payload: str = "") -> List[SecurityLayerResult]:
        """
        Detect all security layers that may have blocked the request
        
        Args:
            response: The HTTP response to analyze
            payload: The payload that was tested (for context)
            
        Returns:
            List of SecurityLayerResult objects
        """
        results = []
        
        # 1. Detect WAF blocks
        waf_results = self._detect_waf_blocks(response, payload)
        results.extend(waf_results)
        
        # 2. Detect rate limiting
        rate_limit_result = self._detect_rate_limiting(response, payload)
        if rate_limit_result:
            results.append(rate_limit_result)
        
        # 3. Detect authentication blocks
        auth_result = self._detect_auth_blocks(response, payload)
        if auth_result:
            results.append(auth_result)
        
        # 4. Detect captcha/challenge
        captcha_result = self._detect_captcha_challenge(response, payload)
        if captcha_result:
            results.append(captcha_result)
        
        return results

    def _detect_waf_blocks(self, response: requests.Response, payload: str) -> List[SecurityLayerResult]:
        """Detect WAF blocks from various providers"""
        results = []
        text_lower = response.text.lower()
        
        # Track the best WAF match
        best_waf_match = None
        best_score = 0.0
        
        for waf_name, patterns in self.waf_patterns.items():
            score = 0.0
            evidence = {
                'waf_type': waf_name,
                'status_code': response.status_code,
                'payload': payload,
                'indicators_found': []
            }
            
            # Check for WAF indicators in response text
            for indicator in patterns['indicators']:
                if indicator in text_lower:
                    score += 0.2
                    evidence['indicators_found'].append(indicator)
            
            # Check for WAF-specific status codes
            if response.status_code in patterns['status_codes']:
                score += 0.3
                evidence['status_codes_matched'] = True
            
            # Check for WAF-specific headers (highest confidence)
            for header in patterns['headers']:
                if header.lower() in [h.lower() for h in response.headers.keys()]:
                    score += 0.4
                    evidence['waf_headers_found'] = True
                    evidence['waf_headers'] = [h for h in response.headers.keys() if h.lower() == header.lower()]
            
            # Check for HTML structure (WAF pages are usually HTML)
            if '<html' in text_lower and '<body' in text_lower:
                score += 0.2
                evidence['html_structure'] = True
            
            # Check for specific WAF patterns
            if waf_name == 'cloudflare':
                if 'ray id' in text_lower:
                    score += 0.3
                    evidence['cloudflare_ray_id'] = True
                if 'checking your browser' in text_lower:
                    score += 0.3
                    evidence['cloudflare_challenge'] = True
            
            # Only consider high confidence matches
            if score > 0.5:
                # If this is a better match than the current best, update
                if score > best_score:
                    best_score = score
                    best_waf_match = SecurityLayerResult(
                        layer_type='waf',
                        confidence=min(score, 1.0),
                        details=evidence,
                        is_blocked=True,
                        block_reason=f"Blocked by {waf_name.upper()} WAF"
                    )
        
        # Only return the best WAF match
        if best_waf_match:
            results.append(best_waf_match)
        
        return results

    def _detect_rate_limiting(self, response: requests.Response, payload: str) -> Optional[SecurityLayerResult]:
        """Detect rate limiting blocks"""
        text_lower = response.text.lower()
        score = 0.0
        evidence = {
            'status_code': response.status_code,
            'payload': payload,
            'indicators_found': []
        }
        
        # Check for rate limit indicators
        for indicator in self.rate_limit_patterns['indicators']:
            if indicator in text_lower:
                score += 0.3
                evidence['indicators_found'].append(indicator)
        
        # Check for rate limit status codes
        if response.status_code in self.rate_limit_patterns['status_codes']:
            score += 0.4
            evidence['rate_limit_status_code'] = True
        
        # Check for rate limit headers
        for header in self.rate_limit_patterns['headers']:
            if header.lower() in [h.lower() for h in response.headers.keys()]:
                score += 0.3
                evidence['rate_limit_headers'] = [h for h in response.headers.keys() if h.lower() == header.lower()]
        
        # Only detect rate limiting if we have strong indicators and it's not a WAF block
        if score > 0.6 and not self._is_likely_waf_block(response):
            return SecurityLayerResult(
                layer_type='rate_limit',
                confidence=min(score, 1.0),
                details=evidence,
                is_blocked=True,
                block_reason="Rate limited - too many requests"
            )
        
        return None

    def _detect_auth_blocks(self, response: requests.Response, payload: str) -> Optional[SecurityLayerResult]:
        """Detect authentication blocks"""
        text_lower = response.text.lower()
        score = 0.0
        evidence = {
            'status_code': response.status_code,
            'payload': payload,
            'indicators_found': []
        }
        
        # Check for auth indicators
        for indicator in self.auth_block_patterns['indicators']:
            if indicator in text_lower:
                score += 0.2
                evidence['indicators_found'].append(indicator)
        
        # Check for auth status codes
        if response.status_code in self.auth_block_patterns['status_codes']:
            score += 0.4
            evidence['auth_status_code'] = True
        
        # Check for auth headers
        for header in self.auth_block_patterns['headers']:
            if header.lower() in [h.lower() for h in response.headers.keys()]:
                score += 0.3
                evidence['auth_headers'] = [h for h in response.headers.keys() if h.lower() == header.lower()]
        
        # Only detect auth blocks if we have strong indicators and it's not a WAF block
        # WAF blocks often have auth-like status codes but are actually WAF blocks
        if score > 0.6 and not self._is_likely_waf_block(response):
            return SecurityLayerResult(
                layer_type='auth_block',
                confidence=min(score, 1.0),
                details=evidence,
                is_blocked=True,
                block_reason="Authentication required or failed"
            )
        
        return None

    def _is_likely_waf_block(self, response: requests.Response) -> bool:
        """Check if response is likely a WAF block rather than auth block"""
        text_lower = response.text.lower()
        
        # WAF blocks typically have HTML structure
        if '<html' in text_lower and '<body' in text_lower:
            return True
        
        # WAF blocks often contain specific keywords
        waf_indicators = ['cloudflare', 'ray id', 'blocked', 'security', 'firewall', 'protection']
        if any(indicator in text_lower for indicator in waf_indicators):
            return True
        
        return False

    def _detect_captcha_challenge(self, response: requests.Response, payload: str) -> Optional[SecurityLayerResult]:
        """Detect captcha/challenge blocks"""
        text_lower = response.text.lower()
        score = 0.0
        evidence = {
            'status_code': response.status_code,
            'payload': payload,
            'indicators_found': []
        }
        
        # Check for captcha indicators
        for indicator in self.captcha_patterns['indicators']:
            if indicator in text_lower:
                score += 0.3
                evidence['indicators_found'].append(indicator)
        
        # Check for captcha status codes
        if response.status_code in self.captcha_patterns['status_codes']:
            score += 0.3
            evidence['captcha_status_code'] = True
        
        # Only detect captcha if we have strong indicators and it's not a WAF block
        if score > 0.5 and not self._is_likely_waf_block(response):
            return SecurityLayerResult(
                layer_type='captcha',
                confidence=min(score, 1.0),
                details=evidence,
                is_blocked=True,
                block_reason="Captcha/Challenge required"
            )
        
        return None

    def get_security_summary(self, results: List[SecurityLayerResult]) -> Dict:
        """Get summary of security layer detection results"""
        if not results:
            return {
                'total_blocks': 0,
                'block_types': [],
                'is_protected': False,
                'protection_layers': []
            }
        
        block_types = list(set(r.layer_type for r in results))
        total_blocks = len(results)
        
        return {
            'total_blocks': total_blocks,
            'block_types': block_types,
            'is_protected': total_blocks > 0,
            'protection_layers': [
                {
                    'type': r.layer_type,
                    'confidence': r.confidence,
                    'reason': r.block_reason,
                    'details': r.details
                } for r in results
            ]
        }

    def format_block_message(self, results: List[SecurityLayerResult]) -> str:
        """Format a user-friendly message about security blocks"""
        if not results:
            return "✅ No security blocks detected - request processed normally"
        
        messages = []
        for result in results:
            if result.layer_type == 'waf':
                waf_name = result.details.get('waf_type', 'WAF').upper()
                messages.append(f"🛡️ Blocked by {waf_name} (Confidence: {result.confidence:.1%})")
            elif result.layer_type == 'rate_limit':
                messages.append(f"⏱️ Rate limited (Confidence: {result.confidence:.1%})")
            elif result.layer_type == 'auth_block':
                messages.append(f"🔐 Authentication required (Confidence: {result.confidence:.1%})")
            elif result.layer_type == 'captcha':
                messages.append(f"🤖 Captcha/Challenge required (Confidence: {result.confidence:.1%})")
        
        return " | ".join(messages) 