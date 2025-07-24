#!/usr/bin/env python3
"""
Debug WAF detection with known blocking payloads
"""

import requests
import urllib3
from scraper.security_layer_detector import SecurityLayerDetector

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def debug_waf_detection():
    """Debug WAF detection with payloads we know get blocked"""
    
    test_url = "https://api.uat-nesfb.com/banking/tpap/tpap/v1/home"
    headers = {
        "isSavingsAccountOnboarded": "true",
        "sp-device-id": "D8CBA312-59C8-4CF3-9475-A5E9CDBA514E",
        "u-access-token": "FysNCgWnZzzNFKHKCgDsHdtepraJwdx8",
        "u-session-token": "01K0YZ325YYZ6QHCZ5VCSBE147",
        "Content-Type": "application/json"
    }
    
    detector = SecurityLayerDetector()
    
    # Test payloads we know get blocked
    test_payloads = [
        ("'; DROP TABLE users;--", "sql_injection"),
        ("1' OR '1' = '1'--", "sql_injection"),
        ("' OR 1=1--", "sql_injection"),  # This one doesn't get blocked
    ]
    
    print("🔍 Debugging WAF Detection...")
    print("=" * 60)
    
    for payload, attack_type in test_payloads:
        print(f"\n🧪 Testing: {payload}")
        
        try:
            # Test with payload in URL parameter
            test_url_with_payload = f"{test_url}?test={payload}"
            response = requests.get(test_url_with_payload, headers=headers, timeout=10, verify=False)
            
            print(f"   📈 Response Details:")
            print(f"      Status Code: {response.status_code}")
            print(f"      Content Length: {len(response.text)}")
            print(f"      Headers: {dict(response.headers)}")
            print(f"      Content Preview: {response.text[:200]}...")
            
            # Test security layer detection
            security_results = detector.detect_security_layers(response, payload)
            
            print(f"   🛡️ Security Layer Detection Results:")
            if security_results:
                for result in security_results:
                    print(f"      Layer Type: {result.layer_type}")
                    print(f"      Is Blocked: {result.is_blocked}")
                    print(f"      Confidence: {result.confidence:.2f}")
                    print(f"      Block Reason: {result.block_reason}")
                    print(f"      Details: {result.details}")
            else:
                print(f"      No security layers detected")
                
                # Manual analysis
                print(f"   🔍 Manual Analysis:")
                if response.status_code == 403:
                    print(f"      ⚠️ 403 status code indicates blocking!")
                if 'cloudflare' in str(response.headers).lower():
                    print(f"      ⚠️ Cloudflare headers detected!")
                if 'cf-ray' in response.headers:
                    print(f"      ⚠️ CF-Ray header found: {response.headers.get('cf-ray')}")
                if 'blocked' in response.text.lower():
                    print(f"      ⚠️ 'blocked' found in response content!")
                if len(response.text) < 1000:  # WAF block pages are usually short
                    print(f"      ⚠️ Short response length suggests blocking page!")
            
        except Exception as e:
            print(f"   ❌ Request failed: {e}")
        
        print("-" * 40)

if __name__ == "__main__":
    debug_waf_detection() 