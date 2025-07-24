#!/usr/bin/env python3
"""
Debug script to see the actual data structure returned from API scanner
"""

import json
from scraper import api_scanner

def debug_data_structure():
    """Debug the data structure returned from API scanner"""
    
    # Test with a simple URL
    test_url = "https://httpbin.org/get"
    
    print("🔍 Testing API scanner data structure...")
    print(f"Target: {test_url}")
    print("-" * 60)
    
    # Run the scan
    results = api_scanner.scan_api(test_url, severity='all')
    
    print("📊 Raw Results Structure:")
    print(f"Type: {type(results)}")
    print(f"Keys: {list(results.keys()) if isinstance(results, dict) else 'Not a dict'}")
    print()
    
    if isinstance(results, dict):
        for key, value in results.items():
            print(f"🔍 Key: {key}")
            print(f"   Type: {type(value)}")
            if isinstance(value, dict):
                print(f"   Keys: {list(value.keys())}")
                if 'blocked_requests' in value:
                    print(f"   Blocked Requests: {len(value['blocked_requests'])}")
                if 'security_layers' in value:
                    print(f"   Security Layers: {len(value['security_layers'])}")
            elif isinstance(value, list):
                print(f"   Length: {len(value)}")
            print()
    
    print("📋 Detailed Security Layers Info:")
    if isinstance(results, dict) and 'security_layers' in results:
        security_layers = results['security_layers']
        print(f"WAF Detected: {security_layers.get('waf_detected', False)}")
        print(f"Rate Limiting Detected: {security_layers.get('rate_limiting_detected', False)}")
        print(f"Auth Blocks Detected: {security_layers.get('auth_blocks_detected', False)}")
        print(f"Blocked Requests: {len(security_layers.get('blocked_requests', []))}")
        print(f"Security Layers: {len(security_layers.get('security_layers', []))}")
        
        if security_layers.get('blocked_requests'):
            print("\n🔍 Sample Blocked Requests:")
            for i, block in enumerate(security_layers['blocked_requests'][:3]):
                print(f"  {i+1}. {block}")
    
    print("\n" + "=" * 60)
    print("JSON Structure:")
    print(json.dumps(results, indent=2, default=str))

if __name__ == "__main__":
    debug_data_structure() 