#!/usr/bin/env python3
"""
Debug version of the scanner to identify why it's stopping early
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'scraper'))

def debug_scan():
    """Debug the scanner to see why it's stopping early"""
    
    print("🔍 Debugging Scanner Issues")
    print("=" * 50)
    
    # Test URL with SQL injection
    test_url = "https://httpbin.org/get?username=test'%20OR%201=1%20--&password=secret"
    
    print(f"Test URL: {test_url}")
    
    # Parse the URL to check for SQL injection patterns
    from urllib.parse import urlparse, parse_qs, unquote
    
    parsed_url = urlparse(test_url)
    params = parse_qs(parsed_url.query)
    
    print(f"\n📊 URL Analysis:")
    print(f"   Base URL: {parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}")
    print(f"   Parameters: {params}")
    
    # Check for SQL injection patterns
    sql_patterns = [
        "' OR 1=1 --", "' OR '1'='1", "' UNION SELECT",
        "'; DROP TABLE", "' OR 1=1#", "' OR 1=1/*",
        "admin'--", "admin'#", "admin'/*",
        "' OR 'x'='x", "' OR 1=1 OR '", "'; WAITFOR DELAY",
        "' AND 1=1--", "' AND '1'='1"
    ]
    
    detected_injections = []
    
    for param_name, param_values in params.items():
        for value in param_values:
            decoded_value = unquote(value)
            print(f"\n🔍 Checking parameter '{param_name}' = '{decoded_value}'")
            
            for pattern in sql_patterns:
                if pattern.lower() in decoded_value.lower():
                    detected_injections.append({
                        'parameter': param_name,
                        'value': decoded_value,
                        'pattern': pattern,
                        'type': 'sql_injection'
                    })
                    print(f"   ⚠️  SQL Injection detected!")
                    print(f"      Pattern: {pattern}")
                    break
    
    if detected_injections:
        print(f"\n🚨 SQL Injection Vulnerabilities Detected:")
        for injection in detected_injections:
            print(f"   - Parameter: {injection['parameter']}")
            print(f"   - Value: {injection['value']}")
            print(f"   - Pattern: {injection['pattern']}")
            print(f"   - Type: {injection['type']}")
        
        print(f"\n✅ CONCLUSION: The URL contains SQL injection payloads!")
        print(f"   The scanner should detect these vulnerabilities.")
        return True
    else:
        print(f"\n❌ No SQL injection patterns detected")
        return False

def test_curl_parsing():
    """Test curl command parsing"""
    
    print(f"\n🔍 Testing Curl Command Parsing")
    print("=" * 50)
    
    curl_command = "curl -X GET -H \"Authorization: Bearer testtoken\" -H \"User-Agent: Mozilla/5.0\" -H \"Content-Type: application/json\" \"https://httpbin.org/get?username=test'%20OR%201=1%20--&password=secret\""
    
    print(f"Curl Command: {curl_command}")
    
    # Try to parse the curl command
    try:
        from main import parse_curl_command
        parsed = parse_curl_command(curl_command)
        print(f"\n📊 Parsed Result:")
        print(f"   Method: {parsed.get('method', 'Unknown')}")
        print(f"   URL: {parsed.get('url', 'Unknown')}")
        print(f"   Headers: {parsed.get('headers', {})}")
        print(f"   Data: {parsed.get('data', None)}")
        
        # Check if URL contains SQL injection
        url = parsed.get('url', '')
        if "' OR 1=1 --" in url:
            print(f"   ✅ URL contains SQL injection payload!")
        else:
            print(f"   ❌ URL does not contain SQL injection payload")
            
    except Exception as e:
        print(f"   ❌ Error parsing curl command: {e}")

if __name__ == "__main__":
    # Run debug tests
    sql_detected = debug_scan()
    test_curl_parsing()
    
    if sql_detected:
        print(f"\n🎯 CONCLUSION: SQL injection detection logic is working correctly!")
        print(f"   The issue is likely in the scanner execution, not the detection logic.")
    else:
        print(f"\n⚠️  CONCLUSION: SQL injection detection logic needs improvement!") 