#!/usr/bin/env python3
"""
Simple test script to verify the backend is working
"""
import requests
import json
import time
import sys

def test_backend():
    base_url = "http://localhost:8000"
    
    print("🔍 Testing CyberSec Bot Backend API...")
    print(f"Base URL: {base_url}")
    print()
    
    # Test 1: Health Check
    print("1. Testing health check...")
    try:
        response = requests.get(f"{base_url}/api/health", timeout=5)
        if response.status_code == 200:
            print("✅ Health check passed")
            print(f"   Response: {response.json()}")
        else:
            print(f"❌ Health check failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Health check failed: {e}")
        return False
    
    print()
    
    # Test 2: Start a scan
    print("2. Testing scan start...")
    try:
        scan_data = {
            "target": "https://httpbin.org/get",
            "severity": "critical"
        }
        response = requests.post(f"{base_url}/api/scan/start", 
                               json=scan_data, 
                               timeout=10)
        if response.status_code == 200:
            scan_result = response.json()
            print("✅ Scan started successfully")
            print(f"   Scan ID: {scan_result['scan_id']}")
            print(f"   Target: {scan_result['target']}")
            scan_id = scan_result['scan_id']
        else:
            print(f"❌ Scan start failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return False
    except Exception as e:
        print(f"❌ Scan start failed: {e}")
        return False
    
    print()
    
    # Test 3: Check scan status
    print("3. Testing scan status...")
    try:
        response = requests.get(f"{base_url}/api/scan/{scan_id}", timeout=5)
        if response.status_code == 200:
            status = response.json()
            print("✅ Scan status retrieved")
            print(f"   Status: {status['status']}")
            print(f"   Progress: {status['progress']}%")
            print(f"   Step: {status['current_step']}")
        else:
            print(f"❌ Scan status failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Scan status failed: {e}")
        return False
    
    print()
    
    # Test 4: List scans
    print("4. Testing scan list...")
    try:
        response = requests.get(f"{base_url}/api/scans", timeout=5)
        if response.status_code == 200:
            scans = response.json()
            print("✅ Scan list retrieved")
            print(f"   Total scans: {len(scans['scans'])}")
        else:
            print(f"❌ Scan list failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Scan list failed: {e}")
        return False
    
    print()
    print("🎉 All backend tests passed!")
    print()
    print("✅ Backend is working correctly!")
    print("🌐 You can now start the frontend with: cd frontend && npm start")
    
    return True

if __name__ == "__main__":
    if not test_backend():
        print()
        print("❌ Backend tests failed!")
        print("🔧 Try these troubleshooting steps:")
        print("   1. Make sure the backend is running: cd backend && source venv/bin/activate && python3 app.py")
        print("   2. Check for error messages in the backend console")
        print("   3. Verify the virtual environment is set up correctly")
        sys.exit(1) 