#!/usr/bin/env python3
"""
Check what's in the response that contains "ls"
"""

import requests
import json

def check_ls_in_response():
    """Check what's in the response that contains 'ls'"""
    
    # Target URL
    base_url = "https://api.uat-nesfb.com/banking/tpap/tpap/v1/home"
    
    # Query parameters
    params = {
        "isUpiS2s": "true",
        "myQrFunctionality": "true", 
        "switchConsent": "true",
        "isAvatarCached": "false"
    }
    
    # Headers from the curl command
    headers = {
        "app_build": "89376",
        "u-session-token": "01K0YCF6G4XWSB43B0E9Y2APMK",
        "isSavingsAccountOnboarded": "true",
        "device_name": "iPhone",
        "slotId": "1",
        "x-slice-checksum": "0098f57966ee68430f8fc2a31cc7738461fbf02756877fd51e9bad265de60bfb|1753366519783|IST",
        "traceparent": "00-0DE1D375E2514FB28B8066451AC885B6-00000000ba3542b2-01",
        "modular-flow-version": "v0.0",
        "u-access-token": "FysNCgWnZzzNFKHKCgDsHdtepraJwdx8",
        "Content-Type": "application/json",
        "Platform": "ios:89376",
        "app_version": "13.0.0",
        "device-id": "D8CBA312-59C8-4CF3-9475-A5E9CDBA514E",
        "ssid": "123456789",
        "latitude": "0.0",
        "x-date": "2025-07-24T19:45:19+05:30",
        "sp-device-id": "D8CBA312-59C8-4CF3-9475-A5E9CDBA514E",
        "networkType": "Wi-Fi",
        "device_model": "iPhone 12",
        "longitude": "0.0",
        "deviceId": "D8CBA312-59C8-4CF3-9475-A5E9CDBA514E",
        "Cookie": "__cf_bm=xXV2ivF_ahLpKyVdptdL94Z1P8HqG.GmNV_FdATV3lE-1753366436-1.0.1.1-CC6FLodK3pvEzlCQa4CxEB87v3gQ76xfGYzxI3fnFaT.K2c33SI82KwFFUgEaqwsH7lz9i0ln3JGbJExroadGPFewEmN9C4syv8LDrGolJA"
    }
    
    print("🔍 Checking what contains 'ls' in the response")
    print("=" * 60)
    
    try:
        resp = requests.get(base_url, headers=headers, params=params, timeout=10)
        print(f"Status: {resp.status_code}")
        print(f"Content Length: {len(resp.text)}")
        
        # Find all occurrences of "ls" in the response
        response_text = resp.text.lower()
        ls_positions = []
        
        start = 0
        while True:
            pos = response_text.find('ls', start)
            if pos == -1:
                break
            ls_positions.append(pos)
            start = pos + 1
        
        print(f"\nFound {len(ls_positions)} occurrences of 'ls' in response")
        
        # Show context around each "ls" occurrence
        for i, pos in enumerate(ls_positions):
            start = max(0, pos - 50)
            end = min(len(resp.text), pos + 50)
            context = resp.text[start:end]
            print(f"\nOccurrence {i+1} (position {pos}):")
            print(f"Context: ...{context}...")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    check_ls_in_response() 