#!/usr/bin/env python3
"""
Demo script showing detailed security layer reporting
"""

def demo_detailed_security_report():
    """Demonstrate what the detailed security layer reporting looks like"""
    
    print("🔍 **Detailed Security Layer Analysis Demo**")
    print("=" * 60)
    print()
    print("When security layers are detected, the report shows:")
    print()
    
    # Demo WAF Protection
    print("### 🛡️ WAF Protection (95% confidence)")
    print()
    print("**SQL Injection Attacks Blocked:**")
    print("- `' OR 1=1--`")
    print("  - Reason: Blocked by CLOUDFLARE WAF")
    print("- `'; DROP TABLE users;--`")
    print("  - Reason: Blocked by CLOUDFLARE WAF")
    print("- `' UNION SELECT version(),database(),user()--`")
    print("  - Reason: Blocked by CLOUDFLARE WAF")
    print()
    
    print("**XSS Attacks Blocked:**")
    print("- `<script>alert('xss')</script>`")
    print("  - Reason: Blocked by CLOUDFLARE WAF")
    print("- `<img src=x onerror=alert('xss')>`")
    print("  - Reason: Blocked by CLOUDFLARE WAF")
    print()
    
    print("**Command Injection Attacks Blocked:**")
    print("- `; ls -la`")
    print("  - Reason: Blocked by CLOUDFLARE WAF")
    print("- `| whoami`")
    print("  - Reason: Blocked by CLOUDFLARE WAF")
    print()
    
    print("**Banking Attacks Blocked:**")
    print("- `{\"amount\": -1000, \"to_account\": \"1234567890\"}`")
    print("  - Reason: Blocked by CLOUDFLARE WAF")
    print("- `{\"promo_code\": \"FIRST50\", \"user_id\": \"new_user_123\"}`")
    print("  - Reason: Blocked by CLOUDFLARE WAF")
    print()
    
    # Demo Rate Limiting
    print("### ⏱️ Rate Limit Protection (90% confidence)")
    print()
    print("**SQL Injection Attacks Blocked:**")
    print("- `' OR 1=1--`")
    print("  - Reason: Rate limited - too many requests")
    print("- `'; DROP TABLE users;--`")
    print("  - Reason: Rate limited - too many requests")
    print()
    
    print("**XSS Attacks Blocked:**")
    print("- `<script>alert('xss')</script>`")
    print("  - Reason: Rate limited - too many requests")
    print()
    
    # Demo Auth Blocks
    print("### 🔐 Auth Block Protection (85% confidence)")
    print()
    print("**Auth Bypass Attacks Blocked:**")
    print("- `admin:admin`")
    print("  - Reason: Authentication required or failed")
    print("- `admin:password`")
    print("  - Reason: Authentication required or failed")
    print("- `user:user`")
    print("  - Reason: Authentication required or failed")
    print()
    
    # Demo CAPTCHA
    print("### 🤖 CAPTCHA Protection (80% confidence)")
    print()
    print("**Automated Attack Detection:**")
    print("- Multiple rapid requests detected")
    print("  - Reason: CAPTCHA challenge required")
    print("- Bot-like behavior patterns")
    print("  - Reason: CAPTCHA challenge required")
    print()
    
    # Summary Statistics
    print("**📈 Security Summary:**")
    print("- Total attacks blocked: **15**")
    print("- Attack types protected: **6**")
    print("- Security layers active: **4**")
    print()
    
    print("=" * 60)
    print("**🎯 What This Means:**")
    print()
    print("✅ **WAF Protection:** Your API is protected by a Web Application Firewall")
    print("✅ **Rate Limiting:** Prevents brute force and DDoS attacks")
    print("✅ **Authentication:** Proper auth validation is in place")
    print("✅ **CAPTCHA:** Additional protection against automated attacks")
    print()
    print("**🛡️ Security Score: 95/100**")
    print("**🔒 Overall Status: WELL PROTECTED**")

if __name__ == "__main__":
    demo_detailed_security_report() 