#!/usr/bin/env python3
"""
Demo script showing Security Layer Analysis with detected blocks
"""

def demo_blocked_attacks():
    """Demonstrate Security Layer Analysis with detected blocks"""
    
    print("## 🛡️ Security Layer Analysis")
    print("**🎯 Attacks Blocked by Security Layers:**\n")
    
    print("### 🛡️ WAF Protection (80% confidence)")
    print("\n**SQL Injection Attacks Blocked:**")
    print("- `' OR 1=1--`")
    print("  - Reason: Blocked by CLOUDFLARE WAF")
    print("- `'; DROP TABLE users;--`")
    print("  - Reason: Blocked by CLOUDFLARE WAF")
    print("- `UNION SELECT version(),database(),user()--`")
    print("  - Reason: Blocked by CLOUDFLARE WAF")
    
    print("\n**XSS Attacks Blocked:**")
    print("- `<img src=x onerror=alert('xss')>`")
    print("  - Reason: Blocked by CLOUDFLARE WAF")
    print("- `javascript:alert('xss')`")
    print("  - Reason: Blocked by CLOUDFLARE WAF")
    
    print("\n**Command Injection Attacks Blocked:**")
    print("- `& cat /etc/passwd`")
    print("  - Reason: Blocked by CLOUDFLARE WAF")
    
    print("\n**Path Traversal Attacks Blocked:**")
    print("- `../../../etc/passwd`")
    print("  - Reason: Blocked by CLOUDFLARE WAF")
    print("- `..\\..\\..\\windows\\win.ini`")
    print("  - Reason: Blocked by CLOUDFLARE WAF")
    
    print("\n**Auth Bypass Attacks Blocked:**")
    print("- `user:user`")
    print("  - Reason: Blocked by CLOUDFLARE WAF")
    
    print("\n**Banking Attacks Blocked:**")
    print("- `{\"amount\": -1000, \"to_account\": \"1234567890\"}`")
    print("  - Reason: Blocked by CLOUDFLARE WAF")
    
    print("\n**📈 Security Layer Summary:**")
    print("- Total attacks blocked: **10**")
    print("- Attack types protected: **6**")
    print("- Security layers active: **1**")

if __name__ == "__main__":
    demo_blocked_attacks() 