#!/usr/bin/env python3
"""
Create a mock security layer analysis report showing blocked attacks
"""

def create_mock_security_layer_report():
    """Generate mock report content exactly like the image"""
    
    mock_findings = {
        'api': {
            'vulnerabilities': {'critical': [], 'high': [], 'medium': [], 'low': []},
            'security_layers': {
                'waf_detected': True,
                'rate_limiting_detected': False,
                'auth_blocks_detected': False,
                'captcha_detected': False,
                'challenge_detected': False,
                'blocked_requests': [
                    {
                        'payload': "' OR 1=1--",
                        'layer_type': 'waf',
                        'block_reason': 'Blocked by CLOUDFLARE WAF',
                        'confidence': 0.8,
                        'attack_type': 'sql_injection'
                    },
                    {
                        'payload': "'; DROP TABLE users;--",
                        'layer_type': 'waf',
                        'block_reason': 'Blocked by CLOUDFLARE WAF',
                        'confidence': 0.8,
                        'attack_type': 'sql_injection'
                    },
                    {
                        'payload': "' UNION SELECT version(),database(),user()--",
                        'layer_type': 'waf',
                        'block_reason': 'Blocked by CLOUDFLARE WAF',
                        'confidence': 0.8,
                        'attack_type': 'sql_injection'
                    },
                    {
                        'payload': "<img src=x onerror=alert('xss')>",
                        'layer_type': 'waf',
                        'block_reason': 'Blocked by CLOUDFLARE WAF',
                        'confidence': 0.8,
                        'attack_type': 'xss'
                    },
                    {
                        'payload': "javascript:alert('xss')",
                        'layer_type': 'waf',
                        'block_reason': 'Blocked by CLOUDFLARE WAF',
                        'confidence': 0.8,
                        'attack_type': 'xss'
                    },
                    {
                        'payload': "& cat /etc/passwd",
                        'layer_type': 'waf',
                        'block_reason': 'Blocked by CLOUDFLARE WAF',
                        'confidence': 0.8,
                        'attack_type': 'command_injection'
                    },
                    {
                        'payload': "../../../etc/passwd",
                        'layer_type': 'waf',
                        'block_reason': 'Blocked by CLOUDFLARE WAF',
                        'confidence': 0.8,
                        'attack_type': 'path_traversal'
                    },
                    {
                        'payload': "..\\..\\..\\windows\\win.ini",
                        'layer_type': 'waf',
                        'block_reason': 'Blocked by CLOUDFLARE WAF',
                        'confidence': 0.8,
                        'attack_type': 'path_traversal'
                    },
                    {
                        'payload': "user:user",
                        'layer_type': 'waf',
                        'block_reason': 'Blocked by CLOUDFLARE WAF',
                        'confidence': 0.8,
                        'attack_type': 'auth_bypass'
                    },
                    {
                        'payload': '{"amount": -1000, "to_account": "1234567890"}',
                        'layer_type': 'waf',
                        'block_reason': 'Blocked by CLOUDFLARE WAF',
                        'confidence': 0.8,
                        'attack_type': 'banking_attacks'
                    }
                ],
                'security_layers': [],
                'attack_blocks': {
                    'sql_injection': [],
                    'xss': [],
                    'command_injection': [],
                    'path_traversal': [],
                    'auth_bypass': [],
                    'banking_attacks': []
                }
            }
        }
    }
    
    return mock_findings

def generate_mock_report():
    """Generate the exact security layer analysis from the image"""
    
    print("## 🛡️ Security Layer Analysis")
    print("**🎯 Attacks Blocked by Security Layers:**\n")
    
    print("### 🛡️ WAF Protection (80% confidence)")
    
    print("\n**SQL Injection Attacks Blocked:**")
    print("- `' OR 1=1--`")
    print("  - Reason: Blocked by CLOUDFLARE WAF")
    print("- `'; DROP TABLE users;--`")
    print("  - Reason: Blocked by CLOUDFLARE WAF")
    print("- `' UNION SELECT version(),database(),user()--`")
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
    print("=== MOCK SECURITY LAYER ANALYSIS (What you want to see) ===\n")
    generate_mock_report()
    print("\n" + "="*60)
    print("This is what the report should look like when WAF blocks are detected!")
    print("The current APIs you're testing are not triggering any blocks.")
    print("You need to test against APIs with active WAF protection.") 