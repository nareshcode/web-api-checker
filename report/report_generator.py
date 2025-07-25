import json
from datetime import datetime

def categorize_finding(finding_type, finding_data=""):
    """
    Categorize individual findings and return priority, timeline, risk assessment, and CVSS score
    """
    # Vulnerability categorization matrix with CVSS scores
    categorization_matrix = {
        'sql_injection': ('Critical', '0-24h', 'Complete database compromise possible', 9.8),
        'command_injection': ('Critical', '0-24h', 'Server takeover and system compromise', 9.8),
        'xxe': ('Critical', '0-24h', 'File disclosure and SSRF attacks', 9.1),
        'ssrf': ('Critical', '0-24h', 'Internal network access and data exposure', 8.8),
        'double_spending': ('Critical', '0-24h', 'Financial fraud and monetary theft', 9.5),
        'race_conditions': ('Critical', '0-24h', 'Financial inconsistencies and fraud', 9.2),
        'https': ('Critical', '0-24h', 'Data interception and man-in-the-middle attacks', 7.4),
        'open_endpoint': ('Critical', '0-24h', 'Unauthorized access to protected resources', 8.5),
        
        'xss': ('High', '1-7 days', 'Session hijacking and user impersonation', 7.2),
        'nosql_injection': ('High', '1-7 days', 'Database manipulation and data theft', 7.5),
        'ldap_injection': ('High', '1-7 days', 'Directory service compromise', 7.3),
        'path_traversal': ('High', '1-7 days', 'Unauthorized file system access', 7.1),
        'auth_bypass': ('High', '1-7 days', 'Unauthorized access to protected resources', 8.2),
        'privilege_escalation': ('High', '1-7 days', 'Unauthorized admin access', 7.8),
        'bola_attacks': ('High', '1-7 days', 'Unauthorized access to sensitive data', 7.5),
        'transaction_manipulation': ('High', '1-7 days', 'Financial manipulation and fraud', 8.0),
        'session_fixation': ('High', '1-7 days', 'Session hijacking and account takeover', 7.0),
        'kyc_bypass': ('High', '1-7 days', 'KYC verification circumvention', 7.5),
        'loan_abuse': ('High', '1-7 days', 'Fraudulent loan approvals', 7.8),
        'webhook_abuse': ('High', '1-7 days', 'Malicious webhook exploitation', 6.8),
        'open_redirects': ('High', '1-7 days', 'Phishing and malicious redirects', 6.5),
        
        'security_headers': ('Medium', '1-30 days', 'Various client-side attacks possible', 5.4),
        'security_header': ('Medium', '1-30 days', 'Client-side security weaknesses', 5.4),
        'cors': ('Medium', '1-30 days', 'Cross-origin data access', 5.8),
        'rate_limiting': ('Medium', '1-30 days', 'Denial of service and abuse', 5.2),
        'error_handling': ('Medium', '1-30 days', 'System information leakage', 4.3),
        'metadata_leakage': ('Medium', '1-30 days', 'System information disclosure', 4.3),
        'verbose_errors': ('Medium', '1-30 days', 'Detailed error information exposure', 4.0),
        'discount_abuse': ('Medium', '1-30 days', 'Discount system exploitation', 5.0),
        'micro_transactions': ('Medium', '1-30 days', 'Micro-transaction abuse', 4.5),
        'idempotency_check': ('Medium', '1-30 days', 'Request replay vulnerabilities', 5.0),
        
        'general': ('Low', '1-90 days', 'Minor security improvement needed', 3.0),
        'information_disclosure': ('Low', '1-90 days', 'Minor information leakage', 3.5)
    }
    
    # Get categorization or default to low priority
    return categorization_matrix.get(finding_type, ('Low', '1-90 days', 'Minor security concern', 3.0))

def tuple_to_dict_finding(finding_tuple, finding_type=None):
    """
    Convert tuple-based finding to dictionary format for consistency
    Tuple format: (finding_type, description, priority, timeline, risk, payloads, url)
    """
    if isinstance(finding_tuple, dict):
        return finding_tuple  # Already a dict
    
    if len(finding_tuple) >= 7:
        type_name, description, priority, timeline, risk, payloads, url = finding_tuple[:7]
        
        # Extract CVSS score from categorize_finding
        _, _, _, cvss = categorize_finding(type_name)
        
        return {
            'type': type_name,
            'name': description,
            'cvss': cvss,
            'description': description,
            'impact': risk,
            'url': url,
            'payloads': payloads or []
        }
    else:
        return {
            'type': finding_type or 'unknown',
            'name': str(finding_tuple),
            'cvss': 3.0,
            'description': str(finding_tuple),
            'impact': 'Unknown impact',
            'url': '',
            'payloads': []
        }

def generate_report(findings, report_path, api_url=None, curl_cmd=None, curl_info=None, severity='all'):
    """
    Generate a professional security assessment report from a senior engineer's perspective.
    Focus on actionable insights, clear risk assessment, and practical remediation steps.
    """
    
    def get_cvss_explanation():
        """Provide a clear explanation of CVSS scoring for stakeholders"""
        return """
**CVSS (Common Vulnerability Scoring System)** is the industry standard for assessing vulnerability severity:

| Score Range | Severity | Description | Business Impact |
|-------------|----------|-------------|-----------------|
| 9.0 - 10.0  | **Critical** | Immediate threat requiring emergency patching | System compromise, data breach |
| 7.0 - 8.9   | **High** | Serious vulnerability requiring urgent attention | Unauthorized access, service disruption |
| 4.0 - 6.9   | **Medium** | Moderate risk requiring timely remediation | Limited access, minor data exposure |
| 0.1 - 3.9   | **Low** | Minor security improvement | Minimal impact, best practice |

*CVSS factors include: Attack Vector, Complexity, Privileges Required, User Interaction, and Impact on Confidentiality, Integrity, and Availability.*
"""

    def section(title):
        """Generate a markdown section header"""
        return f"\n## {title}\n\n"

    def categorize_findings_professional(findings, api_url=None):
        """Categorize findings with professional risk assessment"""
        critical_findings = []
        high_findings = []
        medium_findings = []
        low_findings = []
        passed_controls = []
        
        api_findings = findings.get('api', {})
        
        # Professional vulnerability categorization
        vulnerability_matrix = {
            'critical': {
                'sql_injection': ('SQL Injection', 9.8, 'Complete database compromise possible'),
                'command_injection': ('Command Injection', 9.8, 'Server takeover and system compromise'),
                'xxe': ('XML External Entity', 9.1, 'File disclosure and SSRF attacks'),
                'ssrf': ('Server-Side Request Forgery', 8.8, 'Internal network access and data exposure')
            },
            'high': {
                'xss': ('Cross-Site Scripting', 7.2, 'Session hijacking and user impersonation'),
                'nosql_injection': ('NoSQL Injection', 7.5, 'Database manipulation and data theft'),
                'ldap_injection': ('LDAP Injection', 7.3, 'Directory service compromise'),
                'path_traversal': ('Path Traversal', 7.1, 'Unauthorized file system access'),
                'auth_bypass': ('Authentication Bypass', 8.2, 'Unauthorized access to protected resources')
            },
            'medium': {
                'security_headers': ('Missing Security Headers', 5.4, 'Various client-side attacks possible'),
                'cors': ('CORS Misconfiguration', 5.8, 'Cross-origin data access'),
                'rate_limiting': ('Missing Rate Limiting', 5.2, 'Denial of service and abuse'),
                'error_handling': ('Information Disclosure', 4.3, 'System information leakage')
            }
        }
        
        # Process findings
        for vuln_type, vuln_data in api_findings.items():
            if vuln_type == 'https':
                if vuln_data:
                    passed_controls.append(('HTTPS Implementation', 'Transport encryption properly configured'))
                else:
                    critical_findings.append({
                        'type': 'https',
                        'name': 'Missing HTTPS',
                        'cvss': 7.4,
                        'description': 'API lacks transport encryption',
                        'impact': 'Data interception and man-in-the-middle attacks',
                        'url': api_url,
                        'payloads': []
                    })
            
            elif vuln_type == 'open_endpoints':
                if not vuln_data:
                    passed_controls.append(('Authentication Controls', 'All endpoints require proper authentication'))
                else:
                    for endpoint in vuln_data:
                        high_findings.append({
                            'type': 'open_endpoint',
                            'name': 'Unauthenticated Endpoint',
                            'cvss': 6.5,
                            'description': 'Endpoint accessible without authentication',
                            'impact': 'Unauthorized data access and potential abuse',
                            'url': endpoint,
                            'payloads': []
                        })
            
            elif vuln_type in ['sql_injection', 'xss', 'command_injection', 'xxe', 'nosql_injection', 
                               'ldap_injection', 'path_traversal'] and vuln_data:
                for vuln in vuln_data:
                    vuln_url = vuln.get('url', api_url)
                    payloads = vuln.get('payloads', [])
                    
                    # Determine severity
                    if vuln_type in vulnerability_matrix['critical']:
                        name, cvss, impact = vulnerability_matrix['critical'][vuln_type]
                        critical_findings.append({
                            'type': vuln_type,
                            'name': name,
                            'cvss': cvss,
                            'description': f'{name} vulnerability detected',
                            'impact': impact,
                            'url': vuln_url,
                            'payloads': payloads[:3]  # Limit to top 3 payloads
                        })
                    elif vuln_type in vulnerability_matrix['high']:
                        name, cvss, impact = vulnerability_matrix['high'][vuln_type]
                        high_findings.append({
                            'type': vuln_type,
                            'name': name,
                            'cvss': cvss,
                            'description': f'{name} vulnerability detected',
                            'impact': impact,
                            'url': vuln_url,
                            'payloads': payloads[:3]
                        })
            
            elif vuln_type in ['sql_injection', 'xss', 'command_injection', 'xxe', 'nosql_injection', 
                               'ldap_injection', 'path_traversal'] and not vuln_data:
                passed_controls.append((f'{vuln_type.replace("_", " ").title()} Protection', 
                                       f'No {vuln_type.replace("_", " ")} vulnerabilities detected'))
            
            elif vuln_type == 'security_headers':
                missing_headers = []
                present_headers = []
                
                # Handle string format from scanner
                if isinstance(vuln_data, str) and vuln_data.startswith('MISSING_SECURITY_HEADERS:'):
                    missing_headers_str = vuln_data.replace('MISSING_SECURITY_HEADERS: ', '')
                    missing_headers_list = [h.strip() for h in missing_headers_str.split(',')]
                    for header in missing_headers_list:
                        missing_headers.append((header, api_url))
                
                # Handle dictionary format
                elif isinstance(vuln_data, dict):
                    for url, headers in vuln_data.items():
                        for header, value in headers.items():
                            if value is None:
                                missing_headers.append((header, url))
                            else:
                                present_headers.append((header, value, url))
                
                # Group missing headers
                if missing_headers:
                    medium_findings.append({
                        'type': 'security_headers',
                        'name': 'Missing Security Headers',
                        'cvss': 5.4,
                        'description': f'{len(missing_headers)} security headers missing',
                        'impact': 'Various client-side attacks possible',
                        'url': api_url,
                        'payloads': [f'{h[0]} on {h[1]}' for h in missing_headers[:5]]
                    })
                
                # Record present headers as passed controls
                for header, value, url in present_headers:
                    passed_controls.append((f'{header} Header', f'Properly configured: {value}'))
        
        return critical_findings, high_findings, medium_findings, low_findings, passed_controls

    def generate_remediation_table(finding):
        """Generate professional remediation guidance"""
        remediation_map = {
            'sql_injection': {
                'immediate': 'Implement parameterized queries immediately',
                'short_term': 'Deploy input validation and WAF rules',
                'long_term': 'Conduct code review and security training'
            },
            'xss': {
                'immediate': 'Implement output encoding for all user input',
                'short_term': 'Deploy Content Security Policy (CSP)',
                'long_term': 'Regular security testing and developer training'
            },
            'command_injection': {
                'immediate': 'Remove or sanitize system command calls',
                'short_term': 'Implement input validation and command allowlists',
                'long_term': 'Replace system calls with safe APIs'
            },
            'security_headers': {
                'immediate': 'Configure missing security headers',
                'short_term': 'Implement comprehensive header policy',
                'long_term': 'Regular security header audits'
            }
        }
        
        return remediation_map.get(finding['type'], {
            'immediate': 'Address this vulnerability immediately',
            'short_term': 'Implement comprehensive security controls',
            'long_term': 'Regular security assessments'
        })

    # Generate the report
    critical_findings, high_findings, medium_findings, low_findings, passed_controls = categorize_findings_professional(findings, api_url)
    
    # Extract API findings for later use
    api_findings = findings.get('api', {})
    
    # Calculate professional security score
    total_critical = len(critical_findings)
    total_high = len(high_findings)
    total_medium = len(medium_findings)
    total_low = len(low_findings)
    total_issues = total_critical + total_high + total_medium + total_low
    
    # Professional scoring algorithm
    security_score = max(0, 100 - (total_critical * 40 + total_high * 20 + total_medium * 10 + total_low * 5))
    
    # Determine risk level
    if security_score >= 90:
        risk_level = "EXCELLENT"
        risk_color = "🟢"
    elif security_score >= 75:
        risk_level = "GOOD"
        risk_color = "🟡"
    elif security_score >= 50:
        risk_level = "MODERATE"
        risk_color = "🟠"
    else:
        risk_level = "HIGH RISK"
        risk_color = "🔴"
    # Handle new structure where vulnerabilities are nested
    if isinstance(api_findings, dict) and 'vulnerabilities' in api_findings:
        api_findings = api_findings['vulnerabilities']

    # Process API findings - handle both old format (by finding type) and new format (by severity)
    if isinstance(api_findings, dict) and any(key in api_findings for key in ['critical', 'high', 'medium', 'low']):
        # New format: findings organized by severity level
        passed = []  # Initialize passed controls list for new format
        
        for severity_level, findings_list in api_findings.items():
            for finding in findings_list:
                if isinstance(finding, str):
                    if finding.startswith('MISSING_SECURITY_HEADERS:'):
                        # Parse security headers finding
                        missing_headers_str = finding.replace('MISSING_SECURITY_HEADERS: ', '')
                        missing_headers = [h.strip() for h in missing_headers_str.split(',')]
                        
                        for header in missing_headers:
                            priority, timeline, risk, cvss = categorize_finding('security_header', header)
                            if severity_level == 'critical':
                                critical_findings.append(('security_headers', f"Missing security header: {header}", priority, timeline, risk, [header], api_url))
                            elif severity_level == 'high':
                                high_findings.append(('security_headers', f"Missing security header: {header}", priority, timeline, risk, [header], api_url))
                            elif severity_level == 'medium':
                                medium_findings.append(('security_headers', f"Missing security header: {header}", priority, timeline, risk, [header], api_url))
                            elif severity_level == 'low':
                                low_findings.append(('security_headers', f"Missing security header: {header}", priority, timeline, risk, [header], api_url))
                    
                    elif finding.startswith('METADATA_LEAKAGE:'):
                        # Parse metadata leakage finding
                        priority, timeline, risk, cvss = categorize_finding('metadata_leakage', finding)
                        if severity_level == 'critical':
                            critical_findings.append(('metadata_leakage', finding, priority, timeline, risk, [], api_url))
                        elif severity_level == 'high':
                            high_findings.append(('metadata_leakage', finding, priority, timeline, risk, [], api_url))
                        elif severity_level == 'medium':
                            medium_findings.append(('metadata_leakage', finding, priority, timeline, risk, [], api_url))
                        elif severity_level == 'low':
                            low_findings.append(('metadata_leakage', finding, priority, timeline, risk, [], api_url))
                    
                    else:
                        # Handle other finding types
                        priority, timeline, risk, cvss = categorize_finding('general', finding)
                        if severity_level == 'critical':
                            critical_findings.append(('general', finding, priority, timeline, risk, [], api_url))
                        elif severity_level == 'high':
                            high_findings.append(('general', finding, priority, timeline, risk, [], api_url))
                        elif severity_level == 'medium':
                            medium_findings.append(('general', finding, priority, timeline, risk, [], api_url))
                        elif severity_level == 'low':
                            low_findings.append(('general', finding, priority, timeline, risk, [], api_url))
    else:
        # Old format: findings organized by finding type
        # Initialize passed controls list for old format
        passed = []
        
        for finding_type, finding_data in api_findings.items():
            if finding_type == 'https' and finding_data:
                passed.append(("HTTPS enabled", "API uses HTTPS"))
            elif finding_type == 'https' and not finding_data:
                priority, timeline, risk, cvss = categorize_finding('https', finding_data)
                critical_findings.append((finding_type, f"API not using HTTPS", priority, timeline, risk, [], api_url))
        
            elif finding_type == 'open_endpoints' and not finding_data:
                passed.append(("All endpoints require authentication", "No open endpoints found"))
            elif finding_type == 'open_endpoints' and finding_data:
                for endpoint in finding_data:
                    priority, timeline, risk, cvss = categorize_finding('open_endpoint', endpoint)
                    high_findings.append((finding_type, f"Open endpoint: {endpoint}", priority, timeline, risk, [], endpoint))
        
            elif finding_type in ['sql_injection', 'xss', 'command_injection', 'xxe', 'nosql_injection', 'ldap_injection', 'path_traversal'] and finding_data:
                for vuln in finding_data:
                    url = vuln.get('url', api_url)
                    payloads = vuln.get('payloads', [])
                    priority, timeline, risk, cvss = categorize_finding(finding_type, vuln)
                    
                    if priority == 'Critical':
                        critical_findings.append((finding_type, f"{finding_type.replace('_', ' ').title()} on: {url} (Payloads: {len(payloads)})", priority, timeline, risk, payloads, url))
                    elif priority == 'High':
                        high_findings.append((finding_type, f"{finding_type.replace('_', ' ').title()} on: {url} (Payloads: {len(payloads)})", priority, timeline, risk, payloads, url))
        
            elif finding_type in ['sql_injection', 'xss', 'command_injection', 'xxe', 'nosql_injection', 'ldap_injection', 'path_traversal'] and not finding_data:
                passed.append((f"No {finding_type.replace('_', ' ')} vulnerabilities detected", f"All endpoints safe from {finding_type.replace('_', ' ')}"))
        
            elif finding_type == 'security_headers':
                # Handle security headers findings from scanner
                if isinstance(finding_data, str) and finding_data.startswith('MISSING_SECURITY_HEADERS:'):
                    # Parse the missing headers from the scanner format
                    missing_headers_str = finding_data.replace('MISSING_SECURITY_HEADERS: ', '')
                    missing_headers = [h.strip() for h in missing_headers_str.split(',')]
                    
                    for header in missing_headers:
                        priority, timeline, risk, cvss = categorize_finding('security_header', header)
                        medium_findings.append(('security_headers', f"Missing security header: {header}", priority, timeline, risk, [header], api_url))
                elif isinstance(finding_data, dict):
                    # Handle the expected format with header details
                    for url, headers in finding_data.items():
                        missing_headers = [h for h, v in headers.items() if v is None]
                        present_headers = [h for h, v in headers.items() if v is not None]
                        
                        for header in missing_headers:
                            priority, timeline, risk, cvss = categorize_finding('security_header', header)
                            medium_findings.append(('security_headers', f"Missing security header {header} on {url}", priority, timeline, risk, [header], url))
                        
                        for header in present_headers:
                            passed.append((f"{header} set on {url}", headers[header]))
        
            elif finding_type == 'metadata_leakage' and finding_data:
                # Handle metadata leakage findings
                if isinstance(finding_data, str):
                    priority, timeline, risk, cvss = categorize_finding('metadata_leakage', finding_data)
                    medium_findings.append(('metadata_leakage', finding_data, priority, timeline, risk, [], api_url))

    with open(report_path, 'w') as f:
        # Professional Report Header
        f.write("# API Security Assessment Report\n\n")
        f.write("**Prepared by:** CyberSec Bot - Automated Security Scanner  \n")
        f.write("**Assessment Date:** " + str(datetime.now().strftime('%Y-%m-%d %H:%M:%S')) + "  \n")
        f.write("**Assessment Level:** " + severity.upper() + " Security Analysis  \n\n")
        
        # Risk Assessment Matrix - moved to top for immediate visibility
        f.write("## 🎯 Executive Summary\n\n")
        f.write("| **Risk Level** | **Count** | **Timeline** | **Business Impact** |\n")
        f.write("|----------------|-----------|--------------|---------------------|\n")
        f.write(f"| 🔴 **Critical** | {total_critical} | **Immediate (0-24h)** | System compromise, data breach |\n")
        f.write(f"| 🟠 **High** | {total_high} | **Urgent (1-7 days)** | Unauthorized access, service disruption |\n")
        f.write(f"| 🟡 **Medium** | {total_medium} | **Planned (1-30 days)** | Limited exposure, compliance issues |\n")
        f.write(f"| ⚪ **Low** | {total_low} | **Scheduled (1-90 days)** | Minor improvements, best practices |\n\n")
        
        # Overall Security Score
        f.write(f"**Overall Security Score:** {risk_color} **{security_score}/100** ({risk_level})\n\n")
        
        # Critical Findings
        if critical_findings:
            f.write("## 🚨 Critical Vulnerabilities - Immediate Action Required\n\n")
            f.write("*These vulnerabilities pose immediate risks and require emergency remediation.*\n\n")
            
            for i, finding in enumerate(critical_findings, 1):
                # Convert tuple to dict format if needed
                finding_dict = tuple_to_dict_finding(finding)
                remediation = generate_remediation_table(finding_dict)
                f.write(f"### {i}. {finding_dict['name']} (CVSS: {finding_dict['cvss']})\n\n")
                
                # Vulnerability Details Table
                f.write("| **Attribute** | **Details** |\n")
                f.write("|---------------|-------------|\n")
                f.write(f"| **Vulnerability** | {finding_dict['name']} |\n")
                f.write(f"| **CVSS Score** | **{finding_dict['cvss']}** (Critical) |\n")
                f.write(f"| **Affected URL** | `{finding_dict['url']}` |\n")
                f.write(f"| **Business Impact** | {finding_dict['impact']} |\n")
                f.write(f"| **Exploitation Complexity** | Low - Can be automated |\n")
                f.write(f"| **Authentication Required** | None |\n\n")
                
                # Remediation Timeline
                f.write("**🛠️ Remediation Timeline:**\n\n")
                f.write("| **Phase** | **Action** | **Timeline** |\n")
                f.write("|-----------|------------|-------------|\n")
                f.write(f"| **Immediate** | {remediation['immediate']} | 0-24 hours |\n")
                f.write(f"| **Short-term** | {remediation['short_term']} | 1-7 days |\n")
                f.write(f"| **Long-term** | {remediation['long_term']} | 1-30 days |\n\n")
                
                if finding_dict['payloads']:
                    f.write("**🎯 Evidence (Sample Payloads):**\n")
                    for j, payload in enumerate(finding_dict['payloads'][:3], 1):
                        f.write(f"{j}. `{payload}`\n")
                    f.write("\n")
                
                f.write("---\n\n")
        else:
            f.write("## ✅ Critical Vulnerabilities - None Found\n\n")
            f.write("No critical vulnerabilities were identified in this assessment.\n\n")
        
        # High Priority Findings
        if high_findings:
            f.write("## ⚠️ High Priority Vulnerabilities\n\n")
            f.write("*Address within 7 days to maintain security posture.*\n\n")
            
            for i, finding in enumerate(high_findings, 1):
                # Convert tuple to dict format if needed
                finding_dict = tuple_to_dict_finding(finding)
                remediation = generate_remediation_table(finding_dict)
                f.write(f"### {i}. {finding_dict['name']} (CVSS: {finding_dict['cvss']})\n\n")
                
                f.write("| **Attribute** | **Details** |\n")
                f.write("|---------------|-------------|\n")
                f.write(f"| **Vulnerability** | {finding_dict['name']} |\n")
                f.write(f"| **CVSS Score** | **{finding_dict['cvss']}** (High) |\n")
                f.write(f"| **Affected URL** | `{finding_dict['url']}` |\n")
                f.write(f"| **Business Impact** | {finding_dict['impact']} |\n\n")
                
                f.write("**🛠️ Remediation Steps:**\n")
                f.write(f"- **Immediate:** {remediation['immediate']}\n")
                f.write(f"- **Short-term:** {remediation['short_term']}\n")
                f.write(f"- **Long-term:** {remediation['long_term']}\n\n")
                
                f.write("---\n\n")
        else:
            f.write("## ✅ High Priority Vulnerabilities - None Found\n\n")
            f.write("## 🔄 Dynamic Security Checks\n")
            f.write("No new dynamic checks found yet. The scraper runs every 15 minutes.\n\n")

        # --- Security Layer Analysis ---
        f.write("## 🛡️ Security Layer Analysis\n")
        
        # Check for security layers in findings
        security_layers = None
        if isinstance(findings.get('api'), dict) and 'security_layers' in findings['api']:
            security_layers = findings['api']['security_layers']
        elif isinstance(findings.get('api'), dict) and 'vulnerabilities' in findings['api']:
            # Handle new structure where vulnerabilities and security_layers are separate
            security_layers = findings['api'].get('security_layers')
        
        if security_layers:
            # Show blocked requests details
            blocked_requests = security_layers.get('blocked_requests', [])
            attack_blocks = security_layers.get('attack_blocks', {})
            
            if blocked_requests:
                f.write("**🎯 Attacks Blocked by Security Layers:**\n\n")
                
                # Group by security layer type
                layer_groups = {}
                for block in blocked_requests:
                    layer_type = block['layer_type']
                    if layer_type not in layer_groups:
                        layer_groups[layer_type] = []
                    layer_groups[layer_type].append(block)
                
                for layer_type, blocks in layer_groups.items():
                    confidence = int(blocks[0]['confidence'] * 100)
                    
                    # Check if this layer has partial protection info
                    partial_protection = False
                    block_rate = None
                    for layer in security_layers.get('security_layers', []):
                        if layer.get('type') == layer_type and layer.get('partial_protection'):
                            partial_protection = True
                            block_rate = layer.get('block_rate', 'Unknown')
                            break
                    
                    # Display layer header with partial protection info
                    if partial_protection:
                        f.write(f"### 🛡️ {layer_type.replace('_', ' ').title()} Protection ({confidence}% confidence) - ⚠️ Partial Protection ({block_rate} blocked)\n")
                        f.write(f"**Note:** This security layer blocks some attack patterns but allows others to pass through.\n\n")
                    else:
                        f.write(f"### 🛡️ {layer_type.replace('_', ' ').title()} Protection ({confidence}% confidence)\n")
                    
                    # Group by attack type
                    attack_groups = {}
                    for block in blocks:
                        attack_type = block.get('attack_type', 'unknown')
                        if attack_type not in attack_groups:
                            attack_groups[attack_type] = []
                        attack_groups[attack_type].append(block)
                    
                    for attack_type, attack_blocks in attack_groups.items():
                        f.write(f"\n**{attack_type.replace('_', ' ').title()} Attacks Blocked:**\n")
                        for block in attack_blocks:
                            payload_preview = block['payload'][:50] + "..." if len(block['payload']) > 50 else block['payload']
                            f.write(f"- `{payload_preview}`\n")
                            f.write(f"  - Reason: {block['block_reason']}\n")
                
                # Show summary statistics
                total_blocks = len(blocked_requests)
                unique_attacks = len(set(block.get('attack_type', 'unknown') for block in blocked_requests))
                unique_layers = len(set(block['layer_type'] for block in blocked_requests))
                
                f.write(f"\n**📈 Security Layer Summary:**\n")
                f.write(f"- Total attacks blocked: **{total_blocks}**\n")
                f.write(f"- Attack types protected: **{unique_attacks}**\n")
                f.write(f"- Security layers active: **{unique_layers}**\n")
                
            else:
                f.write("**🎯 Security Layer Testing Results:**\n\n")
                f.write("No security layer blocks were detected during testing.\n\n")
                
                # Simplified security layer results
                security_layer_results = [
                    ("🛡️ WAF Protection", security_layers.get('waf_detected', False)),
                    ("⏱️ Rate Limiting", security_layers.get('rate_limiting_detected', False)),
                    ("🔐 Auth Blocks", security_layers.get('auth_blocks_detected', False)),
                    ("🤖 CAPTCHA", security_layers.get('captcha_detected', False)),
                    ("🎯 Challenge Response", security_layers.get('challenge_detected', False))
                ]
                
                f.write("| Security Layer | Status |\n")
                f.write("|----------------|--------|\n")
                for layer_name, detected in security_layer_results:
                    status = "✅ Active" if detected else "❌ Not Detected"
                    f.write(f"| {layer_name} | {status} |\n")
                f.write("\n")
        else:
            f.write("Security layer detection was not enabled or no data available.\n")
        
        # Medium Priority Findings - moved up to main report
        if medium_findings:
            f.write("## 📋 Medium Priority Issues\n\n")
            f.write("*Address within 30 days for comprehensive security.*\n\n")
            
            for i, finding in enumerate(medium_findings, 1):
                # Convert tuple to dict format if needed
                finding_dict = tuple_to_dict_finding(finding)
                f.write(f"**{i}. {finding_dict['name']}** (CVSS: {finding_dict['cvss']})  \n")
                f.write(f"📍 **Location:** `{finding_dict['url']}`  \n")
                f.write(f"💼 **Impact:** {finding_dict['impact']}  \n")
                if finding_dict['payloads']:
                    f.write(f"📝 **Details:** {', '.join(finding_dict['payloads'][:3])}  \n")
                f.write("\n")
        else:
            f.write("## ✅ Medium Priority Issues - None Found\n\n")
        
        # --- Security Controls Working Well - combined section ---
        f.write("## ✅ Security Controls & Protections\n\n")
        
        security_items = []
        
        # Add security layer protections
        if security_layers:
            if security_layers.get('waf_detected'):
                security_items.append(("🛡️ WAF Protection", "Web Application Firewall is actively blocking malicious requests"))
            
            if security_layers.get('rate_limiting_detected'):
                security_items.append(("⏱️ Rate Limiting", "Rate limiting is protecting against brute force and DDoS attacks"))
            
            if security_layers.get('auth_blocks_detected'):
                security_items.append(("🔐 Authentication Blocks", "Authentication system is properly blocking unauthorized access"))
            
            if security_layers.get('captcha_detected'):
                security_items.append(("🤖 CAPTCHA Protection", "CAPTCHA system is protecting against automated attacks"))
            
            if security_layers.get('challenge_detected'):
                security_items.append(("🎯 Challenge Response", "Challenge-response system is protecting against automated attacks"))
        
        # Add passed controls
        if passed:
            for issue, detail in passed:
                security_items.append((issue, detail))
        
        if passed_controls:
            for control, detail in passed_controls:
                security_items.append((control, detail))
        
        if security_items:
            f.write("The following security measures are properly implemented:\n\n")
            f.write("| **Security Control** | **Status** |\n")
            f.write("|---------------------|------------|\n")
            for control, detail in security_items:
                f.write(f"| {control} | ✅ {detail} |\n")
            f.write("\n")
        else:
            f.write("No security controls are currently working properly.\n\n")
        
        # Professional Recommendations - simplified and moved to main report
        f.write("## 🔧 Recommendations\n\n")
        
        if total_critical > 0:
            f.write("### 🚨 Immediate Actions (0-24h)\n")
            f.write("- Address all critical vulnerabilities immediately\n")
            f.write("- Implement emergency monitoring for exploitation attempts\n\n")
        
        if total_high > 0:
            f.write("### ⚠️ Urgent Actions (1-7 days)\n")
            f.write("- Deploy fixes for high-priority vulnerabilities\n")
            f.write("- Conduct focused security testing\n\n")
        
        if total_medium > 0 or total_low > 0:
            f.write("### 📈 Planned Improvements (1-30 days)\n")
            f.write("- Address medium and low priority findings\n")
            f.write("- Implement regular security assessments\n\n")

        # --- Technical Details Section (Collapsed) ---
        f.write("\n---\n\n")
        f.write("## 📋 Technical Details\n\n")
        f.write("<details>\n<summary>Click to expand technical assessment details</summary>\n\n")
        
        # Testing command
        if curl_cmd:
            f.write("### Test Command\n")
            f.write(f"```bash\n{curl_cmd}\n```\n\n")
        
        # Test results summary
        f.write("### Test Results Summary\n\n")
        
        # Check HTTPS status from the new vulnerability structure
        https_enabled = True  # Default to True, set to False if HTTPS vulnerabilities found
        if isinstance(api_findings, dict):
            # Check critical vulnerabilities for HTTPS issues
            critical_vulns = api_findings.get('critical', [])
            for vuln in critical_vulns:
                if isinstance(vuln, str) and 'HTTPS_NOT_ENABLED' in vuln:
                    https_enabled = False
                    break
        
        test_results = [
            ('HTTPS Implementation', https_enabled),
            ('Authentication Controls', not bool(api_findings.get('open_endpoints', []))),
            ('SQL Injection Protection', not bool(api_findings.get('sql_injection', []))),
            ('XSS Protection', not bool(api_findings.get('xss', []))),
            ('Command Injection Protection', not bool(api_findings.get('command_injection', []))),
            ('Security Headers', bool(passed_controls))
        ]
        
        for test_name, passed in test_results:
            status = "✅ PASS" if passed else "❌ FAIL"
            f.write(f"- **{test_name}:** {status}\n")
        
        # Comprehensive check summary
        f.write("\n### Security Checks Executed\n\n")
        
        # Define all possible checks with descriptions
        all_checks = {
            'https_check': 'HTTPS Usage Verification',
            'open_endpoints': 'Open Endpoint Detection',
            'sql_injection': 'SQL Injection Testing',
            'command_injection': 'Command Injection Testing',
            'xxe': 'XML External Entity (XXE) Testing',
            'ssrf': 'Server-Side Request Forgery (SSRF) Testing',
            'auth_bypass': 'Authentication Bypass Testing',
            'double_spending': 'Double Spending Protection',
            'race_conditions': 'Race Condition Testing',
            'privilege_escalation': 'Privilege Escalation Testing',
            'bola_attacks': 'BOLA (Broken Object Level Authorization) Testing',
            'xss': 'Cross-Site Scripting (XSS) Testing',
            'path_traversal': 'Path Traversal Testing',
            'open_redirects': 'Open Redirect Testing',
            'security_headers': 'Security Headers Analysis',
            'cors_misconfig': 'CORS Misconfiguration Testing',
            'jwt_attacks': 'JWT Token Security Testing',
            'rate_limiting': 'Rate Limiting Analysis',
            'session_management': 'Session Management Testing',
            'transaction_manipulation': 'Transaction Manipulation Testing',
            'session_fixation': 'Session Fixation Testing',
            'kyc_bypass': 'KYC Bypass Testing',
            'loan_abuse': 'Loan Abuse Testing',
            'webhook_abuse': 'Webhook Abuse Testing',
            'idempotency_check': 'Idempotency Testing',
            'verbose_errors': 'Verbose Error Detection',
            'metadata_leakage': 'Metadata Leakage Detection',
            'discount_abuse': 'Discount Abuse Testing',
            'micro_transactions': 'Micro Transaction Testing'
        }
        
        # Get checks based on severity
        severity_checks = {
            'critical': ['https_check', 'open_endpoints', 'sql_injection', 'command_injection'],
            'high': ['https_check', 'open_endpoints', 'sql_injection', 'command_injection', 'xss', 'auth_bypass', 'jwt_attacks'],
            'medium': ['https_check', 'open_endpoints', 'sql_injection', 'command_injection', 'xss', 'auth_bypass', 'jwt_attacks', 'security_headers', 'cors_misconfig', 'rate_limiting', 'session_management'],
            'all': list(all_checks.keys())
        }
        
        checks_to_show = severity_checks.get(severity, severity_checks['all'])
        
        # Summary statistics
        total_checks = len(checks_to_show)
        f.write(f"**📊 Scan Statistics:**\n")
        f.write(f"- Total checks executed: **{total_checks}**\n")
        f.write(f"- Scan severity level: **{severity.upper()}**\n")
        
        # Show security layer testing
        if security_layers:
            f.write(f"- Security layer detection: **ENABLED**\n")
            if security_layers.get('blocked_requests'):
                f.write(f"- Security blocks detected: **{len(security_layers['blocked_requests'])}**\n")
            else:
                f.write(f"- Security blocks detected: **0**\n")
        else:
            f.write(f"- Security layer detection: **DISABLED**\n")

        # Scan errors
        if 'errors' in api_findings:
            f.write("\n### Scan Errors\n\n")
            for err in api_findings['errors']:
                f.write(f"- {err['endpoint']}: {err['error']}\n")
        
        f.write("\n</details>\n\n")
        
        # Report Footer
        f.write("---\n\n")
        f.write("**Report Generated:** " + str(datetime.now().strftime('%Y-%m-%d %H:%M:%S')) + "  \n")
        f.write("**Tool:** CyberSec Bot v2.0  \n")
        f.write("**Methodology:** OWASP API Security Top 10 + Custom Testing  \n\n")

    print(f"Report written to {report_path}") 
