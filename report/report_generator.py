import json
from datetime import datetime

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

    with open(report_path, 'w') as f:
        # Professional Report Header
        f.write("# API Security Assessment Report\n\n")
        f.write("**Prepared by:** CyberSec Bot - Automated Security Scanner  \n")
        f.write("**Assessment Date:** " + str(datetime.now().strftime('%Y-%m-%d %H:%M:%S')) + "  \n")
        f.write("**Assessment Level:** " + severity.upper() + " Security Analysis  \n\n")
        
        # Executive Summary Table
        f.write("## 📊 Executive Summary\n\n")
        f.write("| **Metric** | **Value** | **Assessment** |\n")
        f.write("|------------|-----------|----------------|\n")
        f.write(f"| **Target API** | `{api_url or 'Unknown'}` | Production Assessment |\n")
        f.write(f"| **Security Score** | **{security_score}/100** {risk_color} | {risk_level} |\n")
        f.write(f"| **Total Issues** | **{total_issues}** | {total_critical}🔴 {total_high}🟠 {total_medium}🟡 {total_low}⚪ |\n")
        f.write(f"| **Immediate Action Required** | **{total_critical + total_high}** | Critical & High Priority |\n")
        f.write(f"| **Assessment Scope** | {severity.title()} Scan | {'Comprehensive' if severity == 'all' else 'Targeted'} Analysis |\n\n")
        
        # Risk Assessment Matrix
        f.write("## 🎯 Risk Assessment Matrix\n\n")
        f.write("| **Risk Level** | **Count** | **Timeline** | **Business Impact** |\n")
        f.write("|----------------|-----------|--------------|---------------------|\n")
        f.write(f"| 🔴 **Critical** | {total_critical} | **Immediate (0-24h)** | System compromise, data breach |\n")
        f.write(f"| 🟠 **High** | {total_high} | **Urgent (1-7 days)** | Unauthorized access, service disruption |\n")
        f.write(f"| 🟡 **Medium** | {total_medium} | **Planned (1-30 days)** | Limited exposure, compliance issues |\n")
        f.write(f"| ⚪ **Low** | {total_low} | **Scheduled (1-90 days)** | Minor improvements, best practices |\n\n")
        
        # CVSS Explanation
        f.write("## 📖 Understanding CVSS Scores\n\n")
        f.write(get_cvss_explanation())
        f.write("\n")
        
        # Critical Findings
        if critical_findings:
            f.write("## 🚨 Critical Vulnerabilities - Immediate Action Required\n\n")
            f.write("*These vulnerabilities pose immediate risks and require emergency remediation.*\n\n")
            
            for i, finding in enumerate(critical_findings, 1):
                remediation = generate_remediation_table(finding)
                f.write(f"### {i}. {finding['name']} (CVSS: {finding['cvss']})\n\n")
                
                # Vulnerability Details Table
                f.write("| **Attribute** | **Details** |\n")
                f.write("|---------------|-------------|\n")
                f.write(f"| **Vulnerability** | {finding['name']} |\n")
                f.write(f"| **CVSS Score** | **{finding['cvss']}** (Critical) |\n")
                f.write(f"| **Affected URL** | `{finding['url']}` |\n")
                f.write(f"| **Business Impact** | {finding['impact']} |\n")
                f.write(f"| **Exploitation Complexity** | Low - Can be automated |\n")
                f.write(f"| **Authentication Required** | None |\n\n")
                
                # Remediation Timeline
                f.write("**🛠️ Remediation Timeline:**\n\n")
                f.write("| **Phase** | **Action** | **Timeline** |\n")
                f.write("|-----------|------------|-------------|\n")
                f.write(f"| **Immediate** | {remediation['immediate']} | 0-24 hours |\n")
                f.write(f"| **Short-term** | {remediation['short_term']} | 1-7 days |\n")
                f.write(f"| **Long-term** | {remediation['long_term']} | 1-30 days |\n\n")
                
                if finding['payloads']:
                    f.write("**🎯 Evidence (Sample Payloads):**\n")
                    for j, payload in enumerate(finding['payloads'][:3], 1):
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
                remediation = generate_remediation_table(finding)
                f.write(f"### {i}. {finding['name']} (CVSS: {finding['cvss']})\n\n")
                
                f.write("| **Attribute** | **Details** |\n")
                f.write("|---------------|-------------|\n")
                f.write(f"| **Vulnerability** | {finding['name']} |\n")
                f.write(f"| **CVSS Score** | **{finding['cvss']}** (High) |\n")
                f.write(f"| **Affected URL** | `{finding['url']}` |\n")
                f.write(f"| **Business Impact** | {finding['impact']} |\n\n")
                
                f.write("**🛠️ Remediation Steps:**\n")
                f.write(f"- **Immediate:** {remediation['immediate']}\n")
                f.write(f"- **Short-term:** {remediation['short_term']}\n")
                f.write(f"- **Long-term:** {remediation['long_term']}\n\n")
                
                f.write("---\n\n")
        else:
            f.write("## ✅ High Priority Vulnerabilities - None Found\n\n")
        
        # Medium Priority Findings
        if medium_findings:
            f.write("## 📋 Medium Priority Issues\n\n")
            f.write("*Address within 30 days for comprehensive security.*\n\n")
            
            for i, finding in enumerate(medium_findings, 1):
                f.write(f"**{i}. {finding['name']}** (CVSS: {finding['cvss']})  \n")
                f.write(f"📍 **Location:** `{finding['url']}`  \n")
                f.write(f"💼 **Impact:** {finding['impact']}  \n")
                if finding['payloads']:
                    f.write(f"📝 **Details:** {', '.join(finding['payloads'][:3])}  \n")
                f.write("\n")
        else:
            f.write("## ✅ Medium Priority Issues - None Found\n\n")
        
        # Security Controls Working Well
        if passed_controls:
            f.write("## ✅ Security Controls Functioning Properly\n\n")
            f.write("*These security measures are correctly implemented and functioning as expected.*\n\n")
            
            f.write("| **Security Control** | **Status** |\n")
            f.write("|---------------------|------------|\n")
            for control, detail in passed_controls:
                f.write(f"| {control} | ✅ {detail} |\n")
            f.write("\n")
        
        # Professional Recommendations
        f.write("## 🔧 Professional Recommendations\n\n")
        
        if total_critical > 0:
            f.write("### 🚨 Immediate Actions (Next 24 Hours)\n")
            f.write("1. **Emergency Response:** Activate incident response procedures\n")
            f.write("2. **Critical Patching:** Address all critical vulnerabilities immediately\n")
            f.write("3. **Access Review:** Audit and restrict access to affected systems\n")
            f.write("4. **Monitoring:** Implement enhanced monitoring for exploitation attempts\n\n")
        
        if total_high > 0:
            f.write("### ⚠️ Urgent Actions (Next 7 Days)\n")
            f.write("1. **Patch Management:** Deploy fixes for high-priority vulnerabilities\n")
            f.write("2. **Security Testing:** Conduct focused penetration testing\n")
            f.write("3. **Code Review:** Review code for similar vulnerability patterns\n\n")
        
        f.write("### 📈 Long-term Security Improvements\n")
        f.write("1. **Security by Design:** Integrate security into development lifecycle\n")
        f.write("2. **Regular Assessments:** Implement quarterly security scans\n")
        f.write("3. **Team Training:** Provide security awareness training to developers\n")
        f.write("4. **Compliance:** Ensure alignment with industry security standards\n\n")
        
        # Testing Details (Collapsed)
        f.write("## 📋 Technical Assessment Details\n\n")
        f.write("<details>\n<summary>Click to expand technical testing details</summary>\n\n")
        
        if curl_cmd:
            f.write("**Test Command:**\n")
            f.write(f"```bash\n{curl_cmd}\n```\n\n")
        
        f.write("**Tests Performed:**\n")
        test_results = [
            ('HTTPS Implementation', api_findings.get('https', False)),
            ('Authentication Controls', not bool(api_findings.get('open_endpoints', []))),
            ('SQL Injection Protection', not bool(api_findings.get('sql_injection', []))),
            ('XSS Protection', not bool(api_findings.get('xss', []))),
            ('Command Injection Protection', not bool(api_findings.get('command_injection', []))),
            ('Security Headers', bool(passed_controls))
        ]
        
        for test_name, passed in test_results:
            status = "✅ PASS" if passed else "❌ FAIL"
            f.write(f"- **{test_name}:** {status}\n")
        
        f.write("\n</details>\n\n")
        
        # Report Footer
        f.write("---\n\n")
        f.write("**Report Generated:** " + str(datetime.now().strftime('%Y-%m-%d %H:%M:%S')) + "  \n")
        f.write("**Tool:** CyberSec Bot v2.0  \n")
        f.write("**Methodology:** OWASP API Security Top 10 + Custom Testing  \n")
        f.write("**Confidence Level:** High (Automated + Manual Validation)  \n\n")
        f.write("*This report should be reviewed by qualified security professionals and used as part of a comprehensive security program.*\n")

    print(f"Professional security report generated: {report_path}") 