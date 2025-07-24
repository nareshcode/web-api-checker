import argparse
import sys
from scraper import api_scanner
from simulator import attack_simulator
from report import report_generator
from scraper import daily_attack_scraper
from scraper import db_scanner
from scraper import dynamic_check_scraper
from utils.curl_parser import parse_curl_command
import json
import os

def show_scanner_updates():
    """Display recent scanner updates"""
    try:
        with open('scraper/scanner_updates.json', 'r') as f:
            updates = json.load(f)
        
        print("\n🔄 Recent Scanner Updates:")
        print(f"  Last Update: {updates.get('timestamp', 'Unknown')}")
        print(f"  New Payloads Added: {updates.get('new_payloads_count', 0)}")
        print(f"  New Attack Types: {len(updates.get('new_attack_types', []))}")
        print(f"  Total New Checks: {updates.get('total_new_checks', 0)}")
        print(f"  Backup File: {updates.get('backup_file', 'None')}")
        
        if updates.get('new_attack_types'):
            print(f"  New Attack Types Added: {', '.join(updates['new_attack_types'])}")
        
    except FileNotFoundError:
        print("\n❌ No scanner updates found yet.")
    except Exception as e:
        print(f"\n❌ Error reading updates: {e}")

def main():
    parser = argparse.ArgumentParser(description="CyberSec Bot: API & DB Vulnerability Scanner and Attack Simulator")
    parser.add_argument('target', nargs='?', type=str, help='Target: either a URL or a full curl command')
    parser.add_argument('--db-uri', type=str, help='Database connection URI (e.g., sqlite:///test.db)')
    parser.add_argument('--report', type=str, default='report/output.md', help='Path to save the report')
    parser.add_argument('--simulate', action='store_true', help='Simulate attacks after scanning')
    parser.add_argument('--daily', action='store_true', help='Run daily scraping for new attacks')
    parser.add_argument('--dynamic-checks', action='store_true', help='Enable background scraping for new security checks every 15 minutes')
    parser.add_argument('--update-scanner', action='store_true', help='Update scanner with latest intelligence from web scraping')
    parser.add_argument('--show-updates', action='store_true', help='Show recent scanner updates')
    parser.add_argument('--severity', type=str, choices=['critical', 'high', 'medium', 'all'], default='all', 
                       help='Severity level of checks to run: critical (fastest), high, medium, or all (most comprehensive)')
    args = parser.parse_args()

    # Handle special commands
    if args.show_updates:
        show_scanner_updates()
        return
    
    if args.update_scanner:
        print("[+] Manually updating scanner with latest intelligence...")
        success = dynamic_check_scraper.update_scanner_now()
        if success:
            print("✅ Scanner updated successfully!")
        else:
            print("❌ Scanner update failed!")
        return
    
    # Require target for scanning
    if not args.target:
        print("❌ Error: Please provide a target URL or curl command")
        print("Usage: python3 main.py <target> [options]")
        print("   or: python3 main.py --update-scanner")
        print("   or: python3 main.py --show-updates")
        print("\nSeverity Levels:")
        print("  --severity critical  : Only critical vulnerabilities (SQL injection, Command injection, etc.) - ~5 min")
        print("  --severity high      : Critical + High priority checks (XSS, Auth bypass, etc.) - ~10 min") 
        print("  --severity medium    : High + Medium priority checks (CORS, Headers, etc.) - ~15 min")
        print("  --severity all       : All security checks including informational - ~20 min")
        return

    findings = {}

    # Display severity info
    severity_info = {
        'critical': '🔴 Running CRITICAL checks only (~5 min) - SQL injection, Command injection, RCE',
        'high': '🟠 Running CRITICAL + HIGH checks (~10 min) - Adding XSS, Auth bypass, JWT attacks', 
        'medium': '🟡 Running CRITICAL + HIGH + MEDIUM checks (~15 min) - Adding CORS, Headers, Rate limiting',
        'all': '🔵 Running ALL security checks (~20 min) - Comprehensive security assessment'
    }
    print(f"\n{severity_info[args.severity]}")

    # Start dynamic check scraping if enabled
    if args.dynamic_checks:
        print("[+] Starting dynamic security check scraper...")
        dynamic_check_scraper.start_scraping()

    # Detect if input is a curl command or a URL
    target = args.target.strip()
    if target.lower().startswith('curl'):
        curl_cmd = target
        curl_info = parse_curl_command(curl_cmd)
        api_url = curl_info['url']
    else:
        api_url = target
        curl_cmd = None
        curl_info = {'url': api_url, 'method': 'GET', 'headers': {}, 'data': None}

    if api_url:
        print(f"[+] Scanning API at {api_url}...")
        api_results = api_scanner.scan_api(api_url, curl_info=curl_info, severity=args.severity)
        
        # Handle new structure with security layers
        if isinstance(api_results, dict) and 'vulnerabilities' in api_results:
            findings['api'] = api_results
        else:
            # Handle old structure (backward compatibility)
            findings['api'] = {'vulnerabilities': api_results, 'security_layers': None}
    else:
        print("[!] No valid URL found. Skipping API scan.")

    # 2. Database Vulnerability Scanning
    if args.db_uri:
        print(f"[+] Scanning Database at {args.db_uri}...")
        findings['db'] = db_scanner.scan_db(args.db_uri)
    else:
        print("[!] No DB URI provided. Skipping DB scan.")

    # 3. Simulate Attacks
    if args.simulate:
        print("[+] Simulating attacks...")
        findings['simulation'] = attack_simulator.simulate(findings)
    else:
        print("[!] Skipping attack simulation.")

    # 4. Daily Scraping for New Attacks
    if args.daily:
        print("[+] Scraping for new attack vectors...")
        new_attacks = daily_attack_scraper.scrape_new_attacks()
        print(f"[+] Simulating new attacks: {new_attacks}")
        findings['new_attack_simulation'] = attack_simulator.simulate_new_attacks(new_attacks, api_url, args.db_uri)
    else:
        print("[!] Skipping daily scraping.")

    # 5. Check for new dynamic security checks
    if args.dynamic_checks:
        new_checks = dynamic_check_scraper.get_latest_checks()
        if new_checks:
            print(f"[+] Found {len(new_checks)} new dynamic security checks")
            findings['dynamic_checks'] = new_checks
        else:
            print("[!] No new dynamic checks found yet")

    # 6. Generate Report
    print(f"[+] Generating report at {args.report}...")
    report_generator.generate_report(findings, args.report, api_url=api_url, curl_cmd=curl_cmd, curl_info=curl_info, severity=args.severity)
    print("[+] Done!")
    
    # Show update info if available
    if os.path.exists('scraper/scanner_updates.json'):
        print("\n💡 Tip: Your scanner has been auto-updated with new intelligence!")
        print("   Run 'python3 main.py --show-updates' to see what's new")

if __name__ == "__main__":
    main()
