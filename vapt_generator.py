#!/usr/bin/env python3
"""
VAPT (Vulnerability Assessment and Penetration Testing) Data Generator

Generates realistic vulnerability findings with fake CVE data for testing purposes.
Each CVE is linked with its associated risk, name, description, solution, and VPR score.
Randomly creates findings across IP range 192.168.1.1-250.
All data is sanitized and does not contain any real sensitive information.

Usage:
    python3 vapt_generator.py <count> <output.csv>
    python3 vapt_generator.py 100 findings.csv
    python3 vapt_generator.py 500 large_scan.csv
"""

import csv
import sys
import random
from datetime import datetime
from typing import List, Dict

# Increase CSV field size limit
csv.field_size_limit(sys.maxsize)


class VAPTGenerator:
    """Generator for VAPT findings with fake CVE data (no sensitive information)"""

    def __init__(self, ip_range_start: int = 1, ip_range_end: int = 250):
        """
        Initialize the generator

        Args:
            ip_range_start: Start of IP range (default: 1 for 192.168.1.1)
            ip_range_end: End of IP range (default: 250 for 192.168.1.250)
        """
        self.ip_range_start = ip_range_start
        self.ip_range_end = ip_range_end
        self.cve_templates = []
        self.informational_templates = []

    def load_templates(self):
        """Generate fake CVE and informational templates"""
        # Fake CVE templates
        vulnerability_types = [
            ('Remote Code Execution', 'Critical', ['80', '443', '8080', '8443'], '9.8'),
            ('SQL Injection', 'Critical', ['80', '443', '3306', '5432'], '9.1'),
            ('Cross-Site Scripting (XSS)', 'High', ['80', '443', '8080'], '7.5'),
            ('Authentication Bypass', 'Critical', ['22', '23', '3389', '443'], '9.0'),
            ('Buffer Overflow', 'High', ['21', '22', '23', '80'], '8.4'),
            ('Directory Traversal', 'High', ['80', '443', '8080'], '7.8'),
            ('Command Injection', 'Critical', ['80', '443', '22'], '9.3'),
            ('Privilege Escalation', 'High', ['22', '3389', '445'], '8.1'),
            ('Information Disclosure', 'Medium', ['80', '443', '8080'], '5.3'),
            ('Cross-Site Request Forgery (CSRF)', 'Medium', ['80', '443'], '6.5'),
            ('XML External Entity (XXE)', 'High', ['80', '443', '8080'], '7.9'),
            ('Insecure Deserialization', 'Critical', ['80', '443', '8080'], '9.0'),
            ('Security Misconfiguration', 'Medium', ['80', '443', '22', '3389'], '5.8'),
            ('Broken Access Control', 'High', ['80', '443', '8080'], '7.4'),
            ('Sensitive Data Exposure', 'High', ['80', '443', '21', '22'], '7.7'),
            ('Missing Authentication', 'Critical', ['80', '443', '8080', '9200'], '9.1'),
            ('Weak Cryptography', 'Medium', ['443', '22', '3389'], '6.2'),
            ('Server-Side Request Forgery (SSRF)', 'High', ['80', '443', '8080'], '8.0'),
            ('Path Traversal', 'High', ['80', '443', '21'], '7.5'),
            ('Unsafe File Upload', 'Critical', ['80', '443', '8080'], '9.0'),
            ('Session Fixation', 'Medium', ['80', '443'], '6.8'),
            ('Clickjacking', 'Low', ['80', '443'], '4.3'),
            ('Open Redirect', 'Medium', ['80', '443'], '5.4'),
            ('Race Condition', 'Medium', ['80', '443', '22'], '6.1'),
            ('Denial of Service', 'High', ['80', '443', '22', '53'], '7.5'),
        ]

        # Generate 50 fake CVEs
        for i in range(50):
            vuln_type, risk, ports, vpr = random.choice(vulnerability_types)
            port = random.choice(ports)
            year = random.randint(2020, 2025)
            cve_num = random.randint(1000, 99999)
            cve = f"CVE-{year}-{cve_num}"

            self.cve_templates.append({
                'cve': cve,
                'risk': risk,
                'port': port,
                'name': f"{vuln_type} in Remote Service",
                'description': f"The remote service is affected by a {vuln_type.lower()} vulnerability. "
                              f"An attacker could exploit this to compromise the system. "
                              f"This vulnerability is identified as {cve}.",
                'solution': f"Update the affected service to the latest version. "
                           f"Apply vendor-supplied security patches. "
                           f"Review security configurations and implement access controls.",
                'plugin_output': '',  # Will be generated dynamically
                'vpr_score': vpr
            })

        # Fake informational templates
        info_findings = [
            ('Service Detection', ['80', '443', '22', '21', '25']),
            ('SSL Certificate Information', ['443', '8443']),
            ('Open Port Detection', ['80', '443', '22', '3389', '445']),
            ('OS Identification', ['0']),
            ('Network Device Type', ['0']),
            ('Traceroute Information', ['0']),
            ('Common Platform Enumeration (CPE)', ['0']),
            ('HTTP Server Headers', ['80', '443', '8080']),
            ('SSH Protocol Version', ['22']),
            ('DNS Server Detection', ['53']),
            ('SMTP Banner', ['25', '587']),
            ('FTP Banner', ['21']),
            ('Database Service Detection', ['3306', '5432', '1433', '27017']),
            ('Web Application Framework Detection', ['80', '443']),
            ('Load Balancer Detection', ['80', '443']),
        ]

        for name, ports in info_findings:
            for port in ports:
                self.informational_templates.append({
                    'cve': '',
                    'risk': 'None',
                    'port': port,
                    'name': name,
                    'description': f"This plugin provides information about {name.lower()} on the remote host.",
                    'solution': 'No action required. This is an informational finding.',
                    'plugin_output': '',  # Will be generated dynamically
                    'vpr_score': ''
                })

    def generate_ip(self) -> str:
        """Generate random IP in range 192.168.1.1-250"""
        last_octet = random.randint(self.ip_range_start, self.ip_range_end)
        return f"192.168.1.{last_octet}"

    def generate_plugin_output(self, template: Dict, host: str) -> str:
        """
        Generate realistic but sanitized plugin output without sensitive data

        Args:
            template: CVE or info template
            host: Target host IP

        Returns:
            Plugin output string
        """
        port = template['port']

        # Generic product names instead of real sensitive ones
        products = ['WebServer', 'AppEngine', 'DataStore', 'AuthService',
                   'APIGateway', 'CacheServer', 'FileService', 'MailServer',
                   'LoadBalancer', 'ProxyServer', 'DNSService', 'MessageQueue',
                   'SearchEngine', 'MonitorService', 'BackupService', 'LogServer',
                   'DatabaseServer', 'ApplicationServer', 'ContentManager', 'MediaServer',
                   'StreamService', 'AnalyticsEngine', 'ReportingService', 'WorkflowEngine',
                   'IntegrationHub', 'NotificationService', 'SchedulerService', 'ConfigManager',
                   'IdentityProvider', 'VaultService']

        product = random.choice(products)

        # Generic plugin IDs
        plugin_id = random.randint(10000, 99999)

        # Additional fake metadata
        scan_engines = ['NessusScanner', 'QualysVM', 'OpenVAS', 'Nexpose', 'Acunetix',
                       'Burp Suite', 'OWASP ZAP', 'Nikto', 'Nmap NSE', 'Metasploit']
        scan_engine = random.choice(scan_engines)

        # Fake scan profiles
        scan_profiles = ['Full_Scan', 'Quick_Scan', 'Deep_Inspection', 'Compliance_Check',
                        'Network_Discovery', 'Web_Application_Scan', 'Database_Audit',
                        'Credential_Scan', 'Config_Review', 'Baseline_Assessment']
        scan_profile = random.choice(scan_profiles)

        # Fake scanner hostnames
        scanner_hosts = ['scanner01.corp.local', 'scanner02.corp.local', 'vuln-scanner-prod.local',
                        'security-scan.internal', 'assessment-tool.local', 'pentest-box.local']
        scanner_host = random.choice(scanner_hosts)

        # Fake certificates/hashes for SSL findings
        cert_fingerprints = [
            'A1:B2:C3:D4:E5:F6:01:02:03:04:05:06:07:08:09:10:11:12:13:14',
            '5A:6B:7C:8D:9E:0F:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE',
            'FF:EE:DD:CC:BB:AA:99:88:77:66:55:44:33:22:11:00:AB:CD:EF:12'
        ]

        # Fake vulnerable paths for web findings
        web_paths = ['/admin', '/login', '/api/v1', '/uploads', '/backup', '/config',
                    '/dashboard', '/portal', '/app', '/system']

        # Fake usernames for credential-related findings
        fake_users = ['admin', 'root', 'user', 'guest', 'operator', 'service_account',
                     'webapp_user', 'db_admin', 'app_service', 'test_user']

        if template['cve']:
            # CVE-based vulnerability - generate realistic output
            versions = ['2.4.1', '3.2.0', '1.8.5', '4.1.2', '5.0.1', '2.7.3',
                       '4.5.2', '1.9.8', '3.3.1', '5.1.0', '2.8.4', '6.0.1']
            version = random.choice(versions)

            # Add more details based on port/service type
            additional_info = ""
            if port in ['80', '443', '8080', '8443']:
                path = random.choice(web_paths)
                additional_info = f"\nVulnerable Path: {path}\nHTTP Method: GET"
            elif port in ['22', '23']:
                additional_info = f"\nProtocol: SSH\nAuthentication: Password"
            elif port in ['3306', '5432', '1433']:
                user = random.choice(fake_users)
                additional_info = f"\nDatabase User: {user}\nAccess Level: Read/Write"

            return (f"Plugin Output:\n"
                   f"Plugin ID: {plugin_id}\n"
                   f"Scanner: {scan_engine}\n"
                   f"Scan Profile: {scan_profile}\n"
                   f"Scanner Host: {scanner_host}\n"
                   f"Product: {product} {version}\n"
                   f"The remote service on {host}:{port} is affected by {template['cve']}\n"
                   f"Version detected: {version}{additional_info}\n"
                   f"Scan timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                   f"Recommendation: Apply security patches immediately")
        else:
            # Informational finding - generic service info
            services = ['HTTP', 'HTTPS', 'SSH', 'FTP', 'SMTP', 'MySQL', 'PostgreSQL', 'Redis',
                       'MongoDB', 'Elasticsearch', 'RabbitMQ', 'Kafka', 'Memcached', 'LDAP',
                       'DNS', 'SNMP', 'Telnet', 'RDP', 'VNC', 'SMB']
            service = random.choice(services)

            # Add SSL certificate info for HTTPS services
            ssl_info = ""
            if port in ['443', '8443'] or service == 'HTTPS':
                cert_fp = random.choice(cert_fingerprints)
                ssl_info = f"\nSSL Certificate Fingerprint: {cert_fp}\nCipher Suite: TLS_AES_256_GCM_SHA384"

            return (f"Plugin Output:\n"
                   f"Plugin ID: {plugin_id}\n"
                   f"Scanner: {scan_engine}\n"
                   f"Scan Profile: {scan_profile}\n"
                   f"Scanner Host: {scanner_host}\n"
                   f"Product: {product}\n"
                   f"Service detected on {host}:{port}\n"
                   f"Type: {service}\n"
                   f"Status: Active{ssl_info}\n"
                   f"Scan timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    def generate_finding(self, template: Dict) -> Dict:
        """
        Generate a finding based on template

        Args:
            template: CVE or informational template

        Returns:
            Dictionary with finding data
        """
        host = self.generate_ip()

        return {
            'CVE': template['cve'],
            'Risk': template['risk'],
            'Host': host,
            'Port': template['port'],
            'Name': template['name'],
            'Description': template['description'],
            'Solution': template['solution'],
            'Plugin Output': self.generate_plugin_output(template, host),
            'VPR Score': template['vpr_score']
        }

    def generate_findings(self, count: int, vuln_ratio: float = 0.3) -> List[Dict]:
        """
        Generate multiple findings

        Args:
            count: Number of findings to generate
            vuln_ratio: Ratio of vulnerabilities (CVE) to informational findings (0.0-1.0)

        Returns:
            List of findings
        """
        if not self.cve_templates:
            raise ValueError("No templates loaded. Call load_templates() first.")

        findings = []
        vuln_count = int(count * vuln_ratio)
        info_count = count - vuln_count

        # Generate vulnerabilities
        for _ in range(vuln_count):
            template = random.choice(self.cve_templates)
            findings.append(self.generate_finding(template))

        # Generate informational findings
        if self.informational_templates:
            for _ in range(info_count):
                template = random.choice(self.informational_templates)
                findings.append(self.generate_finding(template))

        # Shuffle to mix vulnerabilities and info
        random.shuffle(findings)

        return findings

    def write_csv(self, findings: List[Dict], output_file: str):
        """
        Write findings to CSV file

        Args:
            findings: List of findings
            output_file: Output CSV file path
        """
        fieldnames = ['CVE', 'Risk', 'Host', 'Port', 'Name', 'Description',
                      'Solution', 'Plugin Output', 'VPR Score']

        with open(output_file, 'w', encoding='utf-8', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(findings)

    def print_statistics(self, findings: List[Dict]):
        """Print statistics about generated findings"""
        stats = {
            'total': len(findings),
            'by_risk': {},
            'unique_hosts': set(),
            'unique_cves': set(),
        }

        for finding in findings:
            risk = finding['Risk']
            stats['by_risk'][risk] = stats['by_risk'].get(risk, 0) + 1
            stats['unique_hosts'].add(finding['Host'])
            if finding['CVE']:
                stats['unique_cves'].add(finding['CVE'])

        print(f"\n✓ Generated {stats['total']} findings")
        print(f"  - {len(stats['unique_cves'])} unique CVEs")
        print(f"  - {len(stats['unique_hosts'])} unique hosts")
        print(f"  - Critical: {stats['by_risk'].get('Critical', 0)}, High: {stats['by_risk'].get('High', 0)}, Medium: {stats['by_risk'].get('Medium', 0)}, Low: {stats['by_risk'].get('Low', 0)}, Info: {stats['by_risk'].get('None', 0)}")


def print_usage():
    """Print usage information"""
    print("VAPT Data Generator")
    print()
    print("Usage:")
    print("  python3 vapt_generator.py <count> <output.csv>")
    print()
    print("Examples:")
    print("  python3 vapt_generator.py 100 findings.csv")
    print("  python3 vapt_generator.py 500 large_scan.csv")
    print("  python3 vapt_generator.py 1000 enterprise.csv")
    print()
    print("Arguments:")
    print("  count       Number of findings to generate (e.g., 100, 500, 1000)")
    print("  output.csv  Output CSV file path")
    print()
    print("Features:")
    print("  - Generates findings with fake CVE data (no real sensitive data)")
    print("  - Random IPs in range 192.168.1.1-250")
    print("  - ~30% vulnerabilities, ~70% informational")
    print("  - Realistic vulnerability types and descriptions")
    print("  - Sanitized plugin output with generic product names")


def main():
    """Main entry point"""
    # Check arguments
    if len(sys.argv) != 3:
        print_usage()
        sys.exit(1)

    # Parse arguments
    try:
        count = int(sys.argv[1])
        output_file = sys.argv[2]
    except ValueError:
        print("Error: First argument must be a number")
        print()
        print_usage()
        sys.exit(1)

    # Validate count
    if count <= 0:
        print("Error: Count must be positive")
        sys.exit(1)

    # Validate output file
    if not output_file.endswith('.csv'):
        print("Error: Output file must end with .csv")
        sys.exit(1)

    # Generate findings
    print(f"Generating {count} VAPT findings...")

    try:
        generator = VAPTGenerator()
        generator.load_templates()

        findings = generator.generate_findings(count, vuln_ratio=0.3)
        generator.write_csv(findings, output_file)
        generator.print_statistics(findings)

        print(f"✓ Saved to: {output_file}")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
