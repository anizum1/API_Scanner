#!/usr/bin/env python3
"""
AAPIPII - Advanced API Discovery and Security Scanner
For authorized security testing only - requires written permission
"""

import sys
import json
import re
import argparse
from urllib.parse import urljoin, urlparse
from datetime import datetime

# Try to import optional dependencies with fallbacks
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("[-] Warning: 'requests' module not found. Install with: pip3 install requests")

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False
    print("[-] Warning: 'beautifulsoup4' module not found. Install with: pip3 install beautifulsoup4")

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib import colors
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    print("[-] Warning: 'reportlab' module not found. Install with: pip3 install reportlab")

# ANSI color codes for terminal
class Colors:
    YELLOW = '\033[93m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_banner():
    """Print ASCII art banner for AAPIPII"""
    banner = f"""
{Colors.YELLOW}{Colors.BOLD}
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║      █████╗  █████╗ ██████╗ ██╗██████╗ ██╗██╗          ║
    ║     ██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗██║██║          ║
    ║     ███████║███████║██████╔╝██║██████╔╝██║██║          ║
    ║     ██╔══██║██╔══██║██╔═══╝ ██║██╔═══╝ ██║██║          ║
    ║     ██║  ██║██║  ██║██║     ██║██║     ██║██║          ║
    ║     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝     ╚═╝╚═╝          ║
    ║                                                           ║
    ║         Advanced API Discovery & Security Scanner        ║
    ║                    Version 2.0                            ║
    ╚═══════════════════════════════════════════════════════════╝
{Colors.RESET}
    {Colors.CYAN}[*] For Authorized Security Testing Only{Colors.RESET}
    {Colors.RED}[!] Requires Written Permission{Colors.RESET}
"""
    print(banner)

class APIScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.discovered_endpoints = set()
        self.vulnerabilities = []
        
        if REQUESTS_AVAILABLE:
            self.session = requests.Session()
            self.session.headers.update({
                'User-Agent': 'AAPIPII-Scanner/2.0 (Authorized Testing)'
            })
        else:
            self.session = None
    
    def discover_endpoints(self):
        """Discover API endpoints through various methods"""
        if not REQUESTS_AVAILABLE:
            print(f"{Colors.RED}[-] Cannot scan: 'requests' module not installed{Colors.RESET}")
            return self.discovered_endpoints
        
        print(f"{Colors.CYAN}[*] Scanning {self.target_url} for API endpoints...{Colors.RESET}")
        
        # Method 1: Check common API paths
        self._check_common_paths()
        
        # Method 2: Parse JavaScript files for endpoints
        if BS4_AVAILABLE:
            self._parse_javascript()
        else:
            print(f"{Colors.YELLOW}[-] Skipping JavaScript parsing (beautifulsoup4 not installed){Colors.RESET}")
        
        # Method 3: Check robots.txt and sitemap
        self._check_meta_files()
        
        return self.discovered_endpoints
    
    def _check_common_paths(self):
        """Check common API endpoint patterns"""
        common_paths = [
            '/api/', '/api/v1/', '/api/v2/', '/api/v3/', '/rest/', '/graphql',
            '/swagger.json', '/openapi.json', '/api-docs', '/docs',
            '/api/swagger', '/api/docs', '/.well-known/api',
            '/v1/', '/v2/', '/v3/', '/api/users', '/api/auth',
            '/api/login', '/api/admin', '/api/config'
        ]
        
        for path in common_paths:
            url = urljoin(self.target_url, path)
            try:
                resp = self.session.get(url, timeout=5, verify=False, allow_redirects=False)
                if resp.status_code in [200, 301, 302, 401, 403]:
                    self.discovered_endpoints.add(url)
                    print(f"{Colors.GREEN}[+] Found: {url} (Status: {resp.status_code}){Colors.RESET}")
            except requests.RequestException as e:
                pass
    
    def _parse_javascript(self):
        """Extract API endpoints from JavaScript files"""
        try:
            resp = self.session.get(self.target_url, timeout=10, verify=False)
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            # Find all script tags
            for script in soup.find_all('script', src=True):
                js_url = urljoin(self.target_url, script['src'])
                try:
                    js_resp = self.session.get(js_url, timeout=5, verify=False)
                    # Look for API endpoint patterns
                    endpoints = re.findall(r'["\']/(api|rest|v\d)/[^"\']*["\']', js_resp.text)
                    for ep in endpoints:
                        clean_ep = ep.strip('"\'')
                        full_url = urljoin(self.target_url, clean_ep)
                        self.discovered_endpoints.add(full_url)
                        print(f"{Colors.GREEN}[+] Found in JS: {full_url}{Colors.RESET}")
                except requests.RequestException:
                    pass
        except requests.RequestException:
            print(f"{Colors.YELLOW}[-] Could not fetch main page{Colors.RESET}")
    
    def _check_meta_files(self):
        """Check robots.txt and sitemap for endpoints"""
        for path in ['/robots.txt', '/sitemap.xml']:
            url = urljoin(self.target_url, path)
            try:
                resp = self.session.get(url, timeout=5, verify=False)
                if resp.status_code == 200:
                    # Extract paths
                    paths = re.findall(r'/(api|rest|v\d)/[^\s<>"\']*', resp.text)
                    for p in paths:
                        full_url = urljoin(self.target_url, p)
                        self.discovered_endpoints.add(full_url)
                        print(f"{Colors.GREEN}[+] Found in {path}: {full_url}{Colors.RESET}")
            except requests.RequestException:
                pass
    
    def check_vulnerabilities(self):
        """Check for common API vulnerabilities"""
        if not REQUESTS_AVAILABLE:
            return self.vulnerabilities
        
        print(f"\n{Colors.CYAN}[*] Checking for vulnerabilities...{Colors.RESET}")
        
        for endpoint in self.discovered_endpoints:
            # Check for missing authentication
            self._check_auth(endpoint)
            
            # Check for information disclosure
            self._check_info_disclosure(endpoint)
            
            # Check HTTP methods
            self._check_http_methods(endpoint)
        
        return self.vulnerabilities
    
    def _check_auth(self, url):
        """Check if endpoint requires authentication"""
        try:
            resp = self.session.get(url, timeout=5, verify=False)
            if resp.status_code == 200:
                self.vulnerabilities.append({
                    'type': 'Potential Missing Authentication',
                    'severity': 'High',
                    'url': url,
                    'description': 'Endpoint accessible without authentication'
                })
        except requests.RequestException:
            pass
    
    def _check_info_disclosure(self, url):
        """Check for sensitive information disclosure"""
        try:
            resp = self.session.get(url, timeout=5, verify=False)
            sensitive_patterns = [
                r'password', r'api[_-]?key', r'secret', r'token',
                r'aws[_-]?access', r'private[_-]?key', r'credential'
            ]
            
            for pattern in sensitive_patterns:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    self.vulnerabilities.append({
                        'type': 'Potential Information Disclosure',
                        'severity': 'Medium',
                        'url': url,
                        'description': f'Sensitive pattern detected: {pattern}'
                    })
                    break
        except requests.RequestException:
            pass
    
    def _check_http_methods(self, url):
        """Check allowed HTTP methods"""
        try:
            resp = self.session.options(url, timeout=5, verify=False)
            if 'Allow' in resp.headers:
                methods = resp.headers['Allow']
                dangerous = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
                for method in dangerous:
                    if method in methods:
                        self.vulnerabilities.append({
                            'type': 'Dangerous HTTP Method Allowed',
                            'severity': 'Medium',
                            'url': url,
                            'description': f'Method {method} is allowed'
                        })
        except requests.RequestException:
            pass
    
    def generate_report(self):
        """Generate security assessment report"""
        print("\n" + Colors.YELLOW + "="*70)
        print("                    SECURITY ASSESSMENT REPORT")
        print("="*70 + Colors.RESET)
        
        print(f"\n{Colors.CYAN}Target:{Colors.RESET} {self.target_url}")
        print(f"{Colors.CYAN}Endpoints Discovered:{Colors.RESET} {len(self.discovered_endpoints)}")
        print(f"{Colors.CYAN}Potential Issues Found:{Colors.RESET} {len(self.vulnerabilities)}")
        
        print(f"\n{Colors.BOLD}--- Discovered Endpoints ---{Colors.RESET}")
        for ep in sorted(self.discovered_endpoints):
            print(f"  {Colors.GREEN}•{Colors.RESET} {ep}")
        
        print(f"\n{Colors.BOLD}--- Potential Vulnerabilities ---{Colors.RESET}")
        if self.vulnerabilities:
            for vuln in self.vulnerabilities:
                severity_color = Colors.RED if vuln['severity'] == 'High' else Colors.YELLOW
                print(f"\n{severity_color}[{vuln['severity']}]{Colors.RESET} {vuln['type']}")
                print(f"  {Colors.CYAN}URL:{Colors.RESET} {vuln['url']}")
                print(f"  {Colors.CYAN}Description:{Colors.RESET} {vuln['description']}")
        else:
            print(f"{Colors.GREEN}No vulnerabilities detected.{Colors.RESET}")
        
        print("\n" + Colors.YELLOW + "="*70 + Colors.RESET)
    
    def save_txt_report(self, filename):
        """Save report as TXT file"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("="*70 + "\n")
                f.write("AAPIPII - API SECURITY ASSESSMENT REPORT\n")
                f.write("="*70 + "\n\n")
                
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Target: {self.target_url}\n")
                f.write(f"Endpoints Discovered: {len(self.discovered_endpoints)}\n")
                f.write(f"Potential Issues Found: {len(self.vulnerabilities)}\n\n")
                
                f.write("-" * 70 + "\n")
                f.write("DISCOVERED ENDPOINTS\n")
                f.write("-" * 70 + "\n")
                for ep in sorted(self.discovered_endpoints):
                    f.write(f"  • {ep}\n")
                
                f.write("\n" + "-" * 70 + "\n")
                f.write("POTENTIAL VULNERABILITIES\n")
                f.write("-" * 70 + "\n\n")
                
                if self.vulnerabilities:
                    for i, vuln in enumerate(self.vulnerabilities, 1):
                        f.write(f"{i}. [{vuln['severity']}] {vuln['type']}\n")
                        f.write(f"   URL: {vuln['url']}\n")
                        f.write(f"   Description: {vuln['description']}\n\n")
                else:
                    f.write("No vulnerabilities detected.\n\n")
                
                f.write("="*70 + "\n")
                f.write("NOTE: This is an automated scan. Manual verification is recommended.\n")
                f.write("="*70 + "\n")
            
            print(f"{Colors.GREEN}[+] TXT report saved to {filename}{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[-] Error saving TXT report: {e}{Colors.RESET}")
    
    def save_pdf_report(self, filename):
        """Save report as PDF file"""
        if not REPORTLAB_AVAILABLE:
            print(f"{Colors.RED}[-] Cannot generate PDF: 'reportlab' module not installed{Colors.RESET}")
            print(f"{Colors.YELLOW}[*] Install with: pip3 install reportlab{Colors.RESET}")
            return
        
        try:
            doc = SimpleDocTemplate(filename, pagesize=letter)
            story = []
            styles = getSampleStyleSheet()
            
            # Custom styles
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#FFD700'),
                spaceAfter=30,
                alignment=1
            )
            
            heading_style = ParagraphStyle(
                'CustomHeading',
                parent=styles['Heading2'],
                fontSize=16,
                textColor=colors.HexColor('#34495E'),
                spaceAfter=12,
                spaceBefore=12
            )
            
            # Title
            story.append(Paragraph("AAPIPII Security Assessment Report", title_style))
            story.append(Spacer(1, 0.2*inch))
            
            # Summary Information
            summary_data = [
                ['Report Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
                ['Target URL:', self.target_url],
                ['Endpoints Discovered:', str(len(self.discovered_endpoints))],
                ['Potential Issues:', str(len(self.vulnerabilities))]
            ]
            
            summary_table = Table(summary_data, colWidths=[2*inch, 4*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ECF0F1')),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
            ]))
            
            story.append(summary_table)
            story.append(Spacer(1, 0.3*inch))
            
            # Discovered Endpoints Section
            story.append(Paragraph("Discovered Endpoints", heading_style))
            
            if self.discovered_endpoints:
                endpoints_data = [['#', 'Endpoint URL']]
                for i, ep in enumerate(sorted(self.discovered_endpoints), 1):
                    endpoints_data.append([str(i), ep])
                
                endpoints_table = Table(endpoints_data, colWidths=[0.5*inch, 5.5*inch])
                endpoints_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3498DB')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 11),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('FONTSIZE', (0, 1), (-1, -1), 9)
                ]))
                
                story.append(endpoints_table)
            else:
                story.append(Paragraph("No endpoints discovered.", styles['Normal']))
            
            story.append(Spacer(1, 0.3*inch))
            
            # Vulnerabilities Section
            story.append(Paragraph("Potential Vulnerabilities", heading_style))
            
            if self.vulnerabilities:
                vuln_data = [['#', 'Severity', 'Type', 'URL', 'Description']]
                
                for i, vuln in enumerate(self.vulnerabilities, 1):
                    display_url = vuln['url'][:50] + '...' if len(vuln['url']) > 50 else vuln['url']
                    vuln_data.append([
                        str(i),
                        vuln['severity'],
                        vuln['type'],
                        display_url,
                        vuln['description']
                    ])
                
                vuln_table = Table(vuln_data, colWidths=[0.3*inch, 0.7*inch, 1.5*inch, 1.5*inch, 2*inch])
                
                table_style = [
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#E74C3C')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP')
                ]
                
                for i, vuln in enumerate(self.vulnerabilities, 1):
                    if vuln['severity'] == 'High':
                        table_style.append(('BACKGROUND', (1, i), (1, i), colors.HexColor('#FFCDD2')))
                    elif vuln['severity'] == 'Medium':
                        table_style.append(('BACKGROUND', (1, i), (1, i), colors.HexColor('#FFF9C4')))
                    else:
                        table_style.append(('BACKGROUND', (1, i), (1, i), colors.HexColor('#C8E6C9')))
                
                vuln_table.setStyle(TableStyle(table_style))
                story.append(vuln_table)
            else:
                story.append(Paragraph("No vulnerabilities detected.", styles['Normal']))
            
            story.append(Spacer(1, 0.3*inch))
            
            disclaimer = Paragraph(
                "<b>DISCLAIMER:</b> This is an automated security scan by AAPIPII. Results may include false positives. "
                "Manual verification by a qualified security professional is strongly recommended. "
                "This tool should only be used on systems you own or have explicit written permission to test.",
                styles['Normal']
            )
            story.append(disclaimer)
            
            doc.build(story)
            print(f"{Colors.GREEN}[+] PDF report saved to {filename}{Colors.RESET}")
            
        except Exception as e:
            print(f"{Colors.RED}[-] Error saving PDF report: {e}{Colors.RESET}")

def check_dependencies():
    """Check if required dependencies are installed"""
    missing = []
    if not REQUESTS_AVAILABLE:
        missing.append('requests')
    if not BS4_AVAILABLE:
        missing.append('beautifulsoup4')
    if not REPORTLAB_AVAILABLE:
        missing.append('reportlab')
    
    if missing:
        print(f"\n{Colors.YELLOW}[!] Missing dependencies:{Colors.RESET}")
        for dep in missing:
            print(f"    - {dep}")
        print(f"\n{Colors.CYAN}[*] Install all dependencies with:{Colors.RESET}")
        print(f"    sudo apt update && sudo apt install python3-pip -y")
        print(f"    pip3 install {' '.join(missing)}")
        print(f"\n{Colors.YELLOW}[*] Or try:{Colors.RESET}")
        print(f"    python3 -m pip install --user {' '.join(missing)}")
        
        if not REQUESTS_AVAILABLE:
            print(f"\n{Colors.RED}[!] 'requests' is required for scanning. Tool cannot run without it.{Colors.RESET}")
            return False
    return True

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description='AAPIPII - Advanced API Discovery and Security Scanner (Authorized Use Only)',
        epilog='WARNING: Only use on systems you own or have written permission to test'
    )
    parser.add_argument('url', nargs='?', help='Target URL (e.g., https://example.com)')
    parser.add_argument('--output', '-o', help='Output file for results (JSON)')
    parser.add_argument('--txt', help='Save report as TXT file')
    parser.add_argument('--pdf', help='Save report as PDF file')
    parser.add_argument('--check-deps', action='store_true', help='Check if dependencies are installed')
    
    args = parser.parse_args()
    
    # Check dependencies if requested
    if args.check_deps or not args.url:
        if check_dependencies():
            print(f"\n{Colors.GREEN}[+] All dependencies are installed!{Colors.RESET}")
        if not args.url:
            sys.exit(0)
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        print(f"{Colors.RED}[-] URL must start with http:// or https://{Colors.RESET}")
        sys.exit(1)
    
    print(f"\n{Colors.RED}{'='*70}")
    print(f"{Colors.BOLD}WARNING: Ensure you have written permission to test this target{Colors.RESET}")
    print(f"{Colors.RED}Unauthorized testing may be illegal in your jurisdiction")
    print(f"{'='*70}{Colors.RESET}\n")
    
    # Check if requests is available
    if not REQUESTS_AVAILABLE:
        print(f"{Colors.RED}[!] Cannot proceed: 'requests' module is required{Colors.RESET}")
        sys.exit(1)
    
    # Initialize scanner
    scanner = APIScanner(args.url)
    
    # Discover endpoints
    endpoints = scanner.discover_endpoints()
    
    # Check vulnerabilities
    if endpoints:
        vulns = scanner.check_vulnerabilities()
    
    # Generate report
    scanner.generate_report()
    
    # Save to JSON if requested
    if args.output:
        report = {
            'tool': 'AAPIPII v2.0',
            'target': args.url,
            'scan_date': datetime.now().isoformat(),
            'endpoints': list(endpoints),
            'vulnerabilities': vulns
        }
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n{Colors.GREEN}[+] JSON report saved to {args.output}{Colors.RESET}")
    
    # Save to TXT if requested
    if args.txt:
        scanner.save_txt_report(args.txt)
    
    # Save to PDF if requested
    if args.pdf:
        scanner.save_pdf_report(args.pdf)

if __name__ == '__main__':
    main()
