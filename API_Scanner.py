#!/usr/bin/env python3
"""
API Discovery and Security Scanner
For authorized security testing only - requires written permission
"""

import requests
import json
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import argparse
import sys
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors

class APIScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.discovered_endpoints = set()
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Security-Scanner/1.0 (Authorized Testing)'
        })
    
    def discover_endpoints(self):
        """Discover API endpoints through various methods"""
        print(f"[*] Scanning {self.target_url} for API endpoints...")
        
        # Method 1: Check common API paths
        self._check_common_paths()
        
        # Method 2: Parse JavaScript files for endpoints
        self._parse_javascript()
        
        # Method 3: Check robots.txt and sitemap
        self._check_meta_files()
        
        return self.discovered_endpoints
    
    def _check_common_paths(self):
        """Check common API endpoint patterns"""
        common_paths = [
            '/api/', '/api/v1/', '/api/v2/', '/rest/', '/graphql',
            '/swagger.json', '/openapi.json', '/api-docs', '/docs',
            '/api/swagger', '/api/docs', '/.well-known/api'
        ]
        
        for path in common_paths:
            url = urljoin(self.target_url, path)
            try:
                resp = self.session.get(url, timeout=5, verify=False)
                if resp.status_code in [200, 301, 302]:
                    self.discovered_endpoints.add(url)
                    print(f"[+] Found: {url} (Status: {resp.status_code})")
            except requests.RequestException:
                pass
    
    def _parse_javascript(self):
        """Extract API endpoints from JavaScript files"""
        try:
            resp = self.session.get(self.target_url, timeout=10)
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            # Find all script tags
            for script in soup.find_all('script', src=True):
                js_url = urljoin(self.target_url, script['src'])
                try:
                    js_resp = self.session.get(js_url, timeout=5)
                    # Look for API endpoint patterns
                    endpoints = re.findall(r'["\']/(api|rest)/[^"\']*["\']', js_resp.text)
                    for ep in endpoints:
                        clean_ep = ep.strip('"\'')
                        full_url = urljoin(self.target_url, clean_ep)
                        self.discovered_endpoints.add(full_url)
                except requests.RequestException:
                    pass
        except requests.RequestException:
            print("[-] Could not fetch main page")
    
    def _check_meta_files(self):
        """Check robots.txt and sitemap for endpoints"""
        for path in ['/robots.txt', '/sitemap.xml']:
            url = urljoin(self.target_url, path)
            try:
                resp = self.session.get(url, timeout=5)
                if resp.status_code == 200:
                    # Extract paths
                    paths = re.findall(r'/(api|rest)/[^\s<>"\']*', resp.text)
                    for p in paths:
                        full_url = urljoin(self.target_url, p)
                        self.discovered_endpoints.add(full_url)
            except requests.RequestException:
                pass
    
    def check_vulnerabilities(self):
        """Check for common API vulnerabilities"""
        print("\n[*] Checking for vulnerabilities...")
        
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
            resp = self.session.get(url, timeout=5)
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
            resp = self.session.get(url, timeout=5)
            sensitive_patterns = [
                r'password', r'api[_-]?key', r'secret', r'token',
                r'aws[_-]?access', r'private[_-]?key'
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
            resp = self.session.options(url, timeout=5)
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
        print("\n" + "="*60)
        print("SECURITY ASSESSMENT REPORT")
        print("="*60)
        
        print(f"\nTarget: {self.target_url}")
        print(f"Endpoints Discovered: {len(self.discovered_endpoints)}")
        print(f"Potential Issues Found: {len(self.vulnerabilities)}")
        
        print("\n--- Discovered Endpoints ---")
        for ep in sorted(self.discovered_endpoints):
            print(f"  • {ep}")
        
        print("\n--- Potential Vulnerabilities ---")
        for vuln in self.vulnerabilities:
            print(f"\n[{vuln['severity']}] {vuln['type']}")
            print(f"  URL: {vuln['url']}")
            print(f"  Description: {vuln['description']}")
        
        print("\n" + "="*60)
    
    def save_txt_report(self, filename):
        """Save report as TXT file"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("="*60 + "\n")
                f.write("API SECURITY ASSESSMENT REPORT\n")
                f.write("="*60 + "\n\n")
                
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Target: {self.target_url}\n")
                f.write(f"Endpoints Discovered: {len(self.discovered_endpoints)}\n")
                f.write(f"Potential Issues Found: {len(self.vulnerabilities)}\n\n")
                
                f.write("-" * 60 + "\n")
                f.write("DISCOVERED ENDPOINTS\n")
                f.write("-" * 60 + "\n")
                for ep in sorted(self.discovered_endpoints):
                    f.write(f"  • {ep}\n")
                
                f.write("\n" + "-" * 60 + "\n")
                f.write("POTENTIAL VULNERABILITIES\n")
                f.write("-" * 60 + "\n\n")
                
                if self.vulnerabilities:
                    for i, vuln in enumerate(self.vulnerabilities, 1):
                        f.write(f"{i}. [{vuln['severity']}] {vuln['type']}\n")
                        f.write(f"   URL: {vuln['url']}\n")
                        f.write(f"   Description: {vuln['description']}\n\n")
                else:
                    f.write("No vulnerabilities detected.\n\n")
                
                f.write("="*60 + "\n")
                f.write("NOTE: This is an automated scan. Manual verification is recommended.\n")
                f.write("="*60 + "\n")
            
            print(f"[+] TXT report saved to {filename}")
        except Exception as e:
            print(f"[-] Error saving TXT report: {e}")
    
    def save_pdf_report(self, filename):
        """Save report as PDF file"""
        try:
            doc = SimpleDocTemplate(filename, pagesize=letter)
            story = []
            styles = getSampleStyleSheet()
            
            # Custom styles
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#2C3E50'),
                spaceAfter=30,
                alignment=1  # Center
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
            story.append(Paragraph("API Security Assessment Report", title_style))
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
                    # Truncate long URLs for PDF display
                    display_url = vuln['url'][:50] + '...' if len(vuln['url']) > 50 else vuln['url']
                    vuln_data.append([
                        str(i),
                        vuln['severity'],
                        vuln['type'],
                        display_url,
                        vuln['description']
                    ])
                
                vuln_table = Table(vuln_data, colWidths=[0.3*inch, 0.7*inch, 1.5*inch, 1.5*inch, 2*inch])
                
                # Color code by severity
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
                
                # Add row coloring based on severity
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
            
            # Disclaimer
            disclaimer = Paragraph(
                "<b>DISCLAIMER:</b> This is an automated security scan. Results may include false positives. "
                "Manual verification by a qualified security professional is strongly recommended. "
                "This tool should only be used on systems you own or have explicit written permission to test.",
                styles['Normal']
            )
            story.append(disclaimer)
            
            # Build PDF
            doc.build(story)
            print(f"[+] PDF report saved to {filename}")
            
        except ImportError:
            print("[-] Error: reportlab library not installed. Install with: pip install reportlab")
        except Exception as e:
            print(f"[-] Error saving PDF report: {e}")

def main():
    parser = argparse.ArgumentParser(
        description='API Discovery and Security Scanner (Authorized Use Only)',
        epilog='WARNING: Only use on systems you own or have written permission to test'
    )
    parser.add_argument('url', help='Target URL (e.g., https://example.com)')
    parser.add_argument('--output', '-o', help='Output file for results (JSON)')
    parser.add_argument('--txt', help='Save report as TXT file')
    parser.add_argument('--pdf', help='Save report as PDF file')
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        print("[-] URL must start with http:// or https://")
        sys.exit(1)
    
    print("\n" + "="*60)
    print("API Security Scanner - For Authorized Testing Only")
    print("="*60)
    print("\nWARNING: Ensure you have written permission to test this target")
    print("Unauthorized testing may be illegal in your jurisdiction\n")
    
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
            'target': args.url,
            'scan_date': datetime.now().isoformat(),
            'endpoints': list(endpoints),
            'vulnerabilities': vulns
        }
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n[+] JSON report saved to {args.output}")
    
    # Save to TXT if requested
    if args.txt:
        scanner.save_txt_report(args.txt)
    
    # Save to PDF if requested
    if args.pdf:
        scanner.save_pdf_report(args.pdf)

if __name__ == '__main__':
    main()
