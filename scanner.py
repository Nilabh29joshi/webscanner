import requests
from bs4 import BeautifulSoup
import logging
from urllib.parse import urljoin, urlparse
import re
import ssl
import socket
import json

logger = logging.getLogger(__name__)

class WebVulnerabilityScanner:
    def __init__(self, url):
        self.url = url
        self.timeout = 30
        self.headers = {
            'User-Agent': 'Security Scanner Testing - Educational Purposes Only'
        }

    def _make_request(self, url, method='get', data=None, allow_redirects=True):
        try:
            if method.lower() == 'get':
                response = requests.get(url, headers=self.headers, timeout=self.timeout, 
                                     allow_redirects=allow_redirects)
            else:
                response = requests.post(url, headers=self.headers, data=data, 
                                      timeout=self.timeout, allow_redirects=allow_redirects)
            return response
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error: {str(e)}")
            return None

    def check_sql_injection(self):
        """A3:2021 - Injection"""
        payloads = [
            "' OR '1'='1",
            "1' OR '1'='1",
            "1; DROP TABLE users--",
            "1' UNION SELECT NULL--",
            "admin' --"
        ]

        findings = []
        for payload in payloads:
            target_url = f"{self.url}?id={payload}"
            response = self._make_request(target_url)

            if response and any(error in response.text.lower() for error in 
                ['sql', 'mysql', 'postgresql', 'oracle', 'syntax error']):
                findings.append(f"Potential SQL Injection vulnerability with payload: {payload}")

        return {
            'name': 'A3:2021 - Injection',
            'vulnerable': len(findings) > 0,
            'findings': findings or ["No SQL Injection vulnerabilities detected"],
            'severity': 'Critical' if findings else 'Low'
        }

    def check_broken_access_control(self):
        """A1:2021 - Broken Access Control"""
        findings = []
        sensitive_paths = ['/admin', '/dashboard', '/config', '/users', '/api/users']

        for path in sensitive_paths:
            target_url = urljoin(self.url, path)
            response = self._make_request(target_url, allow_redirects=False)

            if response and response.status_code == 200:
                findings.append(f"Direct access to {path} possible without authentication")
            elif response and response.status_code == 403:
                findings.append(f"Protected endpoint discovered at {path}")

        return {
            'name': 'A1:2021 - Broken Access Control',
            'vulnerable': len(findings) > 0,
            'findings': findings or ["No direct access vulnerabilities detected"],
            'severity': 'High' if findings else 'Low'
        }

    def check_crypto_failures(self):
        """A2:2021 - Cryptographic Failures"""
        findings = []
        parsed_url = urlparse(self.url)

        # Check HTTPS
        if parsed_url.scheme != 'https':
            findings.append("Site does not use HTTPS")
        else:
            try:
                hostname = parsed_url.hostname
                context = ssl.create_default_context()
                with context.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                    s.connect((hostname, 443))
                    cert = s.getpeercert()

                    # Check SSL/TLS version
                    if s.version() < ssl.TLSVersion.TLSv1_2:
                        findings.append("Outdated TLS version detected")
            except Exception as e:
                findings.append(f"SSL/TLS verification failed: {str(e)}")

        return {
            'name': 'A2:2021 - Cryptographic Failures',
            'vulnerable': len(findings) > 0,
            'findings': findings or ["No cryptographic vulnerabilities detected"],
            'severity': 'High' if findings else 'Low'
        }

    def check_xss(self):
        """Part of A3:2021 - Injection"""
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')"
        ]

        findings = []
        for payload in payloads:
            target_url = f"{self.url}?input={payload}"
            response = self._make_request(target_url)

            if response and payload in response.text:
                findings.append(f"Potential XSS vulnerability with payload: {payload}")

        return {
            'name': 'Cross-Site Scripting (XSS)',
            'vulnerable': len(findings) > 0,
            'findings': findings or ["No XSS vulnerabilities detected"],
            'severity': 'High' if findings else 'Low'
        }

    def check_security_misconfig(self):
        """A5:2021 - Security Misconfiguration"""
        findings = []
        headers_to_check = {
            'X-Frame-Options': 'Missing X-Frame-Options header (clickjacking risk)',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
            'Strict-Transport-Security': 'Missing HSTS header',
            'X-XSS-Protection': 'Missing X-XSS-Protection header'
        }

        response = self._make_request(self.url)
        if response:
            for header, message in headers_to_check.items():
                if header not in response.headers:
                    findings.append(message)

            if 'Server' in response.headers:
                findings.append(f"Server header reveals: {response.headers['Server']}")

        return {
            'name': 'A5:2021 - Security Misconfiguration',
            'vulnerable': len(findings) > 0,
            'findings': findings or ["No security misconfiguration detected"],
            'severity': 'Medium' if findings else 'Low'
        }

    def check_vulnerable_components(self):
        """A6:2021 - Vulnerable and Outdated Components"""
        findings = []
        response = self._make_request(self.url)

        if response:
            # Check for common JavaScript libraries
            js_libs = {
                'jquery-1.': 'Outdated jQuery version',
                'jquery-2.': 'Outdated jQuery version',
                'bootstrap-3.': 'Outdated Bootstrap version',
                'angular.js/1.': 'Outdated AngularJS version'
            }

            for lib, message in js_libs.items():
                if lib in response.text:
                    findings.append(message)

        return {
            'name': 'A6:2021 - Vulnerable Components',
            'vulnerable': len(findings) > 0,
            'findings': findings or ["No vulnerable components detected"],
            'severity': 'Medium' if findings else 'Low'
        }

    def check_auth_failures(self):
        """A7:2021 - Authentication Failures"""
        common_paths = ['/login', '/admin', '/wp-admin', '/administrator']
        common_creds = [
            {'username': 'admin', 'password': 'admin'},
            {'username': 'admin', 'password': 'password'},
            {'username': 'administrator', 'password': 'administrator'}
        ]

        findings = []
        for path in common_paths:
            login_url = urljoin(self.url, path)
            response = self._make_request(login_url)

            if response and response.status_code == 200:
                for creds in common_creds:
                    auth_response = self._make_request(login_url, 'post', data=creds)
                    if auth_response and any(term in auth_response.text.lower() for term in 
                        ['welcome', 'dashboard', 'logged in']):
                        findings.append(f"Weak credentials work at {path}")

        return {
            'name': 'A7:2021 - Authentication Failures',
            'vulnerable': len(findings) > 0,
            'findings': findings or ["No authentication vulnerabilities detected"],
            'severity': 'Critical' if findings else 'Low'
        }

    def check_data_integrity(self):
        """A8:2021 - Software and Data Integrity Failures"""
        findings = []
        response = self._make_request(self.url)

        if response:
            # Check for Subresource Integrity
            soup = BeautifulSoup(response.text, 'html.parser')
            scripts = soup.find_all('script', src=True)
            styles = soup.find_all('link', rel='stylesheet')

            for resource in scripts + styles:
                if not resource.get('integrity'):
                    findings.append(f"Resource missing SRI: {resource.get('src') or resource.get('href')}")

        return {
            'name': 'A8:2021 - Data Integrity',
            'vulnerable': len(findings) > 0,
            'findings': findings or ["No integrity issues detected"],
            'severity': 'Medium' if findings else 'Low'
        }

    def check_logging_monitoring(self):
        """A9:2021 - Security Logging and Monitoring Failures"""
        findings = []
        error_paths = ['/error', '/debug', '/log', '/trace']

        for path in error_paths:
            target_url = urljoin(self.url, path)
            response = self._make_request(target_url)

            if response and response.status_code == 200:
                if any(term in response.text.lower() for term in 
                    ['error', 'exception', 'stack trace', 'debug']):
                    findings.append(f"Exposed error/debug info at {path}")

        return {
            'name': 'A9:2021 - Logging and Monitoring',
            'vulnerable': len(findings) > 0,
            'findings': findings or ["No logging/monitoring issues detected"],
            'severity': 'Medium' if findings else 'Low'
        }

    def check_ssrf(self):
        """A10:2021 - Server-Side Request Forgery"""
        findings = []
        ssrf_payloads = [
            'http://localhost/',
            'http://127.0.0.1/',
            'http://[::1]/',
            'file:///etc/passwd'
        ]

        for payload in ssrf_payloads:
            target_url = f"{self.url}?url={payload}"
            response = self._make_request(target_url)

            if response and any(term in response.text.lower() for term in 
                ['root:', 'localhost', 'internal']):
                findings.append(f"Potential SSRF with payload: {payload}")

        return {
            'name': 'A10:2021 - SSRF',
            'vulnerable': len(findings) > 0,
            'findings': findings or ["No SSRF vulnerabilities detected"],
            'severity': 'High' if findings else 'Low'
        }

    def check_clickjacking(self):
        """Additional check for Clickjacking vulnerabilities"""
        findings = []
        response = self._make_request(self.url)

        if response:
            x_frame_options = response.headers.get('X-Frame-Options', '').upper()
            csp = response.headers.get('Content-Security-Policy', '')

            if not x_frame_options and 'frame-ancestors' not in csp.lower():
                findings.append("No X-Frame-Options header or CSP frame-ancestors directive found")
            elif x_frame_options not in ['DENY', 'SAMEORIGIN']:
                findings.append(f"Weak X-Frame-Options value: {x_frame_options}")

        return {
            'name': 'Clickjacking Protection',
            'vulnerable': len(findings) > 0,
            'findings': findings or ["Clickjacking protection is in place"],
            'severity': 'Medium' if findings else 'Low'
        }

    def check_redirects(self):
        """Additional check for unvalidated redirects and forwards"""
        findings = []
        redirect_params = ['url', 'redirect', 'next', 'target', 'redir', 'dest', 'destination']

        for param in redirect_params:
            malicious_urls = [
                'https://evil.com',
                'http://attacker.example',
                '//external-domain.com'
            ]

            for mal_url in malicious_urls:
                target_url = f"{self.url}?{param}={mal_url}"
                response = self._make_request(target_url, allow_redirects=False)

                if response and response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    if any(url in location for url in malicious_urls):
                        findings.append(f"Open redirect via parameter: {param}")

        return {
            'name': 'Unvalidated Redirects',
            'vulnerable': len(findings) > 0,
            'findings': findings or ["No open redirect vulnerabilities detected"],
            'severity': 'Medium' if findings else 'Low'
        }

    def check_sensitive_exposure(self):
        """Additional check for sensitive information exposure"""
        findings = []
        sensitive_patterns = [
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'Email address'),
            (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', 'IP address'),
            (r'\bapi[_-]?key[=:][A-Za-z0-9]{16,}\b', 'API key'),
            (r'\bsecret[=:][A-Za-z0-9]{16,}\b', 'Secret key'),
            (r'\b(?:access|private|secret)_key[=:][A-Za-z0-9/+]{20,}\b', 'Access key'),
            (r'\bAKIA[0-9A-Z]{16}\b', 'AWS Access Key ID'),
            (r'\bghp_[a-zA-Z0-9]{36}\b', 'GitHub Personal Access Token'),
            (r'\b(?:password|passwd)[=:][^\s]{8,}\b', 'Password'),
            (r'\b(?:BEGIN|END) (?:RSA|DSA|EC|OPENSSH) (?:PRIVATE|PUBLIC) KEY\b', 'Cryptographic key')
        ]

        response = self._make_request(self.url)
        if response:
            html_content = response.text
            
            for pattern, desc in sensitive_patterns:
                import re
                matches = re.findall(pattern, html_content)
                if matches:
                    # Redact the actual sensitive info in the finding
                    finding = f"Potential {desc} exposure found ({len(matches)} occurrences)"
                    findings.append(finding)
            
            # Check for common sensitive file paths
            soup = BeautifulSoup(html_content, 'html.parser')
            for link in soup.find_all(['a', 'link', 'script', 'img']):
                href = link.get('href') or link.get('src') or ''
                sensitive_files = [
                    '.env', '.git', '.htaccess', 'config.php', 'wp-config.php', 
                    'credentials', 'password', 'secret', 'backup', '.sql', '.db'
                ]
                
                for file in sensitive_files:
                    if file in href.lower():
                        findings.append(f"Potential sensitive file reference: {href}")

        return {
            'name': 'Sensitive Information Exposure',
            'vulnerable': len(findings) > 0,
            'findings': findings or ["No sensitive information exposure detected"],
            'severity': 'Critical' if findings else 'Low'
        }

    def run_all_scans(self):
        """Run all vulnerability checks and collate results"""
        scans = [
            self.check_broken_access_control(),      # A1:2021
            self.check_crypto_failures(),            # A2:2021
            self.check_sql_injection(),              # A3:2021 (part 1)
            self.check_xss(),                        # A3:2021 (part 2)
            self.check_security_misconfig(),         # A5:2021
            self.check_vulnerable_components(),      # A6:2021
            self.check_auth_failures(),              # A7:2021
            self.check_data_integrity(),             # A8:2021
            self.check_logging_monitoring(),         # A9:2021
            self.check_ssrf(),                       # A10:2021
            self.check_clickjacking(),               # Additional
            self.check_redirects(),                  # Additional
            self.check_sensitive_exposure()          # Additional
        ]

        return {
            'target_url': self.url,
            'scans': scans
        }
