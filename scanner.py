"""Security scanner — SSL, HTTP headers, and DNS checks, plus Advanced Engine."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import ssl
import ipaddress
import concurrent.futures
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import dns.resolver
import requests
from bs4 import BeautifulSoup
from groq import Groq


REQUIRED_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
]

def is_safe_ip(ip_str: str) -> bool:
    """Prevent SSRF by blocking internal, loopback, and reserved IP ranges."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved)
    except ValueError:
        return False

def resolve_and_check_domain(domain: str) -> bool:
    """Resolves a domain to ensure it does not point to an internal IP."""
    try:
        answers = dns.resolver.resolve(domain, 'A', lifetime=3.0)
        for rdata in answers:
            if not is_safe_ip(rdata.address):
                return False
        return True
    except Exception:
        # Strict approach: must resolve safely.
        return False

def normalize_url(url: str) -> str:
    clean = url.strip()
    if not clean.startswith(("http://", "https://")):
        clean = "https://" + clean
    return clean

def get_domain(url: str) -> str:
    try:
        return urlparse(normalize_url(url)).hostname or url
    except Exception:
        return url

def check_ssl(domain: str) -> dict[str, Any]:
    result: dict[str, Any] = {"valid": False, "issuer": "N/A", "days_remaining": 0, "expiry_date": "N/A"}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y GMT").replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days = (expiry - now).days
                issuer = dict(x[0] for x in cert.get("issuer", []))
                result = {
                    "valid": days > 0,
                    "issuer": issuer.get("organizationName") or issuer.get("commonName", "Unknown"),
                    "days_remaining": max(days, 0),
                    "expiry_date": expiry.isoformat(),
                }
    except ssl.SSLError:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert_bin = ssock.getpeercert(True)
                    if cert_bin:
                        result["error"] = "Certificate is self-signed, expired, or untrusted"
        except Exception as exc:
            result["error"] = str(exc)
    except Exception as exc:
        result["error"] = str(exc)
    return result


def check_exposed_files(base_url: str) -> list[str]:
    exposed = []
    paths = ["/.env", "/.git/config"]
    for path in paths:
        target = base_url.rstrip("/") + path
        try:
            r = requests.get(target, timeout=3, verify=False, allow_redirects=False)
            if r.status_code == 200:
                if ".env" in path and ("=" in r.text or "APP_" in r.text or "DB_" in r.text):
                    exposed.append(path)
                elif ".git" in path and "[core]" in r.text:
                    exposed.append(path)
        except Exception:
            pass
    return exposed


def check_open_ports(domain: str) -> list[int]:
    open_ports = []
    ports_to_check = [21, 22, 3306, 5432, 6379, 27017]
    def try_port(port):
        try:
            with socket.create_connection((domain, port), timeout=1.5):
                return port
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(ports_to_check)) as executor:
        results = executor.map(try_port, ports_to_check)
        for r in results:
            if r:
                open_ports.append(r)
    return open_ports


def check_headers_and_latency(url: str) -> dict[str, Any]:
    clean = normalize_url(url)
    try:
        start = datetime.now()
        # Ensure we don't follow redirects to arbitrary internal IPs
        response = requests.get(clean, timeout=8, allow_redirects=False, verify=False)
        latency = int((datetime.now() - start).total_seconds() * 1000)
        headers = {k.lower(): v for k, v in response.headers.items()}
        missing = [h for h in REQUIRED_HEADERS if h not in headers]
        
        # Tech profiling
        tech_stack = []
        if "server" in headers:
            tech_stack.append(f"Server: {headers['server']}")
        if "x-powered-by" in headers:
            tech_stack.append(f"Powered By: {headers['x-powered-by']}")
            
        # Cookie security
        insecure_cookies = False
        if "set-cookie" in headers:
            cookie_val = headers["set-cookie"].lower()
            if "secure" not in cookie_val or "httponly" not in cookie_val:
                insecure_cookies = True

        content = response.content
        content_size = len(content)
        
        soup = BeautifulSoup(content, "html.parser")
        
        # Meta generator check
        generator = soup.find("meta", {"name": "generator"})
        if generator and generator.get("content"):
            tech_stack.append(f"Generator: {generator['content']}")
            
        structure = "".join([tag.name for tag in soup.find_all(True)])
        content_hash = hashlib.md5(structure.encode('utf-8')).hexdigest()
        
        return {
            "latency": latency,
            "status": response.status_code,
            "headers": headers,
            "missing_headers": missing,
            "content_size": content_size,
            "content_hash": content_hash,
            "tech_stack": tech_stack,
            "insecure_cookies": insecure_cookies
        }
    except Exception:
        return {
            "latency": 0,
            "status": 0,
            "headers": {},
            "missing_headers": REQUIRED_HEADERS[:4],
            "content_size": 0,
            "content_hash": "",
            "tech_stack": [],
            "insecure_cookies": False
        }


def check_dmarc(domain: str) -> bool:
    try:
        txt_records = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=3.0)
        for record in txt_records:
            text = " ".join(s.decode() if isinstance(s, bytes) else s for s in record.strings).lower()
            if "v=dmarc1" in text:
                return True
    except Exception:
        pass
    return False


def check_dns(domain: str) -> dict[str, bool]:
    mx_found = False
    spf_found = False
    try:
        mx_found = bool(dns.resolver.resolve(domain, "MX", lifetime=3.0))
    except Exception:
        pass
    try:
        txt_records = dns.resolver.resolve(domain, "TXT", lifetime=3.0)
        for record in txt_records:
            text = " ".join(s.decode() if isinstance(s, bytes) else s for s in record.strings).lower()
            if "v=spf1" in text:
                spf_found = True
                break
    except Exception:
        pass
        
    dmarc_found = check_dmarc(domain)
    
    return {"mx_found": mx_found, "spf_found": spf_found, "dmarc_found": dmarc_found}


def scan_website(url: str) -> dict[str, Any]:
    domain = get_domain(url)
    
    # SSRF Prevention Check
    if not resolve_and_check_domain(domain):
        return {
            "success": False,
            "error": "Security Restriction: Target resolves to an internal/private IP address."
        }
    
    ssl_result = check_ssl(domain)
    web_result = check_headers_and_latency(url)
    dns_info = check_dns(domain)
    
    # Advanced Active Checks
    exposed_files = check_exposed_files(normalize_url(url))
    open_ports = check_open_ports(domain)

    vulnerabilities = []
    severity_score = 0
    
    # Try AI Analysis first
    api_key = os.environ.get("GROQ_API_KEY")
    if api_key:
        try:
            client = Groq(api_key=api_key, timeout=15.0)
            prompt = f"""
            Analyze the security of a website with these attributes:
            - SSL Valid: {ssl_result.get('valid')}
            - SSL Days Remaining: {ssl_result.get('days_remaining')}
            - Missing Security Headers: {', '.join(web_result['missing_headers'])}
            - SPF Record Found: {dns_info.get('spf_found')}
            - DMARC Record Found: {dns_info.get('dmarc_found')}
            - Tech Stack: {', '.join(web_result.get('tech_stack', []))}
            - Insecure Cookies: {web_result.get('insecure_cookies')}
            - Exposed Sensitive Files: {', '.join(exposed_files) if exposed_files else 'None'}
            - Open Ports (Dangerous): {', '.join(map(str, open_ports)) if open_ports else 'None'}
            
            Respond ONLY with a JSON object containing a "vulnerabilities" array. 
            Each vulnerability must have:
            "title" (string), "severity" ("low", "medium", "high", "critical"), "description" (string), "fix" (string), "cvss" (float).
            If no issues, return {{"vulnerabilities": []}}.
            Be strict. If exposed files like .env exist, it's critical. If database ports are open, it's high/critical.
            """
            response = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {"role": "system", "content": "You are a cyber security expert. Return strictly JSON."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"}
            )
            data = json.loads(response.choices[0].message.content)
            vulnerabilities = data.get("vulnerabilities", [])
            
            for v in vulnerabilities:
                sev = v.get("severity", "low").lower()
                if sev == "critical": severity_score += 30
                elif sev == "high": severity_score += 20
                elif sev == "medium": severity_score += 10
                else: severity_score += 5
        except Exception as e:
            print("Groq AI analysis failed, falling back to static rules:", e)
    
    # Fallback to static rules if AI failed or no API key
    if not vulnerabilities:
        if exposed_files:
            vulnerabilities.append({
                "title": "Sensitive File Exposure",
                "severity": "critical",
                "description": f"The following sensitive files are publicly accessible: {', '.join(exposed_files)}",
                "fix": "Restrict web server access to dotfiles and configuration directories immediately.",
                "cvss": 9.8,
            })
            severity_score += 30
            
        if open_ports:
            vulnerabilities.append({
                "title": "Dangerous Open Ports Detected",
                "severity": "high",
                "description": f"The following potentially sensitive ports are open to the internet: {', '.join(map(str, open_ports))}",
                "fix": "Configure a firewall to block public access to database and management ports.",
                "cvss": 7.5,
            })
            severity_score += 20
            
        if web_result.get("insecure_cookies"):
            vulnerabilities.append({
                "title": "Insecure Session Cookies",
                "severity": "medium",
                "description": "Cookies were issued without Secure or HttpOnly flags, risking XSS token theft.",
                "fix": "Ensure all Set-Cookie headers include HttpOnly, Secure, and SameSite attributes.",
                "cvss": 5.4,
            })
            severity_score += 10
            
        if not dns_info["spf_found"] or not dns_info["dmarc_found"]:
            vulnerabilities.append({
                "title": "Email Spoofing Vulnerability (SPF/DMARC)",
                "severity": "medium",
                "description": "Domain lacks SPF or DMARC records, enabling attackers to send spoofed emails.",
                "fix": "Configure SPF and DMARC TXT records in your DNS zone.",
                "cvss": 5.3,
            })
            severity_score += 10

        if not ssl_result.get("valid"):
            vulnerabilities.append({
                "title": "SSL/TLS Certificate Misconfiguration",
                "severity": "critical",
                "description": ssl_result.get("error", "The SSL certificate is self-signed, expired, or invalid."),
                "fix": "Install a valid SSL/TLS certificate from a recognized Certificate Authority.",
                "cvss": 7.5,
            })
            severity_score += 30
        elif ssl_result.get("days_remaining", 999) < 15:
            vulnerabilities.append({
                "title": "SSL/TLS Certificate Expiring Soon",
                "severity": "medium",
                "description": f"Certificate expires in {ssl_result['days_remaining']} days.",
                "fix": "Renew the SSL certificate before expiration.",
                "cvss": 5.0,
            })
            severity_score += 15

        header_checks = [
            ("content-security-policy", "Missing Content Security Policy (CSP) Header", "high", 20, 6.8),
            ("x-frame-options", "Missing X-Frame-Options Header", "medium", 10, 4.8),
            ("strict-transport-security", "Missing Strict-Transport-Security (HSTS) Header", "medium", 10, 5.3),
            ("x-content-type-options", "Missing X-Content-Type-Options Header", "low", 5, 3.4),
        ]
        for header, title, severity, score, cvss in header_checks:
            if header in web_result["missing_headers"]:
                vulnerabilities.append({
                    "title": title,
                    "severity": severity,
                    "description": f"The {header} header was not found in HTTP responses.",
                    "fix": f"Configure the {header} header on your web server.",
                    "cvss": cvss,
                })
                severity_score += score

    health_score = max(0, 100 - severity_score)
    risk_level = (
        "low" if health_score >= 90 else
        "medium" if health_score >= 70 else
        "high" if health_score >= 45 else
        "critical"
    )

    return {
        "success": True,
        "domain": domain,
        "health_score": health_score,
        "risk_level": risk_level,
        "latency_ms": web_result["latency"],
        "status_code": web_result["status"],
        "content_size": web_result.get("content_size", 0),
        "content_hash": web_result.get("content_hash", ""),
        "ssl": {
            "valid": ssl_result.get("valid", False),
            "issuer": ssl_result.get("issuer", "N/A"),
            "days_remaining": ssl_result.get("days_remaining", 0),
            "expiry_date": ssl_result.get("expiry_date", "N/A"),
        },
        "dns_info": dns_info,
        "vulnerabilities": vulnerabilities,
    }
