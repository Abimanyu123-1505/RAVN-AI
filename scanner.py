"""Security scanner — SSL, HTTP headers, and DNS checks."""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import dns.resolver
import requests


REQUIRED_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
]


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


def check_headers_and_latency(url: str) -> dict[str, Any]:
    clean = normalize_url(url)
    try:
        start = datetime.now()
        response = requests.get(clean, timeout=8, allow_redirects=True, verify=False)
        latency = int((datetime.now() - start).total_seconds() * 1000)
        headers = {k.lower(): v for k, v in response.headers.items()}
        missing = [h for h in REQUIRED_HEADERS if h not in headers]
        return {
            "latency": latency,
            "status": response.status_code,
            "headers": headers,
            "missing_headers": missing,
        }
    except Exception:
        return {
            "latency": 0,
            "status": 0,
            "headers": {},
            "missing_headers": REQUIRED_HEADERS[:4],
        }


def check_dns(domain: str) -> dict[str, bool]:
    mx_found = False
    spf_found = False
    try:
        mx_found = bool(dns.resolver.resolve(domain, "MX"))
    except Exception:
        pass
    try:
        txt_records = dns.resolver.resolve(domain, "TXT")
        for record in txt_records:
            text = " ".join(s.decode() if isinstance(s, bytes) else s for s in record.strings).lower()
            if "v=spf1" in text:
                spf_found = True
                break
    except Exception:
        pass
    return {"mx_found": mx_found, "spf_found": spf_found}


def scan_website(url: str) -> dict[str, Any]:
    domain = get_domain(url)
    ssl_result = check_ssl(domain)
    web_result = check_headers_and_latency(url)
    dns_info = check_dns(domain)

    vulnerabilities: list[dict[str, Any]] = []
    severity_score = 0

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

    if not dns_info["spf_found"]:
        vulnerabilities.append({
            "title": "Missing SPF Email Authentication Record",
            "severity": "low",
            "description": "No SPF record detected. Email spoofing risk is elevated.",
            "fix": "Add an SPF TXT record to your DNS zone.",
            "cvss": 3.1,
        })
        severity_score += 5

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
        "ssl": {
            "valid": ssl_result.get("valid", False),
            "issuer": ssl_result.get("issuer", "N/A"),
            "days_remaining": ssl_result.get("days_remaining", 0),
            "expiry_date": ssl_result.get("expiry_date", "N/A"),
        },
        "dns_info": dns_info,
        "vulnerabilities": vulnerabilities,
    }
