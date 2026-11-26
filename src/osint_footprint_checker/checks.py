"""Exposure checks over a snapshot of your own asset's public footprint."""
from dataclasses import dataclass


@dataclass
class Finding:
    check: str
    severity: str
    detail: str
    fix: str

def check_security_txt(snapshot: dict) -> list[Finding]:
    if not snapshot.get("security_txt"):
        return [Finding("security.txt", "medium",
                        "No security.txt published; researchers have no clear reporting route.",
                        "Publish /.well-known/security.txt with a monitored contact.")]
    return []

def check_headers(snapshot: dict) -> list[Finding]:
    findings = []
    headers = {k.lower(): v for k, v in snapshot.get("headers", {}).items()}
    if "strict-transport-security" not in headers:
        findings.append(Finding("HSTS", "medium", "Strict-Transport-Security header missing.",
                                "Add HSTS with a long max-age once HTTPS is enforced."))
    if "content-security-policy" not in headers:
        findings.append(Finding("CSP", "low", "Content-Security-Policy header missing.",
                                "Add a CSP tuned to your site's resources."))
    if "x-content-type-options" not in headers:
        findings.append(Finding("XCTO", "low", "X-Content-Type-Options header missing.",
                                "Set X-Content-Type-Options: nosniff."))
    return findings

def check_dns(snapshot: dict) -> list[Finding]:
    findings = []
    dns = snapshot.get("dns", {})
    if not dns.get("spf"):
        findings.append(Finding("SPF", "medium", "No SPF record; domain can be spoofed in mail.",
                                "Publish an SPF record listing authorised senders."))
    if not dns.get("dmarc"):
        findings.append(Finding("DMARC", "medium", "No DMARC record.",
                                "Publish a DMARC policy, starting at p=none with reporting."))
    if dns.get("dangling_cname"):
        findings.append(Finding("dangling CNAME", "high",
                                f"CNAME points at unclaimed service: {dns['dangling_cname']}",
                                "Remove the record or reclaim the service immediately."))
    return findings

def check_tls(snapshot: dict) -> list[Finding]:
    findings = []
    tls = snapshot.get("tls", {})
    versions = tls.get("versions", [])
    for old in ("TLSv1.0", "TLSv1.1"):
        if old in versions:
            findings.append(Finding("TLS", "medium", f"{old} still enabled.",
                                    "Disable TLS below 1.2."))
    days = tls.get("days_to_expiry")
    if days is not None and days < 21:
        findings.append(Finding("TLS expiry", "high", f"Certificate expires in {days} days.",
                                "Renew the certificate and automate renewal."))
    return findings

ALL_CHECKS = [check_security_txt, check_headers, check_dns, check_tls]

def run_checks(snapshot: dict) -> list[Finding]:
    findings = []
    for fn in ALL_CHECKS:
        findings.extend(fn(snapshot))
    return findings

def score(findings: list[Finding]) -> int:
    penalty = {"high": 25, "medium": 10, "low": 4}
    return max(0, 100 - sum(penalty[f.severity] for f in findings))
