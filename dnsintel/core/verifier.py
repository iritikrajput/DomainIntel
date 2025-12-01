"""
Domain verification and security checks functionality.
"""

from typing import Dict, Any, List

from dnsintel.core import dns_lookup, ssl_checker
from dnsintel.utils.output import print_info, print_success, print_error, print_warning


def verify_domain(domain: str) -> Dict[str, Any]:
    """
    Perform comprehensive domain verification checks.

    Args:
        domain: Domain name to verify

    Returns:
        Dictionary containing verification results
    """
    results = {
        "domain": domain,
        "checks": [],
        "passed": 0,
        "failed": 0,
        "warnings": 0
    }

    # Check 1: DNS Resolution
    dns_check = check_dns_resolution(domain)
    results["checks"].append(dns_check)
    if dns_check["status"] == "pass":
        results["passed"] += 1
    elif dns_check["status"] == "fail":
        results["failed"] += 1
    else:
        results["warnings"] += 1

    # Check 2: Multiple A records (Load balancing/redundancy)
    redundancy_check = check_redundancy(domain)
    results["checks"].append(redundancy_check)
    if redundancy_check["status"] == "pass":
        results["passed"] += 1
    elif redundancy_check["status"] == "fail":
        results["failed"] += 1
    else:
        results["warnings"] += 1

    # Check 3: MX Records (Email configuration)
    mx_check = check_mx_records(domain)
    results["checks"].append(mx_check)
    if mx_check["status"] == "pass":
        results["passed"] += 1
    elif mx_check["status"] == "fail":
        results["failed"] += 1
    else:
        results["warnings"] += 1

    # Check 4: SPF Record (Email security)
    spf_check = check_spf_record(domain)
    results["checks"].append(spf_check)
    if spf_check["status"] == "pass":
        results["passed"] += 1
    elif spf_check["status"] == "fail":
        results["failed"] += 1
    else:
        results["warnings"] += 1

    # Check 5: DMARC Record (Email security)
    dmarc_check = check_dmarc_record(domain)
    results["checks"].append(dmarc_check)
    if dmarc_check["status"] == "pass":
        results["passed"] += 1
    elif dmarc_check["status"] == "fail":
        results["failed"] += 1
    else:
        results["warnings"] += 1

    # Check 6: SSL Certificate
    ssl_check = check_ssl_certificate(domain)
    results["checks"].append(ssl_check)
    if ssl_check["status"] == "pass":
        results["passed"] += 1
    elif ssl_check["status"] == "fail":
        results["failed"] += 1
    else:
        results["warnings"] += 1

    # Check 7: Name servers
    ns_check = check_nameservers(domain)
    results["checks"].append(ns_check)
    if ns_check["status"] == "pass":
        results["passed"] += 1
    elif ns_check["status"] == "fail":
        results["failed"] += 1
    else:
        results["warnings"] += 1

    return results


def check_dns_resolution(domain: str) -> Dict[str, Any]:
    """Check if domain resolves to IP addresses."""
    check = {
        "name": "DNS Resolution",
        "status": "fail",
        "message": "",
        "details": []
    }

    try:
        result = dns_lookup.query_domain(domain, "A")
        a_records = result.get("records", {}).get("A", [])
        
        if a_records:
            check["status"] = "pass"
            check["message"] = f"Domain resolves to {len(a_records)} IP address(es)"
            check["details"] = a_records
        else:
            check["message"] = "Domain does not resolve to any IP addresses"
    except Exception as e:
        check["message"] = f"Error checking DNS resolution: {str(e)}"

    return check


def check_redundancy(domain: str) -> Dict[str, Any]:
    """Check for redundant A records."""
    check = {
        "name": "Redundancy Check",
        "status": "warning",
        "message": "",
        "details": []
    }

    try:
        result = dns_lookup.query_domain(domain, "A")
        a_records = result.get("records", {}).get("A", [])
        
        if len(a_records) > 1:
            check["status"] = "pass"
            check["message"] = f"Domain has {len(a_records)} A records (good for redundancy)"
        elif len(a_records) == 1:
            check["message"] = "Domain has only 1 A record (consider adding redundancy)"
        else:
            check["status"] = "fail"
            check["message"] = "No A records found"
        
        check["details"] = a_records
    except Exception as e:
        check["message"] = f"Error checking redundancy: {str(e)}"

    return check


def check_mx_records(domain: str) -> Dict[str, Any]:
    """Check for MX records."""
    check = {
        "name": "MX Records",
        "status": "fail",
        "message": "",
        "details": []
    }

    try:
        result = dns_lookup.query_domain(domain, "MX")
        mx_records = result.get("records", {}).get("MX", [])
        
        if mx_records:
            check["status"] = "pass"
            check["message"] = f"Domain has {len(mx_records)} MX record(s) configured"
            check["details"] = mx_records
        else:
            check["status"] = "warning"
            check["message"] = "No MX records found (email may not be configured)"
    except Exception as e:
        check["message"] = f"Error checking MX records: {str(e)}"

    return check


def check_spf_record(domain: str) -> Dict[str, Any]:
    """Check for SPF record in TXT records."""
    check = {
        "name": "SPF Record",
        "status": "fail",
        "message": "",
        "details": []
    }

    try:
        result = dns_lookup.query_domain(domain, "TXT")
        txt_records = result.get("records", {}).get("TXT", [])
        
        spf_records = [record for record in txt_records if "v=spf1" in record.lower()]
        
        if spf_records:
            check["status"] = "pass"
            check["message"] = "SPF record found (email security configured)"
            check["details"] = spf_records
        else:
            check["status"] = "warning"
            check["message"] = "No SPF record found (consider adding for email security)"
    except Exception as e:
        check["message"] = f"Error checking SPF record: {str(e)}"

    return check


def check_dmarc_record(domain: str) -> Dict[str, Any]:
    """Check for DMARC record."""
    check = {
        "name": "DMARC Record",
        "status": "fail",
        "message": "",
        "details": []
    }

    try:
        dmarc_domain = f"_dmarc.{domain}"
        result = dns_lookup.query_domain(dmarc_domain, "TXT")
        txt_records = result.get("records", {}).get("TXT", [])
        
        dmarc_records = [record for record in txt_records if "v=DMARC1" in record]
        
        if dmarc_records:
            check["status"] = "pass"
            check["message"] = "DMARC record found (email security configured)"
            check["details"] = dmarc_records
        else:
            check["status"] = "warning"
            check["message"] = "No DMARC record found (consider adding for email security)"
    except Exception as e:
        check["message"] = f"Error checking DMARC record: {str(e)}"

    return check


def check_ssl_certificate(domain: str) -> Dict[str, Any]:
    """Check SSL certificate validity."""
    check = {
        "name": "SSL Certificate",
        "status": "fail",
        "message": "",
        "details": []
    }

    try:
        result = ssl_checker.check_certificate(domain)
        
        if result.get("valid"):
            check["status"] = "pass"
            check["message"] = "Valid SSL certificate"
            
            cert = result.get("certificate", {})
            issuer = cert.get("issuer", {})
            check["details"].append(f"Issuer: {issuer.get('organizationName', 'Unknown')}")
            check["details"].append(f"Expires: {cert.get('not_after', 'Unknown')}")
        else:
            errors = result.get("errors", [])
            check["message"] = "SSL certificate issue detected"
            check["details"] = errors
    except Exception as e:
        check["message"] = f"Error checking SSL certificate: {str(e)}"

    return check


def check_nameservers(domain: str) -> Dict[str, Any]:
    """Check nameserver configuration."""
    check = {
        "name": "Name Servers",
        "status": "fail",
        "message": "",
        "details": []
    }

    try:
        nameservers = dns_lookup.get_nameservers(domain)
        
        if len(nameservers) >= 2:
            check["status"] = "pass"
            check["message"] = f"Domain has {len(nameservers)} nameserver(s) (good redundancy)"
        elif len(nameservers) == 1:
            check["status"] = "warning"
            check["message"] = "Domain has only 1 nameserver (consider adding redundancy)"
        else:
            check["message"] = "No nameservers found"
        
        check["details"] = nameservers
    except Exception as e:
        check["message"] = f"Error checking nameservers: {str(e)}"

    return check


def display_results(results: Dict[str, Any]) -> None:
    """
    Display verification results.

    Args:
        results: Dictionary containing verification results
    """
    domain = results.get("domain")
    checks = results.get("checks", [])
    passed = results.get("passed", 0)
    failed = results.get("failed", 0)
    warnings = results.get("warnings", 0)
    total = len(checks)

    print_success(f"\nDomain Verification Report: {domain}")
    print_info(f"\nTotal Checks: {total}")
    print_success(f"Passed: {passed}")
    print_error(f"Failed: {failed}")
    print_warning(f"Warnings: {warnings}")

    print_info("\n" + "=" * 60)

    for check in checks:
        name = check.get("name", "Unknown Check")
        status = check.get("status", "unknown")
        message = check.get("message", "")
        details = check.get("details", [])

        print_info(f"\n{name}:")
        
        if status == "pass":
            print_success(f"  ✓ {message}")
        elif status == "fail":
            print_error(f"  ✗ {message}")
        else:
            print_warning(f"  ⚠ {message}")

        if details:
            for detail in details:
                if isinstance(detail, dict):
                    for key, value in detail.items():
                        print_info(f"    {key}: {value}")
                else:
                    print_info(f"    {detail}")

    # Overall score
    print_info("\n" + "=" * 60)
    score_percentage = (passed / total * 100) if total > 0 else 0
    print_info(f"\nOverall Score: {score_percentage:.1f}%")
    
    if score_percentage >= 80:
        print_success("Excellent domain configuration!")
    elif score_percentage >= 60:
        print_info("Good domain configuration with some improvements needed")
    else:
        print_warning("Domain configuration needs attention")

