"""
SSL/TLS certificate checker functionality.
"""

import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from dnsintel.utils.output import print_info, print_success, print_error, print_warning


def get_utc_now() -> datetime:
    """Get current UTC time as naive datetime for comparison."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def check_certificate(domain: str, port: int = 443) -> Dict[str, Any]:
    """
    Check SSL/TLS certificate for a domain.

    Args:
        domain: Domain name to check
        port: Port number (default: 443)

    Returns:
        Dictionary containing certificate information
    """
    results = {
        "domain": domain,
        "port": port,
        "certificate": {},
        "valid": False,
        "errors": []
    }

    try:
        context = ssl.create_default_context()
        
        with socket.create_connection((domain, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Extract certificate information
                results["certificate"] = {
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "version": cert.get("version"),
                    "serial_number": cert.get("serialNumber"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "san": cert.get("subjectAltName", []),
                    "cipher": ssock.cipher(),
                    "protocol": ssock.version(),
                }
                
                # Check if certificate is valid
                not_after_str = cert.get("notAfter")
                not_before_str = cert.get("notBefore")
                
                if not_after_str and not_before_str:
                    not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                    not_before = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z")
                    now = get_utc_now()
                    
                    if not_before <= now <= not_after:
                        results["valid"] = True
                        
                        # Check if certificate is expiring soon
                        days_left = (not_after - now).days
                        if days_left < 30:
                            results["errors"].append(f"Certificate expires in {days_left} days")
                    else:
                        results["valid"] = False
                        if now < not_before:
                            results["errors"].append("Certificate is not yet valid")
                        else:
                            results["errors"].append("Certificate has expired")
                else:
                    results["errors"].append("Could not parse certificate dates")

    except ssl.SSLError as e:
        results["errors"].append(f"SSL error: {str(e)}")
    except socket.timeout:
        results["errors"].append("Connection timeout")
    except socket.gaierror:
        results["errors"].append("Could not resolve hostname")
    except Exception as e:
        results["errors"].append(f"Error: {str(e)}")

    return results


def get_certificate_chain(domain: str, port: int = 443) -> Optional[list]:
    """
    Get the certificate chain for a domain.

    Args:
        domain: Domain name
        port: Port number (default: 443)

    Returns:
        List of certificates in the chain
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                return ssock.getpeercert_chain()
    except Exception:
        return None


def display_results(results: Dict[str, Any]) -> None:
    """
    Display SSL certificate check results.

    Args:
        results: Dictionary containing certificate results
    """
    domain = results.get("domain")
    port = results.get("port")
    cert = results.get("certificate", {})
    valid = results.get("valid")
    errors = results.get("errors", [])

    if not cert and errors:
        print_error("\nSSL Certificate Check Failed:")
        for error in errors:
            print_error(f"  {error}")
        return

    print_success(f"\nSSL Certificate for {domain}:{port}")
    
    # Validity status
    if valid:
        print_success("\n  ✓ Certificate is valid")
    else:
        print_error("\n  ✗ Certificate is NOT valid")
    
    # Subject information
    subject = cert.get("subject", {})
    if subject:
        print_success("\nSubject:")
        for key, value in subject.items():
            print_info(f"  {key}: {value}")
    
    # Issuer information
    issuer = cert.get("issuer", {})
    if issuer:
        print_success("\nIssuer:")
        for key, value in issuer.items():
            print_info(f"  {key}: {value}")
    
    # Validity period
    print_success("\nValidity Period:")
    print_info(f"  Not Before: {cert.get('not_before', 'N/A')}")
    print_info(f"  Not After: {cert.get('not_after', 'N/A')}")
    
    # Calculate days until expiration
    try:
        not_after_str = cert.get("not_after")
        if not_after_str:
            not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (not_after - get_utc_now()).days
            if days_left < 30:
                print_warning(f"  WARNING: Expires in {days_left} days!")
            else:
                print_info(f"  Days until expiration: {days_left}")
    except Exception:
        pass
    
    # Subject Alternative Names
    san = cert.get("san", [])
    if san:
        print_success("\nSubject Alternative Names:")
        for item in san:
            print_info(f"  {item[0]}: {item[1]}")
    
    # Connection details
    cipher = cert.get("cipher")
    if cipher:
        print_success("\nConnection Details:")
        print_info(f"  Protocol: {cert.get('protocol', 'N/A')}")
        print_info(f"  Cipher: {cipher[0]}")
        print_info(f"  Cipher Version: {cipher[1]}")
        print_info(f"  Cipher Bits: {cipher[2]}")
    
    # Additional info
    print_success("\nCertificate Details:")
    print_info(f"  Version: {cert.get('version', 'N/A')}")
    print_info(f"  Serial Number: {cert.get('serial_number', 'N/A')}")
    
    # Display warnings/errors
    if errors:
        print_warning("\nWarnings:")
        for error in errors:
            print_warning(f"  {error}")

