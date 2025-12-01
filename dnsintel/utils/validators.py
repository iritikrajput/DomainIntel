"""
Input validation utilities.
"""

import re
import ipaddress
from typing import Optional


def is_valid_domain(domain: str) -> bool:
    """
    Validate domain name format.

    Args:
        domain: Domain name to validate

    Returns:
        True if valid, False otherwise
    """
    if not domain or len(domain) > 253:
        return False

    # Remove trailing dot if present
    if domain.endswith("."):
        domain = domain[:-1]

    # Domain name regex pattern
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    
    return bool(re.match(pattern, domain))


def is_valid_ip(ip_address: str) -> bool:
    """
    Validate IP address (IPv4 or IPv6).

    Args:
        ip_address: IP address to validate

    Returns:
        True if valid, False otherwise
    """
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False


def is_valid_ipv4(ip_address: str) -> bool:
    """
    Validate IPv4 address.

    Args:
        ip_address: IP address to validate

    Returns:
        True if valid IPv4, False otherwise
    """
    try:
        ip = ipaddress.ip_address(ip_address)
        return isinstance(ip, ipaddress.IPv4Address)
    except ValueError:
        return False


def is_valid_ipv6(ip_address: str) -> bool:
    """
    Validate IPv6 address.

    Args:
        ip_address: IP address to validate

    Returns:
        True if valid IPv6, False otherwise
    """
    try:
        ip = ipaddress.ip_address(ip_address)
        return isinstance(ip, ipaddress.IPv6Address)
    except ValueError:
        return False


def is_valid_port(port: int) -> bool:
    """
    Validate port number.

    Args:
        port: Port number to validate

    Returns:
        True if valid (1-65535), False otherwise
    """
    return isinstance(port, int) and 1 <= port <= 65535


def is_valid_email(email: str) -> bool:
    """
    Validate email address format.

    Args:
        email: Email address to validate

    Returns:
        True if valid, False otherwise
    """
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))


def normalize_domain(domain: str) -> str:
    """
    Normalize domain name (remove protocol, trailing slash, etc.).

    Args:
        domain: Domain name to normalize

    Returns:
        Normalized domain name
    """
    # Remove protocol if present
    domain = re.sub(r"^https?://", "", domain)
    domain = re.sub(r"^ftp://", "", domain)
    
    # Remove www. prefix
    domain = re.sub(r"^www\.", "", domain)
    
    # Remove trailing slash
    domain = domain.rstrip("/")
    
    # Remove port if present
    domain = re.sub(r":\d+$", "", domain)
    
    # Remove path if present
    domain = domain.split("/")[0]
    
    return domain.lower()


def extract_domain_from_url(url: str) -> Optional[str]:
    """
    Extract domain from URL.

    Args:
        url: URL to extract domain from

    Returns:
        Domain name if found, None otherwise
    """
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split("/")[0]
        return normalize_domain(domain)
    except Exception:
        return None


def validate_dns_record_type(record_type: str) -> bool:
    """
    Validate DNS record type.

    Args:
        record_type: DNS record type to validate

    Returns:
        True if valid, False otherwise
    """
    valid_types = [
        "A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR", 
        "SRV", "CAA", "DNSKEY", "DS", "NAPTR", "ALL"
    ]
    return record_type.upper() in valid_types

