"""
DNSIntel - A comprehensive DNS intelligence and reconnaissance tool.
"""

__version__ = "0.1.0"
__author__ = "Your Name"
__email__ = "your.email@example.com"

from dnsintel.core import dns_lookup, whois_lookup, ssl_checker, ip_info, verifier

__all__ = [
    "dns_lookup",
    "whois_lookup",
    "ssl_checker",
    "ip_info",
    "verifier",
]

