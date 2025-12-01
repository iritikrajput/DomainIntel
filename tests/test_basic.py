"""
Basic tests for DNSIntel package.
"""

import pytest
from dnsintel.utils.validators import (
    is_valid_domain,
    is_valid_ip,
    is_valid_ipv4,
    is_valid_ipv6,
    is_valid_port,
    is_valid_email,
    normalize_domain,
    validate_dns_record_type,
)


class TestValidators:
    """Test validator functions."""

    def test_valid_domain(self):
        """Test valid domain validation."""
        assert is_valid_domain("example.com") is True
        assert is_valid_domain("subdomain.example.com") is True
        assert is_valid_domain("test-domain.co.uk") is True
        assert is_valid_domain("example.co") is True

    def test_invalid_domain(self):
        """Test invalid domain validation."""
        assert is_valid_domain("") is False
        assert is_valid_domain("invalid") is False
        assert is_valid_domain("invalid..com") is False
        assert is_valid_domain("-invalid.com") is False
        assert is_valid_domain("invalid-.com") is False
        assert is_valid_domain("192.168.1.1") is False

    def test_valid_ipv4(self):
        """Test valid IPv4 validation."""
        assert is_valid_ip("192.168.1.1") is True
        assert is_valid_ip("8.8.8.8") is True
        assert is_valid_ip("127.0.0.1") is True
        assert is_valid_ipv4("192.168.1.1") is True

    def test_valid_ipv6(self):
        """Test valid IPv6 validation."""
        assert is_valid_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334") is True
        assert is_valid_ip("::1") is True
        assert is_valid_ip("fe80::1") is True
        assert is_valid_ipv6("2001:db8::1") is True

    def test_invalid_ip(self):
        """Test invalid IP validation."""
        assert is_valid_ip("") is False
        assert is_valid_ip("256.256.256.256") is False
        assert is_valid_ip("invalid") is False
        assert is_valid_ip("192.168.1") is False

    def test_valid_port(self):
        """Test valid port validation."""
        assert is_valid_port(80) is True
        assert is_valid_port(443) is True
        assert is_valid_port(1) is True
        assert is_valid_port(65535) is True

    def test_invalid_port(self):
        """Test invalid port validation."""
        assert is_valid_port(0) is False
        assert is_valid_port(65536) is False
        assert is_valid_port(-1) is False
        assert is_valid_port("80") is False

    def test_valid_email(self):
        """Test valid email validation."""
        assert is_valid_email("test@example.com") is True
        assert is_valid_email("user.name@example.co.uk") is True
        assert is_valid_email("user+tag@example.com") is True

    def test_invalid_email(self):
        """Test invalid email validation."""
        assert is_valid_email("") is False
        assert is_valid_email("invalid") is False
        assert is_valid_email("@example.com") is False
        assert is_valid_email("user@") is False
        assert is_valid_email("user@.com") is False

    def test_normalize_domain(self):
        """Test domain normalization."""
        assert normalize_domain("https://example.com") == "example.com"
        assert normalize_domain("http://www.example.com/") == "example.com"
        assert normalize_domain("example.com:443") == "example.com"
        assert normalize_domain("example.com/path") == "example.com"
        assert normalize_domain("EXAMPLE.COM") == "example.com"

    def test_validate_dns_record_type(self):
        """Test DNS record type validation."""
        assert validate_dns_record_type("A") is True
        assert validate_dns_record_type("AAAA") is True
        assert validate_dns_record_type("MX") is True
        assert validate_dns_record_type("a") is True  # Case insensitive
        assert validate_dns_record_type("INVALID") is False
        assert validate_dns_record_type("") is False


class TestDNSLookup:
    """Test DNS lookup functionality."""

    def test_import_dns_lookup(self):
        """Test importing dns_lookup module."""
        from dnsintel.core import dns_lookup
        assert hasattr(dns_lookup, "query_domain")
        assert hasattr(dns_lookup, "reverse_lookup")
        assert hasattr(dns_lookup, "get_nameservers")
        assert hasattr(dns_lookup, "get_mx_records")
        assert hasattr(dns_lookup, "check_mail_configuration")

    def test_mx_records_structure(self):
        """Test MX records return proper structure."""
        from dnsintel.core import dns_lookup
        
        # Test with a known domain (gmail.com has MX records)
        mx_records = dns_lookup.get_mx_records("gmail.com")
        
        # Should return a list
        assert isinstance(mx_records, list)
        
        # If records found, check structure
        if mx_records:
            for mx in mx_records:
                assert isinstance(mx, dict)
                assert "priority" in mx
                assert "exchange" in mx
                assert isinstance(mx["priority"], int)
                assert isinstance(mx["exchange"], str)

    def test_mail_configuration_structure(self):
        """Test mail configuration check returns proper structure."""
        from dnsintel.core import dns_lookup
        
        config = dns_lookup.check_mail_configuration("example.com")
        
        # Check structure
        assert isinstance(config, dict)
        assert "domain" in config
        assert "mx_records" in config
        assert "spf_record" in config
        assert "dmarc_record" in config
        assert "has_mail" in config
        assert "issues" in config
        
        # Check types
        assert isinstance(config["mx_records"], list)
        assert isinstance(config["has_mail"], bool)
        assert isinstance(config["issues"], list)


class TestWhoisLookup:
    """Test WHOIS lookup functionality."""

    def test_import_whois_lookup(self):
        """Test importing whois_lookup module."""
        from dnsintel.core import whois_lookup
        assert hasattr(whois_lookup, "get_whois")
        assert hasattr(whois_lookup, "display_results")


class TestSSLChecker:
    """Test SSL checker functionality."""

    def test_import_ssl_checker(self):
        """Test importing ssl_checker module."""
        from dnsintel.core import ssl_checker
        assert hasattr(ssl_checker, "check_certificate")
        assert hasattr(ssl_checker, "display_results")


class TestIPInfo:
    """Test IP info functionality."""

    def test_import_ip_info(self):
        """Test importing ip_info module."""
        from dnsintel.core import ip_info
        assert hasattr(ip_info, "get_ip_info")
        assert hasattr(ip_info, "display_results")
        assert hasattr(ip_info, "is_private_ip")

    def test_is_private_ip(self):
        """Test private IP detection."""
        from dnsintel.core.ip_info import is_private_ip
        
        # Private IPs
        assert is_private_ip("192.168.1.1") is True
        assert is_private_ip("10.0.0.1") is True
        assert is_private_ip("172.16.0.1") is True
        assert is_private_ip("127.0.0.1") is True
        
        # Public IPs
        assert is_private_ip("8.8.8.8") is False
        assert is_private_ip("1.1.1.1") is False


class TestVerifier:
    """Test domain verifier functionality."""

    def test_import_verifier(self):
        """Test importing verifier module."""
        from dnsintel.core import verifier
        assert hasattr(verifier, "verify_domain")
        assert hasattr(verifier, "display_results")


class TestPackage:
    """Test package-level functionality."""

    def test_package_import(self):
        """Test importing the main package."""
        import dnsintel
        assert hasattr(dnsintel, "__version__")
        assert hasattr(dnsintel, "dns_lookup")
        assert hasattr(dnsintel, "whois_lookup")
        assert hasattr(dnsintel, "ssl_checker")
        assert hasattr(dnsintel, "ip_info")
        assert hasattr(dnsintel, "verifier")

    def test_version(self):
        """Test package version."""
        import dnsintel
        assert dnsintel.__version__ == "0.1.0"

