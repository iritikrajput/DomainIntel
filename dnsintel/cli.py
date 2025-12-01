#!/usr/bin/env python3
"""
Command-line interface for DNSIntel.
"""

import argparse
import sys

from dnsintel.core import dns_lookup, whois_lookup, ssl_checker, ip_info, verifier
from dnsintel.utils.output import print_header, print_success, print_error, print_info, print_warning
from dnsintel.utils.validators import is_valid_domain, is_valid_ip


def setup_parser() -> argparse.ArgumentParser:
    """Set up command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="dnsintel",
        description="DNS Intelligence and Reconnaissance Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--version", action="version", version="%(prog)s 0.1.0")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # DNS lookup command
    dns_parser = subparsers.add_parser("dns", help="Perform DNS lookup")
    dns_parser.add_argument("domain", help="Domain name to query")
    dns_parser.add_argument(
        "-t",
        "--type",
        default="A",
        choices=["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR", "ALL"],
        help="DNS record type (default: A)",
    )

    # MX records command
    mx_parser = subparsers.add_parser("mx", help="Check MX (mail) records")
    mx_parser.add_argument("domain", help="Domain name to check")
    mx_parser.add_argument(
        "--full",
        action="store_true",
        help="Show full email configuration (MX, SPF, DMARC)"
    )

    # WHOIS lookup command
    whois_parser = subparsers.add_parser("whois", help="Perform WHOIS lookup")
    whois_parser.add_argument("domain", help="Domain name to query")

    # SSL certificate check command
    ssl_parser = subparsers.add_parser("ssl", help="Check SSL certificate")
    ssl_parser.add_argument("domain", help="Domain name to check")
    ssl_parser.add_argument("-p", "--port", type=int, default=443, help="Port (default: 443)")

    # IP information command
    ip_parser = subparsers.add_parser("ip", help="Get IP address information")
    ip_parser.add_argument("ip_address", help="IP address to query")

    # Domain verification command
    verify_parser = subparsers.add_parser("verify", help="Verify domain configuration")
    verify_parser.add_argument("domain", help="Domain name to verify")

    # All-in-one command
    all_parser = subparsers.add_parser("all", help="Get all available information")
    all_parser.add_argument("target", help="Domain name or IP address")

    return parser


def handle_dns_command(args: argparse.Namespace) -> int:
    """Handle DNS lookup command."""
    if not is_valid_domain(args.domain):
        print_error(f"Invalid domain name: {args.domain}")
        return 1

    print_header(f"DNS Lookup: {args.domain}")
    try:
        results = dns_lookup.query_domain(args.domain, args.type)
        dns_lookup.display_results(results, args.type)
        return 0
    except Exception as e:
        print_error(f"DNS lookup failed: {e}")
        return 1


def handle_mx_command(args: argparse.Namespace) -> int:
    """Handle MX records command."""
    if not is_valid_domain(args.domain):
        print_error(f"Invalid domain name: {args.domain}")
        return 1

    print_header(f"MX Records Check: {args.domain}")
    
    try:
        if args.full:
            # Show full email configuration
            config = dns_lookup.check_mail_configuration(args.domain)
            
            # Display MX records
            mx_records = config.get("mx_records", [])
            if mx_records:
                print_success("\nMX Records Found:")
                for i, mx in enumerate(mx_records, 1):
                    print_info(f"  {i}. Priority: {mx['priority']:3d} → {mx['exchange']}")
            else:
                print_error("\nNo MX records found!")
                print_info("  This domain may not be configured to receive email.")
            
            # Display SPF
            print_success("\nSPF Record:")
            spf = config.get("spf_record")
            if spf:
                print_info(f"  {spf}")
            else:
                print_warning("  No SPF record found")
            
            # Display DMARC
            print_success("\nDMARC Record:")
            dmarc = config.get("dmarc_record")
            if dmarc:
                print_info(f"  {dmarc}")
            else:
                print_warning("  No DMARC record found")
            
            # Display issues
            issues = config.get("issues", [])
            if issues:
                print_warning("\nConfiguration Issues:")
                for issue in issues:
                    print_warning(f"  ⚠ {issue}")
            else:
                print_success("\n✓ Email configuration looks good!")
        else:
            # Show just MX records
            mx_records = dns_lookup.get_mx_records(args.domain)
            
            if mx_records:
                print_success(f"\nFound {len(mx_records)} MX record(s):\n")
                for i, mx in enumerate(mx_records, 1):
                    print_info(f"  {i}. Priority: {mx['priority']:3d} → {mx['exchange']}")
                
                print_info(f"\n  Tip: Use 'dnsintel mx {args.domain} --full' for complete email configuration")
            else:
                print_error("\nNo MX records found!")
                print_info("  This domain may not be configured to receive email.")
                return 1
        
        return 0
        
    except Exception as e:
        print_error(f"MX lookup failed: {e}")
        return 1


def handle_whois_command(args: argparse.Namespace) -> int:
    """Handle WHOIS lookup command."""
    if not is_valid_domain(args.domain):
        print_error(f"Invalid domain name: {args.domain}")
        return 1

    print_header(f"WHOIS Lookup: {args.domain}")
    try:
        results = whois_lookup.get_whois(args.domain)
        whois_lookup.display_results(results)
        return 0
    except Exception as e:
        print_error(f"WHOIS lookup failed: {e}")
        return 1


def handle_ssl_command(args: argparse.Namespace) -> int:
    """Handle SSL certificate check command."""
    if not is_valid_domain(args.domain):
        print_error(f"Invalid domain name: {args.domain}")
        return 1

    print_header(f"SSL Certificate Check: {args.domain}:{args.port}")
    try:
        results = ssl_checker.check_certificate(args.domain, args.port)
        ssl_checker.display_results(results)
        return 0
    except Exception as e:
        print_error(f"SSL check failed: {e}")
        return 1


def handle_ip_command(args: argparse.Namespace) -> int:
    """Handle IP information command."""
    if not is_valid_ip(args.ip_address):
        print_error(f"Invalid IP address: {args.ip_address}")
        return 1

    print_header(f"IP Information: {args.ip_address}")
    try:
        results = ip_info.get_ip_info(args.ip_address)
        ip_info.display_results(results)
        return 0
    except Exception as e:
        print_error(f"IP lookup failed: {e}")
        return 1


def handle_verify_command(args: argparse.Namespace) -> int:
    """Handle domain verification command."""
    if not is_valid_domain(args.domain):
        print_error(f"Invalid domain name: {args.domain}")
        return 1

    print_header(f"Domain Verification: {args.domain}")
    try:
        results = verifier.verify_domain(args.domain)
        verifier.display_results(results)
        return 0
    except Exception as e:
        print_error(f"Verification failed: {e}")
        return 1


def handle_all_command(args: argparse.Namespace) -> int:
    """Handle all-in-one command."""
    target = args.target
    
    print_header(f"Complete Intelligence Report: {target}")
    print_info("This may take a moment...\n")

    exit_code = 0

    # Try DNS lookup
    if is_valid_domain(target):
        try:
            print_header("DNS Records")
            results = dns_lookup.query_domain(target, "ALL")
            dns_lookup.display_results(results, "ALL")
        except Exception as e:
            print_error(f"DNS lookup failed: {e}")
            exit_code = 1

        # WHOIS lookup
        try:
            print_header("WHOIS Information")
            results = whois_lookup.get_whois(target)
            whois_lookup.display_results(results)
        except Exception as e:
            print_error(f"WHOIS lookup failed: {e}")

        # SSL check
        try:
            print_header("SSL Certificate")
            results = ssl_checker.check_certificate(target)
            ssl_checker.display_results(results)
        except Exception as e:
            print_error(f"SSL check failed: {e}")

        # Domain verification
        try:
            print_header("Domain Verification")
            results = verifier.verify_domain(target)
            verifier.display_results(results)
        except Exception as e:
            print_error(f"Verification failed: {e}")

    elif is_valid_ip(target):
        try:
            results = ip_info.get_ip_info(target)
            ip_info.display_results(results)
        except Exception as e:
            print_error(f"IP lookup failed: {e}")
            exit_code = 1
    else:
        print_error(f"Invalid target: {target}")
        return 1

    return exit_code


def main() -> None:
    """Main entry point for the CLI."""
    parser = setup_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    # Command handlers
    handlers = {
        "dns": handle_dns_command,
        "mx": handle_mx_command,
        "whois": handle_whois_command,
        "ssl": handle_ssl_command,
        "ip": handle_ip_command,
        "verify": handle_verify_command,
        "all": handle_all_command,
    }

    handler = handlers.get(args.command)
    if handler:
        exit_code = handler(args)
        sys.exit(exit_code)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()

