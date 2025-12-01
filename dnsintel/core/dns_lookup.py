"""
DNS lookup functionality.
"""

import dns.resolver
import dns.reversename
from typing import Dict, List, Any, Optional

from dnsintel.utils.output import print_info, print_success, print_error


def query_domain(domain: str, record_type: str = "A") -> Dict[str, Any]:
    """
    Query DNS records for a domain.

    Args:
        domain: Domain name to query
        record_type: DNS record type (A, AAAA, MX, NS, TXT, CNAME, SOA, PTR, ALL)

    Returns:
        Dictionary containing DNS query results
    """
    results = {
        "domain": domain,
        "records": {},
        "errors": []
    }

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"] if record_type == "ALL" else [record_type]

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records = []

            for rdata in answers:
                if rtype == "MX":
                    records.append({
                        "priority": rdata.preference,
                        "exchange": str(rdata.exchange)
                    })
                elif rtype == "SOA":
                    records.append({
                        "mname": str(rdata.mname),
                        "rname": str(rdata.rname),
                        "serial": rdata.serial,
                        "refresh": rdata.refresh,
                        "retry": rdata.retry,
                        "expire": rdata.expire,
                        "minimum": rdata.minimum
                    })
                else:
                    records.append(str(rdata))

            results["records"][rtype] = records

        except dns.resolver.NoAnswer:
            results["errors"].append(f"No {rtype} records found")
        except dns.resolver.NXDOMAIN:
            results["errors"].append(f"Domain does not exist")
            break
        except dns.resolver.Timeout:
            results["errors"].append(f"DNS query timeout for {rtype}")
        except Exception as e:
            results["errors"].append(f"Error querying {rtype}: {str(e)}")

    return results


def reverse_lookup(ip_address: str) -> Optional[str]:
    """
    Perform reverse DNS lookup for an IP address.

    Args:
        ip_address: IP address to look up

    Returns:
        Hostname if found, None otherwise
    """
    try:
        reverse_name = dns.reversename.from_address(ip_address)
        answers = dns.resolver.resolve(reverse_name, "PTR")
        return str(answers[0]) if answers else None
    except Exception:
        return None


def get_nameservers(domain: str) -> List[str]:
    """
    Get nameservers for a domain.

    Args:
        domain: Domain name

    Returns:
        List of nameserver addresses
    """
    try:
        answers = dns.resolver.resolve(domain, "NS")
        return [str(rdata) for rdata in answers]
    except Exception:
        return []


def get_mx_records(domain: str) -> List[Dict[str, Any]]:
    """
    Get MX (Mail Exchange) records for a domain.

    Args:
        domain: Domain name to query

    Returns:
        List of MX records with priority and exchange server
    """
    mx_records = []
    try:
        answers = dns.resolver.resolve(domain, "MX")
        for rdata in answers:
            mx_records.append({
                "priority": rdata.preference,
                "exchange": str(rdata.exchange).rstrip('.'),
                "hostname": str(rdata.exchange).rstrip('.')
            })
        # Sort by priority (lower number = higher priority)
        mx_records.sort(key=lambda x: x['priority'])
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.NXDOMAIN:
        pass
    except Exception:
        pass
    
    return mx_records


def check_mail_configuration(domain: str) -> Dict[str, Any]:
    """
    Check email configuration for a domain (MX, SPF, DMARC).

    Args:
        domain: Domain name to check

    Returns:
        Dictionary containing mail configuration details
    """
    config = {
        "domain": domain,
        "mx_records": [],
        "spf_record": None,
        "dmarc_record": None,
        "has_mail": False,
        "issues": []
    }

    # Check MX records
    mx_records = get_mx_records(domain)
    config["mx_records"] = mx_records
    config["has_mail"] = len(mx_records) > 0

    if not mx_records:
        config["issues"].append("No MX records found - email delivery may not work")

    # Check SPF record
    try:
        txt_records = dns.resolver.resolve(domain, "TXT")
        for txt in txt_records:
            txt_str = str(txt).strip('"')
            if txt_str.startswith("v=spf1"):
                config["spf_record"] = txt_str
                break
        
        if not config["spf_record"]:
            config["issues"].append("No SPF record found - email may be marked as spam")
    except Exception:
        config["issues"].append("Could not check SPF record")

    # Check DMARC record
    try:
        dmarc_domain = f"_dmarc.{domain}"
        txt_records = dns.resolver.resolve(dmarc_domain, "TXT")
        for txt in txt_records:
            txt_str = str(txt).strip('"')
            if txt_str.startswith("v=DMARC1"):
                config["dmarc_record"] = txt_str
                break
        
        if not config["dmarc_record"]:
            config["issues"].append("No DMARC record found - email security not configured")
    except Exception:
        config["issues"].append("Could not check DMARC record")

    return config


def display_results(results: Dict[str, Any], record_type: str = "A") -> None:
    """
    Display DNS query results in a formatted manner.

    Args:
        results: Dictionary containing DNS query results
        record_type: Type of DNS record queried
    """
    domain = results.get("domain", "Unknown")
    records = results.get("records", {})
    errors = results.get("errors", [])

    if not records and not errors:
        print_error("No results found")
        return

    # Display records
    for rtype, rdata in records.items():
        print_success(f"\n{rtype} Records:")
        
        if not rdata:
            print_info("  No records found")
            continue

        if rtype == "MX":
            for record in rdata:
                print_info(f"  Priority: {record['priority']}, Server: {record['exchange']}")
        elif rtype == "SOA":
            for record in rdata:
                print_info(f"  Primary NS: {record['mname']}")
                print_info(f"  Admin Email: {record['rname']}")
                print_info(f"  Serial: {record['serial']}")
                print_info(f"  Refresh: {record['refresh']}s")
                print_info(f"  Retry: {record['retry']}s")
                print_info(f"  Expire: {record['expire']}s")
                print_info(f"  Minimum TTL: {record['minimum']}s")
        else:
            for record in rdata:
                print_info(f"  {record}")

    # Display errors if any
    if errors:
        print_error("\nErrors encountered:")
        for error in errors:
            print_error(f"  {error}")

