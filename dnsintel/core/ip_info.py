"""
IP address information and geolocation functionality.
"""

import requests
from typing import Dict, Any, Optional

from dnsintel.utils.output import print_info, print_success, print_error


def get_ip_info(ip_address: str) -> Dict[str, Any]:
    """
    Get information about an IP address using ip-api.com.

    Args:
        ip_address: IP address to query

    Returns:
        Dictionary containing IP information
    """
    results = {
        "ip": ip_address,
        "data": {},
        "error": None
    }

    try:
        # Using ip-api.com free API (no key required)
        url = f"http://ip-api.com/json/{ip_address}"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        
        if data.get("status") == "success":
            results["data"] = {
                "ip": data.get("query"),
                "country": data.get("country"),
                "country_code": data.get("countryCode"),
                "region": data.get("regionName"),
                "region_code": data.get("region"),
                "city": data.get("city"),
                "zip": data.get("zip"),
                "latitude": data.get("lat"),
                "longitude": data.get("lon"),
                "timezone": data.get("timezone"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "as": data.get("as"),
            }
        else:
            results["error"] = data.get("message", "Failed to retrieve IP information")

    except requests.RequestException as e:
        results["error"] = f"Network error: {str(e)}"
    except Exception as e:
        results["error"] = f"Error: {str(e)}"

    return results


def get_reverse_dns(ip_address: str) -> Optional[str]:
    """
    Get reverse DNS for an IP address.

    Args:
        ip_address: IP address

    Returns:
        Hostname if found, None otherwise
    """
    from dnsintel.core.dns_lookup import reverse_lookup
    return reverse_lookup(ip_address)


def is_private_ip(ip_address: str) -> bool:
    """
    Check if an IP address is private.

    Args:
        ip_address: IP address to check

    Returns:
        True if IP is private, False otherwise
    """
    import ipaddress
    try:
        ip = ipaddress.ip_address(ip_address)
        return ip.is_private
    except ValueError:
        return False


def display_results(results: Dict[str, Any]) -> None:
    """
    Display IP information results.

    Args:
        results: Dictionary containing IP information
    """
    if results.get("error"):
        print_error(f"IP lookup failed: {results['error']}")
        return

    data = results.get("data", {})
    
    if not data:
        print_error("No IP information available")
        return

    ip = data.get("ip", results.get("ip"))
    
    print_success(f"\nIP Address Information: {ip}")
    
    # Check if private IP
    if is_private_ip(ip):
        print_info("\n  Note: This is a private IP address")
    
    print_success("\nGeographic Location:")
    print_info(f"  Country: {data.get('country', 'N/A')} ({data.get('country_code', 'N/A')})")
    print_info(f"  Region: {data.get('region', 'N/A')} ({data.get('region_code', 'N/A')})")
    print_info(f"  City: {data.get('city', 'N/A')}")
    print_info(f"  Zip Code: {data.get('zip', 'N/A')}")
    print_info(f"  Timezone: {data.get('timezone', 'N/A')}")
    
    lat = data.get('latitude')
    lon = data.get('longitude')
    if lat and lon:
        print_info(f"  Coordinates: {lat}, {lon}")
        print_info(f"  Map: https://www.google.com/maps?q={lat},{lon}")
    
    print_success("\nNetwork Information:")
    print_info(f"  ISP: {data.get('isp', 'N/A')}")
    print_info(f"  Organization: {data.get('org', 'N/A')}")
    print_info(f"  AS: {data.get('as', 'N/A')}")
    
    # Try to get reverse DNS
    print_success("\nReverse DNS:")
    hostname = get_reverse_dns(ip)
    if hostname:
        print_info(f"  Hostname: {hostname}")
    else:
        print_info("  No PTR record found")

