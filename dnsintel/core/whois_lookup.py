"""
WHOIS lookup functionality.
"""

import whois
from typing import Dict, Any, Optional
from datetime import datetime

from dnsintel.utils.output import print_info, print_success, print_error


def get_naive_datetime(dt: datetime) -> datetime:
    """
    Convert datetime to naive (timezone-unaware) datetime.
    
    Args:
        dt: datetime object (can be aware or naive)
    
    Returns:
        Timezone-naive datetime
    """
    if dt.tzinfo is not None:
        # Convert to UTC then remove timezone info
        return dt.replace(tzinfo=None)
    return dt


def get_whois(domain: str) -> Dict[str, Any]:
    """
    Perform WHOIS lookup for a domain.

    Args:
        domain: Domain name to query

    Returns:
        Dictionary containing WHOIS information
    """
    results = {
        "domain": domain,
        "data": {},
        "error": None
    }

    try:
        w = whois.whois(domain)
        
        results["data"] = {
            "domain_name": w.domain_name if hasattr(w, 'domain_name') else None,
            "registrar": w.registrar if hasattr(w, 'registrar') else None,
            "creation_date": w.creation_date if hasattr(w, 'creation_date') else None,
            "expiration_date": w.expiration_date if hasattr(w, 'expiration_date') else None,
            "updated_date": w.updated_date if hasattr(w, 'updated_date') else None,
            "status": w.status if hasattr(w, 'status') else None,
            "name_servers": w.name_servers if hasattr(w, 'name_servers') else None,
            "registrant_name": w.name if hasattr(w, 'name') else None,
            "registrant_org": w.org if hasattr(w, 'org') else None,
            "registrant_email": w.email if hasattr(w, 'email') else None,
            "registrant_country": w.country if hasattr(w, 'country') else None,
        }

    except Exception as e:
        results["error"] = str(e)

    return results


def format_date(date_value: Any) -> str:
    """
    Format date value for display.

    Args:
        date_value: Date value (can be datetime, list, or string)

    Returns:
        Formatted date string
    """
    if date_value is None:
        return "N/A"
    
    if isinstance(date_value, list):
        date_value = date_value[0] if date_value else None
    
    if isinstance(date_value, datetime):
        return date_value.strftime("%Y-%m-%d %H:%M:%S")
    
    return str(date_value)


def format_list(list_value: Any) -> str:
    """
    Format list value for display.

    Args:
        list_value: List value

    Returns:
        Formatted string
    """
    if list_value is None:
        return "N/A"
    
    if isinstance(list_value, list):
        return ", ".join(str(item) for item in list_value)
    
    return str(list_value)


def display_results(results: Dict[str, Any]) -> None:
    """
    Display WHOIS results in a formatted manner.

    Args:
        results: Dictionary containing WHOIS results
    """
    if results.get("error"):
        print_error(f"WHOIS lookup failed: {results['error']}")
        return

    data = results.get("data", {})
    
    if not data:
        print_error("No WHOIS data available")
        return

    print_success("\nDomain Information:")
    print_info(f"  Domain Name: {format_list(data.get('domain_name'))}")
    print_info(f"  Registrar: {data.get('registrar', 'N/A')}")
    
    print_success("\nImportant Dates:")
    print_info(f"  Created: {format_date(data.get('creation_date'))}")
    print_info(f"  Updated: {format_date(data.get('updated_date'))}")
    print_info(f"  Expires: {format_date(data.get('expiration_date'))}")
    
    # Calculate days until expiration
    expiration = data.get('expiration_date')
    if expiration:
        if isinstance(expiration, list):
            expiration = expiration[0]
        if isinstance(expiration, datetime):
            try:
                # Handle timezone-aware vs naive datetime comparison
                exp_naive = get_naive_datetime(expiration)
                now_naive = datetime.now()
                days_left = (exp_naive - now_naive).days
                if days_left < 30:
                    print_error(f"  WARNING: Domain expires in {days_left} days!")
                else:
                    print_info(f"  Days until expiration: {days_left}")
            except Exception:
                # If calculation fails, just skip showing days left
                pass
    
    print_success("\nStatus:")
    status = data.get('status')
    if status:
        if isinstance(status, list):
            for s in status:
                print_info(f"  {s}")
        else:
            print_info(f"  {status}")
    else:
        print_info("  N/A")
    
    print_success("\nName Servers:")
    nameservers = data.get('name_servers')
    if nameservers:
        if isinstance(nameservers, list):
            for ns in nameservers:
                print_info(f"  {ns}")
        else:
            print_info(f"  {nameservers}")
    else:
        print_info("  N/A")
    
    print_success("\nRegistrant Information:")
    print_info(f"  Name: {data.get('registrant_name', 'N/A')}")
    print_info(f"  Organization: {data.get('registrant_org', 'N/A')}")
    print_info(f"  Email: {data.get('registrant_email', 'N/A')}")
    print_info(f"  Country: {data.get('registrant_country', 'N/A')}")

