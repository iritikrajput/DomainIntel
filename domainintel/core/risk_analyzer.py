"""
Phishing risk analysis and probability calculation.
"""

import re
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple, Optional
from difflib import SequenceMatcher

from domainintel.core import dns_lookup, whois_lookup, ssl_checker
from domainintel.utils.output import print_info, print_success, print_error, print_warning


# Known brand names for typosquatting detection
KNOWN_BRANDS = [
    "google", "facebook", "amazon", "apple", "microsoft", "netflix", "paypal",
    "instagram", "twitter", "linkedin", "whatsapp", "youtube", "dropbox",
    "adobe", "spotify", "uber", "airbnb", "ebay", "walmart", "target",
    "chase", "wellsfargo", "bankofamerica", "citibank", "hsbc", "barclays",
    "santander", "americanexpress", "mastercard", "visa", "coinbase", "binance",
    "blockchain", "metamask", "opensea", "discord", "slack", "zoom", "teams",
    "outlook", "office365", "icloud", "gmail", "yahoo", "hotmail", "protonmail",
    "fedex", "ups", "usps", "dhl", "alibaba", "aliexpress", "shopify",
    "wordpress", "godaddy", "cloudflare", "heroku", "github", "gitlab",
    "bitbucket", "steam", "epic", "playstation", "xbox", "nintendo", "roblox",
    "tiktok", "snapchat", "reddit", "telegram", "signal", "viber", "skype",
]

# Suspicious keywords often found in phishing domains
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "logon", "secure", "security", "verify",
    "verification", "confirm", "confirmation", "update", "validate", "account",
    "password", "credential", "authenticate", "auth", "banking", "wallet",
    "payment", "invoice", "billing", "support", "helpdesk", "service",
    "customer", "client", "alert", "warning", "suspend", "suspended", "locked",
    "unlock", "restore", "recover", "recovery", "reset", "urgent", "immediate",
    "action", "required", "限时", "免费", "promo", "gift", "winner", "prize",
    "claim", "reward", "bonus", "offer", "deal", "discount", "free",
]

# High-risk TLDs often associated with abuse
HIGH_RISK_TLDS = [
    "tk", "ml", "ga", "cf", "gq",  # Free TLDs
    "xyz", "top", "work", "click", "link", "surf", "rest", "fit",
    "icu", "buzz", "monster", "cam", "quest", "beauty", "hair",
    "sbs", "cfd", "cyou", "boats", "stream", "download", "racing",
]

# Trusted TLDs
TRUSTED_TLDS = [
    "gov", "edu", "mil", "int",  # Government/Educational
    "bank", "insurance",  # Verified industries
]

# Risk weights for each factor
RISK_WEIGHTS = {
    "domain_age": 15,
    "whois_privacy": 10,
    "ssl_validity": 15,
    "ssl_issuer": 10,
    "typosquatting": 20,
    "suspicious_keywords": 15,
    "tld_reputation": 10,
    "email_security": 10,
    "dns_anomalies": 10,
    "entropy": 5,
}


def calculate_string_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    from collections import Counter
    import math
    
    if not s:
        return 0.0
    
    counter = Counter(s.lower())
    length = len(s)
    entropy = -sum((count / length) * math.log2(count / length) for count in counter.values())
    return entropy


def levenshtein_similarity(s1: str, s2: str) -> float:
    """Calculate similarity ratio between two strings."""
    return SequenceMatcher(None, s1.lower(), s2.lower()).ratio()


def check_typosquatting(domain: str) -> Tuple[float, List[str]]:
    """
    Check if domain appears to be typosquatting a known brand.
    
    Returns:
        Tuple of (risk_score 0-1, list of similar brands)
    """
    # Extract the main domain name (without TLD)
    parts = domain.split(".")
    if len(parts) < 2:
        return 0.0, []
    
    main_name = parts[0].lower()
    similar_brands = []
    max_similarity = 0.0
    
    for brand in KNOWN_BRANDS:
        # Skip if this IS the actual brand domain (exact match)
        if main_name == brand:
            continue
        
        # Check direct similarity
        similarity = levenshtein_similarity(main_name, brand)
        
        # Check if brand is contained in domain (but domain is longer)
        if brand in main_name and main_name != brand and len(main_name) > len(brand):
            similarity = max(similarity, 0.85)
        
        # Check for common typosquatting patterns
        typo_patterns = [
            brand + "s",           # Adding 's'
            brand + "1",           # Adding '1'
            brand + "-",           # Adding hyphen
            brand.replace("o", "0"),  # o -> 0
            brand.replace("l", "1"),  # l -> 1
            brand.replace("i", "1"),  # i -> 1
            brand.replace("e", "3"),  # e -> 3
            brand.replace("a", "4"),  # a -> 4
            brand + "login",
            brand + "secure",
            brand + "verify",
            "my" + brand,
            "get" + brand,
            brand + "app",
            brand + "official",
            brand + "-login",
            brand + "-secure",
            brand + "-support",
            brand + "help",
            brand + "support",
            brand + "online",
            brand + "web",
            brand + "net",
            brand + "site",
        ]
        
        for pattern in typo_patterns:
            if levenshtein_similarity(main_name, pattern) > 0.8:
                similarity = max(similarity, 0.9)
                break
        
        if similarity > 0.7:
            similar_brands.append((brand, similarity))
            max_similarity = max(max_similarity, similarity)
    
    # Sort by similarity
    similar_brands.sort(key=lambda x: x[1], reverse=True)
    brand_names = [b[0] for b in similar_brands[:3]]
    
    return max_similarity, brand_names


def check_suspicious_keywords(domain: str) -> Tuple[float, List[str]]:
    """
    Check for suspicious keywords in domain.
    
    Returns:
        Tuple of (risk_score 0-1, list of found keywords)
    """
    domain_lower = domain.lower()
    found_keywords = []
    
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in domain_lower:
            found_keywords.append(keyword)
    
    if not found_keywords:
        return 0.0, []
    
    # More keywords = higher risk
    score = min(len(found_keywords) * 0.25, 1.0)
    return score, found_keywords


def check_tld_reputation(domain: str) -> Tuple[float, str]:
    """
    Check TLD reputation.
    
    Returns:
        Tuple of (risk_score 0-1, tld)
    """
    parts = domain.split(".")
    tld = parts[-1].lower() if parts else ""
    
    if tld in TRUSTED_TLDS:
        return 0.0, tld
    elif tld in HIGH_RISK_TLDS:
        return 0.9, tld
    else:
        return 0.3, tld  # Neutral


def check_domain_age(whois_data: Dict[str, Any]) -> Tuple[float, Optional[int]]:
    """
    Check domain age from WHOIS data.
    
    Returns:
        Tuple of (risk_score 0-1, age in days or None)
    """
    data = whois_data.get("data", {})
    creation_date = data.get("creation_date")
    
    if creation_date is None:
        return 0.5, None  # Unknown = moderate risk
    
    if isinstance(creation_date, list):
        creation_date = creation_date[0]
    
    if not isinstance(creation_date, datetime):
        return 0.5, None
    
    # Make timezone-naive for comparison
    if creation_date.tzinfo is not None:
        creation_date = creation_date.replace(tzinfo=None)
    
    now = datetime.now()
    age_days = (now - creation_date).days
    
    # Risk scoring based on age
    if age_days < 7:
        return 1.0, age_days  # Very new = very risky
    elif age_days < 30:
        return 0.9, age_days
    elif age_days < 90:
        return 0.7, age_days
    elif age_days < 180:
        return 0.5, age_days
    elif age_days < 365:
        return 0.3, age_days
    elif age_days < 730:
        return 0.2, age_days
    else:
        return 0.1, age_days  # Old domains are less risky


def check_whois_privacy(whois_data: Dict[str, Any]) -> Tuple[float, bool]:
    """
    Check if WHOIS privacy is enabled.
    
    Returns:
        Tuple of (risk_score 0-1, privacy_enabled)
    """
    data = whois_data.get("data", {})
    
    # Check for privacy indicators
    privacy_indicators = [
        "privacy", "redacted", "protected", "proxy", "guard",
        "whoisguard", "privacyprotect", "contactprivacy", "domainprivacy",
        "withheld", "not disclosed", "data protected"
    ]
    
    fields_to_check = [
        data.get("registrant_name", ""),
        data.get("registrant_org", ""),
        data.get("registrant_email", ""),
    ]
    
    for field in fields_to_check:
        if field:
            field_lower = str(field).lower()
            for indicator in privacy_indicators:
                if indicator in field_lower:
                    return 0.6, True
    
    # Check if all fields are empty/None
    if all(not f for f in fields_to_check):
        return 0.5, True
    
    return 0.2, False


def check_ssl_certificate(ssl_data: Dict[str, Any]) -> Tuple[float, float, Dict[str, Any]]:
    """
    Check SSL certificate validity and issuer.
    
    Returns:
        Tuple of (validity_risk, issuer_risk, details)
    """
    details = {
        "valid": False,
        "issuer": "Unknown",
        "days_left": None,
        "free_cert": False
    }
    
    if not ssl_data.get("certificate"):
        return 0.8, 0.5, details  # No SSL = high risk
    
    cert = ssl_data.get("certificate", {})
    valid = ssl_data.get("valid", False)
    
    details["valid"] = valid
    
    # Get issuer
    issuer = cert.get("issuer", {})
    issuer_org = issuer.get("organizationName", "Unknown")
    details["issuer"] = issuer_org
    
    # Check for free certificate issuers (not bad, but sometimes abused)
    free_issuers = ["let's encrypt", "zerossl", "cloudflare", "buypass"]
    issuer_lower = issuer_org.lower()
    
    for free_issuer in free_issuers:
        if free_issuer in issuer_lower:
            details["free_cert"] = True
            break
    
    # Calculate validity risk
    if not valid:
        validity_risk = 0.9
    else:
        validity_risk = 0.1
    
    # Calculate issuer risk (free certs are slightly riskier due to abuse)
    if details["free_cert"]:
        issuer_risk = 0.4
    else:
        issuer_risk = 0.2
    
    return validity_risk, issuer_risk, details


def check_email_security(domain: str) -> Tuple[float, Dict[str, bool]]:
    """
    Check email security configuration (SPF, DMARC).
    
    Returns:
        Tuple of (risk_score 0-1, config details)
    """
    config = {
        "has_spf": False,
        "has_dmarc": False,
        "has_mx": False
    }
    
    try:
        mail_config = dns_lookup.check_mail_configuration(domain)
        config["has_mx"] = mail_config.get("has_mail", False)
        config["has_spf"] = mail_config.get("spf_record") is not None
        config["has_dmarc"] = mail_config.get("dmarc_record") is not None
    except Exception:
        pass
    
    # Phishing domains often lack proper email security
    if not config["has_spf"] and not config["has_dmarc"]:
        return 0.7, config
    elif not config["has_spf"] or not config["has_dmarc"]:
        return 0.4, config
    else:
        return 0.1, config


def check_dns_anomalies(domain: str) -> Tuple[float, List[str]]:
    """
    Check for DNS configuration anomalies.
    
    Returns:
        Tuple of (risk_score 0-1, list of anomalies)
    """
    anomalies = []
    
    try:
        # Check nameservers
        nameservers = dns_lookup.get_nameservers(domain)
        
        if len(nameservers) < 2:
            anomalies.append("Single nameserver (no redundancy)")
        
        # Check for free/suspicious DNS providers
        suspicious_dns = ["freedns", "afraid.org", "duckdns", "no-ip", "dynu"]
        for ns in nameservers:
            ns_lower = ns.lower()
            for sus in suspicious_dns:
                if sus in ns_lower:
                    anomalies.append(f"Free/Dynamic DNS: {ns}")
                    break
        
        # Check A records
        result = dns_lookup.query_domain(domain, "A")
        a_records = result.get("records", {}).get("A", [])
        
        if not a_records:
            anomalies.append("No A records found")
        
    except Exception:
        anomalies.append("DNS resolution issues")
    
    if not anomalies:
        return 0.1, anomalies
    
    score = min(len(anomalies) * 0.3, 0.9)
    return score, anomalies


def analyze_risk(domain: str, verbose: bool = False) -> Dict[str, Any]:
    """
    Perform comprehensive phishing risk analysis.
    
    Args:
        domain: Domain name to analyze
        verbose: Include detailed information
    
    Returns:
        Dictionary containing risk analysis results
    """
    results = {
        "domain": domain,
        "risk_score": 0.0,
        "risk_level": "Unknown",
        "risk_factors": [],
        "details": {},
        "recommendations": []
    }
    
    total_weight = sum(RISK_WEIGHTS.values())
    weighted_score = 0.0
    
    # 1. Check typosquatting
    typo_score, similar_brands = check_typosquatting(domain)
    if typo_score > 0.5:
        results["risk_factors"].append({
            "factor": "Typosquatting Detection",
            "score": typo_score,
            "weight": RISK_WEIGHTS["typosquatting"],
            "severity": "HIGH" if typo_score > 0.8 else "MEDIUM",
            "details": f"Similar to: {', '.join(similar_brands)}" if similar_brands else "Possible typosquatting"
        })
    results["details"]["typosquatting"] = {
        "score": typo_score,
        "similar_brands": similar_brands
    }
    weighted_score += typo_score * RISK_WEIGHTS["typosquatting"]
    
    # 2. Check suspicious keywords
    keyword_score, found_keywords = check_suspicious_keywords(domain)
    if keyword_score > 0:
        results["risk_factors"].append({
            "factor": "Suspicious Keywords",
            "score": keyword_score,
            "weight": RISK_WEIGHTS["suspicious_keywords"],
            "severity": "HIGH" if keyword_score > 0.5 else "MEDIUM",
            "details": f"Found: {', '.join(found_keywords)}"
        })
    results["details"]["suspicious_keywords"] = {
        "score": keyword_score,
        "keywords": found_keywords
    }
    weighted_score += keyword_score * RISK_WEIGHTS["suspicious_keywords"]
    
    # 3. Check TLD reputation
    tld_score, tld = check_tld_reputation(domain)
    if tld_score > 0.5:
        results["risk_factors"].append({
            "factor": "TLD Reputation",
            "score": tld_score,
            "weight": RISK_WEIGHTS["tld_reputation"],
            "severity": "HIGH" if tld_score > 0.7 else "MEDIUM",
            "details": f"High-risk TLD: .{tld}"
        })
    results["details"]["tld"] = {
        "score": tld_score,
        "tld": tld
    }
    weighted_score += tld_score * RISK_WEIGHTS["tld_reputation"]
    
    # 4. Check domain entropy (random-looking domains are suspicious)
    # Use smooth proportional scoring: 0 at entropy ≤2.5, linear ramp to 1.0 at entropy ≥4.5
    main_name = domain.split(".")[0]
    entropy = calculate_string_entropy(main_name)
    entropy_score = max(0.0, min((entropy - 2.5) / 2.0, 1.0))
    if entropy_score > 0.5:
        results["risk_factors"].append({
            "factor": "Domain Entropy",
            "score": entropy_score,
            "weight": RISK_WEIGHTS["entropy"],
            "severity": "MEDIUM",
            "details": f"High randomness in domain name (entropy: {entropy:.2f})"
        })
    results["details"]["entropy"] = {
        "score": entropy_score,
        "value": entropy
    }
    weighted_score += entropy_score * RISK_WEIGHTS["entropy"]
    
    # 5. Check WHOIS information
    try:
        whois_data = whois_lookup.get_whois(domain)
        
        # Domain age
        age_score, age_days = check_domain_age(whois_data)
        if age_score > 0.5:
            age_str = f"{age_days} days" if age_days else "Unknown"
            results["risk_factors"].append({
                "factor": "Domain Age",
                "score": age_score,
                "weight": RISK_WEIGHTS["domain_age"],
                "severity": "HIGH" if age_score > 0.8 else "MEDIUM",
                "details": f"Domain age: {age_str}"
            })
        results["details"]["domain_age"] = {
            "score": age_score,
            "days": age_days
        }
        weighted_score += age_score * RISK_WEIGHTS["domain_age"]
        
        # WHOIS privacy
        privacy_score, privacy_enabled = check_whois_privacy(whois_data)
        if privacy_score > 0.4:
            results["risk_factors"].append({
                "factor": "WHOIS Privacy",
                "score": privacy_score,
                "weight": RISK_WEIGHTS["whois_privacy"],
                "severity": "LOW",
                "details": "Registration details hidden/redacted"
            })
        results["details"]["whois_privacy"] = {
            "score": privacy_score,
            "enabled": privacy_enabled
        }
        weighted_score += privacy_score * RISK_WEIGHTS["whois_privacy"]
        
    except Exception:
        weighted_score += 0.5 * RISK_WEIGHTS["domain_age"]
        weighted_score += 0.5 * RISK_WEIGHTS["whois_privacy"]
    
    # 6. Check SSL certificate
    try:
        ssl_data = ssl_checker.check_certificate(domain)
        validity_risk, issuer_risk, ssl_details = check_ssl_certificate(ssl_data)
        
        if validity_risk > 0.5:
            results["risk_factors"].append({
                "factor": "SSL Certificate Validity",
                "score": validity_risk,
                "weight": RISK_WEIGHTS["ssl_validity"],
                "severity": "HIGH",
                "details": "Invalid or missing SSL certificate"
            })
        
        results["details"]["ssl"] = ssl_details
        weighted_score += validity_risk * RISK_WEIGHTS["ssl_validity"]
        weighted_score += issuer_risk * RISK_WEIGHTS["ssl_issuer"]
        
    except Exception:
        weighted_score += 0.7 * RISK_WEIGHTS["ssl_validity"]
        weighted_score += 0.5 * RISK_WEIGHTS["ssl_issuer"]
    
    # 7. Check email security
    email_score, email_config = check_email_security(domain)
    if email_score > 0.4:
        missing = []
        if not email_config["has_spf"]:
            missing.append("SPF")
        if not email_config["has_dmarc"]:
            missing.append("DMARC")
        results["risk_factors"].append({
            "factor": "Email Security",
            "score": email_score,
            "weight": RISK_WEIGHTS["email_security"],
            "severity": "MEDIUM",
            "details": f"Missing: {', '.join(missing)}" if missing else "Email not configured"
        })
    results["details"]["email_security"] = email_config
    weighted_score += email_score * RISK_WEIGHTS["email_security"]
    
    # 8. Check DNS anomalies
    dns_score, dns_anomalies = check_dns_anomalies(domain)
    if dns_score > 0.2:
        results["risk_factors"].append({
            "factor": "DNS Configuration",
            "score": dns_score,
            "weight": RISK_WEIGHTS["dns_anomalies"],
            "severity": "MEDIUM" if dns_score > 0.5 else "LOW",
            "details": "; ".join(dns_anomalies) if dns_anomalies else "Minor issues"
        })
    results["details"]["dns_anomalies"] = dns_anomalies
    weighted_score += dns_score * RISK_WEIGHTS["dns_anomalies"]
    
    # Calculate final risk score (0-100)
    final_score = (weighted_score / total_weight) * 100
    results["risk_score"] = round(final_score, 1)
    
    # Determine risk level
    if final_score >= 70:
        results["risk_level"] = "CRITICAL"
        results["recommendations"].append("⛔ HIGH PROBABILITY OF PHISHING - Avoid this domain")
        results["recommendations"].append("Do not enter any credentials or personal information")
        results["recommendations"].append("Report to abuse@domain-registrar or phishtank.org")
    elif final_score >= 50:
        results["risk_level"] = "HIGH"
        results["recommendations"].append("⚠️ Exercise extreme caution with this domain")
        results["recommendations"].append("Verify legitimacy through official channels")
        results["recommendations"].append("Check URL carefully before proceeding")
    elif final_score >= 30:
        results["risk_level"] = "MEDIUM"
        results["recommendations"].append("⚡ Some risk factors detected")
        results["recommendations"].append("Verify the domain is legitimate before sharing sensitive data")
    elif final_score >= 15:
        results["risk_level"] = "LOW"
        results["recommendations"].append("✓ Low risk indicators detected")
        results["recommendations"].append("Standard security practices recommended")
    else:
        results["risk_level"] = "MINIMAL"
        results["recommendations"].append("✓ Domain appears legitimate")
        results["recommendations"].append("No significant risk factors detected")
    
    # Sort risk factors by score
    results["risk_factors"].sort(key=lambda x: x["score"], reverse=True)
    
    return results


def display_results(results: Dict[str, Any], verbose: bool = False) -> None:
    """
    Display risk analysis results with risk matrix table.
    
    Args:
        results: Risk analysis results
        verbose: Show detailed information
    """
    from tabulate import tabulate
    
    domain = results.get("domain")
    risk_score = results.get("risk_score", 0)
    risk_level = results.get("risk_level", "Unknown")
    risk_factors = results.get("risk_factors", [])
    recommendations = results.get("recommendations", [])
    details = results.get("details", {})
    
    # Risk level colors
    level_colors = {
        "CRITICAL": "\033[91m",  # Red
        "HIGH": "\033[91m",      # Red
        "MEDIUM": "\033[93m",    # Yellow
        "LOW": "\033[92m",       # Green
        "MINIMAL": "\033[92m",   # Green
    }
    reset = "\033[0m"
    color = level_colors.get(risk_level, "")
    
    # Header
    print_success(f"\n{'='*70}")
    print_success(f"  PHISHING RISK ANALYSIS: {domain}")
    print_success(f"{'='*70}")
    
    # Risk Score Display
    print_info(f"\n  Risk Score: {color}{risk_score}/100{reset}")
    print_info(f"  Risk Level: {color}{risk_level}{reset}")
    
    # Visual risk meter
    filled = int(risk_score / 5)
    empty = 20 - filled
    
    if risk_score >= 70:
        bar_color = "\033[91m"  # Red
    elif risk_score >= 50:
        bar_color = "\033[93m"  # Yellow
    else:
        bar_color = "\033[92m"  # Green
    
    meter = f"  [{bar_color}{'█' * filled}{reset}{'░' * empty}] {risk_score}%"
    print(meter)
    
    # Risk Matrix Table
    print_success(f"\n{'─'*70}")
    print_success("  RISK FACTOR MATRIX")
    print_success(f"{'─'*70}")
    
    if risk_factors:
        table_data = []
        for factor in risk_factors:
            severity = factor.get("severity", "UNKNOWN")
            if severity == "HIGH":
                sev_display = f"\033[91m● {severity}\033[0m"
            elif severity == "MEDIUM":
                sev_display = f"\033[93m● {severity}\033[0m"
            else:
                sev_display = f"\033[92m● {severity}\033[0m"
            
            score_pct = int(factor.get("score", 0) * 100)
            weight = factor.get("weight", 0)
            impact = round(factor.get("score", 0) * weight, 1)
            
            table_data.append([
                factor.get("factor", "Unknown"),
                sev_display,
                f"{score_pct}%",
                f"{weight}",
                f"{impact}",
                factor.get("details", "")[:35] + "..." if len(factor.get("details", "")) > 35 else factor.get("details", "")
            ])
        
        headers = ["Risk Factor", "Severity", "Score", "Weight", "Impact", "Details"]
        print(tabulate(table_data, headers=headers, tablefmt="simple"))
    else:
        print_info("  No significant risk factors detected.")
    
    # Probability Assessment
    print_success(f"\n{'─'*70}")
    print_success("  PHISHING PROBABILITY ASSESSMENT")
    print_success(f"{'─'*70}")
    
    prob_table = [
        ["Very Low (0-15%)", "✓" if risk_score < 15 else "", "Domain appears legitimate"],
        ["Low (15-30%)", "✓" if 15 <= risk_score < 30 else "", "Minor risk indicators"],
        ["Medium (30-50%)", "✓" if 30 <= risk_score < 50 else "", "Some suspicious characteristics"],
        ["High (50-70%)", "✓" if 50 <= risk_score < 70 else "", "Multiple risk factors present"],
        ["Critical (70-100%)", "✓" if risk_score >= 70 else "", "Strong phishing indicators"],
    ]
    
    print(tabulate(prob_table, headers=["Probability Range", "Current", "Description"], tablefmt="simple"))
    
    # Detailed Analysis (if verbose)
    if verbose:
        print_success(f"\n{'─'*70}")
        print_success("  DETAILED ANALYSIS")
        print_success(f"{'─'*70}")
        
        # Typosquatting
        typo = details.get("typosquatting", {})
        if typo.get("similar_brands"):
            print_warning(f"\n  Typosquatting Analysis:")
            print_info(f"    Similar to brands: {', '.join(typo['similar_brands'])}")
            print_info(f"    Similarity score: {typo['score']*100:.0f}%")
        
        # Domain Age
        age = details.get("domain_age", {})
        if age.get("days") is not None:
            if age["days"] < 365:
                print_warning(f"\n  Domain Age: {age['days']} days")
            else:
                print_info(f"\n  Domain Age: {age['days']} days ({age['days']//365} years)")
        
        # SSL Details
        ssl = details.get("ssl", {})
        if ssl:
            print_info(f"\n  SSL Certificate:")
            print_info(f"    Valid: {'Yes' if ssl.get('valid') else 'No'}")
            print_info(f"    Issuer: {ssl.get('issuer', 'Unknown')}")
            if ssl.get("free_cert"):
                print_warning(f"    Note: Free certificate (commonly abused)")
        
        # Email Security
        email = details.get("email_security", {})
        if email:
            print_info(f"\n  Email Security:")
            print_info(f"    SPF Record: {'✓' if email.get('has_spf') else '✗'}")
            print_info(f"    DMARC Record: {'✓' if email.get('has_dmarc') else '✗'}")
            print_info(f"    MX Records: {'✓' if email.get('has_mx') else '✗'}")
    
    # Recommendations
    print_success(f"\n{'─'*70}")
    print_success("  RECOMMENDATIONS")
    print_success(f"{'─'*70}")
    
    for rec in recommendations:
        print_info(f"  {rec}")
    
    print_info(f"\n{'='*70}")
    print_info(f"  Analysis completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print_info(f"{'='*70}\n")
