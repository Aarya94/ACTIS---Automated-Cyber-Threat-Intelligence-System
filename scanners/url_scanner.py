"""
ACTIS URL Scanner Module
Extracts 19 morphological features from URLs, normalizes domains,
and routes URLs through the unified detection engine.
"""

from urllib.parse import urlparse
from typing import Dict, Any, List
from config.config import get_logger

logger = get_logger("URLScanner")


def normalize_url(url: str) -> str:
    """Normalizes URL scheme, lowercase domain, and strips www prefix."""
    clean = url.strip()
    if not clean.startswith(("http://", "https://")):
        clean = "http://" + clean

    parsed = urlparse(clean)
    domain = (parsed.netloc or "").lower()

    if domain.startswith("www."):
        domain = domain[4:]

    # Reconstruct normalized URL
    scheme = parsed.scheme.lower()
    path = parsed.path
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{scheme}://{domain}{path}{query}"


def extract_url_features(url: str) -> List[int]:
    """
    Extracts the exact 19 morphological features in schema order
    required by the trained Random Forest phishing classifier.
    """
    normalized = normalize_url(url)
    
    # Feature 1: url_length
    url_length = len(normalized)
    
    # Features 2-18: Character counts
    n_dots = normalized.count(".")
    n_hypens = normalized.count("-")
    n_underline = normalized.count("_")
    n_slash = normalized.count("/")
    n_questionmark = normalized.count("?")
    n_equal = normalized.count("=")
    n_at = normalized.count("@")
    n_and = normalized.count("&")
    n_exclamation = normalized.count("!")
    n_space = normalized.count(" ")
    n_tilde = normalized.count("~")
    n_comma = normalized.count(",")
    n_plus = normalized.count("+")
    n_asterisk = normalized.count("*")
    n_hastag = normalized.count("#")
    n_dollar = normalized.count("$")
    n_percent = normalized.count("%")
    
    # Feature 19: count of '//' after the protocol
    parsed = urlparse(normalized)
    path_query = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    n_redirection = path_query.count("//")

    return [
        url_length,
        n_dots,
        n_hypens,
        n_underline,
        n_slash,
        n_questionmark,
        n_equal,
        n_at,
        n_and,
        n_exclamation,
        n_space,
        n_tilde,
        n_comma,
        n_plus,
        n_asterisk,
        n_hastag,
        n_dollar,
        n_percent,
        n_redirection
    ]


def scan_url_logic(url: str, check_external: bool = False) -> Dict[str, Any]:
    """
    Core business logic for scanning a URL through the central detection engine.
    Returns structured results for UI, API, or CLI consumption.
    """
    from detection_engine.threat_detector import threat_detector
    return threat_detector.analyze_url(url, check_external=check_external)


def scan_url_cli():
    """Terminal CLI helper function for scanning a URL."""
    url = input("Enter URL to scan: ").strip()
    if not url:
        print("[!] No URL entered.")
        return

    print(f"\n[*] Scanning: {url}")
    res = scan_url_logic(url)
    
    print("\n" + "="*50)
    print(f"ACTIS Threat Analysis: {res['url']}")
    print(f"Risk Score: {res['score']}/100 | Severity: {res['risk_level']}")
    print(f"Is Threat: {res['is_threat']}")
    print("="*50)
    
    print("\n[+] Evidence & Explanations:")
    for reason in res["reasons"]:
        print(f"  • {reason}")
        
    print(f"\n[+] Recommended Action:\n  {res['recommended_action']}\n")
