"""
ACTIS URL Scanner Module
Extracts 19 morphological features from URLs, normalizes domains,
and routes URLs through the unified detection engine.
"""

import re
from urllib.parse import urlparse, urlunparse
from typing import Dict, Any, List, Optional, Tuple, Union
from config.config import get_logger

logger = get_logger("URLScanner")

# Constants for URL validation & normalization
MAX_URL_LENGTH = 4096
ALLOWED_SCHEMES = ("http", "https")
CONTROL_CHARS_PATTERN = re.compile(r"[\x00-\x1f\x7f]")
VALID_HOSTNAME_PATTERN = re.compile(
    r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"
)
IPV4_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def validate_url(url: Any) -> Tuple[bool, Optional[str]]:
    """
    Validates a URL candidate for syntactic correctness, safe length, and valid structure.
    Returns (is_valid, error_reason).
    """
    if url is None:
        return False, "URL input is None."

    if not isinstance(url, str):
        return False, f"URL must be a string, received {type(url).__name__}."

    cleaned = url.strip()
    if not cleaned:
        return False, "URL input is empty or whitespace only."

    if len(cleaned) > MAX_URL_LENGTH:
        return False, f"URL exceeds maximum allowed length of {MAX_URL_LENGTH} characters ({len(cleaned)} chars)."

    if CONTROL_CHARS_PATTERN.search(cleaned):
        return False, "URL contains illegal control characters or null bytes."

    # Prepend scheme if missing for parsing check
    candidate = cleaned
    if not candidate.startswith(("http://", "https://")):
        candidate = "http://" + candidate

    try:
        parsed = urlparse(candidate)
    except Exception as e:
        return False, f"URL parsing failed: {e}"

    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        return False, f"Unsupported URL scheme '{scheme}'. Only HTTP and HTTPS are permitted."

    hostname = (parsed.hostname or "").strip()
    if not hostname:
        return False, "URL lacks a valid hostname or domain."

    # Validate hostname syntax (allow valid domain labels or IPv4 / IPv6 addresses)
    if not (VALID_HOSTNAME_PATTERN.match(hostname) or IPV4_PATTERN.match(hostname) or "[" in hostname):
        return False, f"Malformed hostname '{hostname}' contains invalid characters."

    return True, None


def is_valid_url(url: Any) -> bool:
    """Convenience helper returning True if candidate URL is valid."""
    valid, _ = validate_url(url)
    return valid



def extract_domain(url: str) -> str:
    """
    Safely extracts lowercase domain/hostname from a URL string, stripping 'www.' prefix and ports.
    Returns empty string on invalid or missing domain.
    """
    if not url or not isinstance(url, str):
        return ""
    clean = url.strip()
    if not clean.startswith(("http://", "https://")):
        clean = "http://" + clean
    try:
        parsed = urlparse(clean)
        host = (parsed.hostname or "").lower()
        if host.startswith("www."):
            host = host[4:]
        return host
    except Exception:
        return ""


def normalize_url(url: Any) -> str:
    """
    Normalizes URL into a canonical representation:
    - Strips surrounding whitespace and wrapping quotes/brackets
    - Defaults missing scheme to http://
    - Lowercases scheme and hostname
    - Strips www. prefix from hostname
    - Strips default ports (80 for http, 443 for https) while preserving non-standard ports
    - Preserves path, queries, and fragments without mutating semantic destination
    - Returns empty string safely on None or empty input
    """
    if url is None or not isinstance(url, str):
        return ""

    clean = url.strip().strip("'\"<>[]()")
    if not clean:
        return ""

    if not clean.startswith(("http://", "https://")):
        clean = "http://" + clean

    try:
        parsed = urlparse(clean)
    except Exception as e:
        logger.warning(f"Failed to parse URL '{url}': {e}")
        return clean.strip()

    scheme = (parsed.scheme or "http").lower()
    hostname = (parsed.hostname or "").lower()

    if hostname.startswith("www."):
        hostname = hostname[4:]

    # Canonical port handling
    port = parsed.port
    is_default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    if port and not is_default_port:
        netloc = f"{hostname}:{port}"
    else:
        netloc = hostname

    # Preserve userinfo if explicitly present (rare in clean URLs, but preserved)
    if parsed.username:
        user_info = f"{parsed.username}:{parsed.password}@" if parsed.password else f"{parsed.username}@"
        netloc = f"{user_info}{netloc}"

    path = parsed.path
    query = f"?{parsed.query}" if parsed.query else ""
    fragment = f"#{parsed.fragment}" if parsed.fragment else ""

    return f"{scheme}://{netloc}{path}{query}{fragment}"



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
