"""
ACTIS URL Scanner Module
Advanced URL de-obfuscation, standards-aware canonical normalization,
morphological feature extraction (19 features), and safe redirect inspection integration.
Operates strictly in read-only defensive mode: zero browser JavaScript execution,
zero arbitrary payload downloads, and strict SSRF destination policies.
"""

import ipaddress
import re
import unicodedata
from urllib.parse import urlparse, urlunparse, unquote, quote
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple, Union, Callable

from config.config import get_logger
from scanners.redirect_inspector import (
    RedirectInspector,
    RedirectInspectionResult,
    SSRFValidator
)

logger = get_logger("URLScanner")

# Constants for URL validation & normalization
MAX_URL_LENGTH = 4096
ALLOWED_SCHEMES = ("http", "https")
CONTROL_CHARS_PATTERN = re.compile(r"[\x00-\x1f\x7f\x80-\x9f]")
VALID_HOSTNAME_PATTERN = re.compile(
    r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])\.?$"
)
IPV4_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# Invisible and zero-width unicode characters frequently abused in obfuscation
ZERO_WIDTH_CHARS = {
    "\u200b": "Zero-Width Space (ZWSP)",
    "\u200c": "Zero-Width Non-Joiner (ZWNJ)",
    "\u200d": "Zero-Width Joiner (ZWJ)",
    "\ufeff": "Zero-Width No-Break Space (BOM)",
    "\u200e": "Left-to-Right Mark (LRM)",
    "\u200f": "Right-to-Left Mark (RLM)",
    "\u202a": "Left-to-Right Embedding (LRE)",
    "\u202b": "Right-to-Left Embedding (RLE)",
    "\u202c": "Pop Directional Formatting (PDF)",
    "\u202d": "Left-to-Right Override (LRO)",
    "\u202e": "Right-to-Left Override (RLO)",
    "\u00a0": "Non-Breaking Space (NBSP)",
}

# Delimiters and structural tokens that indicate deceptive percent-encoding
PERCENT_ENCODED_DELIMITERS = {
    "%2e": ".",
    "%2f": "/",
    "%40": "@",
    "%3a": ":",
    "%5c": "\\",
    "%23": "#",
    "%3f": "?",
}

PERCENT_HEX_PATTERN = re.compile(r"%([0-9a-fA-F]{2})")
DOUBLE_PERCENT_PATTERN = re.compile(r"%25([0-9a-fA-F]{2})", re.IGNORECASE)


@dataclass
class URLAnalysisResult:
    """
    Authoritative structured representation of URL de-obfuscation and analysis.
    Preserves original and normalized representations, structural components,
    encoding findings, Unicode/IDN observations, and redirect hops.
    """
    original_input: str
    normalized_url: str
    parsed_scheme: str
    parsed_hostname: str
    parsed_port: Optional[int]
    parsed_path: str
    parsed_query: str
    parsed_fragment: str
    ascii_hostname: str = ""
    unicode_hostname: str = ""
    is_valid: bool = True
    validation_error: Optional[str] = None
    normalization_warnings: List[str] = field(default_factory=list)
    suspicious_encoding_findings: List[str] = field(default_factory=list)
    unicode_or_idn_observations: List[str] = field(default_factory=list)
    redirect_result: Optional[RedirectInspectionResult] = None
    redirect_hops: List[Dict[str, Any]] = field(default_factory=list)
    final_destination: Optional[str] = None
    redirect_loop_detected: bool = False
    redirect_limit_exhausted: bool = False
    network_failure: Optional[str] = None
    analysis_completeness: str = "COMPLETE"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "original_input": self.original_input,
            "normalized_url": self.normalized_url,
            "parsed_scheme": self.parsed_scheme,
            "parsed_hostname": self.parsed_hostname,
            "parsed_port": self.parsed_port,
            "parsed_path": self.parsed_path,
            "parsed_query": self.parsed_query,
            "parsed_fragment": self.parsed_fragment,
            "ascii_hostname": self.ascii_hostname,
            "unicode_hostname": self.unicode_hostname,
            "is_valid": self.is_valid,
            "validation_error": self.validation_error,
            "normalization_warnings": list(self.normalization_warnings),
            "suspicious_encoding_findings": list(self.suspicious_encoding_findings),
            "unicode_or_idn_observations": list(self.unicode_or_idn_observations),
            "redirect_hops": list(self.redirect_hops),
            "final_destination": self.final_destination,
            "redirect_loop_detected": self.redirect_loop_detected,
            "redirect_limit_exhausted": self.redirect_limit_exhausted,
            "network_failure": self.network_failure,
            "analysis_completeness": self.analysis_completeness
        }


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

    if "\\" in cleaned:
        return False, "URL contains illegal backslashes or filesystem path separators."

    # Prepend scheme if missing for parsing check
    candidate = cleaned
    if not candidate.lower().startswith(("http://", "https://")):
        if "://" in candidate or candidate.lower().startswith(("javascript:", "mailto:", "data:", "file:", "ftp:")):
            return False, "Unsupported URL scheme. Only HTTP and HTTPS are permitted."
        candidate = "http://" + candidate

    # Deobfuscate percent-encoded '@' (%40) in authority portion
    # RFC 3986 allows userinfo to be delimited by '@'. Phishing URLs frequently percent-encode
    # '%40' in the authority to bypass naive domain parsers.
    if "%40" in candidate.lower():
        scheme_sep = candidate.find("://")
        if scheme_sep != -1:
            auth_start = scheme_sep + 3
            auth_end = candidate.find("/", auth_start)
            if auth_end == -1:
                auth_end = len(candidate)
            q_idx = candidate.find("?", auth_start)
            if q_idx != -1 and q_idx < auth_end:
                auth_end = q_idx
            frag_idx = candidate.find("#", auth_start)
            if frag_idx != -1 and frag_idx < auth_end:
                auth_end = frag_idx
            authority = candidate[auth_start:auth_end]
            if "%40" in authority.lower():
                normalized_auth = re.sub(r"%40", "@", authority, flags=re.IGNORECASE)
                candidate = candidate[:auth_start] + normalized_auth + candidate[auth_end:]

    try:
        parsed = urlparse(candidate)
        port = parsed.port
        if port is not None and not (1 <= port <= 65535):
            return False, f"Port number out of valid range 1-65535: {port}."
    except Exception as e:
        return False, f"URL parsing failed: {e}"

    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        return False, f"Unsupported URL scheme '{scheme}'. Only HTTP and HTTPS are permitted."

    hostname = (parsed.hostname or "").strip()
    if not hostname:
        return False, "URL lacks a valid hostname or domain."

    # Validate hostname syntax
    # 1. Bracketed IPv6
    if hostname.startswith("[") and hostname.endswith("]"):
        try:
            ipaddress.IPv6Address(hostname[1:-1])
            return True, None
        except ValueError:
            return False, f"Malformed IPv6 literal '{hostname}'."

    # 2. IPv4 dotted-decimal
    if IPV4_PATTERN.match(hostname):
        try:
            ipaddress.IPv4Address(hostname)
            return True, None
        except ValueError:
            return False, f"Malformed IPv4 address '{hostname}'."

    # 3. Numeric / Special IP encodings (dword, hex, octal)
    numeric_ip = SSRFValidator.parse_numeric_or_special_ip(hostname)
    if numeric_ip is not None:
        return True, None

    # 4. IDN / Unicode hostname check
    try:
        ascii_host = hostname.rstrip(".").encode("idna").decode("ascii")
        if VALID_HOSTNAME_PATTERN.match(ascii_host):
            return True, None
    except Exception:
        pass

    # 5. Standard ASCII domain pattern
    clean_host = hostname.rstrip(".")
    if VALID_HOSTNAME_PATTERN.match(clean_host) or VALID_HOSTNAME_PATTERN.match(hostname):
        return True, None

    return False, f"Malformed hostname '{hostname}' contains invalid characters."


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
    if not clean.lower().startswith(("http://", "https://")):
        clean = "http://" + clean
    try:
        parsed = urlparse(clean)
        host = (parsed.hostname or "").lower().rstrip(".")
        if host.startswith("www."):
            host = host[4:]
        return host
    except Exception:
        return ""


def _detect_homoglyphs(label: str) -> List[str]:
    """Detects mixed scripts within a domain label (e.g. Cyrillic + Latin)."""
    scripts = set()
    for ch in label:
        if ch.isalpha():
            try:
                name = unicodedata.name(ch)
                if name.startswith("CYRILLIC"):
                    scripts.add("CYRILLIC")
                elif name.startswith("LATIN"):
                    scripts.add("LATIN")
                elif name.startswith("GREEK"):
                    scripts.add("GREEK")
            except ValueError:
                pass
    findings = []
    if len(scripts) > 1:
        findings.append(f"Mixed-script homoglyph detected in label '{label}': {', '.join(sorted(scripts))}")
    return findings


def deobfuscate_and_analyze_url(
    url: Any,
    follow_redirects: bool = False,
    http_fetcher: Optional[Callable[[str, str, float], Tuple[int, Dict[str, str]]]] = None,
    dns_resolver: Optional[Callable[[str], List[str]]] = None
) -> URLAnalysisResult:
    """
    Performs comprehensive de-obfuscation and structural analysis on a candidate URL.
    Inspects Unicode/zero-width formatting, IDN/punycode mappings, percent-encoding tricks,
    alternative numerical IP representations, userinfo tricks, and optional bounded redirect hops.
    Guarantees deterministic, idempotent execution with zero browser execution.
    """
    original_str = str(url or "")
    if url is None or not isinstance(url, str):
        return URLAnalysisResult(
            original_input=original_str,
            normalized_url="",
            parsed_scheme="",
            parsed_hostname="",
            parsed_port=None,
            parsed_path="",
            parsed_query="",
            parsed_fragment="",
            is_valid=False,
            validation_error="URL is None or not a string",
            analysis_completeness="FAILED"
        )

    # 1. Stripping surrounding wrappers and whitespace
    clean = url.strip().strip("'\"<>[]()")
    if not clean:
        return URLAnalysisResult(
            original_input=original_str,
            normalized_url="",
            parsed_scheme="",
            parsed_hostname="",
            parsed_port=None,
            parsed_path="",
            parsed_query="",
            parsed_fragment="",
            is_valid=False,
            validation_error="URL is empty or whitespace only",
            analysis_completeness="FAILED"
        )

    normalization_warnings: List[str] = []
    suspicious_encoding_findings: List[str] = []
    unicode_or_idn_observations: List[str] = []

    # 2. Check for invisible / zero-width characters
    for zw_char, desc in ZERO_WIDTH_CHARS.items():
        if zw_char in clean:
            unicode_or_idn_observations.append(f"Contains {desc} (U+{ord(zw_char):04X})")
            normalization_warnings.append(f"Stripped invisible character {desc}")
            clean = clean.replace(zw_char, "")

    # 3. Check for repeated or double percent encoding
    double_matches = DOUBLE_PERCENT_PATTERN.findall(clean)
    if double_matches:
        suspicious_encoding_findings.append(
            f"Double percent-encoding detected (%25{double_matches[0]} -> %{double_matches[0]})"
        )

    # 4. Check for percent-encoded delimiters
    clean_lower = clean.lower()
    for enc_token, char_val in PERCENT_ENCODED_DELIMITERS.items():
        if enc_token in clean_lower:
            suspicious_encoding_findings.append(
                f"URL contains percent-encoded delimiter '{enc_token}' representing '{char_val}'"
            )

    # 4b. Deobfuscate percent-encoded '@' (%40) in authority portion
    if "%40" in clean.lower():
        scheme_sep = clean.find("://")
        auth_start = scheme_sep + 3 if scheme_sep != -1 else 0
        auth_end = clean.find("/", auth_start)
        if auth_end == -1:
            auth_end = len(clean)
        q_idx = clean.find("?", auth_start)
        if q_idx != -1 and q_idx < auth_end:
            auth_end = q_idx
        frag_idx = clean.find("#", auth_start)
        if frag_idx != -1 and frag_idx < auth_end:
            auth_end = frag_idx
        authority = clean[auth_start:auth_end]
        if "%40" in authority.lower():
            normalized_auth = re.sub(r"%40", "@", authority, flags=re.IGNORECASE)
            clean = clean[:auth_start] + normalized_auth + clean[auth_end:]
            normalization_warnings.append(f"Deobfuscated percent-encoded '@' in authority: '{authority}' -> '{normalized_auth}'")

    # 5. Syntactic validation
    is_valid, val_err = validate_url(clean)
    if not is_valid:
        return URLAnalysisResult(
            original_input=original_str,
            normalized_url=clean,
            parsed_scheme="",
            parsed_hostname="",
            parsed_port=None,
            parsed_path="",
            parsed_query="",
            parsed_fragment="",
            is_valid=False,
            validation_error=val_err,
            normalization_warnings=normalization_warnings,
            suspicious_encoding_findings=suspicious_encoding_findings,
            unicode_or_idn_observations=unicode_or_idn_observations,
            analysis_completeness="FAILED"
        )

    # 6. Parse URL components
    candidate = clean
    if not candidate.lower().startswith(("http://", "https://")):
        normalization_warnings.append("Defaulted missing scheme to http://")
        candidate = "http://" + candidate

    try:
        parsed = urlparse(candidate)
    except Exception as e:
        return URLAnalysisResult(
            original_input=original_str,
            normalized_url=candidate,
            parsed_scheme="",
            parsed_hostname="",
            parsed_port=None,
            parsed_path="",
            parsed_query="",
            parsed_fragment="",
            is_valid=False,
            validation_error=f"Parsing error: {e}",
            analysis_completeness="FAILED"
        )

    scheme = (parsed.scheme or "http").lower()
    raw_hostname = (parsed.hostname or "").strip()

    # 7. Hostname De-obfuscation & IDN/Punycode Analysis
    ascii_hostname = ""
    unicode_hostname = ""
    normalized_hostname = raw_hostname.lower()

    # Check for trailing dot in hostname
    if normalized_hostname.endswith(".") and len(normalized_hostname) > 1:
        normalization_warnings.append(f"Stripped trailing dot from hostname '{normalized_hostname}'")
        normalized_hostname = normalized_hostname.rstrip(".")

    # Check for numerical / special IP formats (dword decimal, octal, hex)
    numeric_ip = SSRFValidator.parse_numeric_or_special_ip(normalized_hostname)
    if numeric_ip is not None:
        canonical_ip_str = str(numeric_ip)
        if canonical_ip_str != normalized_hostname:
            suspicious_encoding_findings.append(
                f"Alternative numeric IP encoding detected: '{normalized_hostname}' evaluates to '{canonical_ip_str}'"
            )
            normalization_warnings.append(
                f"Normalized alternative numeric IP '{normalized_hostname}' to canonical '{canonical_ip_str}'"
            )
            normalized_hostname = canonical_ip_str

    # Check for Punycode & IDN
    if normalized_hostname.startswith("xn--") or ".xn--" in normalized_hostname:
        try:
            unicode_hostname = normalized_hostname.encode("ascii").decode("idna")
            ascii_hostname = normalized_hostname
            unicode_or_idn_observations.append(
                f"Punycode IDN hostname '{ascii_hostname}' resolves to Unicode '{unicode_hostname}'"
            )
            # Check homoglyphs in decoded Unicode labels
            for label in unicode_hostname.split("."):
                homoglyphs = _detect_homoglyphs(label)
                for h in homoglyphs:
                    unicode_or_idn_observations.append(h)
                    suspicious_encoding_findings.append(h)
        except Exception:
            ascii_hostname = normalized_hostname
            unicode_hostname = normalized_hostname
    elif any(ord(c) > 127 for c in normalized_hostname):
        # Non-ASCII Unicode hostname
        unicode_hostname = normalized_hostname
        try:
            ascii_hostname = normalized_hostname.encode("idna").decode("ascii")
            unicode_or_idn_observations.append(
                f"Unicode IDN hostname '{unicode_hostname}' encoded as Punycode '{ascii_hostname}'"
            )
            # Check homoglyphs in Unicode labels
            for label in unicode_hostname.split("."):
                homoglyphs = _detect_homoglyphs(label)
                for h in homoglyphs:
                    unicode_or_idn_observations.append(h)
                    suspicious_encoding_findings.append(h)
        except Exception as idna_err:
            normalization_warnings.append(f"Failed IDN Punycode encoding: {idna_err}")
            ascii_hostname = normalized_hostname
    else:
        ascii_hostname = normalized_hostname
        unicode_hostname = normalized_hostname

    # Strip www. prefix for canonical hostname
    if normalized_hostname.startswith("www."):
        normalized_hostname = normalized_hostname[4:]

    # 8. Userinfo Handling & Deceptive Authority Tricks
    userinfo_str = ""
    if "@" in candidate.split("/", 3)[2] if len(candidate.split("/", 3)) > 2 else "":
        # Netloc contains @
        if parsed.username or parsed.password:
            user = parsed.username or ""
            pwd = f":{parsed.password}" if parsed.password else ""
            userinfo_str = f"{user}{pwd}@"
            suspicious_encoding_findings.append(
                f"Deceptive userinfo before hostname ('{userinfo_str}') obscures destination '{normalized_hostname}'"
            )

    # 9. Port normalization
    port = parsed.port
    is_default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    if is_default_port:
        normalization_warnings.append(f"Stripped default port {port} for scheme {scheme}")
        port_str = ""
    elif port:
        port_str = f":{port}"
    else:
        port_str = ""

    # Reconstruct netloc
    if ":" in normalized_hostname and not (normalized_hostname.startswith("[") and normalized_hostname.endswith("]")):
        netloc = f"[{normalized_hostname}]{port_str}"
    elif normalized_hostname.startswith("[") and normalized_hostname.endswith("]"):
        netloc = f"{normalized_hostname}{port_str}"
    else:
        netloc = f"{userinfo_str}{normalized_hostname}{port_str}"

    path = parsed.path or ""
    query = f"?{parsed.query}" if parsed.query else ""
    fragment = f"#{parsed.fragment}" if parsed.fragment else ""

    normalized_url = f"{scheme}://{netloc}{path}{query}{fragment}"

    # 10. Safe Bounded Redirect Inspection (if enabled)
    redirect_res = None
    redirect_hops: List[Dict[str, Any]] = []
    final_dest = normalized_url
    loop_detected = False
    limit_exhausted = False
    net_fail = None
    completeness = "COMPLETE"

    if follow_redirects:
        inspector = RedirectInspector()
        redirect_res = inspector.inspect_redirects(
            start_url=normalized_url,
            http_fetcher=http_fetcher,
            dns_resolver=dns_resolver
        )
        redirect_hops = [h.to_dict() for h in redirect_res.hops]
        final_dest = redirect_res.final_destination
        loop_detected = redirect_res.is_loop_detected
        limit_exhausted = redirect_res.is_limit_exhausted
        net_fail = redirect_res.error_reason

        if redirect_res.ssrf_blocked:
            completeness = "PARTIAL"
            suspicious_encoding_findings.append(f"SSRF violation in redirect chain: {redirect_res.error_reason}")
        elif redirect_res.error_reason:
            completeness = "PARTIAL"
    else:
        redirect_res = RedirectInspectionResult.not_evaluated(normalized_url)

    return URLAnalysisResult(
        original_input=original_str,
        normalized_url=normalized_url,
        parsed_scheme=scheme,
        parsed_hostname=normalized_hostname,
        parsed_port=port,
        parsed_path=path,
        parsed_query=query,
        parsed_fragment=fragment,
        ascii_hostname=ascii_hostname,
        unicode_hostname=unicode_hostname,
        is_valid=True,
        validation_error=None,
        normalization_warnings=normalization_warnings,
        suspicious_encoding_findings=suspicious_encoding_findings,
        unicode_or_idn_observations=unicode_or_idn_observations,
        redirect_result=redirect_res,
        redirect_hops=redirect_hops,
        final_destination=final_dest,
        redirect_loop_detected=loop_detected,
        redirect_limit_exhausted=limit_exhausted,
        network_failure=net_fail,
        analysis_completeness=completeness
    )


def normalize_url(url: Any) -> str:
    """
    Normalizes URL into a canonical representation:
    - Strips surrounding whitespace and wrapping quotes/brackets
    - Defaults missing scheme to http://
    - Lowercases scheme and hostname
    - Strips www. prefix from hostname
    - Strips default ports (80 for http, 443 for https) while preserving non-standard ports
    - Normalizes alternative numeric IPs and strips trailing dots
    - Preserves path, queries, and fragments without mutating semantic destination
    - Returns empty string safely on None or empty input
    """
    if url is None or not isinstance(url, str):
        return ""

    res = deobfuscate_and_analyze_url(url, follow_redirects=False)
    if not res.is_valid:
        # Fallback to stripped string if unparseable
        clean = url.strip().strip("'\"<>[]()")
        return clean

    return res.normalized_url


# Exact 19 feature names expected by the trained Random Forest phishing model
PHISHING_URL_FEATURE_NAMES: List[str] = [
    "url_length",
    "n_dots",
    "n_hypens",
    "n_underline",
    "n_slash",
    "n_questionmark",
    "n_equal",
    "n_at",
    "n_and",
    "n_exclamation",
    "n_space",
    "n_tilde",
    "n_comma",
    "n_plus",
    "n_asterisk",
    "n_hastag",
    "n_dollar",
    "n_percent",
    "n_redirection"
]


def extract_url_features(url: Any, is_already_normalized: bool = False) -> List[int]:
    """
    Extracts the exact 19 morphological features in schema order
    required by the trained Random Forest phishing classifier.
    Safely handles empty, malformed, non-string, and None inputs without crashing.
    """
    if not url or not isinstance(url, str):
        return [0] * len(PHISHING_URL_FEATURE_NAMES)

    if is_already_normalized:
        normalized = url
    else:
        normalized = normalize_url(url)

    if not normalized:
        return [0] * len(PHISHING_URL_FEATURE_NAMES)

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
    try:
        parsed = urlparse(normalized)
        path_query = (parsed.path or "") + (f"?{parsed.query}" if parsed.query else "") + (f"#{parsed.fragment}" if parsed.fragment else "")
        n_redirection = path_query.count("//")
    except Exception:
        n_redirection = 0

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


def extract_url_features_dict(url: Any) -> Dict[str, int]:
    """
    Extracts morphological features and returns a mapping from feature name to value.
    """
    feature_list = extract_url_features(url)
    return dict(zip(PHISHING_URL_FEATURE_NAMES, feature_list))


def validate_extracted_features(features: Any) -> Tuple[bool, Optional[str]]:
    """
    Validates that a feature vector matches the 19 morphological features schema.
    """
    if not isinstance(features, (list, tuple)):
        return False, f"Expected list or tuple of features, received {type(features).__name__}."

    if len(features) != len(PHISHING_URL_FEATURE_NAMES):
        return False, f"Expected {len(PHISHING_URL_FEATURE_NAMES)} features, received {len(features)}."

    for idx, val in enumerate(features):
        if not isinstance(val, (int, float)):
            return False, f"Feature at index {idx} ('{PHISHING_URL_FEATURE_NAMES[idx]}') is non-numeric: {val}."
        if isinstance(val, float) and (val != val or val == float("inf") or val == float("-inf")):
            return False, f"Feature at index {idx} ('{PHISHING_URL_FEATURE_NAMES[idx]}') contains NaN or Inf."

    return True, None


def scan_url_logic(url: str, check_external: bool = False, follow_redirects: bool = False) -> Dict[str, Any]:
    """
    Core business logic for scanning a URL through the central detection engine.
    Returns structured results for UI, API, or CLI consumption.
    """
    from detection_engine.threat_detector import threat_detector
    return threat_detector.analyze_url(url, check_external=check_external, follow_redirects=follow_redirects)


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
