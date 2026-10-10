"""
ACTIS Indicator Validation and Normalization Module
Provides defensive validation, canonical normalization, type detection,
and privacy-boundary filtering (such as private/loopback IP shielding)
for external threat intelligence lookups.
"""

import re
import ipaddress
from typing import Tuple, Optional, Union, Any
from urllib.parse import urlparse

from detection_engine.threat_intel_contract import IndicatorType
from scanners.url_scanner import validate_url, normalize_url, extract_domain
from config.config import get_logger

logger = get_logger("IndicatorValidator")

HEX_SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
HEX_MD5_PATTERN = re.compile(r"^[0-9a-fA-F]{32}$")
HEX_SHA1_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")
DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def is_safe_public_ip(ip_str: str) -> Tuple[bool, Optional[str]]:
    """
    Validates whether an IP address is a valid public routable IP.
    Rejects private (RFC 1918), loopback, link-local, multicast, and reserved addresses
    to strictly enforce privacy boundaries and prevent information disclosure.
    """
    clean_ip = ip_str.strip()
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
    except ValueError:
        return False, f"Invalid IP address format: '{ip_str}'."

    if ip_obj.is_loopback:
        return False, f"Loopback address '{clean_ip}' must not be transmitted externally."
    if ip_obj.is_private:
        return False, f"Private / RFC 1918 address '{clean_ip}' is shielded by local privacy boundary."
    if ip_obj.is_link_local:
        return False, f"Link-local address '{clean_ip}' must not be transmitted externally."
    if ip_obj.is_multicast:
        return False, f"Multicast address '{clean_ip}' is not an external routable host."
    if ip_obj.is_reserved:
        return False, f"Reserved IP address '{clean_ip}' cannot be queried externally."

    return True, None


def detect_indicator_type(indicator: Any) -> Optional[IndicatorType]:
    """
    Infers the IndicatorType from raw indicator string format.
    Returns IndicatorType enum or None if unrecognized.
    """
    if not indicator or not isinstance(indicator, str):
        return None

    clean = indicator.strip()

    # 1. Cryptographic hashes
    if HEX_SHA256_PATTERN.match(clean):
        return IndicatorType.SHA256
    if HEX_MD5_PATTERN.match(clean):
        return IndicatorType.MD5
    if HEX_SHA1_PATTERN.match(clean):
        return IndicatorType.SHA1

    # 2. IP address
    try:
        ipaddress.ip_address(clean)
        return IndicatorType.IP_ADDRESS
    except ValueError:
        pass

    # 3. URL
    if clean.lower().startswith(("http://", "https://")) or ("/" in clean and not clean.startswith("/")):
        is_val, _ = validate_url(clean)
        if is_val:
            return IndicatorType.URL

    # 4. Domain
    if DOMAIN_PATTERN.match(clean.lower()):
        return IndicatorType.DOMAIN

    return None


def validate_and_normalize_indicator(
    indicator: Any,
    expected_type: Optional[Union[str, IndicatorType]] = None,
    allow_private_ip: bool = False
) -> Tuple[bool, Optional[str], Optional[str], Optional[IndicatorType]]:
    """
    Defensively validates and normalizes an indicator string.
    
    Returns:
        (is_valid: bool, normalized_value: Optional[str], error_message: Optional[str], indicator_type: Optional[IndicatorType])
    """
    if indicator is None:
        return False, None, "Indicator is None.", None

    if not isinstance(indicator, str):
        return False, None, f"Indicator must be a string, got {type(indicator).__name__}.", None

    clean = indicator.strip()
    if not clean:
        return False, None, "Indicator string is empty or whitespace only.", None

    # Resolve target indicator type
    resolved_type: Optional[IndicatorType] = None
    if expected_type:
        if isinstance(expected_type, IndicatorType):
            resolved_type = expected_type
        else:
            try:
                resolved_type = IndicatorType[expected_type.upper()]
            except KeyError:
                resolved_type = detect_indicator_type(clean)
    else:
        resolved_type = detect_indicator_type(clean)

    if not resolved_type:
        return False, None, f"Unable to determine indicator type for '{clean}'.", None

    # Type-specific validation and canonical normalization
    if resolved_type == IndicatorType.SHA256:
        if not HEX_SHA256_PATTERN.match(clean):
            return False, None, f"Malformed SHA-256 hash. Must be 64 hexadecimal characters, got {len(clean)}.", resolved_type
        return True, clean.lower(), None, resolved_type

    elif resolved_type == IndicatorType.MD5:
        if not HEX_MD5_PATTERN.match(clean):
            return False, None, f"Malformed MD5 hash. Must be 32 hexadecimal characters, got {len(clean)}.", resolved_type
        return True, clean.lower(), None, resolved_type

    elif resolved_type == IndicatorType.SHA1:
        if not HEX_SHA1_PATTERN.match(clean):
            return False, None, f"Malformed SHA-1 hash. Must be 40 hexadecimal characters, got {len(clean)}.", resolved_type
        return True, clean.lower(), None, resolved_type

    elif resolved_type == IndicatorType.IP_ADDRESS:
        if not allow_private_ip:
            is_pub, err = is_safe_public_ip(clean)
            if not is_pub:
                return False, None, err, resolved_type
        try:
            ip_obj = ipaddress.ip_address(clean)
            return True, str(ip_obj), None, resolved_type
        except ValueError as e:
            return False, None, f"Invalid IP address: {e}", resolved_type

    elif resolved_type == IndicatorType.URL:
        is_val, err = validate_url(clean)
        if not is_val:
            return False, None, f"Invalid URL: {err}", resolved_type
        normalized = normalize_url(clean)
        if "#" in normalized:
            normalized = normalized.split("#", 1)[0]
        return True, normalized, None, resolved_type

    elif resolved_type == IndicatorType.DOMAIN:
        clean_domain = clean.lower()
        if clean_domain.startswith("www."):
            clean_domain = clean_domain[4:]
        if not DOMAIN_PATTERN.match(clean_domain):
            return False, None, f"Malformed domain syntax '{clean}'.", resolved_type
        return True, clean_domain, None, resolved_type

    return False, None, f"Unsupported indicator type: {resolved_type}", resolved_type
