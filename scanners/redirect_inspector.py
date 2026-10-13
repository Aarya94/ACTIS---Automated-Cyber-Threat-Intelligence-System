"""
ACTIS Safe Redirect Analysis & SSRF Destination Validator
Provides bounded redirect inspection, cycle detection, protocol transition analysis,
and strict destination policy enforcement against SSRF and internal network probing.
Strictly non-intrusive: zero browser JavaScript execution, zero credential transmission,
zero arbitrary payload downloads, and strict per-hop validation.
"""

import ipaddress
import re
import socket
import time
import urllib.parse
import urllib.request
import http.client
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from config.config import get_logger

logger = get_logger("RedirectInspector")

# Configurable defaults
DEFAULT_MAX_HOPS = 5
DEFAULT_PER_REQUEST_TIMEOUT = 2.0
DEFAULT_OVERALL_TIMEOUT = 5.0
DEFAULT_MAX_HEADER_SIZE = 16384  # 16 KB

# Prohibited internal/private domain patterns
PROHIBITED_HOSTNAME_PATTERNS = [
    re.compile(r"^localhost$", re.IGNORECASE),
    re.compile(r".*\.localhost$", re.IGNORECASE),
    re.compile(r".*\.local$", re.IGNORECASE),
    re.compile(r".*\.internal$", re.IGNORECASE),
    re.compile(r".*\.lan$", re.IGNORECASE),
    re.compile(r".*\.corp$", re.IGNORECASE),
    re.compile(r".*\.home$", re.IGNORECASE),
    re.compile(r".*\.localdomain$", re.IGNORECASE),
    re.compile(r"^metadata\.google\.internal$", re.IGNORECASE),
]

# Explicit cloud metadata IP strings
CLOUD_METADATA_IPS = {
    "169.254.169.254",   # AWS, Azure, GCP, OpenStack
    "100.100.100.200",   # Alibaba Cloud
    "fd00:ec2::254",     # AWS IPv6 metadata
}


class SSRFValidator:
    """
    Centralized destination validator protecting against Server-Side Request Forgery (SSRF).
    Inspects IP literals, numerical encodings, resolved DNS records, and prohibited domains.
    """

    @staticmethod
    def parse_numeric_or_special_ip(hostname: str) -> Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]:
        """
        Parses IPv4/IPv6 literals, bracketed IPv6, dword integers, hex, and octal IP representations.
        Returns ipaddress object if valid IP literal representation, else None.
        """
        if not hostname or not isinstance(hostname, str):
            return None

        clean = hostname.strip().strip("[]").strip()

        # 1. Standard IPv4 / IPv6
        try:
            return ipaddress.ip_address(clean)
        except ValueError:
            pass

        # 2. Dword Decimal Integer (e.g., 2130706433 -> 127.0.0.1)
        if clean.isdigit():
            try:
                val = int(clean)
                if 0 <= val <= 0xFFFFFFFF:
                    return ipaddress.IPv4Address(val)
            except (ValueError, OverflowError):
                pass

        # 3. Hex Integer (e.g., 0x7f000001 -> 127.0.0.1)
        if clean.lower().startswith("0x"):
            try:
                val = int(clean, 16)
                if 0 <= val <= 0xFFFFFFFF:
                    return ipaddress.IPv4Address(val)
            except (ValueError, OverflowError):
                pass

        # 4. Mixed Dotted Notation (e.g., 0177.0.0.1, 0x7f.0.0.1, 127.1)
        parts = clean.split(".")
        if 1 <= len(parts) <= 4:
            try:
                octets = []
                for p in parts:
                    if p.lower().startswith("0x"):
                        octets.append(int(p, 16))
                    elif p.startswith("0") and len(p) > 1 and p.isdigit():
                        octets.append(int(p, 8))
                    elif p.isdigit():
                        octets.append(int(p, 10))
                    else:
                        return None

                if len(octets) == 4 and all(0 <= o <= 255 for o in octets):
                    return ipaddress.IPv4Address(bytes(octets))
                elif len(octets) == 1 and 0 <= octets[0] <= 0xFFFFFFFF:
                    return ipaddress.IPv4Address(octets[0])
            except (ValueError, OverflowError):
                pass

        return None

    @classmethod
    def is_prohibited_ip(cls, ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> Tuple[bool, Optional[str]]:
        """
        Checks whether an IP address belongs to a private, loopback, link-local,
        multicast, reserved, or cloud metadata network range.
        Returns (is_prohibited, reason).
        """
        str_ip = str(ip)
        if str_ip in CLOUD_METADATA_IPS:
            return True, f"Prohibited cloud metadata endpoint: {str_ip}"

        if ip.is_loopback:
            return True, f"Prohibited loopback address: {str_ip}"

        if ip.is_private:
            return True, f"Prohibited private network address: {str_ip}"

        if ip.is_link_local:
            return True, f"Prohibited link-local address: {str_ip}"

        if ip.is_multicast:
            return True, f"Prohibited multicast address: {str_ip}"

        if ip.is_reserved:
            return True, f"Prohibited reserved address: {str_ip}"

        if ip.is_unspecified:
            return True, f"Prohibited unspecified address: {str_ip}"

        # Carrier-grade NAT (100.64.0.0/10) check
        if isinstance(ip, ipaddress.IPv4Address):
            if ip in ipaddress.IPv4Network("100.64.0.0/10"):
                return True, f"Prohibited Shared Address Space (CGNAT): {str_ip}"

        return False, None

    @classmethod
    def is_prohibited_hostname(cls, hostname: str) -> Tuple[bool, Optional[str]]:
        """Checks if a hostname matches internal, local, or prohibited domain names."""
        clean = hostname.strip().lower()
        for pattern in PROHIBITED_HOSTNAME_PATTERNS:
            if pattern.match(clean):
                return True, f"Prohibited internal hostname pattern: '{clean}'"
        return False, None

    @classmethod
    def validate_destination(
        cls,
        hostname: str,
        port: Optional[int] = None,
        dns_resolver: Optional[Callable[[str], List[str]]] = None
    ) -> Tuple[bool, Optional[str], List[str]]:
        """
        Validates target hostname or IP before any outbound connection is initiated.
        Resolves DNS and verifies all resolved IP addresses against SSRF policies.
        Returns (is_allowed, error_reason, resolved_ips).
        """
        if not hostname:
            return False, "Target hostname is empty.", []

        # 1. Check prohibited hostname patterns
        is_bad_host, host_reason = cls.is_prohibited_hostname(hostname)
        if is_bad_host:
            return False, host_reason, []

        # 2. Check direct IP literal or alternative numeric representation
        ip_obj = cls.parse_numeric_or_special_ip(hostname)
        if ip_obj:
            is_bad_ip, ip_reason = cls.is_prohibited_ip(ip_obj)
            if is_bad_ip:
                return False, ip_reason, [str(ip_obj)]
            return True, None, [str(ip_obj)]

        # 3. DNS Resolution & All-Address Validation
        resolved_ips: List[str] = []
        try:
            if dns_resolver is not None:
                resolved_ips = list(dns_resolver(hostname))
            else:
                addr_info = socket.getaddrinfo(
                    hostname,
                    port or 80,
                    family=socket.AF_UNSPEC,
                    type=socket.SOCK_STREAM
                )
                for item in addr_info:
                    sockaddr = item[4]
                    ip_str = sockaddr[0]
                    if ip_str not in resolved_ips:
                        resolved_ips.append(ip_str)
        except (socket.gaierror, socket.herror, Exception) as exc:
            return False, f"DNS resolution failed for '{hostname}': {str(exc)}", []

        if not resolved_ips:
            return False, f"DNS returned zero address records for '{hostname}'.", []

        # Validate EVERY resolved IP
        for ip_str in resolved_ips:
            try:
                ip_val = ipaddress.ip_address(ip_str)
                is_bad, reason = cls.is_prohibited_ip(ip_val)
                if is_bad:
                    return False, f"Resolved IP {ip_str} for '{hostname}' is prohibited: {reason}", resolved_ips
            except ValueError:
                return False, f"DNS returned invalid IP representation '{ip_str}' for '{hostname}'.", resolved_ips

        return True, None, resolved_ips


@dataclass(frozen=True)
class RedirectHop:
    """Immutable record of an individual observed redirect hop."""
    hop_number: int
    url: str
    status_code: int
    location_header: Optional[str]
    resolved_target: Optional[str]
    resolved_ip: Optional[str]
    latency_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hop_number": self.hop_number,
            "url": self.url,
            "status_code": self.status_code,
            "location_header": self.location_header,
            "resolved_target": self.resolved_target,
            "resolved_ip": self.resolved_ip,
            "latency_ms": round(self.latency_ms, 2)
        }


@dataclass
class RedirectInspectionResult:
    """Structured result of safe redirect chain analysis."""
    initial_url: str
    final_destination: str
    hops: List[RedirectHop] = field(default_factory=list)
    hop_count: int = 0
    is_loop_detected: bool = False
    is_limit_exhausted: bool = False
    is_deadline_exhausted: bool = False
    ssrf_blocked: bool = False
    protocol_downgraded: bool = False
    error_reason: Optional[str] = None
    evaluated: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "initial_url": self.initial_url,
            "final_destination": self.final_destination,
            "hops": [h.to_dict() for h in self.hops],
            "hop_count": self.hop_count,
            "is_loop_detected": self.is_loop_detected,
            "is_limit_exhausted": self.is_limit_exhausted,
            "is_deadline_exhausted": self.is_deadline_exhausted,
            "ssrf_blocked": self.ssrf_blocked,
            "protocol_downgraded": self.protocol_downgraded,
            "error_reason": self.error_reason,
            "evaluated": self.evaluated
        }

    @classmethod
    def not_evaluated(cls, url: str, reason: str = "Redirect inspection disabled or not requested") -> "RedirectInspectionResult":
        return cls(
            initial_url=url,
            final_destination=url,
            hops=[],
            hop_count=0,
            error_reason=reason,
            evaluated=False
        )


class RedirectInspector:
    """
    Safely executes bounded HTTP/HTTPS redirect inspection.
    Enforces SSRF validation before every hop, tracks loop cycles,
    measures per-hop latency, and never executes JavaScript or arbitrary bodies.
    """

    def __init__(
        self,
        max_hops: int = DEFAULT_MAX_HOPS,
        per_request_timeout: float = DEFAULT_PER_REQUEST_TIMEOUT,
        overall_timeout: float = DEFAULT_OVERALL_TIMEOUT,
        max_header_size: int = DEFAULT_MAX_HEADER_SIZE
    ):
        self.max_hops = max(1, min(20, int(max_hops)))
        self.per_request_timeout = max(0.1, min(30.0, float(per_request_timeout)))
        self.overall_timeout = max(0.5, min(60.0, float(overall_timeout)))
        self.max_header_size = max_header_size

    def inspect_redirects(
        self,
        start_url: str,
        http_fetcher: Optional[Callable[[str, str, float], Tuple[int, Dict[str, str]]]] = None,
        dns_resolver: Optional[Callable[[str], List[str]]] = None
    ) -> RedirectInspectionResult:
        """
        Traces redirect hops from start_url up to max_hops or until terminal destination reached.
        Pre-validates each hop against SSRF policies before initiating network access.
        """
        current_url = start_url.strip()
        hops: List[RedirectHop] = []
        visited_urls: Set[str] = set()
        deadline = time.time() + self.overall_timeout

        initial_scheme = urllib.parse.urlparse(current_url).scheme.lower()
        protocol_downgraded = False

        for hop_idx in range(1, self.max_hops + 1):
            if time.time() > deadline:
                return RedirectInspectionResult(
                    initial_url=start_url,
                    final_destination=current_url,
                    hops=hops,
                    hop_count=len(hops),
                    is_deadline_exhausted=True,
                    error_reason="Overall redirect inspection deadline exhausted.",
                    protocol_downgraded=protocol_downgraded
                )

            # 1. Parse current hop URL
            try:
                parsed = urllib.parse.urlparse(current_url)
                scheme = (parsed.scheme or "").lower()
                hostname = parsed.hostname or ""
                port = parsed.port
            except Exception as parse_err:
                return RedirectInspectionResult(
                    initial_url=start_url,
                    final_destination=current_url,
                    hops=hops,
                    hop_count=len(hops),
                    error_reason=f"Malformed URL at hop {hop_idx}: {parse_err}",
                    protocol_downgraded=protocol_downgraded
                )

            if scheme not in ("http", "https"):
                return RedirectInspectionResult(
                    initial_url=start_url,
                    final_destination=current_url,
                    hops=hops,
                    hop_count=len(hops),
                    error_reason=f"Unsupported scheme '{scheme}' encountered during redirect chain.",
                    protocol_downgraded=protocol_downgraded
                )

            # Check for protocol downgrade (HTTPS -> HTTP)
            if initial_scheme == "https" and scheme == "http":
                protocol_downgraded = True

            # Loop detection (normalize representation for cycle check)
            normalized_visited_key = f"{scheme}://{hostname.lower()}:{port or (443 if scheme=='https' else 80)}{parsed.path}"
            if normalized_visited_key in visited_urls:
                return RedirectInspectionResult(
                    initial_url=start_url,
                    final_destination=current_url,
                    hops=hops,
                    hop_count=len(hops),
                    is_loop_detected=True,
                    error_reason=f"Redirect loop detected: destination '{current_url}' repeats earlier hop.",
                    protocol_downgraded=protocol_downgraded
                )
            visited_urls.add(normalized_visited_key)

            # 2. SSRF Destination Validation BEFORE Outbound Call
            is_allowed, ssrf_reason, resolved_ips = SSRFValidator.validate_destination(
                hostname=hostname,
                port=port,
                dns_resolver=dns_resolver
            )
            if not is_allowed:
                return RedirectInspectionResult(
                    initial_url=start_url,
                    final_destination=current_url,
                    hops=hops,
                    hop_count=len(hops),
                    ssrf_blocked=True,
                    error_reason=f"SSRF policy blocked redirect to '{current_url}': {ssrf_reason}",
                    protocol_downgraded=protocol_downgraded
                )

            # 3. Execute Non-Intrusive Request (HEAD preferred, 0-byte body)
            t_start = time.time()
            try:
                if http_fetcher is not None:
                    status_code, headers = http_fetcher(current_url, "HEAD", self.per_request_timeout)
                else:
                    status_code, headers = self._default_fetch_head(current_url, self.per_request_timeout)
                latency_ms = (time.time() - t_start) * 1000.0
            except Exception as req_err:
                latency_ms = (time.time() - t_start) * 1000.0
                return RedirectInspectionResult(
                    initial_url=start_url,
                    final_destination=current_url,
                    hops=hops,
                    hop_count=len(hops),
                    error_reason=f"Network request failed at hop {hop_idx} ('{current_url}'): {str(req_err)}",
                    protocol_downgraded=protocol_downgraded
                )

            # 4. Check for Redirect Status Code (301, 302, 303, 307, 308)
            is_redirect = status_code in (301, 302, 303, 307, 308)
            location_hdr = headers.get("Location") or headers.get("location")

            resolved_target = None
            if is_redirect:
                if not location_hdr or not location_hdr.strip():
                    hops.append(RedirectHop(
                        hop_number=hop_idx,
                        url=current_url,
                        status_code=status_code,
                        location_header=None,
                        resolved_target=None,
                        resolved_ip=resolved_ips[0] if resolved_ips else None,
                        latency_ms=latency_ms
                    ))
                    return RedirectInspectionResult(
                        initial_url=start_url,
                        final_destination=current_url,
                        hops=hops,
                        hop_count=len(hops),
                        error_reason=f"Redirect status {status_code} received without valid Location header.",
                        protocol_downgraded=protocol_downgraded
                    )

                # Resolve relative Location against current URL
                try:
                    resolved_target = urllib.parse.urljoin(current_url, location_hdr.strip())
                except Exception as join_err:
                    hops.append(RedirectHop(
                        hop_number=hop_idx,
                        url=current_url,
                        status_code=status_code,
                        location_header=location_hdr,
                        resolved_target=None,
                        resolved_ip=resolved_ips[0] if resolved_ips else None,
                        latency_ms=latency_ms
                    ))
                    return RedirectInspectionResult(
                        initial_url=start_url,
                        final_destination=current_url,
                        hops=hops,
                        hop_count=len(hops),
                        error_reason=f"Malformed Location header '{location_hdr}': {join_err}",
                        protocol_downgraded=protocol_downgraded
                    )

            hops.append(RedirectHop(
                hop_number=hop_idx,
                url=current_url,
                status_code=status_code,
                location_header=location_hdr,
                resolved_target=resolved_target,
                resolved_ip=resolved_ips[0] if resolved_ips else None,
                latency_ms=latency_ms
            ))

            if not is_redirect or not resolved_target:
                # Terminal destination reached (e.g. 200 OK, 404 Not Found, etc.)
                return RedirectInspectionResult(
                    initial_url=start_url,
                    final_destination=current_url,
                    hops=hops,
                    hop_count=len(hops),
                    protocol_downgraded=protocol_downgraded
                )

            # Advance to next hop
            current_url = resolved_target

        # Reached max hops without terminal response
        return RedirectInspectionResult(
            initial_url=start_url,
            final_destination=current_url,
            hops=hops,
            hop_count=len(hops),
            is_limit_exhausted=True,
            error_reason=f"Exhausted maximum redirect hop limit ({self.max_hops}).",
            protocol_downgraded=protocol_downgraded
        )

    def _default_fetch_head(self, url: str, timeout: float) -> Tuple[int, Dict[str, str]]:
        """
        Executes a single HEAD request without automatically following redirects.
        Falls back to GET with 0-byte read if server returns 405 Method Not Allowed.
        """
        parsed = urllib.parse.urlparse(url)
        is_https = parsed.scheme.lower() == "https"
        port = parsed.port or (443 if is_https else 80)
        host = parsed.hostname or ""
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        conn_cls = http.client.HTTPSConnection if is_https else http.client.HTTPConnection
        conn = conn_cls(host, port, timeout=timeout)
        try:
            conn.putrequest("HEAD", path, skip_host=True, skip_accept_encoding=True)
            conn.putheader("Host", f"{host}:{port}" if parsed.port else host)
            conn.putheader("User-Agent", "ACTIS-Security-Scanner/0.1.0 (Defensive URL Analysis)")
            conn.putheader("Accept", "*/*")
            conn.endheaders()

            resp = conn.getresponse()
            headers = {k: v for k, v in resp.getheaders()}
            status = resp.status

            if status == 405:  # Method Not Allowed -> fallback to GET without body reading
                conn.close()
                conn = conn_cls(host, port, timeout=timeout)
                conn.putrequest("GET", path, skip_host=True, skip_accept_encoding=True)
                conn.putheader("Host", f"{host}:{port}" if parsed.port else host)
                conn.putheader("User-Agent", "ACTIS-Security-Scanner/0.1.0 (Defensive URL Analysis)")
                conn.putheader("Accept", "*/*")
                conn.endheaders()
                resp = conn.getresponse()
                headers = {k: v for k, v in resp.getheaders()}
                status = resp.status

            return status, headers
        finally:
            conn.close()
