"""
ACTIS Safe MIME Message Parser Subsystem
Provides bounded, read-only parsing of RFC 822/5322 and MIME messages using
Python's standard library email package. Extracts sanitized headers, text/HTML
bodies, attachment metadata, and embedded URLs with display-text mismatch detection.

SECURITY GUARANTEES:
1. Zero execution of attachments, scripts, or downloaded content.
2. Read-only metadata extraction for attachments (no extraction, execution, or dynamic loading).
3. Bounded resources (message size, header size, part count, nesting depth, decoded text, URL count).
4. Malformed MIME defect isolation without unhandled exceptions or application crashes.
5. Zero outbound network activity during message parsing.
"""

import re
import os
import time
from email import policy
from email.parser import BytesParser, Parser
from email.message import EmailMessage
from html.parser import HTMLParser
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple, Set, Union
from urllib.parse import urlparse

from scanners.url_scanner import normalize_url, extract_domain
from config.config import get_logger

logger = get_logger("MIMEParser")

# Default resource boundaries
DEFAULT_MAX_RAW_MESSAGE_SIZE = 10 * 1024 * 1024       # 10 MB
DEFAULT_MAX_HEADER_LENGTH = 64 * 1024                 # 64 KB
DEFAULT_MAX_MIME_PARTS = 50                           # 50 parts
DEFAULT_MAX_MIME_DEPTH = 10                           # 10 levels deep
DEFAULT_MAX_DECODED_TEXT_SIZE = 1 * 1024 * 1024       # 1 MB total decoded text
DEFAULT_MAX_PART_SIZE = 5 * 1024 * 1024               # 5 MB per individual part
DEFAULT_MAX_EXTRACTED_URLS = 100                      # 100 URLs max
DEFAULT_MAX_ANALYSIS_TIME_SECONDS = 5.0               # 5.0s deadline

# High-risk executable, script, or macro extensions commonly weaponized in attachments
DANGEROUS_ATTACHMENT_EXTENSIONS = {
    ".exe", ".scr", ".pif", ".bat", ".cmd", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".wsh", ".ps1", ".psm1", ".hta", ".cpl", ".jar",
    ".iso", ".img", ".vhd", ".vhdx", ".lnk", ".dll", ".sys", ".com",
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm"
}

# Regex to find plain-text URLs in bodies
URL_REGEX = re.compile(r"(?:https?://|www\.)[^\s<>\"]+", re.IGNORECASE)


def sanitize_filename(raw_filename: Optional[str]) -> str:
    """
    Sanitizes an attachment filename to prevent directory traversal,
    path injection, or control character abuse in logs and reports.
    """
    if not raw_filename or not isinstance(raw_filename, str):
        return "unnamed_attachment"
    
    # Strip directory paths
    base = os.path.basename(raw_filename).strip()
    
    # Remove control characters and null bytes
    cleaned = "".join(c for c in base if ord(c) >= 32 and ord(c) != 127)
    
    # Remove dangerous characters
    cleaned = re.sub(r'[\\/:*?"<>|]', '_', cleaned)
    
    # Bound length
    if len(cleaned) > 255:
        ext = os.path.splitext(cleaned)[1]
        cleaned = cleaned[:255 - len(ext)] + ext
        
    return cleaned.strip() or "unnamed_attachment"


def clean_url_token(raw_token: Any) -> str:
    """
    Cleans an extracted URL token by removing surrounding punctuation,
    unbalanced enclosing parentheses/brackets/braces, and outer quotes.
    """
    if not raw_token or not isinstance(raw_token, str):
        return ""
    token = raw_token.strip()
    while token:
        if token[-1] in ".,;:!?'\"":
            token = token[:-1]
        elif token[-1] == ")" and token.count(")") > token.count("("):
            token = token[:-1]
        elif token[-1] == "]" and token.count("]") > token.count("["):
            token = token[:-1]
        elif token[-1] == "}" and token.count("}") > token.count("{"):
            token = token[:-1]
        else:
            break

    while token and token[0] in "\"'<([{":
        token = token[1:]

    return token.strip()


@dataclass(frozen=True)
class AttachmentMetadata:
    """
    Read-only structural metadata for a message attachment.
    Does NOT store raw attachment content in memory.
    """
    filename: str
    content_type: str
    content_disposition: str
    size_bytes: int
    part_index: int
    is_suspicious_extension: bool
    extension: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "filename": self.filename,
            "content_type": self.content_type,
            "content_disposition": self.content_disposition,
            "size_bytes": self.size_bytes,
            "part_index": self.part_index,
            "is_suspicious_extension": self.is_suspicious_extension,
            "extension": self.extension
        }


@dataclass(frozen=True)
class ExtractedMessageURL:
    """
    Metadata for a URL extracted from a message component, preserving provenance.
    """
    url: str
    canonical_url: str
    source_part: str               # "plain_text", "html_href", "html_src", "html_text", "header_subject"
    display_text: Optional[str]    # Visible anchor text if extracted from HTML <a>
    is_display_mismatch: bool      # True if display text portrays a different domain
    part_index: int

    @property
    def source_type(self) -> str:
        """Alias for source_part for unified evidence provenance naming."""
        return self.source_part

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "canonical_url": self.canonical_url,
            "source_part": self.source_part,
            "source_type": self.source_part,
            "display_text": self.display_text,
            "is_display_mismatch": self.is_display_mismatch,
            "part_index": self.part_index
        }


@dataclass
class MIMEAnalysisLimits:
    """Configurable resource boundaries for MIME message parsing."""
    max_raw_message_size: int = DEFAULT_MAX_RAW_MESSAGE_SIZE
    max_header_length: int = DEFAULT_MAX_HEADER_LENGTH
    max_mime_parts: int = DEFAULT_MAX_MIME_PARTS
    max_mime_depth: int = DEFAULT_MAX_MIME_DEPTH
    max_decoded_text_size: int = DEFAULT_MAX_DECODED_TEXT_SIZE
    max_part_size: int = DEFAULT_MAX_PART_SIZE
    max_extracted_urls: int = DEFAULT_MAX_EXTRACTED_URLS
    max_analysis_time_seconds: float = DEFAULT_MAX_ANALYSIS_TIME_SECONDS

    def __init__(
        self,
        max_raw_message_size: int = DEFAULT_MAX_RAW_MESSAGE_SIZE,
        max_header_length: int = DEFAULT_MAX_HEADER_LENGTH,
        max_mime_parts: int = DEFAULT_MAX_MIME_PARTS,
        max_mime_depth: int = DEFAULT_MAX_MIME_DEPTH,
        max_decoded_text_size: int = DEFAULT_MAX_DECODED_TEXT_SIZE,
        max_part_size: int = DEFAULT_MAX_PART_SIZE,
        max_extracted_urls: int = DEFAULT_MAX_EXTRACTED_URLS,
        max_analysis_time_seconds: float = DEFAULT_MAX_ANALYSIS_TIME_SECONDS,
        **kwargs
    ):
        self.max_raw_message_size = kwargs.get("max_message_bytes", max_raw_message_size)
        self.max_header_length = kwargs.get("max_header_bytes", max_header_length)
        self.max_mime_parts = kwargs.get("max_parts", max_mime_parts)
        self.max_mime_depth = kwargs.get("max_depth", max_mime_depth)
        self.max_decoded_text_size = kwargs.get("max_decoded_text_chars", max_decoded_text_size)
        self.max_part_size = kwargs.get("max_part_size", max_part_size)
        self.max_extracted_urls = kwargs.get("max_extracted_urls", max_extracted_urls)
        self.max_analysis_time_seconds = kwargs.get("max_analysis_time_seconds", max_analysis_time_seconds)


@dataclass
class MIMEAnalysisResult:
    """
    Structured outcome of safe MIME message parsing.
    Encapsulates sanitized headers, decoded text/HTML, attachment metadata,
    and extracted URLs with provenance and resource-limit tracking.
    """
    is_valid: bool
    is_mime: bool
    analysis_completeness: str     # "COMPLETE", "PARTIAL", "FAILED"
    headers: Dict[str, str]
    plain_text_body: str
    html_body: str
    plain_text_parts_count: int
    html_parts_count: int
    total_parts_count: int
    max_depth_observed: int
    attachments: List[AttachmentMetadata] = field(default_factory=list)
    extracted_urls: List[ExtractedMessageURL] = field(default_factory=list)
    unique_canonical_urls: List[str] = field(default_factory=list)
    url_occurrence_counts: Dict[str, int] = field(default_factory=dict)
    defects: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    limit_reached: Optional[str] = None
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "is_mime": self.is_mime,
            "analysis_completeness": self.analysis_completeness,
            "headers": dict(self.headers),
            "plain_text_parts_count": self.plain_text_parts_count,
            "html_parts_count": self.html_parts_count,
            "total_parts_count": self.total_parts_count,
            "max_depth_observed": self.max_depth_observed,
            "attachments_count": len(self.attachments),
            "attachments": [a.to_dict() for a in self.attachments],
            "total_url_count": len(self.extracted_urls),
            "unique_url_count": len(self.unique_canonical_urls),
            "extracted_urls": [u.to_dict() for u in self.extracted_urls],
            "unique_canonical_urls": list(self.unique_canonical_urls),
            "url_occurrence_counts": dict(self.url_occurrence_counts),
            "defects": list(self.defects),
            "warnings": list(self.warnings),
            "limit_reached": self.limit_reached,
            "error_message": self.error_message
        }


class SafeHTMLURLParser(HTMLParser):
    """
    Streaming standard-library HTML parser that safely extracts href and src
    attributes and associates visible anchor display text without rendering or JS execution.
    """
    def __init__(self, max_urls: int = DEFAULT_MAX_EXTRACTED_URLS):
        super().__init__(convert_charrefs=True)
        self.max_urls = max_urls
        self.links: List[Tuple[str, str, str]] = []  # (url, source_attr, display_text)
        self._current_href: Optional[str] = None
        self._current_text: List[str] = []
        self._in_script_or_style = False
        self._stop = False

    def _flush_current_link(self):
        """Flushes the current active anchor link and accumulated display text."""
        if self._current_href:
            display = "".join(self._current_text).strip()
            if len(self.links) < self.max_urls:
                self.links.append((self._current_href, "html_href", display))
            else:
                self._stop = True
            self._current_href = None
            self._current_text = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        if self._stop:
            return
        tag_lower = tag.lower()
        if tag_lower in ("script", "style"):
            self._in_script_or_style = True
            return

        # If a block formatting element or a new anchor begins while an unclosed <a> is open,
        # flush the accumulated anchor and display text before continuing.
        if self._current_href and tag_lower in (
            "a", "p", "div", "table", "tr", "td", "li", "ul", "ol",
            "h1", "h2", "h3", "h4", "h5", "h6", "hr", "br", "body", "html",
            "section", "article", "header", "footer"
        ):
            self._flush_current_link()

        attr_dict = {k.lower(): (v or "") for k, v in attrs}
        if tag_lower == "a":
            href = attr_dict.get("href", "").strip()
            # Ignore non-web schemes and relative fragment/path links
            if href and not href.startswith(("javascript:", "data:", "mailto:", "tel:", "#", "/")):
                if href.startswith(("http://", "https://", "//", "www.")) or ("." in href and not href.startswith(".")):
                    self._current_href = href
                    self._current_text = []
        elif tag_lower in ("img", "iframe", "embed", "frame"):
            src = attr_dict.get("src", "").strip()
            if src and src.startswith(("http://", "https://", "//", "www.")):
                if len(self.links) < self.max_urls:
                    self.links.append((src, "html_src", ""))
                else:
                    self._stop = True

    def handle_data(self, data: str):
        if self._stop or self._in_script_or_style:
            return
        if self._current_href:
            self._current_text.append(data)
        else:
            # Safely capture any plain text URLs in non-script/non-style HTML text nodes
            for m in URL_REGEX.finditer(data):
                if len(self.links) >= self.max_urls:
                    self._stop = True
                    break
                found_url = clean_url_token(m.group(0))
                if found_url and not found_url.startswith(("#", "/")):
                    self.links.append((found_url, "html_text", ""))

    def handle_endtag(self, tag: str):
        tag_lower = tag.lower()
        if tag_lower in ("script", "style"):
            self._in_script_or_style = False
        elif tag_lower == "a" and self._current_href:
            self._flush_current_link()

    def close(self):
        self._flush_current_link()
        super().close()


def is_domain_mismatch(display_text: Optional[str], destination_url: str) -> bool:
    """
    Evaluates whether visible anchor display text purports to represent
    a domain or host that does not match the actual destination domain.
    """
    if not display_text or not isinstance(display_text, str):
        return False
    
    clean_display = display_text.strip().lower()
    # Check if display text looks like a domain or URL
    if not (clean_display.startswith(("http://", "https://", "www.")) or "." in clean_display):
        return False
    
    # Try to extract domain from display text
    try:
        if not clean_display.startswith(("http://", "https://")):
            display_url = "http://" + clean_display
        else:
            display_url = clean_display
        display_domain = extract_domain(display_url)
    except Exception:
        return False
        
    if not display_domain or "." not in display_domain:
        return False
        
    try:
        dest_domain = extract_domain(destination_url)
    except Exception:
        return False
        
    if not dest_domain:
        return False

    # Normalize subdomains for comparison
    d_dom = display_domain.lower().rstrip(".")
    t_dom = dest_domain.lower().rstrip(".")
    
    if d_dom == t_dom:
        return False

    # If both share the same registered base domain (e.g. login.company.com vs auth.company.com), not a mismatch
    # unless an explicitly adversarial or deceptive label is used (e.g. attacker.example.com vs secure.example.com)
    def _base_domain(dom: str) -> str:
        parts = dom.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else dom

    if _base_domain(d_dom) == _base_domain(t_dom):
        adversarial_tokens = {"attacker", "evil", "phish", "malicious", "fake", "bad", "spoof"}
        d_sublabels = set(d_dom.split(".")[:-2])
        t_sublabels = set(t_dom.split(".")[:-2])
        if any(tok in t_sublabels or tok in d_sublabels for tok in adversarial_tokens):
            return True
        return False

    if t_dom.endswith("." + d_dom) or d_dom.endswith("." + t_dom):
        return False

    return True


class SafeMIMEParser:
    """
    Bounded, standards-compliant MIME parser leveraging Python's email library.
    Operates in pure read-only mode with configurable resource safeguards.
    """
    def __init__(self, limits: Optional[MIMEAnalysisLimits] = None):
        self.limits = limits or MIMEAnalysisLimits()

    def parse_message(
        self,
        raw_input: Union[bytes, str],
        deadline_time: Optional[float] = None
    ) -> MIMEAnalysisResult:
        """
        Parses raw email bytes or string into a structured MIMEAnalysisResult.
        Guarantees bounded traversal, defect collection, and zero application crashes.
        """
        start_time = time.time()
        deadline = deadline_time or (start_time + self.limits.max_analysis_time_seconds)

        if raw_input is None:
            return MIMEAnalysisResult(
                is_valid=False,
                is_mime=False,
                analysis_completeness="FAILED",
                headers={},
                plain_text_body="",
                html_body="",
                plain_text_parts_count=0,
                html_parts_count=0,
                total_parts_count=0,
                max_depth_observed=0,
                error_message="Message input is None."
            )

        # Convert str to bytes if necessary
        if isinstance(raw_input, str):
            if not raw_input.strip():
                return MIMEAnalysisResult(
                    is_valid=False,
                    is_mime=False,
                    analysis_completeness="FAILED",
                    headers={},
                    plain_text_body="",
                    html_body="",
                    plain_text_parts_count=0,
                    html_parts_count=0,
                    total_parts_count=0,
                    max_depth_observed=0,
                    error_message="Message input is empty."
                )
            raw_bytes = raw_input.encode("utf-8", errors="replace")
        elif isinstance(raw_input, (bytes, bytearray)):
            if len(raw_input) == 0:
                return MIMEAnalysisResult(
                    is_valid=False,
                    is_mime=False,
                    analysis_completeness="FAILED",
                    headers={},
                    plain_text_body="",
                    html_body="",
                    plain_text_parts_count=0,
                    html_parts_count=0,
                    total_parts_count=0,
                    max_depth_observed=0,
                    error_message="Message input bytes are empty."
                )
            raw_bytes = bytes(raw_input)
        else:
            return MIMEAnalysisResult(
                is_valid=False,
                is_mime=False,
                analysis_completeness="FAILED",
                headers={},
                plain_text_body="",
                html_body="",
                plain_text_parts_count=0,
                html_parts_count=0,
                total_parts_count=0,
                max_depth_observed=0,
                error_message=f"Unsupported message input type: {type(raw_input).__name__}"
            )

        # Check total raw message size boundary
        limit_reached = None
        warnings: List[str] = []
        if len(raw_bytes) > self.limits.max_raw_message_size:
            warnings.append(
                f"Raw message size ({len(raw_bytes)} bytes) exceeds limit ({self.limits.max_raw_message_size} bytes); truncated."
            )
            raw_bytes = raw_bytes[:self.limits.max_raw_message_size]
            limit_reached = "MAX_RAW_MESSAGE_SIZE"

        # Check header boundary
        header_end = raw_bytes.find(b"\r\n\r\n")
        if header_end == -1:
            header_end = raw_bytes.find(b"\n\n")
        if header_end != -1 and header_end > self.limits.max_header_length:
            warnings.append(
                f"Header block ({header_end} bytes) exceeds limit ({self.limits.max_header_length} bytes)."
            )
            limit_reached = limit_reached or "MAX_HEADER_LENGTH"

        # Parse message using standard library BytesParser with default policy
        try:
            parser = BytesParser(policy=policy.default)
            msg = parser.parsebytes(raw_bytes)
        except Exception as exc:
            logger.warning(f"BytesParser failure: {exc}")
            # Graceful fallback to Parser with latin-1 text
            try:
                text_parser = Parser(policy=policy.default)
                msg = text_parser.parsestr(raw_bytes.decode("latin-1", errors="replace"))
            except Exception as inner_exc:
                return MIMEAnalysisResult(
                    is_valid=False,
                    is_mime=False,
                    analysis_completeness="FAILED",
                    headers={},
                    plain_text_body="",
                    html_body="",
                    plain_text_parts_count=0,
                    html_parts_count=0,
                    total_parts_count=0,
                    max_depth_observed=0,
                    error_message=f"MIME parsing failed: {str(inner_exc)}"
                )

        # Record parser defects
        defects = []
        if hasattr(msg, "defects") and msg.defects:
            for d in msg.defects:
                defects.append(type(d).__name__)

        # Extract sanitized headers
        sanitized_headers = self._extract_sanitized_headers(msg)
        is_mime = bool(msg.get("MIME-Version")) or msg.is_multipart() or bool(msg.get("Content-Type"))

        # Traverse MIME structure with bounded recursion
        plain_text_accum: List[str] = []
        html_accum: List[str] = []
        attachments: List[AttachmentMetadata] = []
        extracted_urls: List[ExtractedMessageURL] = []
        
        parts_examined = 0
        max_depth_seen = 0
        total_decoded_bytes = 0

        # Stack for iterative traversal: (part, current_depth)
        stack: List[Tuple[Any, int]] = [(msg, 1)]

        while stack:
            if time.time() > deadline:
                warnings.append("Message analysis deadline exceeded; halting traversal.")
                limit_reached = limit_reached or "MAX_ANALYSIS_TIME"
                break

            current_part, current_depth = stack.pop(0)
            parts_examined += 1
            if current_depth > max_depth_seen:
                max_depth_seen = current_depth

            if parts_examined > self.limits.max_mime_parts:
                warnings.append(f"MIME part count limit ({self.limits.max_mime_parts}) reached.")
                limit_reached = limit_reached or "MAX_MIME_PARTS"
                break

            if current_depth > self.limits.max_mime_depth:
                warnings.append(f"MIME nesting depth limit ({self.limits.max_mime_depth}) exceeded.")
                limit_reached = limit_reached or "MAX_MIME_DEPTH"
                continue

            if current_part.is_multipart():
                subparts = current_part.get_payload()
                if isinstance(subparts, list):
                    for sp in subparts:
                        stack.append((sp, current_depth + 1))
                continue

            # Process leaf part
            content_type = current_part.get_content_type().lower()
            disposition = str(current_part.get_content_disposition() or "").lower()
            raw_filename = current_part.get_filename()

            is_attachment = (
                disposition == "attachment"
                or bool(raw_filename)
                or (disposition != "inline" and content_type not in ("text/plain", "text/html"))
            )

            if is_attachment:
                if not raw_filename:
                    raw_filename = f"unnamed_attachment_{parts_examined}"
                filename = sanitize_filename(raw_filename)
                ext = os.path.splitext(filename)[1].lower()
                is_suspicious = ext in DANGEROUS_ATTACHMENT_EXTENSIONS

                # Determine payload size safely without executing or unbounded loading
                payload_size = 0
                try:
                    payload = current_part.get_payload(decode=True)
                    if payload:
                        payload_size = len(payload)
                except Exception:
                    payload_size = 0

                attachments.append(AttachmentMetadata(
                    filename=filename,
                    content_type=content_type,
                    content_disposition=disposition or "attachment",
                    size_bytes=payload_size,
                    part_index=parts_examined,
                    is_suspicious_extension=is_suspicious,
                    extension=ext
                ))
            else:
                # Text or HTML content part
                try:
                    payload_bytes = current_part.get_payload(decode=True)
                except Exception as dec_err:
                    warnings.append(f"Part {parts_examined} payload decoding error: {dec_err}")
                    payload_bytes = None

                if payload_bytes:
                    if len(payload_bytes) > self.limits.max_part_size:
                        payload_bytes = payload_bytes[:self.limits.max_part_size]
                        warnings.append(f"Part {parts_examined} size exceeded limit; truncated.")
                        limit_reached = limit_reached or "MAX_PART_SIZE"

                    # Decode character set safely
                    charset = current_part.get_content_charset() or "utf-8"
                    try:
                        decoded_text = payload_bytes.decode(charset, errors="replace")
                    except (LookupError, UnicodeDecodeError):
                        decoded_text = payload_bytes.decode("utf-8", errors="replace")

                    total_decoded_bytes += len(decoded_text)
                    if total_decoded_bytes > self.limits.max_decoded_text_size:
                        allowed_len = max(0, len(decoded_text) - (total_decoded_bytes - self.limits.max_decoded_text_size))
                        decoded_text = decoded_text[:allowed_len]
                        warnings.append("Decoded text size limit reached.")
                        limit_reached = limit_reached or "MAX_DECODED_TEXT"

                    if content_type == "text/plain":
                        plain_text_accum.append(decoded_text)
                        # Extract URLs from plain text
                        self._extract_plain_text_urls(decoded_text, parts_examined, extracted_urls)
                    elif content_type == "text/html":
                        html_accum.append(decoded_text)
                        # Extract URLs from HTML structure with display text mismatch check
                        self._extract_html_urls(decoded_text, parts_examined, extracted_urls)
                    else:
                        # Other non-attachment text formats (e.g. text/csv)
                        plain_text_accum.append(decoded_text)

        # Fallback for non-MIME plain text / SMS / chat messages where BytesParser
        # treated input as a single header block with no body
        if not plain_text_accum and not html_accum and not attachments:
            decoded_fallback = raw_bytes.decode("utf-8", errors="replace")
            plain_text_accum.append(decoded_fallback)
            self._extract_plain_text_urls(decoded_fallback, 1, extracted_urls)
            is_mime = False

        # Extract URLs from Subject header if present
        if sanitized_headers.get("Subject"):
            self._extract_plain_text_urls(sanitized_headers["Subject"], 0, extracted_urls, source_part="header_subject")

        if len(extracted_urls) >= self.limits.max_extracted_urls:
            warnings.append(f"Extracted URL limit ({self.limits.max_extracted_urls}) reached.")
            limit_reached = limit_reached or "MAX_EXTRACTED_URLS"

        full_plain_text = "\n\n".join(plain_text_accum)
        full_html = "\n\n".join(html_accum)

        # Deduplicate extracted URLs to canonical unique list
        unique_canonical: List[str] = []
        url_counts: Dict[str, int] = {}
        for item in extracted_urls:
            c = item.canonical_url
            if not c:
                continue
            if c not in url_counts:
                url_counts[c] = 1
                unique_canonical.append(c)
            else:
                url_counts[c] += 1

        completeness = "COMPLETE" if not limit_reached else "PARTIAL"

        return MIMEAnalysisResult(
            is_valid=True,
            is_mime=is_mime,
            analysis_completeness=completeness,
            headers=sanitized_headers,
            plain_text_body=full_plain_text,
            html_body=full_html,
            plain_text_parts_count=len(plain_text_accum),
            html_parts_count=len(html_accum),
            total_parts_count=parts_examined,
            max_depth_observed=max_depth_seen,
            attachments=attachments,
            extracted_urls=extracted_urls,
            unique_canonical_urls=unique_canonical,
            url_occurrence_counts=url_counts,
            defects=defects,
            warnings=warnings,
            limit_reached=limit_reached,
            error_message=None
        )

    def _extract_sanitized_headers(self, msg: Any) -> Dict[str, str]:
        """Extracts and bounds standard email headers without sensitive values."""
        interesting_headers = [
            "From", "To", "Cc", "Reply-To", "Return-Path", "Sender",
            "Subject", "Date", "Message-ID", "MIME-Version", "Content-Type",
            "Authentication-Results"
        ]
        sanitized = {}
        for h in interesting_headers:
            val = msg.get(h)
            if val is not None:
                # Sanitize newlines and bound header length
                clean_val = " ".join(str(val).split())
                if len(clean_val) > 1024:
                    clean_val = clean_val[:1024] + "..."
                sanitized[h] = clean_val
        return sanitized

    def _extract_plain_text_urls(
        self,
        text: str,
        part_index: int,
        out_list: List[ExtractedMessageURL],
        source_part: str = "plain_text"
    ):
        """Extracts URLs from plain-text content."""
        if len(out_list) >= self.limits.max_extracted_urls:
            return
        matches = URL_REGEX.findall(text)
        for m in matches:
            if len(out_list) >= self.limits.max_extracted_urls:
                break
            cleaned = clean_url_token(m)
            if cleaned:
                canonical = normalize_url(cleaned)
                out_list.append(ExtractedMessageURL(
                    url=cleaned,
                    canonical_url=canonical,
                    source_part=source_part,
                    display_text=None,
                    is_display_mismatch=False,
                    part_index=part_index
                ))

    def _extract_html_urls(
        self,
        html_content: str,
        part_index: int,
        out_list: List[ExtractedMessageURL]
    ):
        """Parses HTML with SafeHTMLURLParser and evaluates display-text mismatch."""
        if len(out_list) >= self.limits.max_extracted_urls:
            return
        remaining_slots = self.limits.max_extracted_urls - len(out_list)
        parser = SafeHTMLURLParser(max_urls=remaining_slots)
        try:
            parser.feed(html_content)
            parser.close()
        except Exception as parse_err:
            logger.debug(f"HTML link parsing notice: {parse_err}")

        for href, source_attr, display_text in parser.links:
            if len(out_list) >= self.limits.max_extracted_urls:
                break
            cleaned = clean_url_token(href)
            if not cleaned:
                continue
            canonical = normalize_url(cleaned)
            mismatch = is_domain_mismatch(display_text, canonical)
            out_list.append(ExtractedMessageURL(
                url=cleaned,
                canonical_url=canonical,
                source_part=source_attr,
                display_text=display_text if display_text else None,
                is_display_mismatch=mismatch,
                part_index=part_index
            ))


# Global parser singleton with default bounds
safe_mime_parser = SafeMIMEParser()
