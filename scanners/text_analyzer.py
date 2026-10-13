"""
ACTIS Message & Email Text Analyzer Module
Extracts URLs from emails, SMS, and chat messages, evaluates social-engineering
cues (urgency, credential prompts, impersonation, security evasion), handles safe
MIME message structure, and routes URLs through the unified URL scanner.
"""

import re
from typing import Dict, Any, List, Tuple, Optional, Union
from dataclasses import dataclass, field

from scanners.url_scanner import scan_url_logic, normalize_url
from scanners.mime_parser import (
    safe_mime_parser,
    clean_url_token,
    MIMEAnalysisResult,
    AttachmentMetadata,
    ExtractedMessageURL,
    URL_REGEX
)
from config.config import get_logger

logger = get_logger("TextAnalyzer")

URGENCY_PATTERNS = [
    r"\burgent\b", r"\bimmediate(ly)?\b", r"\bwithin \d+ hours?\b",
    r"\baction required\b", r"\baccount (suspended|locked|terminated)\b",
    r"\bsecurity alert\b", r"\bunauthorized access\b", r"\bexpires? soon\b",
    r"\bfinal warning\b", r"\brespond within\b", r"\bdeadline\b"
]

CREDENTIAL_PATTERNS = [
    r"\bverify (your )?password\b", r"\bconfirm (your )?identity\b",
    r"\benter (your )?pin\b", r"\benter (your )?password\b", r"\bupdate (your )?billing\b",
    r"\blogin credentials\b", r"\bre-enter password\b", r"\bvalidate account\b",
    r"\breset (your )?password\b", r"\bconfirm (your )?credentials\b",
    r"\bverify (your )?credentials\b", r"\bupdate (your )?password\b"
]

FINANCIAL_PATTERNS = [
    r"\bwire transfer\b", r"\bbitcoin payout\b", r"\bclaim your refund\b",
    r"\btax refund\b", r"\brefund payout\b", r"\bbank account details\b",
    r"\byou have won\b", r"\binheritance\b", r"\bprocessing fee\b",
    r"\bcrypto deposit\b", r"\bunclaimed prize\b", r"\bpayment overdue\b",
    r"\binvoice attached\b", r"\bremittance advice\b", r"\bgift card(s)?\b"
]

IMPERSONATION_PATTERNS = [
    r"\bit support\b", r"\bsystem administrator\b", r"\bhelp desk\b",
    r"\bsecurity team\b", r"\bhuman resources\b", r"\bpayroll department\b",
    r"\bexecutive office\b", r"\bmanagement team\b"
]

SECURITY_EVASION_PATTERNS = [
    r"\bignore (security )?warnings?\b", r"\bdisable (your )?antivirus\b",
    r"\bbypass (the )?approval\b", r"\bdo not report\b",
    r"\btrust this certificate\b", r"\boverride protection\b"
]

SENSITIVE_INFO_PATTERNS = [
    r"\bone-time password\b", r"\b2fa code\b", r"\botp\b",
    r"\brecovery codes?\b", r"\bseed phrase\b", r"\bsecurity questions?\b",
    r"\bauthentication token\b"
]


@dataclass
class MessageScanResult:
    """
    Structured message scan result contract.
    Aggregates message-level social-engineering indicators, MIME structure,
    attachment metadata, and per-URL threat intelligence without permanently
    persisting sensitive communication contents.
    """
    total_url_count: int
    unique_url_count: int
    urls_found: List[str]
    url_results: List[Dict[str, Any]]
    threat_urls_count: int
    social_engineering: Dict[str, Any]
    overall_score: float
    overall_risk_level: str
    is_suspicious_message: bool
    explanation_summary: List[str] = field(default_factory=list)
    recommended_action: str = ""
    message_length: int = 0
    is_mime: bool = False
    mime_headers: Dict[str, str] = field(default_factory=dict)
    attachments: List[Dict[str, Any]] = field(default_factory=list)
    extracted_urls_metadata: List[Dict[str, Any]] = field(default_factory=list)
    display_mismatches_count: int = 0
    suspicious_attachments_count: int = 0
    analysis_completeness: str = "COMPLETE"
    mime_defects: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    is_valid: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the message scan result into a standard dictionary representation."""
        return {
            "total_url_count": self.total_url_count,
            "unique_url_count": self.unique_url_count,
            "url_count": self.unique_url_count,  # backward compatibility alias
            "urls_found": list(self.urls_found),
            "url_results": list(self.url_results),
            "threat_urls_count": self.threat_urls_count,
            "social_engineering": dict(self.social_engineering),
            "overall_score": round(self.overall_score, 1),
            "overall_risk_level": self.overall_risk_level,
            "is_suspicious_message": self.is_suspicious_message,
            "explanation_summary": list(self.explanation_summary),
            "reasons": list(self.explanation_summary),  # backward compatibility alias
            "recommended_action": self.recommended_action,
            "message_length": self.message_length,
            "is_mime": self.is_mime,
            "mime_headers": dict(self.mime_headers),
            "attachments_count": len(self.attachments),
            "attachments": list(self.attachments),
            "extracted_urls_metadata": list(self.extracted_urls_metadata),
            "display_mismatches_count": self.display_mismatches_count,
            "suspicious_attachments_count": self.suspicious_attachments_count,
            "analysis_completeness": self.analysis_completeness,
            "mime_defects": list(self.mime_defects),
            "warnings": list(self.warnings),
            "is_valid": self.is_valid
        }


def generate_message_action(risk_level: str) -> str:
    """Produces security recommendation for message analysis."""
    actions = {
        "CRITICAL": "DO NOT click links, open attachments, or supply credentials. Quarantine or report this message immediately.",
        "HIGH": "Strong threat indicators detected in links, attachments, or messaging. Verify authenticity via an independent channel.",
        "MEDIUM": "Suspicious language or anomalous link structures observed. Exercise heightened caution.",
        "LOW": "Standard email hygiene recommended. No high-risk threats detected."
    }
    return actions.get(risk_level, actions["LOW"])


class TextAnalyzer:
    """Analyzes messages, emails, and notes for suspicious links, MIME structures, and engineering cues."""

    @staticmethod
    def extract_raw_urls(text: Any) -> List[str]:
        """
        Extracts all raw URL occurrences from text content in order of appearance,
        including duplicates, after boundary punctuation cleaning.
        Safely returns empty list on empty or non-string input.
        """
        if not text or not isinstance(text, str):
            return []

        raw_matches = URL_REGEX.findall(text)
        cleaned_tokens = []
        for match in raw_matches:
            cleaned = clean_url_token(match)
            if cleaned:
                cleaned_tokens.append(cleaned)
        return cleaned_tokens

    @classmethod
    def extract_urls(cls, text: Any) -> List[str]:
        """
        Extracts cleaned, unique URLs from text content, preserving first-seen order.
        Safely returns empty list on empty or non-string input.
        """
        raw_list = cls.extract_raw_urls(text)
        unique_urls: List[str] = []
        seen = set()
        for u in raw_list:
            if u not in seen:
                seen.add(u)
                unique_urls.append(u)
        return unique_urls

    @classmethod
    def evaluate_social_engineering(cls, text: Any) -> Dict[str, Any]:
        """Identifies suspicious urgency, credential requests, financial lure, impersonation, and evasion keywords."""
        if not text or not isinstance(text, str):
            return {
                "se_score": 0,
                "has_urgency": False,
                "urgency_indicators": [],
                "has_credential_request": False,
                "credential_indicators": [],
                "has_financial_lure": False,
                "financial_indicators": [],
                "has_impersonation": False,
                "impersonation_indicators": [],
                "has_security_evasion": False,
                "security_evasion_indicators": [],
                "has_sensitive_info_prompt": False,
                "sensitive_info_indicators": []
            }

        urgency_hits = []
        for pat in URGENCY_PATTERNS:
            if re.search(pat, text, re.IGNORECASE):
                urgency_hits.append(pat.replace(r"\b", "").replace(r"\d+", "N"))

        cred_hits = []
        for pat in CREDENTIAL_PATTERNS:
            if re.search(pat, text, re.IGNORECASE):
                cred_hits.append(pat.replace(r"\b", ""))

        fin_hits = []
        for pat in FINANCIAL_PATTERNS:
            if re.search(pat, text, re.IGNORECASE):
                fin_hits.append(pat.replace(r"\b", ""))

        imp_hits = []
        for pat in IMPERSONATION_PATTERNS:
            if re.search(pat, text, re.IGNORECASE):
                imp_hits.append(pat.replace(r"\b", ""))

        evasion_hits = []
        for pat in SECURITY_EVASION_PATTERNS:
            if re.search(pat, text, re.IGNORECASE):
                evasion_hits.append(pat.replace(r"\b", ""))

        sensitive_hits = []
        for pat in SENSITIVE_INFO_PATTERNS:
            if re.search(pat, text, re.IGNORECASE):
                sensitive_hits.append(pat.replace(r"\b", ""))

        se_score = (
            (len(urgency_hits) * 15)
            + (len(cred_hits) * 25)
            + (len(fin_hits) * 20)
            + (len(imp_hits) * 15)
            + (len(evasion_hits) * 30)
            + (len(sensitive_hits) * 25)
        )
        se_score = min(100, se_score)

        return {
            "se_score": se_score,
            "has_urgency": bool(urgency_hits),
            "urgency_indicators": urgency_hits,
            "has_credential_request": bool(cred_hits),
            "credential_indicators": cred_hits,
            "has_financial_lure": bool(fin_hits),
            "financial_indicators": fin_hits,
            "has_impersonation": bool(imp_hits),
            "impersonation_indicators": imp_hits,
            "has_security_evasion": bool(evasion_hits),
            "security_evasion_indicators": evasion_hits,
            "has_sensitive_info_prompt": bool(sensitive_hits),
            "sensitive_info_indicators": sensitive_hits
        }

    @classmethod
    def extract_canonical_urls(cls, text: Any) -> Tuple[List[str], Dict[str, int]]:
        """
        Extracts raw URLs, converts each to its canonical normalized form,
        and deduplicates them while maintaining occurrence counts.
        Returns (ordered_unique_canonical_urls, occurrence_counts_dict).
        """
        raw_list = cls.extract_raw_urls(text)
        canonical_unique: List[str] = []
        counts: Dict[str, int] = {}

        for raw_u in raw_list:
            canonical = normalize_url(raw_u)
            if not canonical:
                continue
            if canonical not in counts:
                counts[canonical] = 1
                canonical_unique.append(canonical)
            else:
                counts[canonical] += 1

        return canonical_unique, counts

    @classmethod
    def analyze_message_structured(
        cls,
        text_or_message: Union[str, bytes, Any],
        check_external: bool = False
    ) -> MessageScanResult:
        """
        Parses text or MIME message, checks social-engineering cues, attachment metadata,
        display-text mismatches, deduplicates URLs to canonical representations,
        and delegates per-URL analysis to the common URL scanner logic.
        Returns a strongly-typed MessageScanResult contract.
        """
        if text_or_message is None:
            return MessageScanResult(
                total_url_count=0,
                unique_url_count=0,
                urls_found=[],
                url_results=[],
                threat_urls_count=0,
                social_engineering={
                    "se_score": 0,
                    "has_urgency": False,
                    "urgency_indicators": [],
                    "has_credential_request": False,
                    "credential_indicators": [],
                    "has_financial_lure": False,
                    "financial_indicators": []
                },
                overall_score=0.0,
                overall_risk_level="LOW",
                is_suspicious_message=False,
                explanation_summary=["No message text provided."],
                recommended_action=generate_message_action("LOW"),
                message_length=0,
                is_valid=False
            )

        if isinstance(text_or_message, str) and not text_or_message.strip():
            return MessageScanResult(
                total_url_count=0,
                unique_url_count=0,
                urls_found=[],
                url_results=[],
                threat_urls_count=0,
                social_engineering={
                    "se_score": 0,
                    "has_urgency": False,
                    "urgency_indicators": [],
                    "has_credential_request": False,
                    "credential_indicators": [],
                    "has_financial_lure": False,
                    "financial_indicators": []
                },
                overall_score=0.0,
                overall_risk_level="LOW",
                is_suspicious_message=False,
                explanation_summary=["Message text is empty."],
                recommended_action=generate_message_action("LOW"),
                message_length=0,
                is_valid=True
            )

        # Parse message structure via SafeMIMEParser
        mime_res = safe_mime_parser.parse_message(text_or_message)

        canonical_urls = mime_res.unique_canonical_urls
        url_counts = mime_res.url_occurrence_counts
        total_raw_count = sum(url_counts.values())

        # Construct textual content for social engineering analysis
        text_parts = []
        if mime_res.headers.get("Subject"):
            text_parts.append(mime_res.headers["Subject"])
        if mime_res.plain_text_body:
            text_parts.append(mime_res.plain_text_body)
        elif mime_res.html_body:
            text_parts.append(mime_res.html_body)

        composite_text = "\n\n".join(text_parts) if text_parts else str(text_or_message)
        se_analysis = cls.evaluate_social_engineering(composite_text)

        # Count display mismatches and suspicious attachments
        display_mismatches_count = sum(1 for u in mime_res.extracted_urls if u.is_display_mismatch)
        suspicious_attachments_count = sum(1 for a in mime_res.attachments if a.is_suspicious_extension)

        url_results = []
        max_url_score = 0.0
        threat_urls_count = 0

        # Scan each UNIQUE canonical URL exactly once
        for url in canonical_urls:
            res = scan_url_logic(url, check_external=check_external)
            res_annotated = dict(res)
            res_annotated["occurrence_count"] = url_counts.get(url, 1)
            res_annotated["has_display_mismatch"] = any(
                u.is_display_mismatch for u in mime_res.extracted_urls if u.canonical_url == url
            )
            url_results.append(res_annotated)

            if res.get("is_threat", False):
                threat_urls_count += 1
            if res.get("score", 0) > max_url_score:
                max_url_score = res.get("score", 0)

        # Combine text cues, URL risk, display mismatches, and attachment risk
        combined_score = max_url_score
        if se_analysis["se_score"] > 30 and canonical_urls:
            combined_score = min(100.0, combined_score + (se_analysis["se_score"] * 0.3))
        elif se_analysis["se_score"] >= 40:
            combined_score = min(100.0, max(combined_score, se_analysis["se_score"] * 0.5))

        if display_mismatches_count > 0:
            combined_score = min(100.0, max(combined_score, 60.0) + (display_mismatches_count * 10.0))

        if suspicious_attachments_count > 0:
            combined_score = min(100.0, max(combined_score, 75.0) + (suspicious_attachments_count * 10.0))

        combined_score = min(100.0, max(0.0, combined_score))

        if combined_score >= 80:
            overall_level = "CRITICAL"
        elif combined_score >= 60:
            overall_level = "HIGH"
        elif combined_score >= 35:
            overall_level = "MEDIUM"
        else:
            overall_level = "LOW"

        # Construct explanation audit trail
        explanations: List[str] = []
        if threat_urls_count > 0:
            explanations.append(f"Identified {threat_urls_count} high-risk threat URL(s) in message body.")
            for u_res in url_results:
                if u_res.get("is_threat", False):
                    explanations.append(f"Threat URL '{u_res.get('url')}': {'; '.join(u_res.get('reasons', [])[:2])}")
        elif len(canonical_urls) > 0:
            explanations.append(f"Scanned {len(canonical_urls)} link(s); no confirmed malicious URLs detected.")

        if display_mismatches_count > 0:
            explanations.append(
                f"Display-text mismatch detected in {display_mismatches_count} link(s) (anchor text portrays a different domain than destination)."
            )

        if suspicious_attachments_count > 0:
            dangerous_names = [a.filename for a in mime_res.attachments if a.is_suspicious_extension]
            explanations.append(
                f"Identified {suspicious_attachments_count} suspicious attachment(s) with dangerous executable/script extensions: {', '.join(dangerous_names)}."
            )

        if se_analysis["has_urgency"]:
            explanations.append(f"Urgency cues detected: {', '.join(se_analysis['urgency_indicators'])}.")
        if se_analysis["has_credential_request"]:
            explanations.append(f"Credential lure keywords identified: {', '.join(se_analysis['credential_indicators'])}.")
        if se_analysis["has_financial_lure"]:
            explanations.append(f"Financial lure keywords identified: {', '.join(se_analysis['financial_indicators'])}.")
        if se_analysis.get("has_impersonation"):
            explanations.append(f"Organizational impersonation cues detected: {', '.join(se_analysis['impersonation_indicators'])}.")
        if se_analysis.get("has_security_evasion"):
            explanations.append(f"Security control evasion instructions detected: {', '.join(se_analysis['security_evasion_indicators'])}.")
        if se_analysis.get("has_sensitive_info_prompt"):
            explanations.append(f"Sensitive authentication token/code requests detected: {', '.join(se_analysis['sensitive_info_indicators'])}.")

        if mime_res.limit_reached:
            explanations.append(f"Analysis limitation: Resource boundary {mime_res.limit_reached} reached; partial message evaluation.")

        if not explanations:
            explanations.append("Message appears benign with no detected security anomalies.")

        action = generate_message_action(overall_level)
        msg_len = len(text_or_message) if isinstance(text_or_message, (str, bytes, bytearray)) else len(composite_text)

        return MessageScanResult(
            total_url_count=total_raw_count,
            unique_url_count=len(canonical_urls),
            urls_found=canonical_urls,
            url_results=url_results,
            threat_urls_count=threat_urls_count,
            social_engineering=se_analysis,
            overall_score=round(combined_score, 1),
            overall_risk_level=overall_level,
            is_suspicious_message=(combined_score >= 35),
            explanation_summary=explanations,
            recommended_action=action,
            message_length=msg_len,
            is_mime=mime_res.is_mime,
            mime_headers=mime_res.headers,
            attachments=[a.to_dict() for a in mime_res.attachments],
            extracted_urls_metadata=[u.to_dict() for u in mime_res.extracted_urls],
            display_mismatches_count=display_mismatches_count,
            suspicious_attachments_count=suspicious_attachments_count,
            analysis_completeness=mime_res.analysis_completeness,
            mime_defects=mime_res.defects,
            warnings=mime_res.warnings,
            is_valid=True
        )

    @classmethod
    def analyze_message(
        cls,
        text_or_message: Union[str, bytes, Any],
        check_external: bool = False
    ) -> Dict[str, Any]:
        """
        Parses text or email message, evaluates social-engineering cues, attachment metadata,
        deduplicates URLs to canonical representations, and delegates analysis to common URL scanner.
        Returns a dictionary representation of MessageScanResult.
        """
        structured = cls.analyze_message_structured(text_or_message, check_external=check_external)
        return structured.to_dict()


def analyze_text_cli():
    """CLI interactive helper for message analysis."""
    print("\nPaste message/email text (press Enter twice or Ctrl+Z/D to submit):")
    lines = []
    while True:
        try:
            line = input()
            if not line and lines:
                break
            lines.append(line)
        except EOFError:
            break
    text = "\n".join(lines)

    res = TextAnalyzer.analyze_message(text)
    print("\n" + "="*50)
    print("ACTIS Message / Email Threat Analysis")
    print(f"Overall Risk Level: {res['overall_risk_level']} (Score: {res['overall_score']}/100)")
    print(f"URLs Detected: {res['url_count']} | Threat URLs: {res['threat_urls_count']}")
    if res.get("is_mime"):
        print(f"MIME Message: True | Attachments: {res.get('attachments_count', 0)}")
    print("="*50)

    if res["social_engineering"]["urgency_indicators"]:
        print(f"[-] Urgency Language: {', '.join(res['social_engineering']['urgency_indicators'])}")
    if res["social_engineering"]["credential_indicators"]:
        print(f"[-] Credential Requests: {', '.join(res['social_engineering']['credential_indicators'])}")

    for idx, u_res in enumerate(res["url_results"], 1):
        print(f"\n[{idx}] URL: {u_res['url']}")
        print(f"    Risk: {u_res['risk_level']} ({u_res['score']}/100)")
        for reason in u_res["reasons"]:
            print(f"    • {reason}")
