"""
ACTIS Rule Engine Module
Implements heuristic, signature, and behavioral rules for URLs and Windows PE files.
Produces structured, explainable RuleEvaluationResults that seamlessly convert into
EvidenceSignals for the central detection and risk scoring engine.
"""

import re
import ipaddress
from enum import Enum
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Callable, Tuple

from detection_engine.evidence_model import EvidenceSignal, EvidenceSource, EvidenceSeverity

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".work", ".buzz", ".fit", ".gq", ".cf",
    ".tk", ".ml", ".ga", ".rest", ".monster", ".icu", ".cam", ".zip",
    ".mov", ".country", ".kim", ".stream", ".download"
}

SUSPICIOUS_URL_KEYWORDS = [
    "login", "verify", "banking", "secure", "account", "update",
    "wallet", "password", "confirm", "billing", "signin", "authenticate",
    "paypal", "appleid", "microsoft", "chase", "wellsfargo"
]

SUSPICIOUS_PACKER_SECTIONS = [
    ".upx", "upx0", "upx1", "upx2", ".aspack", ".mpress", ".themida",
    ".vmp", ".enigma", ".fsg", ".petite", ".mew"
]

INJECTION_APIS = {"VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"}
KEYLOGGER_APIS = {"SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState"}
DOWNLOADER_APIS = {"URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenUrlA"}


class RuleSeverity(str, Enum):
    """Rule match severity tier."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def to_evidence_severity(self) -> EvidenceSeverity:
        mapping = {
            RuleSeverity.INFO: EvidenceSeverity.INFO,
            RuleSeverity.LOW: EvidenceSeverity.LOW,
            RuleSeverity.MEDIUM: EvidenceSeverity.MEDIUM,
            RuleSeverity.HIGH: EvidenceSeverity.HIGH,
            RuleSeverity.CRITICAL: EvidenceSeverity.CRITICAL,
        }
        return mapping.get(self, EvidenceSeverity.MEDIUM)


class RuleTargetType(str, Enum):
    """Target category for rule evaluation."""
    URL = "URL"
    PE_FILE = "PE_FILE"
    HASH = "HASH"
    GENERIC = "GENERIC"


@dataclass(frozen=True)
class RuleMatch:
    """
    Immutable record of an individual heuristic rule match.
    Captures rule ID, name, severity, score contribution, and human-readable reason.
    """
    rule_id: str
    rule_name: str
    severity: RuleSeverity
    score_contribution: float
    explanation: str
    evidence_detail: Optional[Dict[str, Any]] = None

    def to_evidence_signal(self) -> EvidenceSignal:
        """Converts rule match into a standardized EvidenceSignal."""
        return EvidenceSignal(
            source=EvidenceSource.HEURISTIC_RULES,
            signal_id=self.rule_id,
            name=self.rule_name,
            description=self.explanation,
            severity=self.severity.to_evidence_severity(),
            score_contribution=self.score_contribution,
            weight=1.0,
            raw_data=self.evidence_detail
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value if isinstance(self.severity, RuleSeverity) else str(self.severity),
            "score_contribution": round(self.score_contribution, 2),
            "explanation": self.explanation,
            "evidence_detail": self.evidence_detail
        }


@dataclass
class RuleEvaluationResult:
    """
    Structured aggregation of all rule matches triggered against an evaluated target.
    """
    target_identifier: str
    target_type: RuleTargetType
    matches: List[RuleMatch] = field(default_factory=list)
    total_score: float = 0.0

    def __post_init__(self):
        if not self.total_score and self.matches:
            self.total_score = min(100.0, sum(m.score_contribution for m in self.matches))

    @property
    def max_severity(self) -> RuleSeverity:
        if not self.matches:
            return RuleSeverity.INFO
        hierarchy = [
            RuleSeverity.INFO,
            RuleSeverity.LOW,
            RuleSeverity.MEDIUM,
            RuleSeverity.HIGH,
            RuleSeverity.CRITICAL
        ]
        matched_sevs = [m.severity for m in self.matches]
        for sev in reversed(hierarchy):
            if sev in matched_sevs:
                return sev
        return RuleSeverity.INFO

    @property
    def matched_count(self) -> int:
        return len(self.matches)

    def get_reasons(self) -> List[str]:
        return [m.explanation for m in sorted(self.matches, key=lambda m: m.score_contribution, reverse=True)]

    def to_evidence_signals(self) -> List[EvidenceSignal]:
        return [m.to_evidence_signal() for m in self.matches]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_identifier": self.target_identifier,
            "target_type": self.target_type.value if isinstance(self.target_type, RuleTargetType) else str(self.target_type),
            "matched_count": self.matched_count,
            "max_severity": self.max_severity.value,
            "total_score": round(self.total_score, 2),
            "matches": [m.to_dict() for m in self.matches],
            "reasons": self.get_reasons()
        }


@dataclass
class RuleDefinition:
    """Configurable security heuristic rule definition."""
    rule_id: str
    name: str
    description: str
    severity: RuleSeverity
    target_type: RuleTargetType
    base_score: float
    condition: Callable[[Any], Tuple[bool, Optional[str], Optional[Dict[str, Any]]]]


class GenericRuleRegistry:
    """Registry allowing extensible, deterministic security rule execution."""

    def __init__(self):
        self._rules: List[RuleDefinition] = []

    def register(self, rule: RuleDefinition) -> None:
        self._rules.append(rule)

    def evaluate(self, target: Any, target_id: str, target_type: RuleTargetType) -> RuleEvaluationResult:
        matches: List[RuleMatch] = []
        for r in self._rules:
            if r.target_type == target_type or r.target_type == RuleTargetType.GENERIC:
                try:
                    matched, reason, details = r.condition(target)
                    if matched:
                        matches.append(RuleMatch(
                            rule_id=r.rule_id,
                            rule_name=r.name,
                            severity=r.severity,
                            score_contribution=r.base_score,
                            explanation=reason or r.description,
                            evidence_detail=details
                        ))
                except Exception:
                    continue
        total_score = min(100.0, sum(m.score_contribution for m in matches))
        return RuleEvaluationResult(
            target_identifier=target_id,
            target_type=target_type,
            matches=matches,
            total_score=total_score
        )


class RuleEngine:
    """Evaluates deterministic security heuristics on URLs and file metadata."""

    @classmethod
    def evaluate_url(cls, url: str) -> Dict[str, Any]:
        """Runs heuristic checks on a URL string."""
        matches: List[RuleMatch] = []

        if not url.startswith(("http://", "https://")):
            url_to_parse = "http://" + url
        else:
            url_to_parse = url

        parsed = urlparse(url_to_parse)
        hostname = (parsed.hostname or "").lower()
        path = parsed.path.lower()

        # 1. IP address in hostname
        try:
            ipaddress.ip_address(hostname)
            matches.append(RuleMatch(
                rule_id="RULE_URL_IP_HOST",
                rule_name="IP Hostname Indicator",
                severity=RuleSeverity.HIGH,
                score_contribution=35.0,
                explanation="URL uses an IP address directly as the hostname instead of a domain.",
                evidence_detail={"hostname": hostname}
            ))
        except ValueError:
            pass

        # 2. Suspicious / Abused TLD
        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                matches.append(RuleMatch(
                    rule_id="RULE_URL_SUSPICIOUS_TLD",
                    rule_name="Suspicious Top-Level Domain",
                    severity=RuleSeverity.MEDIUM,
                    score_contribution=25.0,
                    explanation=f"Domain uses high-risk or commonly abused TLD '{tld}'.",
                    evidence_detail={"tld": tld, "hostname": hostname}
                ))
                break

        # 3. Excessive subdomains
        parts = hostname.split(".")
        if len(parts) > 4:
            matches.append(RuleMatch(
                rule_id="RULE_URL_EXCESSIVE_SUBDOMAINS",
                rule_name="Excessive Subdomains",
                severity=RuleSeverity.LOW,
                score_contribution=20.0,
                explanation=f"Excessive number of subdomains detected ({len(parts)} levels).",
                evidence_detail={"subdomain_count": len(parts)}
            ))

        # 4. Sensitive keywords in path
        matched_keywords = [kw for kw in SUSPICIOUS_URL_KEYWORDS if kw in path]
        if matched_keywords:
            matches.append(RuleMatch(
                rule_id="RULE_URL_CREDENTIAL_KEYWORD",
                rule_name="Credential Keywords",
                severity=RuleSeverity.MEDIUM,
                score_contribution=20.0,
                explanation=f"Sensitive credential or brand keywords detected in URL path: {', '.join(matched_keywords)}.",
                evidence_detail={"keywords": matched_keywords}
            ))

        # 5. '@' character in URL (basic authentication trick)
        if "@" in url:
            matches.append(RuleMatch(
                rule_id="RULE_URL_AT_SYMBOL",
                rule_name="At-Symbol Destination Obfuscation",
                severity=RuleSeverity.HIGH,
                score_contribution=30.0,
                explanation="URL contains '@' character, frequently used to mislead browser destination.",
                evidence_detail={"raw_url": url}
            ))

        # 6. Excessive hyphens in domain
        if hostname.count("-") >= 3:
            matches.append(RuleMatch(
                rule_id="RULE_URL_MANY_HYPHENS",
                rule_name="Excessive Hyphenation",
                severity=RuleSeverity.LOW,
                score_contribution=15.0,
                explanation=f"Suspiciously high hyphen count in domain name ({hostname.count('-')} hyphens).",
                evidence_detail={"hyphen_count": hostname.count("-")}
            ))

        # 7. Redirection pattern
        if "//" in path:
            matches.append(RuleMatch(
                rule_id="RULE_URL_DOUBLE_SLASH",
                rule_name="Open Redirection Double Slash",
                severity=RuleSeverity.MEDIUM,
                score_contribution=20.0,
                explanation="Path contains double slash '//' indicative of open redirection.",
                evidence_detail={"path": path}
            ))

        total_score = min(100.0, sum(m.score_contribution for m in matches))
        reasons = [m.explanation for m in matches]
        rules_triggered = [m.rule_id for m in matches]

        structured = RuleEvaluationResult(
            target_identifier=url,
            target_type=RuleTargetType.URL,
            matches=matches,
            total_score=total_score
        )

        return {
            "score": int(total_score),
            "heuristic_score": int(total_score),
            "rules_triggered": rules_triggered,
            "reasons": reasons,
            "structured_result": structured
        }

    @classmethod
    def evaluate_pe_file(cls, static_info: Dict[str, Any]) -> Dict[str, Any]:
        """Runs heuristic checks on static PE features and metadata."""
        matches: List[RuleMatch] = []
        target_name = static_info.get("filename", "unknown_binary")

        if not static_info.get("is_pe", False):
            entropy = float(static_info.get("entropy", 0.0) or 0.0)
            if entropy > 7.5:
                matches.append(RuleMatch(
                    rule_id="RULE_FILE_HIGH_ENTROPY",
                    rule_name="High File Entropy",
                    severity=RuleSeverity.HIGH,
                    score_contribution=25.0,
                    explanation=f"File exhibits unusually high Shannon entropy ({entropy:.2f}/8.0), suggesting encryption or packing.",
                    evidence_detail={"entropy": entropy}
                ))
            total_score = min(100.0, sum(m.score_contribution for m in matches))
            structured = RuleEvaluationResult(
                target_identifier=target_name,
                target_type=RuleTargetType.PE_FILE,
                matches=matches,
                total_score=total_score
            )
            return {
                "score": int(total_score),
                "heuristic_score": int(total_score),
                "rules_triggered": [m.rule_id for m in matches],
                "reasons": [m.explanation for m in matches],
                "structured_result": structured
            }

        # 1. Section Entropy & Packer Names
        sections = static_info.get("sections", [])
        has_packed_section = False
        for sec in sections:
            name = str(sec.get("name", "")).lower()
            ent = float(sec.get("entropy", 0.0) or 0.0)
            
            for pkr in SUSPICIOUS_PACKER_SECTIONS:
                if pkr in name:
                    has_packed_section = True
                    matches.append(RuleMatch(
                        rule_id="RULE_PE_PACKER_SECTION",
                        rule_name="Known Packer Section",
                        severity=RuleSeverity.HIGH,
                        score_contribution=30.0,
                        explanation=f"Detected known packer section name: '{sec.get('name')}'",
                        evidence_detail={"section_name": sec.get("name")}
                    ))
                    break
                    
            if ent > 7.2:
                matches.append(RuleMatch(
                    rule_id="RULE_PE_SECTION_HIGH_ENTROPY",
                    rule_name="High Section Entropy",
                    severity=RuleSeverity.HIGH,
                    score_contribution=25.0,
                    explanation=f"Section '{sec.get('name')}' has high entropy ({ent:.2f}/8.0), likely packed or encrypted.",
                    evidence_detail={"section_name": sec.get("name"), "entropy": ent}
                ))
                break

        # Check: Writable + Executable section
        for sec in sections:
            if sec.get("is_writable_and_executable", False):
                matches.append(RuleMatch(
                    rule_id="RULE_PE_WX_SECTION",
                    rule_name="Writable and Executable Section",
                    severity=RuleSeverity.CRITICAL,
                    score_contribution=40.0,
                    explanation=f"Section '{sec.get('name')}' is marked both WRITABLE and EXECUTABLE (W+X injection vector).",
                    evidence_detail={"section": sec.get("name")}
                ))
                break

        # 2. Suspicious APIs combinations
        suspicious_apis = set(static_info.get("suspicious_apis_found", []))
        if INJECTION_APIS.issubset(suspicious_apis):
            matches.append(RuleMatch(
                rule_id="RULE_PE_PROCESS_INJECTION",
                rule_name="Process Injection APIs",
                severity=RuleSeverity.HIGH,
                score_contribution=35.0,
                explanation="Executable imports process injection APIs: VirtualAlloc, WriteProcessMemory, CreateRemoteThread.",
                evidence_detail={"apis": list(INJECTION_APIS)}
            ))
        elif len(suspicious_apis) >= 5:
            matches.append(RuleMatch(
                rule_id="RULE_PE_MANY_SUSPICIOUS_APIS",
                rule_name="High Suspicious API Density",
                severity=RuleSeverity.HIGH,
                score_contribution=25.0,
                explanation=f"High number of sensitive/dangerous Windows APIs imported ({len(suspicious_apis)} APIs).",
                evidence_detail={"api_count": len(suspicious_apis)}
            ))

        if KEYLOGGER_APIS.intersection(suspicious_apis):
            matches.append(RuleMatch(
                rule_id="RULE_PE_KEYLOGGING_APIS",
                rule_name="Keystroke Capture APIs",
                severity=RuleSeverity.MEDIUM,
                score_contribution=20.0,
                explanation="Executable imports keystroke capture/hook APIs.",
                evidence_detail={"apis": list(KEYLOGGER_APIS.intersection(suspicious_apis))}
            ))

        if DOWNLOADER_APIS.intersection(suspicious_apis):
            matches.append(RuleMatch(
                rule_id="RULE_PE_DOWNLOADER_APIS",
                rule_name="Remote Download APIs",
                severity=RuleSeverity.MEDIUM,
                score_contribution=15.0,
                explanation="Executable imports web download APIs (URLDownloadToFile / InternetOpenUrl).",
                evidence_detail={"apis": list(DOWNLOADER_APIS.intersection(suspicious_apis))}
            ))

        # 3. Bitcoin address presence
        pe_features = static_info.get("pe_features", {})
        btc_count = pe_features.get("BitcoinAddresses", 0)
        if btc_count > 0:
            matches.append(RuleMatch(
                rule_id="RULE_PE_BITCOIN_ADDRESS",
                rule_name="Cryptocurrency Wallet Indicators",
                severity=RuleSeverity.CRITICAL,
                score_contribution=40.0,
                explanation=f"Cryptocurrency wallet addresses discovered in binary strings ({btc_count} address(es)), indicative of ransomware.",
                evidence_detail={"bitcoin_count": btc_count}
            ))

        # 4. Digital signature check
        is_signed = static_info.get("is_signed", False)
        if not is_signed:
            matches.append(RuleMatch(
                rule_id="RULE_PE_UNSIGNED",
                rule_name="Unsigned Executable",
                severity=RuleSeverity.LOW,
                score_contribution=10.0,
                explanation="Executable is not digitally signed by a trusted vendor.",
                evidence_detail={"is_signed": False}
            ))

        # 5. Anomalous section count
        num_sections = pe_features.get("NumberOfSections", 0) or len(sections)
        if num_sections <= 1 and num_sections > 0:
            matches.append(RuleMatch(
                rule_id="RULE_PE_ABNORMAL_SECTIONS",
                rule_name="Anomalous Low Section Count",
                severity=RuleSeverity.MEDIUM,
                score_contribution=20.0,
                explanation=f"Unusually low number of PE sections ({num_sections}), often seen in packed droppers.",
                evidence_detail={"section_count": num_sections}
            ))
        elif num_sections > 12:
            matches.append(RuleMatch(
                rule_id="RULE_PE_MANY_SECTIONS",
                rule_name="Excessive Section Count",
                severity=RuleSeverity.LOW,
                score_contribution=15.0,
                explanation=f"Unusually high section count ({num_sections}).",
                evidence_detail={"section_count": num_sections}
            ))

        total_score = min(100.0, sum(m.score_contribution for m in matches))
        structured = RuleEvaluationResult(
            target_identifier=target_name,
            target_type=RuleTargetType.PE_FILE,
            matches=matches,
            total_score=total_score
        )

        return {
            "score": int(total_score),
            "heuristic_score": int(total_score),
            "rules_triggered": [m.rule_id for m in matches],
            "reasons": [m.explanation for m in matches],
            "structured_result": structured
        }
