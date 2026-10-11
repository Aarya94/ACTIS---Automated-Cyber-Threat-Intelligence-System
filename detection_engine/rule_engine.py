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

PROCESS_HOLLOWING_UNMAP = {"NtUnmapViewOfSection", "ZwUnmapViewOfSection"}
PROCESS_HOLLOWING_EXEC = {"SetThreadContext", "ResumeThread", "QueueUserAPC", "CreateRemoteThread"}
TOKEN_IMPERSONATION_APIS = {
    "AdjustTokenPrivileges", "LookupPrivilegeValueA", "LookupPrivilegeValueW",
    "DuplicateTokenEx", "ImpersonateLoggedOnUser", "ImpersonateSelf"
}
DYNAMIC_LOADER_APIS = {"LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "LdrLoadDll"}
DYNAMIC_RESOLVER_APIS = {"GetProcAddress", "LdrGetProcedureAddress"}
ANTI_DEBUG_APIS = {
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "OutputDebugStringA", "OutputDebugStringW", "FindWindowA", "FindWindowW"
}
PERSISTENCE_APIS = {
    "CreateServiceA", "CreateServiceW", "OpenSCManagerA", "OpenSCManagerW",
    "RegSetValueExA", "RegSetValueExW"
}



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
    def evaluate_url(cls, url: Any) -> Dict[str, Any]:
        """Runs deterministic heuristic checks on a URL string."""
        matches: List[RuleMatch] = []

        if not url or not isinstance(url, str):
            structured = RuleEvaluationResult(
                target_identifier=str(url or ""),
                target_type=RuleTargetType.URL,
                matches=[],
                total_score=0.0
            )
            return {
                "score": 0,
                "heuristic_score": 0,
                "rules_triggered": [],
                "reasons": [],
                "structured_result": structured
            }

        url_str = url.strip()
        if not url_str.startswith(("http://", "https://")):
            url_to_parse = "http://" + url_str
        else:
            url_to_parse = url_str

        try:
            parsed = urlparse(url_to_parse)
        except Exception:
            parsed = urlparse("http://invalid-url")

        hostname = (parsed.hostname or "").lower()
        path = (parsed.path or "").lower()
        query = (parsed.query or "").lower()

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
        if "@" in url_str:
            matches.append(RuleMatch(
                rule_id="RULE_URL_AT_SYMBOL",
                rule_name="At-Symbol Destination Obfuscation",
                severity=RuleSeverity.HIGH,
                score_contribution=30.0,
                explanation="URL contains '@' character, frequently used to mislead browser destination.",
                evidence_detail={"raw_url": url_str}
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

        # 8. Excessive URL length
        if len(url_str) > 150:
            matches.append(RuleMatch(
                rule_id="RULE_URL_EXCESSIVE_LENGTH",
                rule_name="Excessive URL Length",
                severity=RuleSeverity.LOW,
                score_contribution=15.0,
                explanation=f"URL is unusually long ({len(url_str)} characters), which may obscure destination.",
                evidence_detail={"length": len(url_str)}
            ))

        # 9. Suspicious encoded characters
        encoded_count = url_str.count("%")
        if encoded_count >= 3:
            matches.append(RuleMatch(
                rule_id="RULE_URL_SUSPICIOUS_ENCODING",
                rule_name="Suspicious Percent Encoding",
                severity=RuleSeverity.LOW,
                score_contribution=15.0,
                explanation=f"URL contains repeated percent-encoded sequences ({encoded_count} tokens).",
                evidence_detail={"percent_count": encoded_count}
            ))

        # 10. Non-standard port
        if parsed.port and parsed.port not in (80, 443, 8080, 8443):
            matches.append(RuleMatch(
                rule_id="RULE_URL_SUSPICIOUS_PORT",
                rule_name="Non-Standard Service Port",
                severity=RuleSeverity.MEDIUM,
                score_contribution=20.0,
                explanation=f"URL directs traffic to non-standard service port {parsed.port}.",
                evidence_detail={"port": parsed.port}
            ))

        total_score = min(100.0, sum(m.score_contribution for m in matches))
        reasons = [m.explanation for m in matches]
        rules_triggered = [m.rule_id for m in matches]

        structured = RuleEvaluationResult(
            target_identifier=url_str,
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
            if sec.get("is_writable_and_executable", False) or sec.get("is_write_and_execute", False):
                matches.append(RuleMatch(
                    rule_id="RULE_PE_WX_SECTION",
                    rule_name="Writable and Executable Section",
                    severity=RuleSeverity.CRITICAL,
                    score_contribution=40.0,
                    explanation=f"Section '{sec.get('name')}' is marked both WRITABLE and EXECUTABLE (W+X injection vector).",
                    evidence_detail={"section": sec.get("name")}
                ))
                break

        # Check: Unpacking stub (raw_size near 0, large virtual size for executable section)
        for sec in sections:
            raw_sz = sec.get("raw_size", 0)
            virt_sz = sec.get("virtual_size", 0)
            is_exec = sec.get("is_executable", False) or bool(sec.get("characteristics", 0) & 0x20000000)
            if is_exec and raw_sz < 512 and virt_sz >= 4096:
                matches.append(RuleMatch(
                    rule_id="RULE_PE_SECTION_UNPACKING_STUB",
                    rule_name="Unpacking Stub Section Anomaly",
                    severity=RuleSeverity.HIGH,
                    score_contribution=25.0,
                    explanation=f"Section '{sec.get('name')}' has negligible disk size ({raw_sz}B) but expands to {virt_sz}B in memory (unpacking stub).",
                    evidence_detail={"section_name": sec.get("name"), "raw_size": raw_sz, "virtual_size": virt_sz}
                ))
                break

        # Check: Section Entropy Distribution Anomaly
        entropy_dist = static_info.get("entropy_distribution") or {}
        if entropy_dist.get("is_likely_packed", False) or (
            float(entropy_dist.get("section_entropy_std_dev", 0.0) or 0.0) >= 2.0
            and float(entropy_dist.get("max_section_entropy", 0.0) or 0.0) >= 7.2
        ):
            matches.append(RuleMatch(
                rule_id="RULE_PE_SECTION_ENTROPY_ANOMALY",
                rule_name="Section Entropy Distribution Anomaly",
                severity=RuleSeverity.HIGH,
                score_contribution=25.0,
                explanation="Anomalous section entropy dispersion detected across binary sections indicative of packing or payload encryption.",
                evidence_detail={
                    "std_dev": entropy_dist.get("section_entropy_std_dev"),
                    "max_entropy": entropy_dist.get("max_section_entropy"),
                    "mean_entropy": entropy_dist.get("section_entropy_mean"),
                }
            ))

        # 2. Suspicious APIs combinations
        suspicious_apis = set(static_info.get("suspicious_apis_found", []))

        # Check: Process Hollowing / Injection Sequence
        has_unmap = bool(PROCESS_HOLLOWING_UNMAP.intersection(suspicious_apis))
        has_alloc = bool({"VirtualAllocEx", "VirtualAlloc"}.intersection(suspicious_apis))
        has_write = "WriteProcessMemory" in suspicious_apis
        has_exec_ctrl = bool(PROCESS_HOLLOWING_EXEC.intersection(suspicious_apis))
        if has_unmap or (has_alloc and has_write and has_exec_ctrl):
            hollowing_matched = list((PROCESS_HOLLOWING_UNMAP | {"VirtualAllocEx", "VirtualAlloc", "WriteProcessMemory"} | PROCESS_HOLLOWING_EXEC).intersection(suspicious_apis))
            matches.append(RuleMatch(
                rule_id="RULE_PE_PROCESS_HOLLOWING",
                rule_name="Process Hollowing API Sequence",
                severity=RuleSeverity.CRITICAL,
                score_contribution=45.0,
                explanation="Executable imports API sequence characteristic of process hollowing or injection (memory allocation, remote write, thread context/execution manipulation, or section unmapping).",
                evidence_detail={"apis": sorted(hollowing_matched)}
            ))

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

        # Check: Token Impersonation / Privilege Adjustment
        if "OpenProcessToken" in suspicious_apis and TOKEN_IMPERSONATION_APIS.intersection(suspicious_apis):
            matched_token = list((TOKEN_IMPERSONATION_APIS | {"OpenProcessToken"}).intersection(suspicious_apis))
            matches.append(RuleMatch(
                rule_id="RULE_PE_TOKEN_IMPERSONATION",
                rule_name="Access Token Manipulation APIs",
                severity=RuleSeverity.HIGH,
                score_contribution=30.0,
                explanation="Executable imports access token and privilege adjustment APIs for process token impersonation.",
                evidence_detail={"apis": sorted(matched_token)}
            ))

        # Check: Dynamic API Resolver (LoadLibrary + GetProcAddress with small import footprint)
        imp_meta = static_info.get("import_metadata") or {}
        imp_func_count = imp_meta.get("imported_function_count", 0)
        has_dyn_loader = bool(DYNAMIC_LOADER_APIS.intersection(suspicious_apis))
        has_dyn_resolver = bool(DYNAMIC_RESOLVER_APIS.intersection(suspicious_apis))
        if has_dyn_loader and has_dyn_resolver and imp_func_count <= 25:
            matched_dyn = list((DYNAMIC_LOADER_APIS | DYNAMIC_RESOLVER_APIS).intersection(suspicious_apis))
            matches.append(RuleMatch(
                rule_id="RULE_PE_DYNAMIC_API_RESOLVER",
                rule_name="Dynamic API Resolution Pattern",
                severity=RuleSeverity.HIGH,
                score_contribution=25.0,
                explanation=f"Executable relies on runtime dynamic API loading (LoadLibrary + GetProcAddress) with minimal static imports ({imp_func_count} functions), characteristic of packed or obfuscated payloads.",
                evidence_detail={"apis": sorted(matched_dyn), "imported_function_count": imp_func_count}
            ))

        # Check: Anti-Analysis / Anti-Debugging APIs (>= 2 APIs)
        matched_anti = ANTI_DEBUG_APIS.intersection(suspicious_apis)
        if len(matched_anti) >= 2:
            matches.append(RuleMatch(
                rule_id="RULE_PE_ANTI_ANALYSIS",
                rule_name="Anti-Analysis / Anti-Debugging APIs",
                severity=RuleSeverity.MEDIUM,
                score_contribution=20.0,
                explanation=f"Executable imports multiple anti-debugging and environment inspection APIs ({len(matched_anti)} APIs detected).",
                evidence_detail={"apis": sorted(list(matched_anti)), "count": len(matched_anti)}
            ))

        # Check: Persistence APIs (Service / Registry creation or modification)
        matched_pers = PERSISTENCE_APIS.intersection(suspicious_apis)
        if matched_pers:
            matches.append(RuleMatch(
                rule_id="RULE_PE_PERSISTENCE_APIS",
                rule_name="Service / Registry Persistence APIs",
                severity=RuleSeverity.MEDIUM,
                score_contribution=20.0,
                explanation="Executable imports Windows service creation or registry modification APIs commonly used to establish system persistence.",
                evidence_detail={"apis": sorted(list(matched_pers))}
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
