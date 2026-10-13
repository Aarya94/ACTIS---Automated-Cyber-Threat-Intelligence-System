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
    MESSAGE = "MESSAGE"


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
    """Evaluates deterministic security heuristics on URLs, files, and messages."""

    # Message / Email Heuristic Rules (Day 25)
    RULE_MSG_URGENCY_PRESSURE = "RULE_MSG_URGENCY_PRESSURE"
    RULE_MSG_CREDENTIAL_HARVEST = "RULE_MSG_CREDENTIAL_HARVEST"
    RULE_MSG_FINANCIAL_LURE = "RULE_MSG_FINANCIAL_LURE"
    RULE_MSG_IMPERSONATION = "RULE_MSG_IMPERSONATION"
    RULE_MSG_SECURITY_EVASION = "RULE_MSG_SECURITY_EVASION"
    RULE_MSG_SENSITIVE_INFO_PROMPT = "RULE_MSG_SENSITIVE_INFO_PROMPT"
    RULE_MSG_DISPLAY_TEXT_MISMATCH = "RULE_MSG_DISPLAY_TEXT_MISMATCH"
    RULE_MSG_SUSPICIOUS_ATTACHMENT = "RULE_MSG_SUSPICIOUS_ATTACHMENT"
    RULE_MSG_MIME_DEFECT_ANOMALY = "RULE_MSG_MIME_DEFECT_ANOMALY"

    @classmethod
    def evaluate_url(cls, url: Any, analysis_result: Optional[Any] = None) -> Dict[str, Any]:
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

        # If analysis_result not passed, compute lightweight de-obfuscation
        if analysis_result is None:
            try:
                from scanners.url_scanner import deobfuscate_and_analyze_url
                analysis_result = deobfuscate_and_analyze_url(url_str, follow_redirects=False)
            except Exception:
                analysis_result = None

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

        # 11. De-obfuscation & Redirect Rules (from URLAnalysisResult)
        if analysis_result is not None:
            # A. Mixed-script Homoglyphs & IDN Deception
            homoglyphs = [obs for obs in getattr(analysis_result, "unicode_or_idn_observations", []) if "homoglyph" in obs.lower()]
            if homoglyphs:
                matches.append(RuleMatch(
                    rule_id="RULE_URL_HOMOGLYPH_IDN",
                    rule_name="Mixed-Script Homoglyph Deception",
                    severity=RuleSeverity.HIGH,
                    score_contribution=30.0,
                    explanation="Hostname contains deceptive mixed-script homoglyphs (e.g. Cyrillic/Latin character substitution).",
                    evidence_detail={"findings": homoglyphs}
                ))

            # B. Invisible Zero-Width Characters
            zw_obs = [obs for obs in getattr(analysis_result, "unicode_or_idn_observations", []) if "Zero-Width" in obs or "BOM" in obs or "Mark" in obs or "Override" in obs]
            if zw_obs:
                matches.append(RuleMatch(
                    rule_id="RULE_URL_ZERO_WIDTH_CHARS",
                    rule_name="Invisible Zero-Width Characters",
                    severity=RuleSeverity.HIGH,
                    score_contribution=30.0,
                    explanation="URL contains invisible zero-width or directional control characters used for obfuscation.",
                    evidence_detail={"observations": zw_obs}
                ))

            # C. Double Percent Encoding
            double_enc = [f for f in getattr(analysis_result, "suspicious_encoding_findings", []) if "Double percent" in f]
            if double_enc:
                matches.append(RuleMatch(
                    rule_id="RULE_URL_DOUBLE_ENCODING",
                    rule_name="Double Percent Encoding",
                    severity=RuleSeverity.MEDIUM,
                    score_contribution=25.0,
                    explanation="URL contains repeated or double percent-encoded character sequences.",
                    evidence_detail={"findings": double_enc}
                ))

            # D. Alternative Numeric IP Encoding
            num_ips = [f for f in getattr(analysis_result, "suspicious_encoding_findings", []) if "Alternative numeric IP" in f]
            if num_ips:
                matches.append(RuleMatch(
                    rule_id="RULE_URL_IP_NUMERIC_OBFUSCATION",
                    rule_name="Alternative Numeric IP Encoding",
                    severity=RuleSeverity.HIGH,
                    score_contribution=35.0,
                    explanation="Hostname is disguised using an alternative numeric format (dword decimal, octal, or hex IP).",
                    evidence_detail={"findings": num_ips}
                ))

            # E. Deceptive Userinfo Authority
            userinfo = [f for f in getattr(analysis_result, "suspicious_encoding_findings", []) if "Deceptive userinfo" in f]
            if userinfo:
                matches.append(RuleMatch(
                    rule_id="RULE_URL_USERINFO_OBFUSCATION",
                    rule_name="Deceptive Userinfo Authority",
                    severity=RuleSeverity.HIGH,
                    score_contribution=30.0,
                    explanation="URL authority uses misleading credentials before the actual destination hostname.",
                    evidence_detail={"findings": userinfo}
                ))

            # F. SSRF Prohibited Target Attempt
            redir = getattr(analysis_result, "redirect_result", None)
            if redir and getattr(redir, "ssrf_blocked", False):
                matches.append(RuleMatch(
                    rule_id="RULE_URL_SSRF_PROHIBITED",
                    rule_name="Prohibited SSRF Destination",
                    severity=RuleSeverity.CRITICAL,
                    score_contribution=45.0,
                    explanation=f"Target or redirect attempted access to prohibited internal or metadata network: {redir.error_reason}",
                    evidence_detail={"error": redir.error_reason}
                ))

            # G. Redirect Loop Cycle
            if getattr(analysis_result, "redirect_loop_detected", False):
                matches.append(RuleMatch(
                    rule_id="RULE_URL_REDIRECT_LOOP",
                    rule_name="Circular Redirect Loop",
                    severity=RuleSeverity.HIGH,
                    score_contribution=30.0,
                    explanation="Redirect inspection identified a circular destination loop.",
                    evidence_detail={"hops": getattr(analysis_result, "redirect_hops", [])}
                ))

            # H. Suspicious Redirect Behavior (protocol downgrade or excessive hops)
            hop_val = getattr(redir, "hop_count", 0) if redir else 0
            is_excessive_hops = isinstance(hop_val, (int, float)) and hop_val >= 4
            is_downgraded = bool(getattr(redir, "protocol_downgraded", False)) if redir else False
            if redir and (is_downgraded or is_excessive_hops):
                reasons_r = []
                if is_downgraded:
                    reasons_r.append("Protocol downgraded from HTTPS to insecure HTTP")
                if is_excessive_hops:
                    reasons_r.append(f"Excessive redirect hop count ({hop_val} hops)")
                matches.append(RuleMatch(
                    rule_id="RULE_URL_SUSPICIOUS_REDIRECT",
                    rule_name="Suspicious Redirect Behavior",
                    severity=RuleSeverity.MEDIUM,
                    score_contribution=25.0,
                    explanation=f"Anomalous redirect chain detected: {'; '.join(reasons_r)}.",
                    evidence_detail={"hop_count": hop_val, "downgraded": is_downgraded}
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

            # Non-PE Archive & Script Static Heuristics
            non_pe = static_info.get("non_pe_features", {})
            archive_meta = non_pe.get("archive_metadata") or {}
            script_meta = non_pe.get("script_metadata") or {}

            # Archive Rules
            if archive_meta:
                if archive_meta.get("is_suspicious_bomb", False):
                    matches.append(RuleMatch(
                        rule_id="RULE_ARCHIVE_ZIP_BOMB",
                        rule_name="Decompression Bomb Indicator",
                        severity=RuleSeverity.CRITICAL,
                        score_contribution=45.0,
                        explanation=f"Archive exhibits dangerous compression ratio ({archive_meta.get('compression_ratio', 0)}:1) or excessive uncompressed payload size characteristic of a decompression bomb attack.",
                        evidence_detail={"compression_ratio": archive_meta.get("compression_ratio"), "total_uncompressed": archive_meta.get("total_uncompressed_size")}
                    ))
                if archive_meta.get("has_double_extension", False):
                    double_entries = archive_meta.get("double_extension_entries", [])
                    matches.append(RuleMatch(
                        rule_id="RULE_ARCHIVE_DOUBLE_EXTENSION",
                        rule_name="Double Extension File Camouflage",
                        severity=RuleSeverity.HIGH,
                        score_contribution=30.0,
                        explanation=f"Archive contains deceptive double-extension files commonly used in social engineering / phishing campaigns: {', '.join(double_entries[:3])}.",
                        evidence_detail={"entries": list(double_entries)}
                    ))
                if archive_meta.get("has_executable_entries", False):
                    exec_entries = archive_meta.get("executable_entries", [])
                    matches.append(RuleMatch(
                        rule_id="RULE_ARCHIVE_EXECUTABLE_CONTENT",
                        rule_name="Executable Binaries or Scripts in Archive",
                        severity=RuleSeverity.MEDIUM,
                        score_contribution=20.0,
                        explanation=f"Archive packages executable binaries or script files ({', '.join(exec_entries[:3])}).",
                        evidence_detail={"executables": list(exec_entries)}
                    ))
                if archive_meta.get("entry_count", 0) > 5000:
                    matches.append(RuleMatch(
                        rule_id="RULE_ARCHIVE_EXCESSIVE_ENTRIES",
                        rule_name="Excessive Archive Entry Count",
                        severity=RuleSeverity.LOW,
                        score_contribution=15.0,
                        explanation=f"Archive contains unusually large number of file entries ({archive_meta.get('entry_count')}).",
                        evidence_detail={"entry_count": archive_meta.get("entry_count")}
                    ))
                if archive_meta.get("has_encrypted_entries", False):
                    matches.append(RuleMatch(
                        rule_id="RULE_ARCHIVE_ENCRYPTED_ENTRIES",
                        rule_name="Encrypted / Password-Protected Archive",
                        severity=RuleSeverity.LOW,
                        score_contribution=10.0,
                        explanation="Archive contains encrypted entries that obscure content from static security inspection.",
                        evidence_detail={"has_encrypted": True}
                    ))

            # Script Rules
            if script_meta:
                matched_ind = set(script_meta.get("matched_indicators", []))
                if script_meta.get("has_download_cradle", False) and script_meta.get("has_dynamic_eval", False):
                    matches.append(RuleMatch(
                        rule_id="RULE_SCRIPT_POWERSHELL_DOWNLOAD_EXECUTE",
                        rule_name="PowerShell Download-and-Execute Cradle",
                        severity=RuleSeverity.CRITICAL,
                        score_contribution=45.0,
                        explanation="Script combines remote web download primitives (DownloadString/DownloadFile) with dynamic in-memory execution (IEX/Invoke-Expression).",
                        evidence_detail={"indicators": list(matched_ind)}
                    ))
                if script_meta.get("has_shadow_copy_tampering", False):
                    matches.append(RuleMatch(
                        rule_id="RULE_SCRIPT_SHADOW_COPY_DELETION",
                        rule_name="System Recovery & Shadow Copy Deletion",
                        severity=RuleSeverity.CRITICAL,
                        score_contribution=45.0,
                        explanation="Script contains commands attempting to delete Volume Shadow Copies or disable Windows recovery (characteristic of ransomware defense inhibition).",
                        evidence_detail={"indicators": list(matched_ind)}
                    ))
                if script_meta.get("has_encoded_payload", False):
                    matches.append(RuleMatch(
                        rule_id="RULE_SCRIPT_POWERSHELL_ENCODED_COMMAND",
                        rule_name="Encoded PowerShell Command Payload",
                        severity=RuleSeverity.HIGH,
                        score_contribution=35.0,
                        explanation="Script invokes PowerShell with base64-encoded command payload (-EncodedCommand) to obscure command intent.",
                        evidence_detail={"indicators": list(matched_ind)}
                    ))
                if {"VBS_HTTP_DOWNLOAD", "VBS_ADODB_STREAM", "VBS_SHELL_EXEC"}.issubset(matched_ind):
                    matches.append(RuleMatch(
                        rule_id="RULE_SCRIPT_VBSCRIPT_DOWNLOAD_DROPPER",
                        rule_name="VBScript Dropper Sequence",
                        severity=RuleSeverity.HIGH,
                        score_contribution=35.0,
                        explanation="VBScript downloads remote stream via HTTP, writes to disk via ADODB.Stream, and invokes shell execution.",
                        evidence_detail={"indicators": list(matched_ind)}
                    ))
                if "BATCH_CERTUTIL_DOWNLOAD" in matched_ind or "BATCH_BITSADMIN_DOWNLOAD" in matched_ind:
                    matches.append(RuleMatch(
                        rule_id="RULE_SCRIPT_BATCH_DOWNLOAD_EXECUTE",
                        rule_name="Batch Ingress Download Utility",
                        severity=RuleSeverity.HIGH,
                        score_contribution=30.0,
                        explanation="Batch script abuses Windows system tools (certutil or bitsadmin) to download external files from the network.",
                        evidence_detail={"indicators": list(matched_ind)}
                    ))
                if "PY_DYNAMIC_EXEC" in matched_ind:
                    matches.append(RuleMatch(
                        rule_id="RULE_SCRIPT_PYTHON_DYNAMIC_EXECUTION",
                        rule_name="Python Dynamic Execution with Network/Decode",
                        severity=RuleSeverity.HIGH,
                        score_contribution=30.0,
                        explanation="Python script dynamically evaluates decoded base64 strings or remote network streams via exec() or eval().",
                        evidence_detail={"indicators": list(matched_ind)}
                    ))
                if script_meta.get("has_execution_bypass", False):
                    matches.append(RuleMatch(
                        rule_id="RULE_SCRIPT_POWERSHELL_EXECUTION_BYPASS",
                        rule_name="Execution Policy Bypass or Hidden Window",
                        severity=RuleSeverity.MEDIUM,
                        score_contribution=20.0,
                        explanation="Script attempts to bypass PowerShell execution policy (-ExecutionPolicy Bypass) or hide console window from user.",
                        evidence_detail={"indicators": list(matched_ind)}
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

    # Alias for universal static file evaluation (supporting both PE and non-PE files)
    evaluate_file = evaluate_pe_file

    @classmethod
    def evaluate_message(cls, message_data: Any) -> Dict[str, Any]:
        """
        Evaluates deterministic heuristic rules against a message or email scan result.
        Analyzes social engineering pressure, credential lures, financial lures,
        organizational impersonation, security evasion, display-text mismatches,
        suspicious attachments, and MIME defect anomalies.
        """
        matches: List[RuleMatch] = []
        if not message_data:
            structured = RuleEvaluationResult(
                target_identifier="message",
                target_type=RuleTargetType.MESSAGE,
                matches=[],
                total_score=0.0
            )
            return {
                "score": 0,
                "heuristic_score": 0.0,
                "rules_triggered": [],
                "reasons": [],
                "structured_result": structured
            }

        # Accept dict or MessageScanResult
        if hasattr(message_data, "to_dict"):
            data = message_data.to_dict()
        elif isinstance(message_data, dict):
            data = message_data
        else:
            data = {}

        se = data.get("social_engineering", {})
        if not isinstance(se, dict):
            se = {}

        # 1. Urgency Pressure
        if se.get("has_urgency"):
            hits = se.get("urgency_indicators", [])
            matches.append(RuleMatch(
                rule_id=cls.RULE_MSG_URGENCY_PRESSURE,
                rule_name="Social Engineering Urgency Cues",
                severity=RuleSeverity.HIGH,
                score_contribution=25.0,
                explanation=f"Message employs artificial urgency or deadline pressure ({', '.join(hits[:3])}).",
                evidence_detail={"urgency_indicators": hits}
            ))

        # 2. Credential Harvesting Prompt
        if se.get("has_credential_request"):
            hits = se.get("credential_indicators", [])
            matches.append(RuleMatch(
                rule_id=cls.RULE_MSG_CREDENTIAL_HARVEST,
                rule_name="Credential Solicitation Pattern",
                severity=RuleSeverity.HIGH,
                score_contribution=30.0,
                explanation=f"Message prompts user to verify or supply credentials ({', '.join(hits[:3])}).",
                evidence_detail={"credential_indicators": hits}
            ))

        # 3. Financial Lure
        if se.get("has_financial_lure"):
            hits = se.get("financial_indicators", [])
            matches.append(RuleMatch(
                rule_id=cls.RULE_MSG_FINANCIAL_LURE,
                rule_name="Financial Lure Keyword Pattern",
                severity=RuleSeverity.MEDIUM,
                score_contribution=20.0,
                explanation=f"Message contains financial inducement or payout lure ({', '.join(hits[:3])}).",
                evidence_detail={"financial_indicators": hits}
            ))

        # 4. Impersonation
        if se.get("has_impersonation"):
            hits = se.get("impersonation_indicators", [])
            matches.append(RuleMatch(
                rule_id=cls.RULE_MSG_IMPERSONATION,
                rule_name="Organizational Impersonation Pattern",
                severity=RuleSeverity.MEDIUM,
                score_contribution=20.0,
                explanation=f"Message displays authority or department impersonation language ({', '.join(hits[:3])}).",
                evidence_detail={"impersonation_indicators": hits}
            ))

        # 5. Security Control Evasion
        if se.get("has_security_evasion"):
            hits = se.get("security_evasion_indicators", [])
            matches.append(RuleMatch(
                rule_id=cls.RULE_MSG_SECURITY_EVASION,
                rule_name="Security Control Evasion Instruction",
                severity=RuleSeverity.CRITICAL,
                score_contribution=35.0,
                explanation=f"Message instructs recipient to bypass security controls or ignore warnings ({', '.join(hits[:3])}).",
                evidence_detail={"security_evasion_indicators": hits}
            ))

        # 6. Sensitive Information Prompt (2FA/OTP)
        if se.get("has_sensitive_info_prompt"):
            hits = se.get("sensitive_info_indicators", [])
            matches.append(RuleMatch(
                rule_id=cls.RULE_MSG_SENSITIVE_INFO_PROMPT,
                rule_name="Sensitive Authentication Token Request",
                severity=RuleSeverity.HIGH,
                score_contribution=25.0,
                explanation=f"Message solicits one-time passwords or security recovery codes ({', '.join(hits[:3])}).",
                evidence_detail={"sensitive_info_indicators": hits}
            ))

        # 7. Display Text Mismatch
        mismatch_cnt = data.get("display_mismatches_count", 0)
        if mismatch_cnt > 0:
            matches.append(RuleMatch(
                rule_id=cls.RULE_MSG_DISPLAY_TEXT_MISMATCH,
                rule_name="Link Display Text / Destination Mismatch",
                severity=RuleSeverity.CRITICAL,
                score_contribution=35.0,
                explanation=f"Detected {mismatch_cnt} hyperlink(s) where displayed text portrays a different domain than actual target.",
                evidence_detail={"display_mismatches_count": mismatch_cnt}
            ))

        # 8. Suspicious Attachment
        susp_att_cnt = data.get("suspicious_attachments_count", 0)
        if susp_att_cnt > 0:
            att_list = [a.get("filename", "") for a in data.get("attachments", []) if a.get("is_suspicious_extension")]
            matches.append(RuleMatch(
                rule_id=cls.RULE_MSG_SUSPICIOUS_ATTACHMENT,
                rule_name="Dangerous Executable/Script Attachment",
                severity=RuleSeverity.CRITICAL,
                score_contribution=35.0,
                explanation=f"Message contains {susp_att_cnt} attachment(s) with dangerous executable or script extensions ({', '.join(att_list[:3])}).",
                evidence_detail={"suspicious_attachments": att_list}
            ))

        # 9. MIME Defect Anomaly
        defects = data.get("mime_defects", [])
        if defects:
            matches.append(RuleMatch(
                rule_id=cls.RULE_MSG_MIME_DEFECT_ANOMALY,
                rule_name="MIME Structural Defect Anomaly",
                severity=RuleSeverity.LOW,
                score_contribution=10.0,
                explanation=f"MIME message exhibits structural parsing defects ({', '.join(defects[:3])}).",
                evidence_detail={"defects": defects}
            ))

        total_score = min(100.0, sum(m.score_contribution for m in matches))
        target_name = data.get("mime_headers", {}).get("Subject") or "message_body"

        structured = RuleEvaluationResult(
            target_identifier=target_name,
            target_type=RuleTargetType.MESSAGE,
            matches=matches,
            total_score=total_score
        )

        return {
            "score": int(total_score),
            "heuristic_score": round(total_score, 2),
            "rules_triggered": [m.rule_id for m in matches],
            "reasons": [m.explanation for m in matches],
            "structured_result": structured
        }
