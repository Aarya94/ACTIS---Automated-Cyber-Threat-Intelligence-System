"""
ACTIS Rule Engine Module
Implements heuristic, signature, and behavioral rules for URLs and Windows PE files.
Produces interpretable risk evidence alongside machine-learning models.
"""

import re
import ipaddress
from urllib.parse import urlparse
from typing import Dict, Any, List

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


class RuleEngine:
    """Evaluates deterministic security heuristics on URLs and file metadata."""

    @classmethod
    def evaluate_url(cls, url: str) -> Dict[str, Any]:
        """Runs heuristic checks on a URL string."""
        score = 0
        reasons = []
        rules_triggered = []

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
            score += 35
            reasons.append("URL uses an IP address directly as the hostname instead of a domain.")
            rules_triggered.append("RULE_URL_IP_HOST")
        except ValueError:
            pass

        # 2. Suspicious / Abused TLD
        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                score += 25
                reasons.append(f"Domain uses high-risk or commonly abused TLD '{tld}'.")
                rules_triggered.append("RULE_URL_SUSPICIOUS_TLD")
                break

        # 3. Excessive subdomains
        parts = hostname.split(".")
        if len(parts) > 4:
            score += 20
            reasons.append(f"Excessive number of subdomains detected ({len(parts)} levels).")
            rules_triggered.append("RULE_URL_EXCESSIVE_SUBDOMAINS")

        # 4. Sensitive keywords in path
        matched_keywords = [kw for kw in SUSPICIOUS_URL_KEYWORDS if kw in path]
        if matched_keywords:
            score += 20
            reasons.append(f"Sensitive credential or brand keywords detected in URL path: {', '.join(matched_keywords)}.")
            rules_triggered.append("RULE_URL_CREDENTIAL_KEYWORD")

        # 5. '@' character in URL (basic authentication trick)
        if "@" in url:
            score += 30
            reasons.append("URL contains '@' character, frequently used to mislead browser destination.")
            rules_triggered.append("RULE_URL_AT_SYMBOL")

        # 6. Excessive hyphens in domain
        if hostname.count("-") >= 3:
            score += 15
            reasons.append(f"Suspiciously high hyphen count in domain name ({hostname.count('-')} hyphens).")
            rules_triggered.append("RULE_URL_MANY_HYPHENS")

        # 7. Redirection pattern
        if "//" in path:
            score += 20
            reasons.append("Path contains double slash '//' indicative of open redirection.")
            rules_triggered.append("RULE_URL_DOUBLE_SLASH")

        normalized_score = min(100, score)
        return {
            "heuristic_score": normalized_score,
            "rules_triggered": rules_triggered,
            "reasons": reasons
        }

    @classmethod
    def evaluate_pe_file(cls, static_info: Dict[str, Any]) -> Dict[str, Any]:
        """Runs heuristic checks on static PE features and metadata."""
        score = 0
        reasons = []
        rules_triggered = []

        if not static_info.get("is_pe", False):
            # Generic file heuristics
            entropy = static_info.get("entropy", 0.0)
            if entropy > 7.5:
                score += 25
                reasons.append(f"File exhibits unusually high Shannon entropy ({entropy}/8.0), suggesting encryption or packing.")
                rules_triggered.append("RULE_FILE_HIGH_ENTROPY")
            return {
                "heuristic_score": min(100, score),
                "rules_triggered": rules_triggered,
                "reasons": reasons
            }

        # 1. Section Entropy & Packer Names
        sections = static_info.get("sections", [])
        has_packed_section = False
        for sec in sections:
            name = sec.get("name", "").lower()
            ent = sec.get("entropy", 0.0)
            
            # Check known packer section names
            for pkr in SUSPICIOUS_PACKER_SECTIONS:
                if pkr in name:
                    has_packed_section = True
                    rules_triggered.append("RULE_PE_PACKER_SECTION")
                    reasons.append(f"Detected known packer section name: '{sec.get('name')}'")
                    break
                    
            # Check high entropy in executable sections
            if ent > 7.2:
                rules_triggered.append("RULE_PE_SECTION_HIGH_ENTROPY")
                reasons.append(f"Section '{sec.get('name')}' has high entropy ({ent}/8.0), likely packed or encrypted.")
                score += 25
                break

        if has_packed_section:
            score += 30

        # 2. Suspicious APIs combinations
        suspicious_apis = set(static_info.get("suspicious_apis_found", []))
        if INJECTION_APIS.issubset(suspicious_apis):
            score += 35
            reasons.append("Executable imports process injection APIs: VirtualAlloc, WriteProcessMemory, CreateRemoteThread.")
            rules_triggered.append("RULE_PE_PROCESS_INJECTION")
        elif len(suspicious_apis) >= 5:
            score += 25
            reasons.append(f"High number of sensitive/dangerous Windows APIs imported ({len(suspicious_apis)} APIs).")
            rules_triggered.append("RULE_PE_MANY_SUSPICIOUS_APIS")

        if KEYLOGGER_APIS.intersection(suspicious_apis):
            score += 20
            reasons.append("Executable imports keystroke capture/hook APIs.")
            rules_triggered.append("RULE_PE_KEYLOGGING_APIS")

        if DOWNLOADER_APIS.intersection(suspicious_apis):
            score += 15
            reasons.append("Executable imports web download APIs (URLDownloadToFile / InternetOpenUrl).")
            rules_triggered.append("RULE_PE_DOWNLOADER_APIS")

        # 3. Bitcoin address presence
        pe_features = static_info.get("pe_features", {})
        btc_count = pe_features.get("BitcoinAddresses", 0)
        if btc_count > 0:
            score += 40
            reasons.append(f"Cryptocurrency wallet addresses discovered in binary strings ({btc_count} address(es)), indicative of ransomware.")
            rules_triggered.append("RULE_PE_BITCOIN_ADDRESS")

        # 4. Digital signature check
        is_signed = static_info.get("is_signed", False)
        if not is_signed:
            score += 10
            reasons.append("Executable is not digitally signed by a trusted vendor.")
            rules_triggered.append("RULE_PE_UNSIGNED")

        # 5. Anomalous section count
        num_sections = pe_features.get("NumberOfSections", 0)
        if num_sections <= 1:
            score += 20
            reasons.append(f"Unusually low number of PE sections ({num_sections}), often seen in packed droppers.")
            rules_triggered.append("RULE_PE_ABNORMAL_SECTIONS")
        elif num_sections > 12:
            score += 15
            reasons.append(f"Unusually high section count ({num_sections}).")
            rules_triggered.append("RULE_PE_MANY_SECTIONS")

        normalized_score = min(100, score)
        return {
            "heuristic_score": normalized_score,
            "rules_triggered": rules_triggered,
            "reasons": reasons
        }
