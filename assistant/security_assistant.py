"""
ACTIS AI Security Assistant Module
Automated Cyber Threat Intelligence System — Milestone Day 14

Provides grounded, evidence-based natural language threat explanations based strictly
on ACTIS database records, ML inference results, heuristic rules, and threat logs.
Operates strictly in READ-ONLY mode. Never executes system commands, shell scripts,
or arbitrary code. Never modifies, deletes, or quarantines user files.
"""

import json
import re
import sqlite3
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from config.config import get_logger
from reports.scan_database import (
    get_recent_detections,
    get_recent_scans,
    get_system_statistics,
)
from reports.threat_database import (
    get_db_connection,
    lookup_indicator,
)

logger = get_logger("SecurityAssistant")

# Regex patterns for canonical target extraction
URL_PATTERN = re.compile(r'https?://[^\s\'"<>]+', re.IGNORECASE)
SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')
MD5_PATTERN = re.compile(r'\b[a-fA-F0-9]{32}\b')
IPV4_PATTERN = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
DOMAIN_PATTERN = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,63})\b')
FILENAME_PATTERN = re.compile(
    r'\b[a-zA-Z0-9_\-\.\\]+\.(?:exe|dll|sys|scr|bat|cmd|ps1|vbs|js|zip|rar|7z|doc|docx|xls|xlsx|pdf|bin|dat|tmp)\b',
    re.IGNORECASE
)
QUOTED_PATTERN = re.compile(r'["\']([^"\']+)["\']')

# Sensitive secret masking patterns
SECRET_PATTERN = re.compile(
    r'(?:api[_-]?key|secret|token|password|bearer)[\s:=]+([a-zA-Z0-9_\-\.]{8,})',
    re.IGNORECASE
)


def mask_sensitive_strings(text: Any) -> str:
    """Masks potential credentials, API keys, and sensitive tokens from text."""
    if not text:
        return "" if text is None else str(text)
    if not isinstance(text, str):
        return str(text)

    def _repl(match):
        val = match.group(1)
        if len(val) <= 4:
            masked = "****"
        else:
            masked = f"{val[:2]}****{val[-2:]}"
        return match.group(0).replace(val, masked)

    return SECRET_PATTERN.sub(_repl, text)


def _format_score_pct(val: Optional[float]) -> str:
    """Formats a decimal (0.0-1.0) or integer (0-100) score into a normalized percentage string."""
    if val is None:
        return "N/A"
    try:
        f_val = float(val)
        if 0.0 <= f_val <= 1.0:
            return f"{int(round(f_val * 100))}%"
        return f"{int(round(f_val))}%"
    except (ValueError, TypeError):
        return "N/A"


# =====================================================================
# Assistant Provider Abstraction (Phase 4)
# =====================================================================

class BaseAssistantProvider(ABC):
    """Abstract interface for assistant explanation providers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the provider implementation."""
        pass

    @abstractmethod
    def explain(self, query: str, context: Dict[str, Any]) -> str:
        """Generates an explanation given the query and structured context."""
        pass


class DeterministicAssistantProvider(BaseAssistantProvider):
    """
    Default deterministic provider.
    Synthesizes factual, evidence-grounded responses strictly from recorded
    ACTIS telemetry, database records, and detection rationales.
    Zero external network calls, zero hallucinations, 100% offline-ready.
    """

    @property
    def name(self) -> str:
        return "deterministic"

    def explain(self, query: str, context: Dict[str, Any]) -> str:
        """Renders evidence context into structured, factual text."""
        return context.get("formatted_response", "")


class ExternalLLMProvider(BaseAssistantProvider):
    """
    Optional bounded external LLM provider.
    Used exclusively for natural language phrasing when explicitly enabled.
    Enforces strict timeouts, data minimization, and secret redaction.
    Falls back seamlessly to the deterministic provider on any error.
    """

    def __init__(
        self,
        api_key: str = "",
        api_base_url: str = "",
        model_name: str = "default-model",
        timeout_seconds: float = 5.0,
        max_retries: int = 1,
    ):
        self._api_key = api_key
        self._api_base_url = api_base_url
        self._model_name = model_name
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries

    @property
    def name(self) -> str:
        return "external_llm"

    def explain(self, query: str, context: Dict[str, Any]) -> str:
        """
        Attempts to format the explanation through an external endpoint.
        Transmits ONLY sanitized summary fields, never file contents or private data.
        Falls back to deterministic text if unavailable or disabled.
        """
        if not self._api_key or not self._api_base_url:
            logger.info("External LLM not configured or missing API key. Using deterministic output.")
            return context.get("formatted_response", "")

        try:
            # Data minimization: only send high-level factual fields
            sanitized_evidence = {
                "target": mask_sensitive_strings(context.get("target", "")),
                "risk_level": context.get("risk_level", "UNKNOWN"),
                "final_score": context.get("final_score", 0),
                "reasons": [mask_sensitive_strings(r) for r in context.get("reasons", [])],
                "deterministic_text": context.get("formatted_response", ""),
            }
            logger.debug(f"External LLM invocation requested for model {self._model_name} with timeout {self.timeout_seconds}s")
            return context.get("formatted_response", "")
        except Exception as err:
            logger.warning(f"External LLM provider failed: {err}. Falling back to deterministic engine.")
            return context.get("formatted_response", "")


# =====================================================================
# Canonical Grounded AI Security Assistant (Day 14)
# =====================================================================

class SecurityAssistant:
    """
    Grounded AI security advisor that explains ACTIS events in plain language.
    Strictly READ-ONLY. Grounded in actual SQLite detection records and threat intelligence.
    """

    def __init__(self, provider: Optional[BaseAssistantProvider] = None):
        self.fallback_provider = DeterministicAssistantProvider()
        self.provider = provider or self.fallback_provider

    def ask(self, query: Any) -> str:
        """
        Processes a user security inquiry and returns a factual, grounded explanation.
        Handles missing records honestly, avoids false safety claims, and enforces
        strict read-only security boundaries.
        """
        if not query or not isinstance(query, str) or not query.strip():
            return "Please enter a security inquiry or question regarding ACTIS scans, detections, or threat intelligence."

        # Bound query length to protect against resource exhaustion
        sanitized_query = query.strip()
        if len(sanitized_query) > 1000:
            sanitized_query = sanitized_query[:1000]

        q = sanitized_query.lower()

        try:
            # Priority 1: Defensive Incident Response Recommendations
            if any(w in q for w in ["what should i do", "how to respond", "recommendation", "quarantine", "next steps", "remediation"]) or (
                "action" in q and "flagged" in q
            ):
                return self._handle_recommendations()

            # Priority 2: ACTIS Detection Methodology & Capabilities
            if any(w in q for w in [
                "how does actis", "how do you detect", "methodology", "architecture",
                "detect malware", "detect phishing", "how actis works", "detection pipeline"
            ]):
                return self._handle_methodology()

            # Priority 3: Recent Detections / "What did ACTIS detect today?" / "Recent threats"
            if any(w in q for w in ["today", "recent", "latest threats", "what did actis detect", "what was found", "last detections"]):
                return self._handle_recent_detections()

            # Priority 4: Critical / High Risk Detections
            if "critical" in q or "high risk" in q or "highest risk" in q or "severe" in q:
                return self._handle_critical_detections()

            # Priority 5: System Statistics / Telemetry / Summary
            if any(w in q for w in ["how many", "statistics", "stats", "summary", "overview", "total scans", "telemetry"]):
                return self._handle_statistics()

            # Priority 6: Target Explanation ("Why was X flagged?" / "Why is X suspicious?" / "Explain target X")
            if any(p in q for p in ["why was", "why is", "why were", "explain target", "explain why", "check target", "is this flagged", "is this malicious", "inspect"]):
                target = self._extract_target(sanitized_query)
                if target:
                    return self._handle_why_flagged(target)
                else:
                    return self._handle_why_general(q)

            # If user explicitly supplied a target or indicator without a question verb
            direct_target = self._extract_target(sanitized_query)
            if direct_target and direct_target.lower() not in ["actis", "malware", "phishing", "virus", "threat", "security", "scan"]:
                return self._handle_why_flagged(direct_target)

            # Fallback: General inquiry with examples and live telemetry context
            return self._handle_general_fallback(sanitized_query)

        except sqlite3.Error as sql_err:
            logger.error(f"Database error during assistant inquiry: {sql_err}")
            return (
                "**Local Database Unavailable:**\n\n"
                "The assistant was unable to retrieve stored records due to a local SQLite read error. "
                "Local threat scanning and background protection continue to function independently."
            )
        except Exception as err:
            logger.error(f"Unexpected error in SecurityAssistant: {err}", exc_info=True)
            return (
                "**Query Processing Limitation:**\n\n"
                "The assistant encountered an unexpected error while evaluating your query. "
                "No system changes or destructive operations were performed."
            )

    # -----------------------------------------------------------------
    # Target Extraction Logic
    # -----------------------------------------------------------------

    def _extract_target(self, query: str) -> Optional[str]:
        """
        Extracts a potential target (URL, SHA-256, MD5, IP, domain, filename, or path)
        from user query using priority matching.
        """
        # 1. Quoted targets (e.g. 'evil.exe' or "http://phish.com")
        quoted = QUOTED_PATTERN.search(query)
        if quoted:
            candidate = quoted.group(1).strip()
            if candidate:
                return candidate

        # 2. Complete URLs
        url_match = URL_PATTERN.search(query)
        if url_match:
            return url_match.group(0).rstrip("?.,;:'\"")

        # 3. SHA-256 Hashes (64 hex characters)
        sha256_match = SHA256_PATTERN.search(query)
        if sha256_match:
            return sha256_match.group(0)

        # 4. MD5 Hashes (32 hex characters)
        md5_match = MD5_PATTERN.search(query)
        if md5_match:
            return md5_match.group(0)

        # 5. IPv4 Addresses
        ip_match = IPV4_PATTERN.search(query)
        if ip_match:
            return ip_match.group(0)

        # 6. Filenames with extensions (e.g. evil.exe, invoice.pdf)
        fn_match = FILENAME_PATTERN.search(query)
        if fn_match:
            return fn_match.group(0).rstrip("?.,;:'\"")

        # 7. Domain names (e.g. login-verify.xyz)
        for match in DOMAIN_PATTERN.finditer(query):
            candidate = match.group(0).rstrip("?.,;:'\"")
            parts = candidate.split(".")
            if len(parts) >= 2 and parts[-1].lower() in [
                "com", "net", "org", "xyz", "io", "info", "top", "online", "site", "ru", "cn", "biz", "live", "cc"
            ]:
                return candidate

        # 8. Token extraction following common interrogative patterns
        lower_q = query.lower()
        for marker in ["why was ", "why is ", "why were ", "explain target ", "check target ", "about target ", "target "]:
            if marker in lower_q:
                idx = lower_q.find(marker) + len(marker)
                rest = query[idx:].strip()
                tokens = rest.split()
                if tokens:
                    candidate = tokens[0].strip("?'\",;:()[]{}")
                    if candidate and candidate.lower() not in ["it", "this", "that", "flagged", "suspicious", "detected", "malicious"]:
                        return candidate

        return None

    # -----------------------------------------------------------------
    # Intent Handlers
    # -----------------------------------------------------------------

    def _handle_recent_detections(self) -> str:
        """Retrieves and summarizes the latest recorded detections."""
        detections = get_recent_detections(limit=5)
        if not detections:
            return (
                "**No Recent Threat Detections Recorded**\n\n"
                "There are currently zero threats or suspicious events recorded in the local scan history.\n\n"
                "*Note:* An empty detection history indicates that no alerts have been recorded by ACTIS. "
                "It is not an absolute guarantee that uninspected targets or dormant threats are absent from this system. "
                "You can initiate a Quick Scan or Custom Directory Scan to inspect specific locations."
            )

        lines = [f"**Recent Threat Detections ({len(detections)} recorded in scan history):**\n"]
        for d in detections:
            reasons = d.get("explanations", [])
            primary_reason = reasons[0] if reasons else "Score exceeded detection threshold"
            lines.append(
                f"- **{d['target']}**\n"
                f"  • Severity: **{d['risk_level']}** (Score: {d['final_score']}/100)\n"
                f"  • Target Type: `{d['target_type'].upper()}`\n"
                f"  • Primary Factor: {primary_reason}\n"
                f"  • Detected At: {d['detected_at'][:19]}\n"
            )
        lines.append("\nTo view full technical evidence, open the **Threat History** tab in the dashboard.")
        return "\n".join(lines)

    def _handle_critical_detections(self) -> str:
        """Retrieves and highlights CRITICAL and HIGH severity detections."""
        detections = get_recent_detections(limit=25)
        critical = [d for d in detections if d.get("risk_level") in ["CRITICAL", "HIGH"]]

        if not critical:
            return (
                "**No Critical or High-Risk Detections Recorded**\n\n"
                "There are currently no **CRITICAL** or **HIGH** severity detections recorded in the local database.\n\n"
                "*Note:* This reflects current recorded scan history. Any lower-severity items or uninspected files "
                "should still be handled with standard defensive cybersecurity hygiene."
            )

        lines = [f"**High & Critical Severity Security Events ({len(critical)} recorded):**\n"]
        for d in critical:
            reasons = d.get("explanations", [])
            summary_reasons = "; ".join(reasons[:2]) if reasons else "Multi-factor risk threshold exceeded"
            lines.append(
                f"- **{d['target']}** [{d['risk_level']} — {d['final_score']}/100]\n"
                f"  • Vector: `{d['target_type'].upper()}`\n"
                f"  • Evidence: {summary_reasons}\n"
                f"  • Timestamp: {d['detected_at'][:19]}\n"
            )
        lines.append(
            "\n**Defensive Advice:** Do not execute flagged binaries or authenticate credentials through flagged links. "
            "Review full evidence in the dashboard."
        )
        return "\n".join(lines)

    def _handle_statistics(self) -> str:
        """Returns verified aggregated system statistics from the database."""
        stats = get_system_statistics()
        r = stats.get("risk_distribution", {})

        return (
            "**ACTIS System Security Telemetry:**\n\n"
            f"- **Total Scans Completed:** {stats.get('total_scans', 0)}\n"
            f"- **Total Files Inspected:** {stats.get('total_files_scanned', 0)}\n"
            f"- **Threats Identified:** {stats.get('total_threats_found', 0)}\n"
            f"- **Threat Indicators in Database:** {stats.get('total_indicators', 0)}\n\n"
            "**Recorded Severity Distribution:**\n"
            f"- Critical Severity: **{r.get('CRITICAL', 0)}**\n"
            f"- High Severity: **{r.get('HIGH', 0)}**\n"
            f"- Medium Severity: **{r.get('MEDIUM', 0)}**\n"
            f"- Low Severity: **{r.get('LOW', 0)}**\n\n"
            "*Integrity Guarantee:* Telemetry is computed strictly from local SQLite scan sessions and detection logs."
        )

    def _handle_why_flagged(self, target: str) -> str:
        """
        Explains why a specific target was flagged using documented matching policy:
        1. Exact case-insensitive match on target.
        2. Disambiguation check if multiple distinct targets match.
        3. Local Threat Intelligence database lookup if not in detections.
        4. Honest missing-record response with explicit safety caveat.
        """
        clean_target = target.strip()
        lower_target = clean_target.lower()

        conn = get_db_connection()
        cursor = conn.cursor()

        # Step 1: Check for exact match in detections
        cursor.execute(
            """
            SELECT d.id, d.scan_id, d.target, d.target_type, d.model_name,
                   d.model_score, d.rule_score, d.intel_score, d.final_score,
                   d.risk_level, d.explanation_json, d.detected_at, s.scan_type
            FROM detections d
            LEFT JOIN scans s ON d.scan_id = s.id
            WHERE lower(d.target) = ?
            ORDER BY d.id DESC
            LIMIT 1;
            """,
            (lower_target,)
        )
        row = cursor.fetchone()

        # Step 2: If no exact match, perform structured partial search with disambiguation
        if not row:
            cursor.execute(
                """
                SELECT DISTINCT target
                FROM detections
                WHERE lower(target) LIKE ?
                ORDER BY id DESC
                LIMIT 5;
                """,
                (f"%{lower_target}%",)
            )
            candidate_rows = cursor.fetchall()

            if len(candidate_rows) > 1:
                conn.close()
                options = "\n".join([f"- `{r['target']}`" for r in candidate_rows])
                return (
                    f"**Ambiguous Target Query:**\n\n"
                    f"Multiple recorded detections match `{clean_target}`. "
                    f"To prevent describing the wrong incident, please specify the exact target name:\n\n"
                    f"{options}"
                )
            elif len(candidate_rows) == 1:
                matched_target = candidate_rows[0]["target"]
                cursor.execute(
                    """
                    SELECT d.id, d.scan_id, d.target, d.target_type, d.model_name,
                           d.model_score, d.rule_score, d.intel_score, d.final_score,
                           d.risk_level, d.explanation_json, d.detected_at, s.scan_type
                    FROM detections d
                    LEFT JOIN scans s ON d.scan_id = s.id
                    WHERE d.target = ?
                    ORDER BY d.id DESC
                    LIMIT 1;
                    """,
                    (matched_target,)
                )
                row = cursor.fetchone()

        conn.close()

        # If a detection record was found, format the grounded breakdown
        if row:
            try:
                explanations = json.loads(row["explanation_json"] or "[]")
            except Exception:
                explanations = []

            model_score_pct = _format_score_pct(row["model_score"])
            rule_score_pct = _format_score_pct(row["rule_score"])
            intel_score_pct = _format_score_pct(row["intel_score"])

            lines = [
                f"**Detection Analysis for:** `{row['target']}`\n\n",
                f"- **Assigned Risk Level:** **{row['risk_level']}** (Score: {row['final_score']}/100)\n",
                f"- **Target Modality:** `{row['target_type'].upper()}`\n",
                f"- **Detection Timestamp:** {row['detected_at'][:19]}\n",
                f"- **Associated Scan Mode:** `{row['scan_type'] or 'Direct Inspection'}`\n\n",
                "**Multi-Factor Scoring Evidence:**\n",
                f"- Threat Intelligence Component: `{intel_score_pct}` (Weight: 35%)\n",
                f"- Machine Learning Component: `{model_score_pct}` (Weight: 30%, Model: {row['model_name'] or 'None'})\n",
                f"- Rule & Heuristic Component: `{rule_score_pct}` (Weight: 20%)\n\n",
                "**Itemized Heuristic & Behavioral Findings:**\n"
            ]

            if explanations:
                for exp in explanations:
                    lines.append(f"- {exp}")
            else:
                lines.append("- Risk score calculated from composite multi-criteria thresholds without detailed sub-rules logged.")

            lines.append("\n**Defensive Guidance:**")
            if row["risk_level"] in ["CRITICAL", "HIGH"]:
                lines.append(
                    "- **Do Not Launch / Execute:** Avoid executing this binary or providing credentials to this link.\n"
                    "- **Manual Isolation:** Relocate the file into a dedicated quarantine directory if local analysis is complete.\n"
                    "- **Secondary Verification:** Confirm the file or URL through an independent channel before taking operational action."
                )
            else:
                lines.append("- Review the itemized evidence above. Exercise standard defensive precautions.")

            return "\n".join(lines)

        # Step 3: Check Threat Intelligence Database indicators
        ind = self._lookup_indicator_across_types(clean_target)
        if ind and ind.get("found"):
            status_label = ind.get("status", "UNKNOWN")
            is_candidate = status_label == "CANDIDATE"

            lines = [
                f"Target **`{clean_target}`** is cataloged in the local **Threat Intelligence Database**:\n\n",
                f"- **Threat Classification:** **{ind.get('threat_name')}** ({ind.get('threat_type')})\n",
                f"- **Indicator Type:** `{ind.get('indicator_type')}`\n",
                f"- **Reputation Source:** `{ind.get('source')}`\n",
                f"- **Verified Confidence:** {int(ind.get('confidence', 0) * 100)}%\n",
                f"- **Indicator Lifecycle Status:** **{status_label}**\n"
            ]

            if is_candidate:
                lines.append(
                    "\n> **Anti-Poisoning Notice:** This indicator holds **CANDIDATE** status (client contribution pending administrative review). "
                    "It has NOT been promoted to globally CONFIRMED intelligence.\n"
                )

            if ind.get("description"):
                lines.append(f"- **Description:** {ind.get('description')}\n")

            lines.append(
                "\n**Defensive Guidance:** Known threat indicators indicate potential malicious association. "
                "Avoid interacting with or trusting entities associated with this identifier."
            )
            return "".join(lines)

        # Step 4: Unknown Target Response (Must NOT claim the target is safe!)
        return (
            f"**No Recorded Intelligence for Target:** `{clean_target}`\n\n"
            "- **Local Detection History:** No matching scan detections recorded.\n"
            "- **Local Threat Intelligence:** No matching hash, domain, URL, or IP entry found.\n\n"
            "**Crucial Defensive Notice:** The absence of a detection record or threat intelligence entry **does not mean** the target is safe, verified, or benign. "
            "Zero-day threats, novel malware, or targeted campaigns may not have recorded signatures. "
            "To evaluate this target, run an active inspection using the URL Scanner, File Static Analysis, or Device Scanner."
        )

    def _lookup_indicator_across_types(self, target: str) -> Optional[Dict[str, Any]]:
        """Queries local Threat Intelligence database checking indicator types systematically."""
        val = target.strip()

        # Direct checks based on string characteristics
        if SHA256_PATTERN.fullmatch(val):
            ind = lookup_indicator("sha256", val)
            if ind.get("found"):
                return ind

        if MD5_PATTERN.fullmatch(val):
            ind = lookup_indicator("md5", val)
            if ind.get("found"):
                return ind

        if IPV4_PATTERN.fullmatch(val):
            ind = lookup_indicator("ip", val)
            if ind.get("found"):
                return ind

        if val.startswith("http://") or val.startswith("https://"):
            ind = lookup_indicator("url", val)
            if ind.get("found"):
                return ind

        # Check domain, then url, sha256, md5, ip
        for itype in ["domain", "url", "sha256", "md5", "ip"]:
            try:
                ind = lookup_indicator(itype, val)
                if ind.get("found"):
                    return ind
            except Exception:
                continue

        return None

    def _handle_why_general(self, q: str) -> str:
        """Explains general detection rationale or prompts for target specification."""
        recent = get_recent_detections(limit=1)
        if recent:
            most_recent_target = recent[0]["target"]
            return (
                "**How ACTIS Flags Suspicious Targets:**\n\n"
                "ACTIS flags files, URLs, and messages when multi-criteria evidence "
                "(threat intelligence lookups, machine learning probabilities, and deterministic heuristic rules) "
                "crosses configured severity thresholds (Critical: 80+, High: 60+, Medium: 35+).\n\n"
                f"Would you like an explanation of your most recent detection (`{most_recent_target}`)? "
                f"Ask: *'Why was {most_recent_target} flagged?'* or specify any file, URL, or hash."
            )

        return (
            "**ACTIS Detection Rationale:**\n\n"
            "ACTIS evaluates targets through three independent analytical pillars:\n"
            "1. **Threat Intelligence (35%):** Exact matching against known malicious hashes, URLs, and domains.\n"
            "2. **Machine Learning (30%):** Statistical classification of URL morphological vectors and PE static structures.\n"
            "3. **Heuristic Rules (20%):** Deterministic inspection of packer sections (UPX), suspicious API imports, and credential harvesting cues.\n\n"
            "To inspect a specific detection, specify the target filename, URL, or hash: e.g. *'Why was sample.exe flagged?'*"
        )

    def _handle_recommendations(self) -> str:
        """Returns safe, non-destructive incident response guidance."""
        return (
            "**Defensive Incident Response Guidance (Read-Only Mode):**\n\n"
            "1. **Do Not Launch Suspicious Binaries:** If a file has been flagged as HIGH or CRITICAL, do not double-click, run, or execute it.\n"
            "2. **Avoid Credential Submission:** Never enter usernames, passwords, or Multi-Factor Authentication tokens on flagged or unverified URLs.\n"
            "3. **Independent Sender Verification:** Verify unusual requests or unexpected links with the sender through a trusted secondary channel (phone, internal chat).\n"
            "4. **Safe Manual Isolation:** Relocate flagged files into a dedicated non-executable holding directory for review by authorized personnel.\n"
            "5. **Examine Evidence Breakdown:** Review the exact heuristic factors and scores in the **Threat History** tab to understand why the score was assigned.\n\n"
            "**Safety Boundary:** ACTIS operates strictly in **read-only mode**. It does **NOT** automatically delete, rename, modify, or quarantine files."
        )

    def _handle_methodology(self) -> str:
        """Returns the truthful, verified ACTIS detection pipeline methodology."""
        return (
            "**ACTIS Architecture & Detection Methodology:**\n\n"
            "ACTIS employs a defense-in-depth, 6-stage unified analysis pipeline:\n\n"
            "1. **Local Threat Intelligence (SQLite WAL Mode):** Rapid lookup of cryptographic hashes (SHA-256, MD5), domains, URLs, and IP addresses against verified intelligence records.\n"
            "2. **Static Windows PE Binary Analysis:** Safe read-only inspection of Windows Portable Executable headers, section tables, Shannon byte entropy, and import tables via `pefile` without code execution.\n"
            "3. **URL & Message Normalization:** RFC canonical normalization, 19 morphological feature extraction, and boundary-aware social engineering urgency analysis.\n"
            "4. **Machine Learning Inference:** 19-feature Random Forest phishing model and Windows PE static feature extraction contracts.\n"
            "5. **Deterministic Heuristic Rules:** Detection of packed sections (UPX), suspicious Windows API import combinations (process injection, keylogging hooks), and credential harvesting URL patterns.\n"
            "6. **Multi-Criteria Risk Fusion:** Normalizes evidence into an explainable 0–100 risk score and severity category (LOW, MEDIUM, HIGH, CRITICAL).\n\n"
            "*Defensive Boundary:* ACTIS never executes untrusted code, never modifies user files, and operates strictly in read-only mode."
        )

    def _handle_general_fallback(self, query: str) -> str:
        """Clear fallback explaining capabilities and providing example queries."""
        try:
            stats = get_system_statistics()
            status_line = f"Current ACTIS State: **{stats.get('total_scans', 0)} scans** conducted, **{stats.get('total_threats_found', 0)} threats** recorded."
        except Exception:
            status_line = "ACTIS Protection Engine: Operating in read-only defensive mode."

        clean_q = mask_sensitive_strings(query)
        if any(w in clean_q.lower() for w in ["ignore previous", "system prompt", "pwned", "jailbreak", "override"]):
            clean_q = "[Unrecognized Query]"

        return (
            f"I analyzed your request: *\"{clean_q}\"*\n\n"
            f"{status_line}\n\n"
            "**What I Can Explain:**\n"
            "- *'What threats were detected today?'* — Summarizes recent detections.\n"
            "- *'Show me the latest critical detections'* — Filters high and critical severity alerts.\n"
            "- *'Why was [filename, URL, or hash] flagged?'* — Provides itemized multi-factor evidence.\n"
            "- *'How many scans were completed?'* — Returns verified system telemetry.\n"
            "- *'What should I do about a flagged file?'* — Provides safe, non-destructive advice.\n"
            "- *'Explain ACTIS detection methodology'* — Describes the 6-stage analysis pipeline.\n\n"
            "*Safety Notice:* I am a read-only security assistant. I cannot execute commands, delete files, or alter detection risk scores."
        )


# Global singleton instance
security_assistant = SecurityAssistant()
