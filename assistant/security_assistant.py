"""
ACTIS AI Security Assistant Module
Provides grounded, natural-language threat explanations based strictly on
ACTIS database records, ML inference results, heuristic rules, and threat logs.
Operates strictly in READ-ONLY mode. Never executes system commands or shell scripts.
"""

import re
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from reports.scan_database import get_system_statistics, get_recent_detections, get_recent_scans
from reports.threat_database import lookup_indicator, get_db_connection
from config.config import get_logger

logger = get_logger("SecurityAssistant")


class SecurityAssistant:
    """Grounded AI security advisor that explains ACTIS events in plain language."""

    def ask(self, query: str) -> str:
        """Processes user security inquiry and returns a factual, grounded explanation."""
        q = query.strip().lower()

        # Intent 1: "What did ACTIS detect today?" / "Recent threats" / "What was found?"
        if any(w in q for w in ["today", "recent", "latest threats", "what did actis detect", "what was found"]):
            return self._handle_recent_detections()

        # Intent 2: "Show me critical detections" / "High risk"
        if "critical" in q or "high" in q:
            return self._handle_critical_detections()

        # Intent 3: "How many threats" / "Statistics" / "Summary" / "How many scans"
        if any(w in q for w in ["how many", "statistics", "stats", "summary", "overview", "total"]):
            return self._handle_statistics()

        # Intent 4: "Why was X flagged?" / "Why is X suspicious?"
        if "why was" in q or "why is" in q or "explain" in q:
            # Extract target name/URL/file from query if present
            words = query.split()
            potential_target = None
            for w in words:
                if "." in w or "/" in w or "\\" in w:
                    potential_target = w.strip("?'\",;:")
                    break

            if potential_target:
                return self._handle_why_flagged(potential_target)
            else:
                return self._handle_why_general(q)

        # Intent 5: "What should I do?" / "Recommended action"
        if "what should i do" in q or "action" in q or "how to respond" in q or "quarantine" in q:
            return self._handle_recommendations()

        # Intent 6: How ACTIS works / architecture
        if any(w in q for w in ["how does actis", "how do you detect", "methodology", "detect malware", "detect phishing", "how actis works"]):
            return (
                "**ACTIS Detection Methodology:**\n\n"
                "ACTIS employs a defense-in-depth, 6-layer detection pipeline:\n\n"
                "1. **Local Threat Intelligence DB:** Instant hash and URL lookup against known verified threats.\n"
                "2. **Static Metadata Analysis:** Safe inspection of file sizes, formats, and Shannon entropy without execution.\n"
                "3. **Windows PE Static Inspection:** Deep extraction of 15 PE header features (Machine, sections, linker versions, DLL characteristics, cryptocurrency address strings) via `pefile`.\n"
                "4. **Rule-Based Heuristics:** Verification of suspicious section names (UPX/packers), dangerous Windows API import combinations (process injection, keylogging), and URL morphological tricks.\n"
                "5. **Machine Learning Models:** Random Forest classifiers trained on real-world Windows PE malware datasets (99.6% accuracy) and URL phishing datasets (88.8% accuracy).\n"
                "6. **Multi-Criteria Risk Engine:** Fuses all evidence into an explainable 0–100 risk score and severity level (LOW, MEDIUM, HIGH, CRITICAL)."
            )

        # Fallback: General security overview with context
        return self._handle_general_fallback(query)

    def _handle_recent_detections(self) -> str:
        detections = get_recent_detections(limit=5)
        if not detections:
            return "No threats or suspicious events have been detected recently. Your system is operating with a clean security status."

        lines = [f"**Recent Threat Detections ({len(detections)} recorded):**\n"]
        for d in detections:
            reasons_summary = d.get("explanations", ["No specific reason logged"])[0]
            lines.append(
                f"- **{d['target']}**\n"
                f"  • Severity: **{d['risk_level']}** (Score: {d['final_score']}/100)\n"
                f"  • Primary Factor: {reasons_summary}\n"
                f"  • Detected: {d['detected_at'][:19]}\n"
            )
        lines.append("To view full technical details, open the **Threat History** tab in the sidebar.")
        return "\n".join(lines)

    def _handle_critical_detections(self) -> str:
        detections = get_recent_detections(limit=20)
        critical = [d for d in detections if d["risk_level"] in ["CRITICAL", "HIGH"]]
        if not critical:
            return "There are no **CRITICAL** or **HIGH** severity detections on record. All scanned targets are currently within acceptable risk boundaries."

        lines = [f"**Critical & High Severity Security Events ({len(critical)}):**\n"]
        for d in critical:
            lines.append(
                f"- **{d['target']}** [{d['risk_level']} - {d['final_score']}/100]\n"
                f"  • Vector: {d['target_type'].upper()}\n"
                f"  • Reasons: {'; '.join(d.get('explanations', [])[:2])}\n"
            )
        lines.append("\n**Recommendation:** Do not execute, download, or authenticate through these flagged targets.")
        return "\n".join(lines)

    def _handle_statistics(self) -> str:
        stats = get_system_statistics()
        r = stats["risk_distribution"]
        return (
            f"**ACTIS System Security Telemetry:**\n\n"
            f"- **Total Scans Completed:** {stats['total_scans']}\n"
            f"- **Total Files Inspected:** {stats['total_files_scanned']}\n"
            f"- **Threats Identified:** {stats['total_threats_found']}\n"
            f"- **Threat Indicators in Database:** {stats['total_indicators']}\n"
            f"- **Active Severity Distribution:**\n"
            f"  • Critical: {r.get('CRITICAL', 0)}\n"
            f"  • High: {r.get('HIGH', 0)}\n"
            f"  • Medium: {r.get('MEDIUM', 0)}\n"
            f"  • Low: {r.get('LOW', 0)}\n"
        )

    def _handle_why_flagged(self, target: str) -> str:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM detections WHERE lower(target) LIKE ? ORDER BY id DESC LIMIT 1;",
            (f"%{target.lower()}%",)
        )
        row = cursor.fetchone()
        conn.close()

        if not row:
            # Check indicators
            ind = lookup_indicator("sha256", target)
            if not ind.get("found"):
                ind = lookup_indicator("domain", target)
            if not ind.get("found"):
                ind = lookup_indicator("url", target)

            if ind.get("found"):
                return (
                    f"Target **{target}** is recorded in the local Threat Intelligence Database.\n\n"
                    f"- Threat Family: **{ind.get('threat_name')}** ({ind.get('threat_type')})\n"
                    f"- Verification Status: **{ind.get('status')}**\n"
                    f"- Confidence: {int(ind.get('confidence', 0)*100)}%\n"
                    f"- Source: {ind.get('source')}\n"
                    f"- Description: {ind.get('description') or 'Identified threat indicator.'}"
                )
            return f"No detection record or intelligence entry was found matching `{target}`. It may not have been scanned yet."

        try:
            explanations = json.loads(row["explanation_json"] or "[]")
        except Exception:
            explanations = []

        lines = [
            f"**Analysis for:** `{row['target']}`\n\n",
            f"- **Assigned Risk Level:** **{row['risk_level']}** (Score: {row['final_score']}/100)\n",
            f"- **Target Type:** {row['target_type'].upper()}\n",
            f"- **Detection Timestamp:** {row['detected_at'][:19]}\n\n",
            "**Key Evidence & Factors:**\n"
        ]
        for exp in explanations:
            lines.append(f"- {exp}")

        return "\n".join(lines)

    def _handle_why_general(self, q: str) -> str:
        recent = get_recent_detections(limit=1)
        if recent:
            return self._handle_why_flagged(recent[0]["target"])
        return "ACTIS flags targets when multi-layer evidence (threat intelligence databases, machine learning probabilities, and heuristic rules) crosses the threshold for suspicious or malicious behavior."

    def _handle_recommendations(self) -> str:
        return (
            "**General Incident Response Recommendations:**\n\n"
            "1. **Never Execute Suspicious Binaries:** If a file is flagged as HIGH or CRITICAL, do not double-click or launch it.\n"
            "2. **Avoid Phishing URLs:** Do not provide usernames, passwords, or personal identity information on suspicious links.\n"
            "3. **Verify Origin:** Contact the alleged sender via a trusted secondary channel (phone, internal chat) to confirm legitimacy.\n"
            "4. **Isolate:** Move suspicious downloads to a secure quarantine directory or remove them.\n"
            "5. **Share Verified Threat Intelligence:** Submit verified malicious hashes to the ACTIS Central Network via the Settings tab to protect other endpoints."
        )

    def _handle_general_fallback(self, query: str) -> str:
        stats = get_system_statistics()
        return (
            f"I analyzed your request: *\"{query}\"*\n\n"
            f"Current ACTIS Status: **{stats['total_scans']} scans** conducted, **{stats['total_threats_found']} threats** flagged.\n\n"
            f"You can ask me:\n"
            f"- *'What threats were detected today?'*\n"
            f"- *'Why was [filename or URL] flagged?'*\n"
            f"- *'Show me the latest critical detections'* \n"
            f"- *'How does ACTIS detect malware?'*"
        )


security_assistant = SecurityAssistant()
