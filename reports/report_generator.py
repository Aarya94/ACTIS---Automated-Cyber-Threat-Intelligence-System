"""
ACTIS Report Generator Module
Generates structured security audit reports in JSON, CSV, and Markdown formats.
"""

import json
import csv
import io
from datetime import datetime
from typing import Dict, Any, List
from reports.scan_database import get_recent_detections, get_system_statistics


class ReportGenerator:
    """Generates structured security compliance and audit reports."""

    @staticmethod
    def generate_json_report() -> str:
        """Exports complete security status and recent detections as JSON."""
        stats = get_system_statistics()
        detections = get_recent_detections(limit=100)
        report = {
            "title": "ACTIS Security Posture & Threat Detection Audit Report",
            "generated_at": datetime.now().isoformat(),
            "system_statistics": stats,
            "detections_count": len(detections),
            "detections": detections
        }
        return json.dumps(report, indent=4)

    @staticmethod
    def generate_csv_report() -> str:
        """Exports recent detections into a CSV spreadsheet format."""
        detections = get_recent_detections(limit=100)
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow([
            "ID", "Detected At", "Target Type", "Target", "Risk Level",
            "Risk Score", "Model", "Explanations"
        ])
        
        for d in detections:
            writer.writerow([
                d.get("id"),
                d.get("detected_at"),
                d.get("target_type"),
                d.get("target"),
                d.get("risk_level"),
                d.get("final_score"),
                d.get("model_name"),
                "; ".join(d.get("explanations", []))
            ])
            
        return output.getvalue()

    @staticmethod
    def generate_markdown_report() -> str:
        """Exports human-readable Markdown security audit summary."""
        stats = get_system_statistics()
        detections = get_recent_detections(limit=25)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        md = []
        md.append("# ACTIS Security Audit & Threat Intelligence Report")
        md.append(f"**Report Generated:** {now}\n")
        
        md.append("## Executive Summary")
        md.append(f"- **Total Scans Conducted:** {stats['total_scans']}")
        md.append(f"- **Total Files Scanned:** {stats['total_files_scanned']}")
        md.append(f"- **Threats Identified:** {stats['total_threats_found']}")
        md.append(f"- **Recorded Intelligence Indicators:** {stats['total_indicators']}")
        md.append(f"- **Critical Threats:** {stats['risk_distribution'].get('CRITICAL', 0)}")
        md.append(f"- **High Severity Threats:** {stats['risk_distribution'].get('HIGH', 0)}\n")

        md.append("## Recent High-Risk Detections")
        if not detections:
            md.append("No security threats detected in recent scans.\n")
        else:
            md.append("| Timestamp | Type | Target | Risk Level | Score | Primary Reason |")
            md.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
            for d in detections:
                target_short = d.get("target", "")
                if len(target_short) > 40:
                    target_short = target_short[:37] + "..."
                first_reason = d.get("explanations", ["N/A"])[0] if d.get("explanations") else "N/A"
                if len(first_reason) > 50:
                    first_reason = first_reason[:47] + "..."
                md.append(
                    f"| {d.get('detected_at', '')[:19]} | {d.get('target_type')} | `{target_short}` | "
                    f"**{d.get('risk_level')}** | {d.get('final_score')} | {first_reason} |"
                )

        md.append("\n---\n*Report compiled by ACTIS (Automated Cyber Threat Intelligence System)*")
        return "\n".join(md)
