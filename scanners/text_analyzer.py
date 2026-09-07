"""
ACTIS Message & Email Text Analyzer Module
Extracts URLs from emails, SMS, and chat messages, evaluates social-engineering
cues (urgency, credential prompts), and routes URLs through the unified URL scanner.
"""

import re
from typing import Dict, Any, List
from scanners.url_scanner import scan_url_logic
from config.config import get_logger

logger = get_logger("TextAnalyzer")

URL_REGEX = re.compile(r"https?://[^\s<>\"]+|www\.[^\s<>\"]+")

URGENCY_PATTERNS = [
    r"\burgent\b", r"\bimmediate(ly)?\b", r"\bwithin \d+ hours?\b",
    r"\baction required\b", r"\baccount (suspended|locked|terminated)\b",
    r"\bsecurity alert\b", r"\bunauthorized access\b", r"\bexpires? soon\b"
]

CREDENTIAL_PATTERNS = [
    r"\bverify (your )?password\b", r"\bconfirm (your )?identity\b",
    r"\benter (your )?pin\b", r"\bupdate (your )?billing\b",
    r"\blogin credentials\b", r"\bre-enter password\b", r"\bvalidate account\b"
]

FINANCIAL_PATTERNS = [
    r"\bwire transfer\b", r"\bbitcoin payout\b", r"\bclaim your refund\b",
    r"\byou have won\b", r"\binheritance\b", r"\bprocessing fee\b",
    r"\bcrypto deposit\b", r"\bunclaimed prize\b"
]


class TextAnalyzer:
    """Analyzes messages, emails, and notes for suspicious links and engineering cues."""

    @staticmethod
    def extract_urls(text: str) -> List[str]:
        """Extracts unique URLs from text content."""
        raw_urls = URL_REGEX.findall(text)
        cleaned = []
        for u in raw_urls:
            # Strip trailing punctuation often caught in regex
            u_clean = u.rstrip(".,;:!?)'\"")
            if u_clean and u_clean not in cleaned:
                cleaned.append(u_clean)
        return cleaned

    @classmethod
    def evaluate_social_engineering(cls, text: str) -> Dict[str, Any]:
        """Identifies suspicious urgency, credential requests, and financial lure keywords."""
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

        se_score = (len(urgency_hits) * 15) + (len(cred_hits) * 25) + (len(fin_hits) * 20)
        se_score = min(100, se_score)

        return {
            "se_score": se_score,
            "has_urgency": bool(urgency_hits),
            "urgency_indicators": urgency_hits,
            "has_credential_request": bool(cred_hits),
            "credential_indicators": cred_hits,
            "has_financial_lure": bool(fin_hits),
            "financial_indicators": fin_hits
        }

    @classmethod
    def analyze_message(cls, text: str, check_external: bool = False) -> Dict[str, Any]:
        """
        Parses text, checks social-engineering cues, and passes every extracted URL
        through the central URL scanning pipeline.
        """
        if not text or not text.strip():
            return {
                "urls_found": [],
                "url_count": 0,
                "social_engineering": {},
                "url_results": [],
                "overall_risk_level": "LOW",
                "overall_score": 0,
                "summary": "No text provided."
            }

        extracted_urls = cls.extract_urls(text)
        se_analysis = cls.evaluate_social_engineering(text)

        url_results = []
        max_url_score = 0.0
        threat_urls_count = 0

        for url in extracted_urls:
            res = scan_url_logic(url, check_external=check_external)
            url_results.append(res)
            if res.get("is_threat", False):
                threat_urls_count += 1
            if res.get("score", 0) > max_url_score:
                max_url_score = res.get("score", 0)

        # Combine text cues and URL risk
        combined_score = max_url_score
        if se_analysis["se_score"] > 30 and extracted_urls:
            combined_score = min(100.0, combined_score + (se_analysis["se_score"] * 0.3))

        if combined_score >= 80:
            overall_level = "CRITICAL"
        elif combined_score >= 60:
            overall_level = "HIGH"
        elif combined_score >= 35:
            overall_level = "MEDIUM"
        else:
            overall_level = "LOW"

        return {
            "urls_found": extracted_urls,
            "url_count": len(extracted_urls),
            "social_engineering": se_analysis,
            "url_results": url_results,
            "threat_urls_count": threat_urls_count,
            "overall_score": round(combined_score, 1),
            "overall_risk_level": overall_level,
            "is_suspicious_message": (combined_score >= 35)
        }


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
