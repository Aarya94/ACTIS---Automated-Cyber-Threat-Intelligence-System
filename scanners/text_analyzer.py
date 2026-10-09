"""
ACTIS Message & Email Text Analyzer Module
Extracts URLs from emails, SMS, and chat messages, evaluates social-engineering
cues (urgency, credential prompts), and routes URLs through the unified URL scanner.
"""

import re
from typing import Dict, Any, List, Tuple, Optional, Union
from scanners.url_scanner import scan_url_logic, normalize_url
from config.config import get_logger

logger = get_logger("TextAnalyzer")

URL_REGEX = re.compile(r"(?:https?://|www\.)[^\s<>\"]+", re.IGNORECASE)


def clean_url_token(raw_token: str) -> str:
    """
    Cleans an extracted URL token by removing surrounding punctuation,
    unbalanced enclosing parentheses/brackets/braces, and outer quotes.
    Preserves balanced parentheses inside URLs (e.g. Wikipedia links).
    """
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
    def analyze_message(cls, text: str, check_external: bool = False) -> Dict[str, Any]:
        """
        Parses text, evaluates social-engineering cues, deduplicates URLs to canonical
        representations, and delegates analysis to the common URL scanner logic.
        """
        if not text or not isinstance(text, str) or not text.strip():
            return {
                "urls_found": [],
                "url_count": 0,
                "total_url_count": 0,
                "unique_url_count": 0,
                "social_engineering": {
                    "se_score": 0,
                    "has_urgency": False,
                    "urgency_indicators": [],
                    "has_credential_request": False,
                    "credential_indicators": [],
                    "has_financial_lure": False,
                    "financial_indicators": []
                },
                "url_results": [],
                "threat_urls_count": 0,
                "overall_risk_level": "LOW",
                "overall_score": 0.0,
                "is_suspicious_message": False,
                "summary": "No text provided."
            }

        canonical_urls, url_counts = cls.extract_canonical_urls(text)
        total_raw_count = sum(url_counts.values())
        se_analysis = cls.evaluate_social_engineering(text)

        url_results = []
        max_url_score = 0.0
        threat_urls_count = 0

        # Scan each UNIQUE canonical URL exactly once
        for url in canonical_urls:
            res = scan_url_logic(url, check_external=check_external)
            res_annotated = dict(res)
            res_annotated["occurrence_count"] = url_counts.get(url, 1)
            url_results.append(res_annotated)

            if res.get("is_threat", False):
                threat_urls_count += 1
            if res.get("score", 0) > max_url_score:
                max_url_score = res.get("score", 0)

        # Combine text cues and URL risk
        combined_score = max_url_score
        if se_analysis["se_score"] > 30 and canonical_urls:
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
            "urls_found": canonical_urls,
            "url_count": len(canonical_urls),
            "total_url_count": total_raw_count,
            "unique_url_count": len(canonical_urls),
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
