"""
ACTIS Threat Intelligence API Clients
Implements provider abstraction for external threat intelligence services
(VirusTotal, URLhaus, AbuseIPDB) with rate limiting, timeouts, and offline fallback.
"""

import base64
import requests
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

from config.config import VIRUSTOTAL_API_KEY, get_logger

logger = get_logger("APIClients")


class BaseThreatClient(ABC):
    """Abstract base class for external threat intelligence providers."""

    @abstractmethod
    def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    def lookup_url(self, url: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        pass


class VirusTotalClient(BaseThreatClient):
    """VirusTotal v3 API Client with rate-limit and error guards."""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or VIRUSTOTAL_API_KEY
        self.headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }

    def is_configured(self) -> bool:
        return bool(self.api_key and len(self.api_key) >= 16)

    def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        """Queries VirusTotal for file hash (SHA-256 or MD5)."""
        if not self.is_configured():
            return {"source": "VirusTotal", "available": False, "reason": "API key not configured."}

        url = f"{self.BASE_URL}/files/{file_hash}"
        try:
            resp = requests.get(url, headers=self.headers, timeout=5.0)
            if resp.status_code == 200:
                data = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
                total = sum(stats.values())
                is_mal = positives > 2
                conf = round(positives / max(1, total), 2)
                return {
                    "source": "VirusTotal",
                    "available": True,
                    "indicator": file_hash,
                    "indicator_type": "hash",
                    "malicious": is_mal,
                    "positives": positives,
                    "total": total,
                    "confidence": conf,
                    "details": stats
                }
            elif resp.status_code == 404:
                return {
                    "source": "VirusTotal",
                    "available": True,
                    "indicator": file_hash,
                    "indicator_type": "hash",
                    "malicious": False,
                    "positives": 0,
                    "total": 0,
                    "confidence": 0.0,
                    "details": {"status": "hash_not_found"}
                }
            elif resp.status_code == 429:
                return {"source": "VirusTotal", "available": False, "reason": "Rate limit exceeded (429)."}
            else:
                return {"source": "VirusTotal", "available": False, "reason": f"HTTP {resp.status_code}"}
        except Exception as e:
            logger.warning(f"VirusTotal hash lookup failed: {e}")
            return {"source": "VirusTotal", "available": False, "reason": str(e)}

    def lookup_url(self, url_to_check: str) -> Dict[str, Any]:
        """Queries VirusTotal for a URL using base64 URL identifier."""
        if not self.is_configured():
            return {"source": "VirusTotal", "available": False, "reason": "API key not configured."}

        try:
            # VirusTotal v3 uses unpadded URL-safe base64 string of URL
            url_id = base64.urlsafe_b64encode(url_to_check.encode()).decode().strip("=")
            endpoint = f"{self.BASE_URL}/urls/{url_id}"
            resp = requests.get(endpoint, headers=self.headers, timeout=5.0)
            if resp.status_code == 200:
                data = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
                total = sum(stats.values())
                is_mal = positives > 1
                conf = round(positives / max(1, total), 2)
                return {
                    "source": "VirusTotal",
                    "available": True,
                    "indicator": url_to_check,
                    "indicator_type": "url",
                    "malicious": is_mal,
                    "positives": positives,
                    "total": total,
                    "confidence": conf,
                    "details": stats
                }
            elif resp.status_code == 404:
                return {
                    "source": "VirusTotal",
                    "available": True,
                    "indicator": url_to_check,
                    "indicator_type": "url",
                    "malicious": False,
                    "positives": 0,
                    "total": 0,
                    "confidence": 0.0,
                    "details": {"status": "url_not_found"}
                }
            else:
                return {"source": "VirusTotal", "available": False, "reason": f"HTTP {resp.status_code}"}
        except Exception as e:
            logger.warning(f"VirusTotal URL lookup failed: {e}")
            return {"source": "VirusTotal", "available": False, "reason": str(e)}

    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """Queries VirusTotal for domain intelligence."""
        if not self.is_configured():
            return {"source": "VirusTotal", "available": False, "reason": "API key not configured."}

        url = f"{self.BASE_URL}/domains/{domain}"
        try:
            resp = requests.get(url, headers=self.headers, timeout=5.0)
            if resp.status_code == 200:
                data = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
                total = sum(stats.values())
                return {
                    "source": "VirusTotal",
                    "available": True,
                    "indicator": domain,
                    "indicator_type": "domain",
                    "malicious": (positives > 2),
                    "positives": positives,
                    "total": total,
                    "confidence": round(positives / max(1, total), 2)
                }
            else:
                return {"source": "VirusTotal", "available": False, "reason": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"source": "VirusTotal", "available": False, "reason": str(e)}


# Global default client
vt_client = VirusTotalClient()
