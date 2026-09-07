"""
ACTIS Threat Intelligence Synchronization Manager
Coordinates two-way indicator exchange between the local ACTIS installation
and the central threat intelligence backend.
"""

import requests
from typing import Dict, Any, List, Optional
from config.config import ACTIS_BACKEND_URL, ACTIS_CLIENT_API_KEY, get_logger
from reports.threat_database import register_indicator

logger = get_logger("SyncManager")


class SyncManager:
    """Manages threat synchronization with central backend."""

    def __init__(self, backend_url: Optional[str] = None, api_key: Optional[str] = None):
        self.backend_url = (backend_url or ACTIS_BACKEND_URL).rstrip("/")
        self.api_key = api_key or ACTIS_CLIENT_API_KEY
        self.headers = {
            "X-ACTIS-API-Key": self.api_key,
            "Content-Type": "application/json"
        }

    def check_backend_health(self) -> Dict[str, Any]:
        """Checks if central backend is online and reachable."""
        try:
            resp = requests.get(f"{self.backend_url}/api/health", timeout=3.0)
            if resp.status_code == 200:
                return resp.json()
            return {"status": "UNREACHABLE", "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"status": "OFFLINE", "error": str(e)}

    def pull_verified_intelligence(self, min_confidence: float = 0.8) -> Dict[str, Any]:
        """
        Retrieves verified indicators from the central backend and
        updates the local threat database.
        """
        try:
            url = f"{self.backend_url}/api/indicators?min_confidence={min_confidence}&status_filter=CONFIRMED"
            resp = requests.get(url, timeout=5.0)
            if resp.status_code != 200:
                return {"success": False, "error": f"HTTP {resp.status_code}", "synced_count": 0}

            data = resp.json()
            indicators: List[Dict[str, Any]] = data.get("indicators", [])

            synced_count = 0
            for ind in indicators:
                register_indicator(
                    indicator_type=ind["indicator_type"],
                    indicator_value=ind["indicator_value"],
                    source="ACTIS_Central_Network",
                    confidence=ind["confidence"],
                    status=ind["status"],
                    threat_type=ind["threat_type"],
                    threat_name=ind["threat_name"]
                )
                synced_count += 1

            logger.info(f"Pulled and integrated {synced_count} indicators from central threat intelligence.")
            return {"success": True, "synced_count": synced_count}

        except Exception as e:
            logger.warning(f"Failed to pull threat intelligence from central backend: {e}")
            return {"success": False, "error": str(e), "synced_count": 0}

    def push_verified_threat(
        self,
        indicator_type: str,
        indicator_value: str,
        threat_type: str = "Generic Threat",
        threat_name: str = "Local Detection",
        confidence: float = 0.90,
        status: str = "SUSPICIOUS",
        notes: str = ""
    ) -> Dict[str, Any]:
        """
        Submits a locally confirmed threat to the central threat intelligence backend.
        Never transmits user files.
        """
        payload = {
            "indicator_type": indicator_type,
            "indicator_value": indicator_value,
            "threat_type": threat_type,
            "threat_name": threat_name,
            "confidence": confidence,
            "status": status,
            "notes": notes
        }

        try:
            url = f"{self.backend_url}/api/indicator"
            resp = requests.post(url, json=payload, headers=self.headers, timeout=5.0)
            if resp.status_code == 200:
                logger.info(f"Successfully shared indicator '{indicator_value}' with central network.")
                return {"success": True, "data": resp.json()}
            return {"success": False, "error": f"HTTP {resp.status_code}: {resp.text}"}
        except Exception as e:
            logger.warning(f"Failed to push threat intelligence to central backend: {e}")
            return {"success": False, "error": str(e)}


sync_manager = SyncManager()
