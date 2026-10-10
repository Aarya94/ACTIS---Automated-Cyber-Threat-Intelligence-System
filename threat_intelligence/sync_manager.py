"""
ACTIS Threat Intelligence Synchronization Manager
Coordinates two-way indicator exchange between the local ACTIS installation
and the central threat intelligence backend.
Uses defensive indicator validation, private IP shielding, versioned v1 REST contracts,
and idempotent database upserts.
"""

from typing import Any, Dict, List, Optional
import requests

from config.config import ACTIS_BACKEND_URL, ACTIS_CLIENT_API_KEY, get_logger
from detection_engine.threat_intel_contract import IndicatorType
from reports.threat_database import upsert_feed_records
from threat_intelligence.indicator_validator import (
    is_safe_public_ip,
    validate_and_normalize_indicator,
)
from threat_intelligence.sync.sync_models import FeedRecord

logger = get_logger("SyncManager")


class SyncManager:
    """
    Manages threat synchronization and candidate contribution with the central backend.
    Preserves provenance, isolates network outages, and uses idempotent local persistence.
    """

    def __init__(self, backend_url: Optional[str] = None, api_key: Optional[str] = None):
        self.backend_url = (backend_url or ACTIS_BACKEND_URL or "http://127.0.0.1:8000").rstrip("/")
        self.api_key = api_key or ACTIS_CLIENT_API_KEY or "actis-client-default-secret-token"
        self.headers = {
            "X-ACTIS-API-Key": self.api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "ACTIS-SyncManager/1.0",
        }

    def check_backend_health(self) -> Dict[str, Any]:
        """Checks if central backend is online and reachable via versioned health endpoint."""
        for endpoint in ["/api/v1/health", "/api/health"]:
            try:
                resp = requests.get(f"{self.backend_url}{endpoint}", timeout=3.0)
                if resp.status_code == 200:
                    return resp.json()
            except requests.exceptions.RequestException:
                continue
            except Exception as e:
                return {"status": "ERROR", "error": str(e)}

        return {"status": "OFFLINE", "error": "Cannot connect to central backend."}

    def query_indicator(self, indicator_type: str, indicator_value: str) -> Dict[str, Any]:
        """Queries the central backend for a specific indicator by type and value."""
        ind_type = indicator_type.strip().lower()
        val_clean = indicator_value.strip()

        # Local validation
        if ind_type == "ip":
            is_safe, err = is_safe_public_ip(val_clean)
            if not is_safe:
                return {"found": False, "message": f"Private IP shielded: {err}"}

        is_valid, norm_val, err, _ = validate_and_normalize_indicator(val_clean, ind_type)
        if not is_valid:
            return {"found": False, "message": f"Invalid indicator: {err}"}

        target_val = norm_val or val_clean
        for endpoint in [f"/api/v1/indicators/{ind_type}/{target_val}", f"/api/indicator/{ind_type}/{target_val}"]:
            try:
                resp = requests.get(
                    f"{self.backend_url}{endpoint}",
                    headers=self.headers,
                    timeout=5.0,
                )
                if resp.status_code == 200:
                    return resp.json()
            except requests.exceptions.RequestException as e:
                logger.warning(f"Failed query on {endpoint}: {e}")
                break

        return {"found": False, "message": "Indicator query failed or not found."}

    def pull_verified_intelligence(
        self,
        min_confidence: float = 0.8,
        status_filter: str = "CONFIRMED",
        limit: int = 500,
    ) -> Dict[str, Any]:
        """
        Retrieves verified indicators from the central backend, normalizes and validates them,
        and applies idempotent batch upserts into the local threat database.
        """
        endpoints = [
            f"{self.backend_url}/api/v1/indicators?min_confidence={min_confidence}&status_filter={status_filter}&limit={limit}",
            f"{self.backend_url}/api/indicators?min_confidence={min_confidence}&status_filter={status_filter}&limit={limit}",
        ]

        resp = None
        for url in endpoints:
            try:
                resp = requests.get(url, headers=self.headers, timeout=8.0)
                if resp.status_code == 200:
                    break
            except requests.exceptions.RequestException as e:
                logger.warning(f"Failed connecting to {url}: {e}")
                continue

        if not resp or resp.status_code != 200:
            err_msg = f"HTTP {resp.status_code}" if resp else "Connection error"
            return {"success": False, "error": err_msg, "synced_count": 0, "inserted": 0, "updated": 0}

        try:
            data = resp.json()
            indicators: List[Dict[str, Any]] = data.get("indicators", [])

            validated_records: List[FeedRecord] = []
            rejected_count = 0

            for ind in indicators:
                raw_type = str(ind.get("indicator_type", "")).strip().lower()
                raw_val = str(ind.get("indicator_value", "")).strip()

                if not raw_type or not raw_val:
                    rejected_count += 1
                    continue

                if raw_type == "ip":
                    is_safe, _ = is_safe_public_ip(raw_val)
                    if not is_safe:
                        rejected_count += 1
                        continue

                is_valid, norm_val, _, resolved_type = validate_and_normalize_indicator(raw_val, raw_type)
                if not is_valid or not norm_val or not resolved_type:
                    rejected_count += 1
                    continue

                threat_type = str(ind.get("threat_type", "Generic Threat"))
                threat_name = str(ind.get("threat_name", "Central Threat"))
                confidence = float(ind.get("confidence", 0.9))
                rec_status = str(ind.get("status", "CONFIRMED"))
                tags = ind.get("tags", [])
                if isinstance(tags, str):
                    tags = [t.strip() for t in tags.split(",") if t.strip()]

                record = FeedRecord(
                    indicator=norm_val,
                    indicator_type=resolved_type,
                    source_feed="central_actis_network",
                    confidence=confidence,
                    status=rec_status,
                    threat_type=threat_type,
                    threat_name=threat_name,
                    first_seen=ind.get("first_seen"),
                    last_seen=ind.get("last_seen") or ind.get("verified_at"),
                    tags=list(tags),
                    metadata={"notes": str(ind.get("notes") or "Synchronized from central threat intelligence.")},
                )
                validated_records.append(record)

            # Idempotent batch persistence using SQLite layer
            raw_dicts = [r.to_dict() for r in validated_records]
            inserted, updated, unchanged = upsert_feed_records(raw_dicts)
            total_synced = inserted + updated

            logger.info(
                f"Pulled from Central ACTIS: {len(indicators)} received, {inserted} inserted, "
                f"{updated} updated, {rejected_count} rejected."
            )
            return {
                "success": True,
                "synced_count": total_synced,
                "inserted": inserted,
                "updated": updated,
                "rejected": rejected_count,
            }

        except Exception as e:
            logger.error(f"Error parsing Central ACTIS intelligence response: {e}")
            return {"success": False, "error": str(e), "synced_count": 0, "inserted": 0, "updated": 0}

    def push_verified_threat(
        self,
        indicator_type: str,
        indicator_value: str,
        threat_type: str = "Generic Threat",
        threat_name: str = "Local Detection",
        confidence: float = 0.90,
        status: str = "CANDIDATE",
        notes: str = "",
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Submits a locally observed candidate threat to the central threat intelligence backend.
        Submitted records are stored in candidate/reported status for anti-poisoning safety.
        Never transmits user files.
        """
        ind_type = indicator_type.strip().lower()
        raw_val = indicator_value.strip()

        # Local validation before transmission
        if ind_type == "ip":
            is_safe, err = is_safe_public_ip(raw_val)
            if not is_safe:
                return {"success": False, "error": f"Private IP shielded from upload: {err}"}

        is_valid, norm_val, err, _ = validate_and_normalize_indicator(raw_val, ind_type)
        if not is_valid:
            return {"success": False, "error": f"Invalid indicator: {err}"}

        payload = {
            "indicator_type": ind_type,
            "indicator_value": norm_val or raw_val,
            "threat_type": threat_type,
            "threat_name": threat_name,
            "confidence": confidence,
            "status": status,
            "notes": notes,
            "tags": tags or [],
        }

        # Try v1 contributions endpoint, fallback to legacy
        endpoints = [
            f"{self.backend_url}/api/v1/contributions",
            f"{self.backend_url}/api/indicator",
        ]

        last_error = "Unknown error"
        for url in endpoints:
            try:
                resp = requests.post(url, json=payload, headers=self.headers, timeout=5.0)
                if resp.status_code in (200, 201):
                    logger.info(f"Successfully contributed indicator '{norm_val}' to central network.")
                    return {"success": True, "data": resp.json()}
                elif resp.status_code == 404:
                    continue
                else:
                    last_error = f"HTTP {resp.status_code}: {resp.text}"
                    return {"success": False, "error": last_error}
            except requests.exceptions.RequestException as e:
                last_error = str(e)
                continue

        logger.warning(f"Failed to contribute threat to central backend: {last_error}")
        return {"success": False, "error": last_error}


# Singleton instances
sync_manager = SyncManager()
CentralThreatIntelligenceClient = SyncManager

