"""
ACTIS Threat Lookup Module
Coordinates local database lookups and optional external threat feed queries.
"""

from typing import Dict, Any, Optional
from reports.threat_database import lookup_indicator
from threat_intelligence.api_clients import vt_client, BaseThreatClient
from config.config import get_logger

logger = get_logger("ThreatLookup")


class ThreatLookup:
    """Unified threat lookup layer covering local DB and external providers."""

    def __init__(self, external_client: Optional[BaseThreatClient] = None):
        self.external_client = external_client or vt_client

    def lookup_hash(self, sha256_hash: str, query_external: bool = False) -> Dict[str, Any]:
        """Looks up a file hash locally, and optionally queries external intel."""
        local_res = lookup_indicator("sha256", sha256_hash)
        
        external_res = {"available": False}
        if query_external and self.external_client:
            external_res = self.external_client.lookup_hash(sha256_hash)

        return {
            "indicator": sha256_hash,
            "indicator_type": "sha256",
            "local_intel": local_res,
            "external_intel": external_res,
            "is_known_threat": local_res.get("found", False) or external_res.get("malicious", False)
        }

    def lookup_url(self, url: str, domain: str, query_external: bool = False) -> Dict[str, Any]:
        """Looks up a URL and its domain locally and optionally externally."""
        # 1. Check exact URL
        local_url_res = lookup_indicator("url", url)
        # 2. Check parent domain
        local_domain_res = lookup_indicator("domain", domain)
        
        local_res = local_url_res if local_url_res.get("found") else local_domain_res

        external_res = {"available": False}
        if query_external and self.external_client:
            external_res = self.external_client.lookup_url(url)

        return {
            "indicator": url,
            "indicator_type": "url",
            "domain": domain,
            "local_intel": local_res,
            "external_intel": external_res,
            "is_known_threat": local_res.get("found", False) or external_res.get("malicious", False)
        }


# Global instance
threat_lookup = ThreatLookup()
