"""
=============================================================================
MODULE: api_clients.py — External API Integration Layer
=============================================================================

WHY THIS FILE EXISTS:
This module isolates ALL network communication from the rest of the program.
This pattern is called the "Adapter" or "Gateway" pattern in software architecture.

The core rule: nothing outside this file knows HOW we talk to AbuseIPDB
or VirusTotal. If tomorrow the API URL changes, or we add a new source,
we only touch this file.

KEY CONCEPTS:
- requests.Session: Reuses TCP connections (Connection Pooling). Much more
  efficient than creating a new connection per request.
- Timeout: ALWAYS set a timeout on HTTP calls. Without it, a slow API can
  hang your program forever.
- Error Handling Strategy: We use a "Fail Gracefully" approach. If an API
  is down, we return a result object with status=FAILED instead of crashing
  the whole program. This is critical in security tooling — you need partial
  data, not a crash.
- Type hints on all functions: Makes the contract between modules explicit.

ARCHITECTURE PATTERN:
Each API gets its own class. This is the Single Responsibility Principle (SRP):
one class = one job. AbuseIPDBClient only knows about AbuseIPDB.
=============================================================================
"""

import requests
import logging
from typing import Optional
from src.models import (
    AbuseIPDBResult,
    VirusTotalResult,
    APIStatus,
)

# ---------------------------------------------------------------------------
# LOGGING SETUP
# ---------------------------------------------------------------------------
# We use Python's built-in logging instead of print().
# Why? Because print() has no level, no timestamp, and can't be filtered.
# In production security tools, every action must be logged and auditable.

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CONSTANTS
# ---------------------------------------------------------------------------

REQUEST_TIMEOUT_SECONDS = 10  # Never wait more than 10s for an API


# ---------------------------------------------------------------------------
# ABUSEIPDB CLIENT
# ---------------------------------------------------------------------------

class AbuseIPDBClient:
    """
    Handles all communication with the AbuseIPDB v2 API.

    AbuseIPDB is a community-driven database where sysadmins report
    abusive IP addresses (spam, port scanning, brute force, etc.).

    API Docs: https://docs.abuseipdb.com/#check-endpoint
    Free tier: 1,000 requests/day

    Constructor Args:
    - api_key: Your AbuseIPDB API key (kept secret, not hardcoded).
    """

    BASE_URL = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: str):
        self.api_key = api_key
        # Session reuses the TCP connection — more efficient than requests.get()
        self.session = requests.Session()
        self.session.headers.update({
            "Key":    self.api_key,
            "Accept": "application/json",
        })

    def check_ip(self, ip_address: str) -> AbuseIPDBResult:
        """
        Queries AbuseIPDB for reputation data on a given IP.

        Returns an AbuseIPDBResult dataclass — never raises an exception
        to the caller. Errors are captured inside the result object.

        Args:
        - ip_address: A valid IPv4 or IPv6 address string.

        Returns:
        - AbuseIPDBResult with status SUCCESS or FAILED.
        """
        params = {
            "ipAddress":    ip_address,
            "maxAgeInDays": "90",   # Only consider reports from last 90 days
            "verbose":      True,
        }

        try:
            logger.info(f"[AbuseIPDB] Querying IP: {ip_address}")
            response = self.session.get(
                self.BASE_URL,
                params=params,
                timeout=REQUEST_TIMEOUT_SECONDS
            )
            response.raise_for_status()  # Raises HTTPError for 4xx/5xx

            data = response.json().get("data", {})

            return AbuseIPDBResult(
                status=                 APIStatus.SUCCESS,
                abuse_confidence_score= data.get("abuseConfidenceScore", 0),
                total_reports=          data.get("totalReports", 0),
                country_code=           data.get("countryCode"),
                isp=                    data.get("isp"),
                usage_type=             data.get("usageType"),
                is_whitelisted=         data.get("isWhitelisted", False),
            )

        except requests.exceptions.Timeout:
            logger.error("[AbuseIPDB] Request timed out.")
            return AbuseIPDBResult(
                status=APIStatus.FAILED,
                error_message="Request timed out after 10 seconds."
            )
        except requests.exceptions.HTTPError as e:
            logger.error(f"[AbuseIPDB] HTTP error: {e}")
            return AbuseIPDBResult(
                status=APIStatus.FAILED,
                error_message=f"HTTP {response.status_code}: {str(e)}"
            )
        except Exception as e:
            logger.error(f"[AbuseIPDB] Unexpected error: {e}")
            return AbuseIPDBResult(
                status=APIStatus.FAILED,
                error_message=str(e)
            )


# ---------------------------------------------------------------------------
# VIRUSTOTAL CLIENT
# ---------------------------------------------------------------------------

class VirusTotalClient:
    """
    Handles all communication with the VirusTotal v3 API.

    VirusTotal aggregates results from 70+ antivirus engines and URL scanners.
    For IPs, it shows how many engines flagged it as malicious/suspicious.

    API Docs: https://developers.virustotal.com/reference/ip-info
    Free tier: 4 requests/minute, 500 requests/day

    Constructor Args:
    - api_key: Your VirusTotal API key.
    """

    BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            "x-apikey": self.api_key,
            "Accept":   "application/json",
        })

    def check_ip(self, ip_address: str) -> VirusTotalResult:
        """
        Queries VirusTotal for multi-engine analysis of a given IP.

        Returns a VirusTotalResult dataclass — errors are captured inside
        the result, not raised to the caller.

        Args:
        - ip_address: A valid IPv4 or IPv6 address string.

        Returns:
        - VirusTotalResult with status SUCCESS or FAILED.
        """
        url = f"{self.BASE_URL}/{ip_address}"

        try:
            logger.info(f"[VirusTotal] Querying IP: {ip_address}")
            response = self.session.get(url, timeout=REQUEST_TIMEOUT_SECONDS)
            response.raise_for_status()

            data       = response.json().get("data", {})
            attributes = data.get("attributes", {})
            stats      = attributes.get("last_analysis_stats", {})

            # Extract the last analysis date if available
            last_date_ts = attributes.get("last_analysis_date")
            if last_date_ts:
                from datetime import datetime
                last_date = datetime.utcfromtimestamp(last_date_ts).strftime("%Y-%m-%d")
            else:
                last_date = None

            malicious   = stats.get("malicious", 0)
            suspicious  = stats.get("suspicious", 0)
            harmless    = stats.get("harmless", 0)
            undetected  = stats.get("undetected", 0)
            total       = malicious + suspicious + harmless + undetected

            return VirusTotalResult(
                status=             APIStatus.SUCCESS,
                malicious_count=    malicious,
                suspicious_count=   suspicious,
                harmless_count=     harmless,
                undetected_count=   undetected,
                total_engines=      total,
                last_analysis_date= last_date,
            )

        except requests.exceptions.Timeout:
            logger.error("[VirusTotal] Request timed out.")
            return VirusTotalResult(
                status=APIStatus.FAILED,
                error_message="Request timed out after 10 seconds."
            )
        except requests.exceptions.HTTPError as e:
            logger.error(f"[VirusTotal] HTTP error: {e}")
            return VirusTotalResult(
                status=APIStatus.FAILED,
                error_message=f"HTTP {response.status_code}: {str(e)}"
            )
        except Exception as e:
            logger.error(f"[VirusTotal] Unexpected error: {e}")
            return VirusTotalResult(
                status=APIStatus.FAILED,
                error_message=str(e)
            )
