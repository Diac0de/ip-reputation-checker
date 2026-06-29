"""
=============================================================================
MODULE: models.py — Data Layer (Data Structures)
=============================================================================

WHY THIS FILE EXISTS:
In software architecture, separating your DATA from your LOGIC is a core
principle called "Separation of Concerns." This file owns only one job:
defining the shape of data that flows through the entire program.

DATA STRUCTURES USED HERE:
- @dataclass: A Python decorator that auto-generates __init__, __repr__,
  and __eq__ for us. Cleaner than plain dicts because fields are typed,
  named, and documented — not anonymous key-value pairs.
- Enum: Used for fixed sets of values (like verdict levels). This prevents
  bugs caused by typos in raw strings like "MALICIOUS" vs "malicous".
- Optional[T]: Signals that a field can be None — important when an API
  call fails and we still need a valid object to work with.

ARCHITECTURE PATTERN:
This follows the "Value Object" pattern from Domain-Driven Design (DDD).
Each dataclass is an immutable snapshot of data from one point in time.
No methods that change state — just structured containers.
=============================================================================
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from datetime import datetime


# ---------------------------------------------------------------------------
# ENUMS — Fixed vocabularies to prevent string-based bugs
# ---------------------------------------------------------------------------

class Verdict(Enum):
    """
    Represents the final threat assessment of an IP address.
    Using Enum instead of raw strings ensures we never compare
    "MALICIOUS" == "Malicious" and get a wrong result.
    """
    CLEAN      = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS  = "MALICIOUS"
    UNKNOWN    = "UNKNOWN"


class APIStatus(Enum):
    """
    Tracks whether an API call succeeded or failed.
    This lets the report layer know how to interpret missing data.
    """
    SUCCESS = "SUCCESS"
    FAILED  = "FAILED"
    SKIPPED = "SKIPPED"


# ---------------------------------------------------------------------------
# DATA MODELS — Typed containers for each API's response
# ---------------------------------------------------------------------------

@dataclass
class AbuseIPDBResult:
    """
    Holds the parsed response from AbuseIPDB.

    Fields:
    - abuse_confidence_score: 0–100. Higher = more reports of abuse.
    - total_reports: How many users reported this IP.
    - country_code: 2-letter ISO country code (e.g., "RU", "CN").
    - isp: Internet Service Provider name.
    - usage_type: e.g., "Data Center/Web Hosting/Transit".
    - is_whitelisted: If True, AbuseIPDB considers it trusted.
    - status: Whether the API call itself worked.
    - error_message: Populated only if status == FAILED.
    """
    status:                 APIStatus        = APIStatus.SKIPPED
    abuse_confidence_score: int              = 0
    total_reports:          int              = 0
    country_code:           Optional[str]    = None
    isp:                    Optional[str]    = None
    usage_type:             Optional[str]    = None
    is_whitelisted:         bool             = False
    error_message:          Optional[str]    = None


@dataclass
class VirusTotalResult:
    """
    Holds the parsed response from VirusTotal.

    Fields:
    - malicious_count: How many AV engines flagged it as malicious.
    - suspicious_count: How many flagged it as suspicious.
    - harmless_count: How many cleared it.
    - undetected_count: How many didn't analyze it.
    - total_engines: Total engines that scanned the IP.
    - last_analysis_date: When VirusTotal last scanned this IP.
    - status / error_message: Same pattern as AbuseIPDBResult.
    """
    status:             APIStatus        = APIStatus.SKIPPED
    malicious_count:    int              = 0
    suspicious_count:   int              = 0
    harmless_count:     int              = 0
    undetected_count:   int              = 0
    total_engines:      int              = 0
    last_analysis_date: Optional[str]    = None
    error_message:      Optional[str]    = None


@dataclass
class IPReputationReport:
    """
    The final aggregated report combining all sources.

    This is the single object that gets passed to the report renderer.
    It contains raw results from each API plus a final computed verdict.

    Fields:
    - ip_address: The IP that was analyzed.
    - timestamp: When this scan was performed.
    - abuseipdb / virustotal: Individual API results.
    - verdict: The final computed threat level.
    - verdict_reason: A human-readable explanation of why.
    """
    ip_address:     str
    timestamp:      str              = field(default_factory=lambda: datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
    abuseipdb:      AbuseIPDBResult  = field(default_factory=AbuseIPDBResult)
    virustotal:     VirusTotalResult = field(default_factory=VirusTotalResult)
    verdict:        Verdict          = Verdict.UNKNOWN
    verdict_reason: str              = "No data collected."
