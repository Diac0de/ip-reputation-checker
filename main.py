"""
=============================================================================
MODULE: main.py — Orchestration Layer (Entry Point)
=============================================================================

WHY THIS FILE EXISTS:
This is the "Controller" — it wires every module together and defines
the execution pipeline. It does NOT contain any business logic itself.

Its only job is:
1. Load configuration (API keys from environment variables).
2. Accept and validate user input.
3. Call API clients to collect data.
4. Pass data to the verdict engine.
5. Pass the result to the reporter.
6. Handle top-level errors gracefully.

IMPORTANT — WHY ENVIRONMENT VARIABLES FOR API KEYS:
NEVER hardcode API keys in source code. If you commit them to Git,
they're exposed forever (even if you delete the commit later).
The standard practice is to load them from environment variables,
which are set outside the codebase (in a .env file, CI/CD secrets,
or system environment).

We use python-dotenv to load a .env file automatically in development.

PIPELINE ARCHITECTURE:
Input → Validate → [AbuseIPDB Query] → [VirusTotal Query]
     → Build Report → Compute Verdict → Print Report

The two API calls are independent — in a production system you'd
run them concurrently with asyncio or threading. For now, sequential
is correct for a learning project (simpler to debug).
=============================================================================
"""

import os
import sys
import logging
import argparse

# Load .env file into environment variables before anything else
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv is optional; env vars can be set manually

from src.models        import IPReputationReport
from src.validator     import IPValidator, ValidationError
from src.api_clients   import AbuseIPDBClient, VirusTotalClient
from src.verdict_engine import VerdictEngine
from src.reporter      import Reporter


# ---------------------------------------------------------------------------
# LOGGING CONFIGURATION
# ---------------------------------------------------------------------------
# basicConfig sets up the root logger.
# FORMAT includes timestamp, level, module name — essential for debugging.
# Level INFO means we see INFO and above (WARNING, ERROR, CRITICAL).
# Set to DEBUG during development to see every API call.

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ARGUMENT PARSER
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    """
    Defines the CLI interface using argparse.

    argparse is Python's standard library for CLI argument parsing.
    It auto-generates --help output and validates argument types.
    """
    parser = argparse.ArgumentParser(
        prog="ip-checker",
        description="SOC Tier-1 IP Reputation Checker — AbuseIPDB + VirusTotal",
        epilog="Example: python main.py 8.8.8.8"
    )
    parser.add_argument(
        "ip_address",
        help="The IPv4 or IPv6 address to investigate."
    )
    parser.add_argument(
        "--no-abuseipdb",
        action="store_true",
        help="Skip AbuseIPDB lookup."
    )
    parser.add_argument(
        "--no-virustotal",
        action="store_true",
        help="Skip VirusTotal lookup."
    )
    return parser


# ---------------------------------------------------------------------------
# MAIN PIPELINE
# ---------------------------------------------------------------------------

def run(ip_address: str, skip_abuseipdb: bool = False, skip_virustotal: bool = False) -> None:
    """
    Executes the full IP reputation check pipeline.

    Args:
    - ip_address: The raw IP string from CLI input.
    - skip_abuseipdb: If True, skip AbuseIPDB query.
    - skip_virustotal: If True, skip VirusTotal query.
    """

    # --- Step 1: Validate input ---
    validator = IPValidator()
    try:
        clean_ip = validator.validate(ip_address)
    except ValidationError as e:
        print(f"\n[ERROR] Invalid input: {e}\n")
        sys.exit(1)

    logger.info(f"Starting reputation check for: {clean_ip}")

    # --- Step 2: Initialize report (our data accumulator) ---
    report = IPReputationReport(ip_address=clean_ip)

    # --- Step 3: Collect AbuseIPDB data ---
    if not skip_abuseipdb:
        api_key = os.getenv("ABUSEIPDB_API_KEY")
        if not api_key:
            logger.warning("ABUSEIPDB_API_KEY not set. Skipping AbuseIPDB.")
        else:
            client = AbuseIPDBClient(api_key=api_key)
            report.abuseipdb = client.check_ip(clean_ip)

    # --- Step 4: Collect VirusTotal data ---
    if not skip_virustotal:
        api_key = os.getenv("VIRUSTOTAL_API_KEY")
        if not api_key:
            logger.warning("VIRUSTOTAL_API_KEY not set. Skipping VirusTotal.")
        else:
            client = VirusTotalClient(api_key=api_key)
            report.virustotal = client.check_ip(clean_ip)

    # --- Step 5: Compute verdict ---
    engine = VerdictEngine()
    report = engine.compute_verdict(report)

    # --- Step 6: Print report ---
    reporter = Reporter()
    reporter.print_report(report)


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = build_arg_parser()
    args   = parser.parse_args()

    run(
        ip_address=      args.ip_address,
        skip_abuseipdb=  args.no_abuseipdb,
        skip_virustotal= args.no_virustotal,
    )
