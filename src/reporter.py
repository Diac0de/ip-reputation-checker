"""
=============================================================================
MODULE: reporter.py — Presentation / Output Layer
=============================================================================

WHY THIS FILE EXISTS:
This module is the only part of the program that "talks" to the user.
It knows how to take an IPReputationReport and render it as human-readable
terminal output.

Separating presentation from logic means:
- You can add a JSON output format without touching the verdict engine.
- You can add an HTML report without touching the API clients.
- Unit tests for the verdict engine don't need to capture stdout.

This is the "View" in a loose MVC (Model–View–Controller) pattern:
- Model:      models.py
- Controller: main.py (orchestration) + verdict_engine.py (logic)
- View:       THIS FILE

DESIGN NOTE ON COLORS:
We use ANSI escape codes for terminal colors. This is the standard way
to add color in CLI tools — no external library needed.
These codes are invisible in log files and are ignored by most text parsers.
=============================================================================
"""

from src.models import IPReputationReport, Verdict, APIStatus


# ---------------------------------------------------------------------------
# ANSI COLOR CODES — Terminal color constants
# ---------------------------------------------------------------------------

class Color:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GREY    = "\033[90m"


# ---------------------------------------------------------------------------
# VERDICT → COLOR MAPPING
# ---------------------------------------------------------------------------
# Maps each Verdict enum to a display color and label.
# Stored as a dict for O(1) lookup — not a chain of if/elif.

VERDICT_DISPLAY = {
    Verdict.MALICIOUS:  (Color.RED,    "🔴 MALICIOUS"),
    Verdict.SUSPICIOUS: (Color.YELLOW, "🟡 SUSPICIOUS"),
    Verdict.CLEAN:      (Color.GREEN,  "🟢 CLEAN"),
    Verdict.UNKNOWN:    (Color.GREY,   "⚪ UNKNOWN"),
}


# ---------------------------------------------------------------------------
# REPORTER CLASS
# ---------------------------------------------------------------------------

class Reporter:
    """
    Renders IPReputationReport objects to the terminal.

    Stateless: no constructor args, no stored state.
    Just pass a report to print_report() and it handles the rest.
    """

    def print_report(self, report: IPReputationReport) -> None:
        """
        Prints a full, formatted threat report to stdout.

        Args:
        - report: A completed IPReputationReport (verdict already set).
        """
        self._print_header(report)
        self._print_abuseipdb_section(report)
        self._print_virustotal_section(report)
        self._print_verdict_section(report)
        self._print_footer()

    # -----------------------------------------------------------------------
    # PRIVATE SECTION PRINTERS
    # -----------------------------------------------------------------------

    def _print_header(self, report: IPReputationReport) -> None:
        w = 60
        print()
        print(f"{Color.CYAN}{Color.BOLD}{'═' * w}{Color.RESET}")
        print(f"{Color.CYAN}{Color.BOLD}  IP REPUTATION REPORT{Color.RESET}")
        print(f"{Color.CYAN}{'─' * w}{Color.RESET}")
        print(f"  Target IP   : {Color.BOLD}{report.ip_address}{Color.RESET}")
        print(f"  Scan Time   : {Color.GREY}{report.timestamp}{Color.RESET}")
        print(f"{Color.CYAN}{'═' * w}{Color.RESET}")

    def _print_abuseipdb_section(self, report: IPReputationReport) -> None:
        abuse = report.abuseipdb
        print(f"\n{Color.BOLD}  [ AbuseIPDB ]{Color.RESET}")
        print(f"  {'─' * 40}")

        if abuse.status == APIStatus.FAILED:
            print(f"  {Color.RED}✗ Failed: {abuse.error_message}{Color.RESET}")
            return

        if abuse.status == APIStatus.SKIPPED:
            print(f"  {Color.GREY}– Skipped (no API key provided){Color.RESET}")
            return

        score = abuse.abuse_confidence_score
        score_color = (
            Color.RED    if score >= 50 else
            Color.YELLOW if score >= 10 else
            Color.GREEN
        )
        print(f"  Confidence Score : {score_color}{Color.BOLD}{score}/100{Color.RESET}")
        print(f"  Total Reports    : {abuse.total_reports}")
        print(f"  Country          : {abuse.country_code or 'N/A'}")
        print(f"  ISP              : {abuse.isp or 'N/A'}")
        print(f"  Usage Type       : {abuse.usage_type or 'N/A'}")
        print(f"  Whitelisted      : {'Yes' if abuse.is_whitelisted else 'No'}")

    def _print_virustotal_section(self, report: IPReputationReport) -> None:
        vt = report.virustotal
        print(f"\n{Color.BOLD}  [ VirusTotal ]{Color.RESET}")
        print(f"  {'─' * 40}")

        if vt.status == APIStatus.FAILED:
            print(f"  {Color.RED}✗ Failed: {vt.error_message}{Color.RESET}")
            return

        if vt.status == APIStatus.SKIPPED:
            print(f"  {Color.GREY}– Skipped (no API key provided){Color.RESET}")
            return

        print(f"  Malicious        : {Color.RED}{vt.malicious_count}{Color.RESET} / {vt.total_engines} engines")
        print(f"  Suspicious       : {Color.YELLOW}{vt.suspicious_count}{Color.RESET} / {vt.total_engines} engines")
        print(f"  Harmless         : {Color.GREEN}{vt.harmless_count}{Color.RESET}")
        print(f"  Undetected       : {Color.GREY}{vt.undetected_count}{Color.RESET}")
        print(f"  Last Analysis    : {vt.last_analysis_date or 'N/A'}")

    def _print_verdict_section(self, report: IPReputationReport) -> None:
        color, label = VERDICT_DISPLAY.get(
            report.verdict, (Color.GREY, "⚪ UNKNOWN")
        )
        print(f"\n{Color.BOLD}  [ FINAL VERDICT ]{Color.RESET}")
        print(f"  {'─' * 40}")
        print(f"  {color}{Color.BOLD}{label}{Color.RESET}")
        print(f"\n  Reason:")
        for part in report.verdict_reason.split(" | "):
            print(f"    • {part}")

    def _print_footer(self) -> None:
        print(f"\n{Color.CYAN}{'═' * 60}{Color.RESET}")
        print(f"{Color.GREY}  Data from AbuseIPDB & VirusTotal. For SOC use only.{Color.RESET}")
        print(f"{Color.CYAN}{'═' * 60}{Color.RESET}\n")
