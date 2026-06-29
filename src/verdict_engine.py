"""
=============================================================================
MODULE: verdict_engine.py — Business Logic Layer
=============================================================================

WHY THIS FILE EXISTS:
This is the "brain" of the tool. It takes raw API results and applies
decision logic to compute a final threat verdict.

Separating this from api_clients.py is critical:
- The API layer only collects data. It has no opinion about what's bad.
- The verdict engine only makes decisions. It never touches the network.

This pattern is called "Command-Query Separation" (CQS):
- Queries (API clients) return data, no side effects.
- Commands (verdict engine) compute decisions from data.

DECISION LOGIC EXPLAINED:
We use a threshold-based scoring system, common in SOC tooling.
Each source contributes evidence. The final verdict follows the
"Highest Alert Wins" rule — if ANY source screams MALICIOUS, the
overall verdict is MALICIOUS, even if others say CLEAN.

This mimics how a real Tier 1 analyst thinks:
  "One vendor says it's bad? Investigate. Don't dismiss it."

WHY NOT USE ML HERE?
For a beginner project, rule-based thresholds are more auditable,
explainable, and debuggable than a black-box ML model. In a real
SOC product, you'd layer ML on top of these rules, not replace them.
=============================================================================
"""

from src.models import (
    IPReputationReport,
    AbuseIPDBResult,
    VirusTotalResult,
    Verdict,
    APIStatus,
)


# ---------------------------------------------------------------------------
# THRESHOLDS — Tune these to adjust sensitivity
# ---------------------------------------------------------------------------
# These are the decision boundaries. In a real SOC, these are calibrated
# over weeks of observation to reduce false positives.

ABUSEIPDB_MALICIOUS_THRESHOLD  = 50   # Score >= 50 → MALICIOUS
ABUSEIPDB_SUSPICIOUS_THRESHOLD = 10   # Score >= 10 → SUSPICIOUS

VIRUSTOTAL_MALICIOUS_THRESHOLD  = 3   # 3+ engines flagged → MALICIOUS
VIRUSTOTAL_SUSPICIOUS_THRESHOLD = 1   # 1+ engine flagged → SUSPICIOUS


# ---------------------------------------------------------------------------
# VERDICT ENGINE
# ---------------------------------------------------------------------------

class VerdictEngine:
    """
    Computes a final threat verdict from multiple API results.

    Design Principle: Stateless.
    This class holds no data between calls. Every call to compute_verdict()
    is independent. This makes it safe to use in concurrent environments
    and easy to unit test.
    """

    def compute_verdict(self, report: IPReputationReport) -> IPReputationReport:
        """
        Analyzes the API results in the report and sets:
        - report.verdict: The final Verdict enum value.
        - report.verdict_reason: A human-readable explanation.

        Modifies and returns the same report object (in-place update).
        We don't create a new object because the report is the accumulator
        throughout the program's pipeline.

        Args:
        - report: An IPReputationReport with API results already populated.

        Returns:
        - The same report, with verdict and verdict_reason set.
        """
        reasons = []
        highest_verdict = Verdict.UNKNOWN

        # --- Evaluate AbuseIPDB ---
        abuse = report.abuseipdb

        if abuse.status == APIStatus.SUCCESS:
            abuse_verdict, abuse_reason = self._evaluate_abuseipdb(abuse)
            reasons.append(f"[AbuseIPDB] {abuse_reason}")
            highest_verdict = self._escalate(highest_verdict, abuse_verdict)
        elif abuse.status == APIStatus.FAILED:
            reasons.append(f"[AbuseIPDB] API call failed: {abuse.error_message}")

        # --- Evaluate VirusTotal ---
        vt = report.virustotal

        if vt.status == APIStatus.SUCCESS:
            vt_verdict, vt_reason = self._evaluate_virustotal(vt)
            reasons.append(f"[VirusTotal] {vt_reason}")
            highest_verdict = self._escalate(highest_verdict, vt_verdict)
        elif vt.status == APIStatus.FAILED:
            reasons.append(f"[VirusTotal] API call failed: {vt.error_message}")

        # --- Handle edge case: no data collected at all ---
        if not reasons:
            highest_verdict = Verdict.UNKNOWN
            reasons.append("No API data was collected. Check your API keys and network.")

        report.verdict        = highest_verdict
        report.verdict_reason = " | ".join(reasons)
        return report

    # -----------------------------------------------------------------------
    # PRIVATE HELPERS
    # -----------------------------------------------------------------------

    def _evaluate_abuseipdb(
        self, result: AbuseIPDBResult
    ) -> tuple[Verdict, str]:
        """
        Applies threshold rules to AbuseIPDB data.

        Returns:
        - (Verdict, reason_string)
        """
        score = result.abuse_confidence_score

        if result.is_whitelisted:
            return Verdict.CLEAN, f"IP is whitelisted by AbuseIPDB. Score: {score}."

        if score >= ABUSEIPDB_MALICIOUS_THRESHOLD:
            return (
                Verdict.MALICIOUS,
                f"Abuse confidence score is {score}/100 (>= {ABUSEIPDB_MALICIOUS_THRESHOLD}). "
                f"Reported {result.total_reports} times."
            )

        if score >= ABUSEIPDB_SUSPICIOUS_THRESHOLD:
            return (
                Verdict.SUSPICIOUS,
                f"Abuse confidence score is {score}/100 (>= {ABUSEIPDB_SUSPICIOUS_THRESHOLD}). "
                f"Reported {result.total_reports} times."
            )

        return Verdict.CLEAN, f"Abuse confidence score is low: {score}/100."

    def _evaluate_virustotal(
        self, result: VirusTotalResult
    ) -> tuple[Verdict, str]:
        """
        Applies threshold rules to VirusTotal data.

        Returns:
        - (Verdict, reason_string)
        """
        malicious  = result.malicious_count
        suspicious = result.suspicious_count
        total      = result.total_engines

        if malicious >= VIRUSTOTAL_MALICIOUS_THRESHOLD:
            return (
                Verdict.MALICIOUS,
                f"{malicious}/{total} engines flagged as MALICIOUS "
                f"(threshold: {VIRUSTOTAL_MALICIOUS_THRESHOLD})."
            )

        if malicious > 0 or suspicious >= VIRUSTOTAL_SUSPICIOUS_THRESHOLD:
            return (
                Verdict.SUSPICIOUS,
                f"{malicious} malicious, {suspicious} suspicious detections out of {total} engines."
            )

        return Verdict.CLEAN, f"0/{total} engines flagged this IP."

    def _escalate(self, current: Verdict, new: Verdict) -> Verdict:
        """
        Returns the higher-severity verdict between current and new.

        Severity order: UNKNOWN < CLEAN < SUSPICIOUS < MALICIOUS

        This ensures "highest alert wins" across all sources.
        """
        severity_rank = {
            Verdict.UNKNOWN:    0,
            Verdict.CLEAN:      1,
            Verdict.SUSPICIOUS: 2,
            Verdict.MALICIOUS:  3,
        }

        if severity_rank[new] > severity_rank[current]:
            return new
        return current
