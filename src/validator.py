"""
=============================================================================
MODULE: validator.py — Input Validation Layer
=============================================================================

WHY THIS FILE EXISTS:
Never trust user input. This is rule #1 in security engineering.
Before we send any IP to an external API, we must verify it's a real,
routable IP address — not garbage that wastes API quota or causes errors.

We also block private/reserved IP ranges. Querying AbuseIPDB about
192.168.1.1 is pointless — those IPs are never publicly routable and
will return no threat data.

PYTHON STDLIB USED:
- ipaddress module: Built into Python 3.3+. Parses and validates IP
  addresses with full RFC compliance. Much better than a regex.

RESERVED RANGES BLOCKED (RFC 1918 / RFC 5735):
- 10.0.0.0/8       — Private network
- 172.16.0.0/12    — Private network
- 192.168.0.0/16   — Private network
- 127.0.0.0/8      — Loopback
- 169.254.0.0/16   — Link-local
- 0.0.0.0/8        — "This" network
- 224.0.0.0/4      — Multicast
- 240.0.0.0/4      — Reserved
=============================================================================
"""

import ipaddress



class ValidationError(Exception):
    """
    Custom exception for invalid IP inputs.
    Using a custom exception (not ValueError) makes error handling
    more precise in the calling code — you can catch exactly this.
    """
    pass


class IPValidator:
    """
    Validates that an IP address string is:
    1. Syntactically valid (parseable as IPv4 or IPv6).
    2. Not a private, loopback, link-local, or reserved address.
    3. Globally routable (i.e., makes sense to check against threat feeds).
    """

    def validate(self, ip_str: str) -> str:
        """
        Validates and normalizes an IP address string.

        Args:
        - ip_str: Raw string from user input.

        Returns:
        - The normalized IP string (e.g., strips leading zeros).

        Raises:
        - ValidationError: With a clear message explaining what's wrong.
        """
        ip_str = ip_str.strip()

        if not ip_str:
            raise ValidationError("IP address cannot be empty.")

        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            raise ValidationError(
                f"'{ip_str}' is not a valid IPv4 or IPv6 address."
            )

        # Check for non-routable addresses
        if ip_obj.is_private:
            raise ValidationError(
                f"{ip_str} is a private IP address (RFC 1918). "
                "Private IPs are not in threat databases."
            )

        if ip_obj.is_loopback:
            raise ValidationError(
                f"{ip_str} is a loopback address. Not queryable."
            )

        if ip_obj.is_link_local:
            raise ValidationError(
                f"{ip_str} is a link-local address. Not queryable."
            )

        if ip_obj.is_reserved:
            raise ValidationError(
                f"{ip_str} is a reserved address. Not queryable."
            )

        if ip_obj.is_multicast:
            raise ValidationError(
                f"{ip_str} is a multicast address. Not queryable."
            )

        # Return the normalized string representation
        return str(ip_obj)
