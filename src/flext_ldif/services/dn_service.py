r"""DN Service - RFC 4514 Compliant Distinguished Name Operations.

This service provides DN operations using ldap3 for RFC 4514 compliance.
Replaces naive DN parsing from utilities.py with proper LDAP DN handling.

RFC 4514: LDAP Distinguished Names String Representation
- Handles escaped characters (\\, \\2C, etc.)
- Handles quoted values ("Smith, John")
- Handles multi-valued RDNs (cn=user+ou=people)
- Handles special characters (+, =, <, >, #, ;)
- Handles UTF-8 encoding

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

from flext_core import FlextCore
from ldap3.utils.dn import parse_dn, safe_dn


class DnService(FlextCore.Service[FlextCore.Types.Dict]):
    r"""RFC 4514 compliant DN operations using ldap3.

    Provides methods for DN parsing, validation, and normalization
    following RFC 4514 (LDAP Distinguished Names String Representation).

    This service replaces the naive DN parsing from utilities.py which
    violated RFC 4514 by using simple string split operations.

    Example:
        >>> dn_service = DnService()
        >>>
        >>> # Parse DN into components
        >>> result = dn_service.parse_components("cn=Smith\\, John,ou=People,dc=example,dc=com")
        >>> if result.is_success:
        >>>     components = result.unwrap()
        >>>     # Returns: [("cn", "Smith, John", "cn=Smith\\, John"), ...]
        >>>
        >>> # Validate DN format
        >>> result = dn_service.validate_format("cn=test,dc=example,dc=com")
        >>> if result.is_success:
        >>>     is_valid = result.unwrap()  # True
        >>>
        >>> # Normalize DN
        >>> result = dn_service.normalize("CN=Admin,DC=Example,DC=Com")
        >>> if result.is_success:
        >>>     normalized = result.unwrap()  # "cn=Admin,dc=Example,dc=Com"

    """

    def __init__(self) -> None:
        """Initialize DN service."""
        super().__init__()

    @override
    def execute(self) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Execute DN service self-check.

        Returns:
            FlextCore.Result containing service status

        """
        return FlextCore.Result[FlextCore.Types.Dict].ok({
            "service": "DnService",
            "status": "operational",
            "rfc_compliance": "RFC 4514",
            "library": "ldap3",
        })

    def parse_components(
        self, dn: str
    ) -> FlextCore.Result[list[tuple[str, str, str]]]:
        r"""Parse DN into RFC 4514 compliant components using ldap3.

        Uses ldap3.utils.dn.parse_dn() for proper RFC 4514 parsing that handles:
        - Escaped commas: cn=Smith\\, John
        - Quoted values: cn="Smith, John"
        - Multi-valued RDNs: cn=user+ou=people
        - Special characters: +, =, <, >, #, ;
        - UTF-8 encoding
        - Hex escaping: cn=\\23value

        Args:
            dn: Distinguished name string to parse

        Returns:
            FlextCore.Result containing list of (attr, value, rdn) tuples
            where:
            - attr: Attribute name (e.g., "cn")
            - value: Attribute value (e.g., "John Smith")
            - rdn: Full RDN component (e.g., "cn=John Smith")

        Example:
            >>> result = service.parse_components("cn=test,dc=example,dc=com")
            >>> if result.is_success:
            >>>     components = result.unwrap()
            >>>     # [("cn", "test", "cn=test"), ("dc", "example", "dc=example"), ...]

        """
        try:
            # Use ldap3 for RFC 4514 compliant parsing
            components = parse_dn(dn, escape=False, strip=True)
            return FlextCore.Result[list[tuple[str, str, str]]].ok(components)
        except Exception as e:
            return FlextCore.Result[list[tuple[str, str, str]]].fail(
                f"Invalid DN format (RFC 4514): {e}"
            )

    def validate_format(self, dn: str) -> FlextCore.Result[bool]:
        """Validate DN format against RFC 4514 using ldap3.

        Uses ldap3.utils.dn.parse_dn() to validate DN syntax.
        A valid DN must parse successfully according to RFC 4514.

        Args:
            dn: Distinguished name string to validate

        Returns:
            FlextCore.Result containing True if valid, False otherwise

        Example:
            >>> result = service.validate_format("cn=test,dc=example,dc=com")
            >>> if result.is_success:
            >>>     is_valid = result.unwrap()  # True
            >>>
            >>> result = service.validate_format("invalid dn")
            >>> if result.is_success:
            >>>     is_valid = result.unwrap()  # False

        """
        if not dn or not isinstance(dn, str):
            return FlextCore.Result[bool].ok(False)

        try:
            # Try parsing - if it succeeds, DN is valid per RFC 4514
            parse_dn(dn, escape=False, strip=True)
            return FlextCore.Result[bool].ok(True)
        except Exception:
            return FlextCore.Result[bool].ok(False)

    def normalize(self, dn: str) -> FlextCore.Result[str]:
        """Normalize DN using RFC 4514 compliant normalization via ldap3.

        Uses ldap3.utils.dn.safe_dn() for proper RFC 4514 normalization:
        - Lowercases attribute names
        - Preserves case in attribute values
        - Handles escaped characters
        - Handles quoted values
        - Handles special characters
        - Handles UTF-8 encoding

        Args:
            dn: Distinguished name string to normalize

        Returns:
            FlextCore.Result containing normalized DN string

        Example:
            >>> result = service.normalize("CN=Admin,DC=Example,DC=Com")
            >>> if result.is_success:
            >>>     normalized = result.unwrap()
            >>>     # Returns: "cn=Admin,dc=Example,dc=Com"
            >>>     # Note: Attribute names lowercased, values preserved

        """
        try:
            # Use ldap3 for RFC 4514 compliant normalization
            normalized = safe_dn(dn)
            return FlextCore.Result[str].ok(normalized)
        except Exception as e:
            return FlextCore.Result[str].fail(
                f"Failed to normalize DN (RFC 4514): {e}"
            )


__all__ = ["DnService"]
