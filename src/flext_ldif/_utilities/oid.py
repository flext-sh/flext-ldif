"""Extracted nested class from FlextLdifUtilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import operator
import re

# Use flext-core utilities directly to avoid circular dependency
from flext_core import FlextLogger, FlextResult, FlextUtilities

from flext_ldif.models import m

# Aliases for simplified usage - after all imports
# Use flext-core utilities directly (FlextLdifUtilities extends FlextUtilities)
u = FlextUtilities  # Use base class to avoid circular dependency
r = FlextResult  # Shared from flext-core

logger = FlextLogger(__name__)


class FlextLdifUtilitiesOID:
    """OID extraction and validation utilities.

    Pure functions for extracting and validating OIDs from schema definitions.
    Independent of quirks and services - only string/regex operations.

    Methods:
    - extract_from_definition: Extract OID from raw schema definition string
    - extract_from_schema_object: Extract OID from schema model (metadata or field)
    - matches_pattern: Check if OID matches a regex pattern

    """

    @staticmethod
    def extract_from_definition(definition: str) -> str | None:
        """Extract OID from schema definition string.

        Extracts OID from raw attribute or objectClass definition string.
        Looks for OID in parentheses at start: ( 2.5.4.3 ...

        This is a pure utility function with no dependencies on quirks or services.

        Args:
            definition: Raw attribute or objectClass definition string
                       (e.g., "( 2.5.4.3 NAME 'cn' DESC 'Common Name' ...)")

        Returns:
            OID string (e.g., "2.5.4.3") or None if not found

        Example:
            oid = FlextLdifUtilitiesOID.extract_from_definition(
                "( 2.16.840.1.113894.1.1.1 NAME 'orclGuid' ...)"
            )
            # Returns: "2.16.840.1.113894.1.1.1"

        """
        try:
            # Look for OID in parentheses at start: ( 2.16.840.1.113894. ...
            match = re.search(r"\(\s*([\d.]+)", definition)
            if match:
                return match.group(1)
        except (re.error, AttributeError) as e:
            logger.debug(
                "Failed to extract OID from definition",
                error=str(e),
            )
        return None

    @staticmethod
    def extract_from_schema_object(
        schema_obj: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
    ) -> str | None:
        """Extract OID from schema object metadata or model.

        Checks both sources:
        1. Original format in metadata (via regex extraction)
        2. OID field in model (fallback)

        This is a pure utility function with no dependencies on quirks or services.

        Args:
            schema_obj: Attribute or ObjectClass model (already parsed)

        Returns:
            OID string (e.g., "2.5.4.3") or None if not found

        """
        # First try: Extract from original_format if available
        if schema_obj.metadata and schema_obj.metadata.extensions.get(
            "original_format",
        ):
            try:
                # Look for OID in parentheses at start: ( 2.16.840.1.113894. ...
                original_format = schema_obj.metadata.extensions.get("original_format")
                if isinstance(original_format, str):
                    match = re.search(
                        r"\(\s*([\d.]+)",
                        original_format,
                    )
                else:
                    match = None
                if match:
                    return match.group(1)
            except (re.error, AttributeError):
                # Regex error or original_format type issue - continue to fallback
                original_fmt = schema_obj.metadata.extensions.get("original_format")
                debug_msg = (
                    str(original_fmt)[:100]
                    if original_fmt and isinstance(original_fmt, str)
                    else "None"
                )
                original_format_preview = (
                    str(original_fmt)[:200]
                    if original_fmt and isinstance(original_fmt, str)
                    else None
                )
                logger.debug(
                    "Failed to extract OID from original_format: debug_message=%s, original_format_preview=%s",
                    debug_msg,
                    original_format_preview,
                )

        # Fallback: Use OID field from model
        return schema_obj.oid

    @staticmethod
    def matches_pattern(
        definition: str,
        oid_pattern: re.Pattern[str],
    ) -> bool:
        r"""Check if schema definition string matches server's OID pattern.

        Generic method for checking if a schema definition matches an OID pattern.
        Works with raw definition strings BEFORE parsing.

        This is a pure utility function with no dependencies on quirks or services.

        Example:
            # Check if attribute matches Oracle OID pattern
            if FlextLdifUtilitiesOID.matches_pattern(
                attr_definition,  # Raw string: "( 2.16.840.1.113894.1.1.1 ...)"
                re.compile(r'2\.16\.840\.1\.113894\..*')  # Oracle OID pattern
            ):
                # Handle Oracle-specific attribute

        Args:
            definition: Raw attribute or objectClass definition string
            oid_pattern: Compiled regex pattern to match OID (e.g., re.compile(r'2\\.16\\.840\\..*'))

        Returns:
            True if OID matches pattern, False otherwise

        """
        # Extract OID from definition string
        oid = FlextLdifUtilitiesOID.extract_from_definition(definition)
        if not oid:
            return False

        # Check if OID matches server's pattern
        return bool(oid_pattern.match(oid))

    @staticmethod
    def validate_format(oid: str) -> FlextResult[bool]:
        """Validate OID format compliance with LDAP OID syntax.

        Validates that OID follows the numeric dot-separated format:
        - Must start with 0, 1, or 2 (standard LDAP root)
        - Must contain at least one dot
        - All segments must be numeric
        - No leading zeros in segments (except single "0")

        Args:
            oid: OID string to validate (e.g., "1.3.6.1.4.1.1466.115.121.1.7")

        Returns:
            FlextResult containing True if valid OID format, False otherwise

        Example:
            >>> result = FlextLdifUtilitiesOID.validate_format(
            ...     "1.3.6.1.4.1.1466.115.121.1.7"
            ... )
            >>> if result.is_success:
            >>>     is_valid = result.unwrap()  # True

        Note:
            This is the canonical OID validation for all _utilities modules.
            Replaces duplicated local validation functions.

        """
        if not oid:
            return FlextResult[bool].ok(False)

        # OID pattern: numeric.numeric.numeric... (no leading zeros)
        oid_pattern = r"^[0-2](\.[0-9]+)*$"

        try:
            is_valid = bool(re.match(oid_pattern, oid))
            return FlextResult[bool].ok(is_valid)
        except (TypeError, re.error) as e:
            return FlextResult[bool].fail(
                f"Failed to validate OID format: {e}",
            )

    @staticmethod
    def is_oracle_oid(definition_or_oid: str) -> bool:
        """Check if definition/OID matches Oracle Internet Directory pattern.

        Convenience method that checks for Oracle OID pattern (2.16.840.1.113894.*).
        Works with both raw definitions and extracted OIDs.

        Args:
            definition_or_oid: Either raw schema definition or extracted OID string

        Returns:
            True if matches Oracle pattern, False otherwise

        Example:
            >>> FlextLdifUtilitiesOID.is_oracle_oid("( 2.16.840.1.113894.1.1.1 ...)")
            True
            >>> FlextLdifUtilitiesOID.is_oracle_oid("2.16.840.1.113894.1.1.1")
            True

        """
        if not definition_or_oid:
            return False

        # Try as raw definition first
        if definition_or_oid.startswith("("):
            return FlextLdifUtilitiesOID.matches_pattern(
                definition_or_oid,
                FlextLdifUtilitiesOID.ORACLE_OID_PATTERN,
            )

        # Try as extracted OID
        return bool(FlextLdifUtilitiesOID.ORACLE_OID_PATTERN.match(definition_or_oid))

    @staticmethod
    def is_microsoft_ad_oid(definition_or_oid: str) -> bool:
        """Check if definition/OID matches Microsoft Active Directory pattern.

        Convenience method that checks for AD OID pattern (1.2.840.113556.*).
        Works with both raw definitions and extracted OIDs.

        Args:
            definition_or_oid: Either raw schema definition or extracted OID string

        Returns:
            True if matches AD pattern, False otherwise

        """
        if not definition_or_oid:
            return False

        if definition_or_oid.startswith("("):
            return FlextLdifUtilitiesOID.matches_pattern(
                definition_or_oid,
                FlextLdifUtilitiesOID.MICROSOFT_AD_PATTERN,
            )

        return bool(FlextLdifUtilitiesOID.MICROSOFT_AD_PATTERN.match(definition_or_oid))

    @staticmethod
    def is_openldap_oid(definition_or_oid: str) -> bool:
        """Check if definition/OID matches OpenLDAP pattern.

        Convenience method that checks for OpenLDAP OID pattern (1.3.6.1.4.1.4203.*).
        Works with both raw definitions and extracted OIDs.

        Args:
            definition_or_oid: Either raw schema definition or extracted OID string

        Returns:
            True if matches OpenLDAP pattern, False otherwise

        """
        if not definition_or_oid:
            return False

        if definition_or_oid.startswith("("):
            return FlextLdifUtilitiesOID.matches_pattern(
                definition_or_oid,
                FlextLdifUtilitiesOID.OPENLDAP_PATTERN,
            )

        return bool(FlextLdifUtilitiesOID.OPENLDAP_PATTERN.match(definition_or_oid))

    @staticmethod
    def get_server_type_from_oid(definition_or_oid: str) -> str | None:
        """Detect server type from OID pattern.

        Analyzes OID and returns the likely server type based on OID prefix.
        Useful for auto-detection logic.

        Args:
            definition_or_oid: Either raw schema definition or extracted OID string

        Returns:
            Server type string ("oid", "ad", "openldap", etc.) or None if unknown

        Example:
            >>> FlextLdifUtilitiesOID.get_server_type_from_oid(
            ...     "2.16.840.1.113894.1.1.1"
            ... )
            'oid'
            >>> FlextLdifUtilitiesOID.get_server_type_from_oid("1.2.840.113556.1.2.1")
            'ad'

        """
        # Early checks for common patterns
        early_checks = [
            (FlextLdifUtilitiesOID.is_oracle_oid, "oid"),
            (FlextLdifUtilitiesOID.is_microsoft_ad_oid, "ad"),
            (FlextLdifUtilitiesOID.is_openldap_oid, "openldap"),
        ]

        for check_func, server_type in early_checks:
            if check_func(definition_or_oid):
                return server_type

        # Check other patterns
        if not definition_or_oid:
            return None

        oid = definition_or_oid
        if definition_or_oid.startswith("("):
            extracted = FlextLdifUtilitiesOID.extract_from_definition(definition_or_oid)
            if not extracted:
                return None
            oid = extracted

        pattern_checks = [
            (FlextLdifUtilitiesOID.REDHAT_389DS_PATTERN, "ds389"),
            (FlextLdifUtilitiesOID.NOVELL_PATTERN, "novell"),
            (FlextLdifUtilitiesOID.IBM_TIVOLI_PATTERN, "tivoli"),
        ]

        for pattern, server_type in pattern_checks:
            if pattern.match(oid):
                return server_type

        return None

    @staticmethod
    def parse_to_tuple(oid: str) -> tuple[int, ...] | None:
        """Parse OID string to tuple of integers for numeric sorting.

        Converts dot-separated OID string to tuple of integers for comparison.
        Returns None if OID is malformed or contains non-numeric segments.

        Args:
            oid: OID string (e.g., "2.16.840.1.113894")

        Returns:
            Tuple of integers (e.g., (2, 16, 840, 1, 113894)) or None if invalid

        Example:
            >>> FlextLdifUtilitiesOID.parse_to_tuple("2.16.840.1.113894")
            (2, 16, 840, 1, 113894)
            >>> FlextLdifUtilitiesOID.parse_to_tuple("invalid.oid")
            None

        """
        try:
            return tuple(int(x) for x in oid.split("."))
        except ValueError:
            return None

    @staticmethod
    def filter_and_sort_by_oid(
        values: list[str],
        *,
        allowed_oids: set[str] | None = None,
        oid_pattern: re.Pattern[str] | None = None,
    ) -> list[tuple[tuple[int, ...], str]]:
        """Filter schema values by OID whitelist and sort numerically.

        Extracts OIDs from schema definition strings, filters by whitelist,
        and returns sorted by OID numeric value. Used for consistent schema
        ordering across server types (OID, OUD, etc.).

        Args:
            values: List of schema definition strings (RFC format)
            allowed_oids: Optional set of allowed OIDs for filtering.
                If None, all values are accepted (no filtering).
            oid_pattern: Optional compiled regex for OID extraction.
                If None, uses default pattern: ( number.number.number...

        Returns:
            List of tuples (oid_tuple, value) sorted by OID numerically.
            Empty list if no valid OIDs found.

        Example:
            >>> values = [
            ...     "( 2.16.840.1.113894.1.1.2 NAME 'attr2' ... )",
            ...     "( 2.16.840.1.113894.1.1.1 NAME 'attr1' ... )",
            ... ]
            >>> result = FlextLdifUtilitiesOID.filter_and_sort_by_oid(
            ...     values,
            ...     allowed_oids={"2.16.840.1.113894.1.1.1"},
            ... )
            >>> # Returns: [((2, 16, 840, 1, 113894, 1, 1, 1), "( 2.16.840.1.113894.1.1.1 ... )")]

        Note:
            This replaces duplicated OID filtering/sorting logic in server quirks.
            Uses Python 3.13 keyword-only args for clarity.

        """
        # Default OID pattern: ( number.number.number... NAME ...
        pattern = oid_pattern or re.compile(r"\(\s*(\d+(?:\.\d+)*)\s+")

        filtered_values: list[tuple[tuple[int, ...], str]] = []

        for value in values:
            # Extract OID from RFC format
            match = pattern.search(value)
            if not match:
                continue

            oid_str = match.group(1)

            # Filter by whitelist if provided
            if allowed_oids is not None and oid_str not in allowed_oids:
                continue

            # Parse OID for sorting
            oid_tuple = FlextLdifUtilitiesOID.parse_to_tuple(oid_str)
            if oid_tuple is None:
                continue

            filtered_values.append((oid_tuple, value))

        # Sort by OID numerically
        return sorted(filtered_values, key=operator.itemgetter(0))

    # Pre-compiled OID patterns for common LDAP servers
    # These eliminate the need for repeated re.compile() calls in server code
    ORACLE_OID_PATTERN: re.Pattern[str] = re.compile(r"2\.16\.840\.1\.113894\..*")
    MICROSOFT_AD_PATTERN: re.Pattern[str] = re.compile(r"1\.2\.840\.113556\..*")
    OPENLDAP_PATTERN: re.Pattern[str] = re.compile(r"1\.3\.6\.1\.4\.1\.4203\..*")
    REDHAT_389DS_PATTERN: re.Pattern[str] = re.compile(r"2\.16\.840\.1\.113730\..*")
    NOVELL_PATTERN: re.Pattern[str] = re.compile(r"2\.16\.840\.1\.113719\..*")
    IBM_TIVOLI_PATTERN: re.Pattern[str] = re.compile(r"1\.3\.18\.0\.2\..*")


__all__ = [
    "FlextLdifUtilitiesOID",
]
