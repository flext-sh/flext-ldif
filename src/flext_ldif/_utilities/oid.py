"""Extracted nested class from FlextLdifUtilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import logging
import re

from flext_core import FlextResult

from flext_ldif.models import FlextLdifModels

logger = logging.getLogger(__name__)


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
                "Failed to extract OID from definition: %s",
                e,
            )
        return None

    @staticmethod
    def extract_from_schema_object(
        schema_obj: FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass,
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
            "original_format"
        ):
            try:
                # Look for OID in parentheses at start: ( 2.16.840.1.113894. ...
                match = re.search(
                    r"\(\s*([\d.]+)",
                    schema_obj.metadata.extensions.get("original_format"),
                )
                if match:
                    return match.group(1)
            except (re.error, AttributeError):
                # Regex error or original_format type issue - continue to fallback
                logger.debug(
                    "Failed to extract OID from original_format: %s",
                    schema_obj.metadata.extensions.get("original_format")[:100]
                    if schema_obj.metadata.extensions.get("original_format")
                    else "None",
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
        if FlextLdifUtilitiesOID.is_oracle_oid(definition_or_oid):
            return "oid"
        if FlextLdifUtilitiesOID.is_microsoft_ad_oid(definition_or_oid):
            return "ad"
        if FlextLdifUtilitiesOID.is_openldap_oid(definition_or_oid):
            return "openldap"

        # Check other patterns
        if not definition_or_oid:
            return None

        oid = definition_or_oid
        if definition_or_oid.startswith("("):
            extracted = FlextLdifUtilitiesOID.extract_from_definition(definition_or_oid)
            if not extracted:
                return None
            oid = extracted

        if FlextLdifUtilitiesOID.REDHAT_389DS_PATTERN.match(oid):
            return "ds389"
        if FlextLdifUtilitiesOID.NOVELL_PATTERN.match(oid):
            return "novell"
        if FlextLdifUtilitiesOID.IBM_TIVOLI_PATTERN.match(oid):
            return "tivoli"

        return None

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
