"""Extracted nested class from FlextLdifUtilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import logging
import re

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
        if schema_obj.metadata and schema_obj.metadata.original_format:
            try:
                # Look for OID in parentheses at start: ( 2.16.840.1.113894. ...
                match = re.search(r"\(\s*([\d.]+)", schema_obj.metadata.original_format)
                if match:
                    return match.group(1)
            except (re.error, AttributeError):
                # Regex error or original_format type issue - continue to fallback
                logger.debug(
                    "Failed to extract OID from original_format: %s",
                    schema_obj.metadata.original_format[:100]
                    if schema_obj.metadata.original_format
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


__all__ = [
    "FlextLdifUtilitiesOID",
]
