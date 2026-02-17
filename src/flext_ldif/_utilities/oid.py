"""Extracted nested class from FlextLdifUtilities."""

from __future__ import annotations

import re

from flext_core import FlextLogger, FlextResult, FlextUtilities

from flext_ldif._models.domain import FlextLdifModelsDomains

# REMOVED: Type aliases redundantes - use m.* diretamente (já importado com runtime alias)
# SchemaAttribute: TypeAlias = FlextLdifModelsDomains.SchemaAttribute  # Use m.Ldif.SchemaAttribute directly
# SchemaObjectClass: TypeAlias = FlextLdifModelsDomains.SchemaObjectClass  # Use m.Ldif.SchemaObjectClass directly

# Aliases for simplified usage - after all imports
# Use flext-core utilities directly (FlextLdifUtilities extends FlextUtilities)
u = FlextUtilities  # Use base class to avoid circular dependency
r = FlextResult  # Shared from flext-core

logger = FlextLogger(__name__)


class FlextLdifUtilitiesOID:
    """OID extraction and validation utilities."""

    @staticmethod
    def extract_from_definition(definition: str) -> str | None:
        """Extract OID from schema definition string."""
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
        schema_obj: FlextLdifModelsDomains.SchemaAttribute
        | FlextLdifModelsDomains.SchemaObjectClass,
    ) -> str | None:
        """Extract OID from schema object metadata or model."""
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
        """Validate OID format compliance with LDAP OID syntax."""
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
        """Check if definition/OID matches Oracle Internet Directory pattern."""
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
        """Check if definition/OID matches Microsoft Active Directory pattern."""
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
        """Check if definition/OID matches OpenLDAP pattern."""
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
        """Detect server type from OID pattern."""
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
        """Parse OID string to tuple of integers for numeric sorting."""
        try:
            return tuple(int(x) for x in oid.split("."))
        except ValueError:
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
