"""Extracted nested class from FlextLdifUtilities."""

from __future__ import annotations

import re

from flext_core import FlextLogger, FlextUtilities, r

from flext_ldif._models.domain import FlextLdifModelsDomains

u = FlextUtilities
logger = FlextLogger(__name__)


class FlextLdifUtilitiesOID:
    """OID extraction and validation utilities."""

    @staticmethod
    def extract_from_definition(definition: str) -> r[str]:
        """Extract OID from schema definition string."""
        try:
            match = re.search(r"\(\s*([\d.]+)", definition)
            if match:
                return r[str].ok(match.group(1))
            return r[str].fail(f"missing an OID in definition: {definition!r}")
        except (re.error, AttributeError) as e:
            logger.debug("Failed to extract OID from definition", error=str(e))
            return r[str].fail(f"OID extraction failed: {e}")

    @staticmethod
    def extract_from_schema_object(
        schema_obj: FlextLdifModelsDomains.SchemaAttribute
        | FlextLdifModelsDomains.SchemaObjectClass,
    ) -> str | None:
        """Extract OID from schema object metadata or model."""
        if schema_obj.metadata and schema_obj.metadata.extensions:
            original_format = schema_obj.metadata.extensions.original_format
            if not isinstance(original_format, str):
                return schema_obj.oid
            original_format_value = original_format
            try:
                match = re.search(r"\(\s*([\d.]+)", original_format_value)
                if match:
                    return match.group(1)
            except (re.error, AttributeError):
                debug_msg = original_format_value[:100]
                original_format_preview = original_format_value[:200]
                preview_for_log: str = original_format_preview
                logger.debug(
                    "Failed to extract OID from original_format: debug_message=%s, original_format_preview=%s",
                    debug_msg,
                    preview_for_log,
                )
        return schema_obj.oid

    @staticmethod
    def get_server_type_from_oid(definition_or_oid: str) -> r[str]:
        """Detect server type from OID pattern."""
        early_checks = [
            (FlextLdifUtilitiesOID.is_oracle_oid, "oid"),
            (FlextLdifUtilitiesOID.is_microsoft_ad_oid, "ad"),
            (FlextLdifUtilitiesOID.is_openldap_oid, "openldap"),
        ]
        for check_func, server_type in early_checks:
            if check_func(definition_or_oid):
                return r[str].ok(server_type)
        if not definition_or_oid:
            return r[str].fail("Empty definition or OID")
        oid = definition_or_oid
        if definition_or_oid.startswith("("):
            extracted_result = FlextLdifUtilitiesOID.extract_from_definition(
                definition_or_oid,
            )
            if extracted_result.is_failure:
                return r[str].fail(f"Cannot extract OID: {extracted_result.error}")
            oid = extracted_result.value
        pattern_checks = [
            (FlextLdifUtilitiesOID.REDHAT_389DS_PATTERN, "ds389"),
            (FlextLdifUtilitiesOID.NOVELL_PATTERN, "novell"),
            (FlextLdifUtilitiesOID.IBM_TIVOLI_PATTERN, "tivoli"),
        ]
        for pattern, server_type in pattern_checks:
            if pattern.match(oid):
                return r[str].ok(server_type)
        return r[str].fail(f"Unknown server type for OID: {oid!r}")

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
    def is_oracle_oid(definition_or_oid: str) -> bool:
        """Check if definition/OID matches Oracle Internet Directory pattern."""
        if not definition_or_oid:
            return False
        if definition_or_oid.startswith("("):
            return FlextLdifUtilitiesOID.matches_pattern(
                definition_or_oid,
                FlextLdifUtilitiesOID.ORACLE_OID_PATTERN,
            )
        return bool(FlextLdifUtilitiesOID.ORACLE_OID_PATTERN.match(definition_or_oid))

    @staticmethod
    def matches_pattern(definition: str, oid_pattern: re.Pattern[str]) -> bool:
        r"""Check if schema definition string matches server's OID pattern.

        Generic method for checking if a schema definition matches an OID pattern.
        Works with raw definition strings BEFORE parsing.

        This is a pure utility function with no dependencies on quirks or services.

        Example:
            # Check if attribute matches Oracle OID pattern
            if FlextLdifUtilitiesOID.matches_pattern(
                attr_definition,  # Raw string: "( 2.16.840.1.113894.1.1.1 ...)"
                re.compile(r'2\\.16\\.840\\.1\\.113894\\..*')  # Oracle OID pattern
            ):
                # Handle Oracle-specific attribute

        Args:
            definition: Raw attribute or objectClass definition string
            oid_pattern: Compiled regex pattern to match OID (e.g., re.compile(r'2\\\\.16\\\\.840\\\\..*'))

        Returns:
            True if OID matches pattern, False otherwise

        """
        result = FlextLdifUtilitiesOID.extract_from_definition(definition)
        if result.is_failure:
            return False
        return bool(oid_pattern.match(result.value))

    @staticmethod
    def parse_to_tuple(oid: str) -> r[tuple[int, ...]]:
        """Parse OID string to tuple of integers for numeric sorting."""
        try:
            return r[tuple[int, ...]].ok(tuple(int(x) for x in oid.split(".")))
        except ValueError as e:
            return r[tuple[int, ...]].fail(f"Invalid OID format {oid!r}: {e}")

    @staticmethod
    def validate_format(oid: str) -> r[bool]:
        """Validate OID format compliance with LDAP OID syntax."""
        if not oid:
            return r[bool].ok(False)
        oid_pattern = "^[0-2](\\.[0-9]+)*$"
        try:
            is_valid = bool(re.match(oid_pattern, oid))
            return r[bool].ok(is_valid)
        except (TypeError, re.error) as e:
            return r[bool].fail(f"Failed to validate OID format: {e}")

    ORACLE_OID_PATTERN: re.Pattern[str] = re.compile(r"2\\.16\\.840\\.1\\.113894\\..*")
    MICROSOFT_AD_PATTERN: re.Pattern[str] = re.compile(r"1\\.2\\.840\\.113556\\..*")
    OPENLDAP_PATTERN: re.Pattern[str] = re.compile(r"1\\.3\\.6\\.1\\.4\\.1\\.4203\\..*")
    REDHAT_389DS_PATTERN: re.Pattern[str] = re.compile(
        r"2\\.16\\.840\\.1\\.113730\\..*",
    )
    NOVELL_PATTERN: re.Pattern[str] = re.compile(r"2\\.16\\.840\\.1\\.113719\\..*")
    IBM_TIVOLI_PATTERN: re.Pattern[str] = re.compile(r"1\\.3\\.18\\.0\\.2\\..*")


__all__ = ["FlextLdifUtilitiesOID"]
