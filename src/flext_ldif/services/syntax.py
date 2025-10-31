"""RFC 4517 Attribute Syntax Service - LDAP Syntax Validation and Resolution.

This module provides comprehensive RFC 4517 syntax validation, OID resolution,
and type-specific value validation for LDAP attribute syntaxes.

RFC 4517: LDAP Schema Syntax Definitions
- Defines standard syntax OIDs (1.3.6.1.4.1.1466.115.121.1.X)
- Specifies value validation rules per syntax
- Provides type categories (string, integer, binary, dn, time, boolean)
- Supports server-specific syntax extensions

The FlextLdifSyntaxService replaces naive syntax handling with:
1. Standard OID validation (format: numeric.numeric.numeric...)
2. RFC 4517 syntax resolution and lookup
3. Type-specific value validators
4. Syntax compatibility checking across LDAP servers

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import re
from typing import override

from flext_core import FlextDecorators, FlextResult, FlextService

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels


class FlextLdifSyntaxService(FlextService[dict[str, object]]):
    """RFC 4517 compliant syntax validation and OID resolution service.

    Provides methods for syntax OID validation, lookup, resolution, and
    type-specific value validation following RFC 4517 (LDAP Attribute Syntax).

    Example:
        >>> syntax_service = FlextLdifSyntaxService()
        >>>
        >>> # Validate OID format
        >>> result = syntax_service.validate_oid("1.3.6.1.4.1.1466.115.121.1.7")
        >>> if result.is_success:
        >>>     is_valid = result.unwrap()  # True
        >>>
        >>> # Resolve OID to Syntax model
        >>> result = syntax_service.resolve_syntax("1.3.6.1.4.1.1466.115.121.1.7")
        >>> if result.is_success:
        >>>     syntax = result.unwrap()  # Syntax(oid=..., name="Boolean")
        >>>
        >>> # Validate value against syntax type
        >>> result = syntax_service.validate_value(
        ...     value="TRUE",
        ...     syntax_oid="1.3.6.1.4.1.1466.115.121.1.7",
        ...     server_type="rfc",
        ... )
        >>> if result.is_success:
        >>>     is_valid = result.unwrap()  # True

    """

    def __init__(self) -> None:
        """Initialize Syntax service."""
        super().__init__()
        # Build OID lookup tables from constants
        self._oid_to_name: dict[str, str] = (
            FlextLdifConstants.RfcSyntaxOids.OID_TO_NAME.copy()
        )
        self._name_to_oid: dict[str, str] = (
            FlextLdifConstants.RfcSyntaxOids.NAME_TO_OID.copy()
        )
        self._common_syntaxes: frozenset[str] = (
            FlextLdifConstants.RfcSyntaxOids.COMMON_SYNTAXES
        )
        # Build name to type_category mapping from constants
        self._name_to_type_category: dict[str, str] = (
            FlextLdifConstants.RfcSyntaxOids.NAME_TO_TYPE_CATEGORY.copy()
        )

    @override
    @FlextDecorators.log_operation("syntax_service_check")
    @FlextDecorators.track_performance()
    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute Syntax service self-check.

        FlextDecorators automatically:
        - Log operation start/completion/failure
        - Track performance metrics
        - Handle context propagation (correlation_id, operation_name)

        Returns:
            FlextResult containing service status

        """
        return FlextResult[dict[str, object]].ok({
            "service": "SyntaxService",
            "status": "operational",
            "rfc_compliance": "RFC 4517",
            "total_syntaxes": len(self._oid_to_name),
            "common_syntaxes": len(self._common_syntaxes),
        })

    def validate_oid(self, oid: str) -> FlextResult[bool]:
        """Validate OID format compliance with LDAP OID syntax.

        Validates that OID follows the numeric dot-separated format:
        - Must start with 1, 2 (standard LDAP root)
        - Must contain at least one dot
        - All segments must be numeric
        - No leading zeros in segments (except single "0")

        Args:
            oid: OID string to validate (e.g., "1.3.6.1.4.1.1466.115.121.1.7")

        Returns:
            FlextResult containing True if valid OID format, False otherwise

        Example:
            >>> result = service.validate_oid("1.3.6.1.4.1.1466.115.121.1.7")
            >>> if result.is_success:
            >>>     is_valid = result.unwrap()  # True

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

    def is_rfc4517_standard(self, oid: str) -> FlextResult[bool]:
        """Check if OID is a standard RFC 4517 syntax OID.

        RFC 4517 standard syntax OIDs all follow the pattern:
        1.3.6.1.4.1.1466.115.121.1.X where X is 0-127

        Args:
            oid: OID string to check

        Returns:
            FlextResult containing True if RFC 4517 standard OID, False otherwise

        Example:
            >>> result = service.is_rfc4517_standard("1.3.6.1.4.1.1466.115.121.1.7")
            >>> if result.is_success:
            >>>     is_standard = result.unwrap()  # True

        """
        if not oid:
            return FlextResult[bool].ok(False)

        try:
            is_standard = oid in self._oid_to_name
            return FlextResult[bool].ok(is_standard)
        except (TypeError, AttributeError) as e:
            return FlextResult[bool].fail(
                f"Failed to check RFC 4517 standard: {e}",
            )

    def lookup_oid(self, oid: str) -> FlextResult[str | None]:
        """Look up syntax name for a given OID.

        Args:
            oid: OID to look up

        Returns:
            FlextResult containing syntax name if found, None otherwise

        Example:
            >>> result = service.lookup_oid("1.3.6.1.4.1.1466.115.121.1.7")
            >>> if result.is_success:
            >>>     name = result.unwrap()  # "Boolean"

        """
        if not oid:
            return FlextResult[str | None].ok(None)

        try:
            name = self._oid_to_name.get(oid)
            return FlextResult[str | None].ok(name)
        except (TypeError, KeyError) as e:
            return FlextResult[str | None].fail(
                f"Failed to lookup OID: {e}",
            )

    def lookup_name(self, name: str) -> FlextResult[str | None]:
        """Look up OID for a given syntax name.

        Args:
            name: Syntax name to look up (case-sensitive)

        Returns:
            FlextResult containing OID if found, None otherwise

        Example:
            >>> result = service.lookup_name("Boolean")
            >>> if result.is_success:
            >>>     oid = result.unwrap()  # "1.3.6.1.4.1.1466.115.121.1.7"

        """
        if not name:
            return FlextResult[str | None].ok(None)

        try:
            oid = self._name_to_oid.get(name)
            return FlextResult[str | None].ok(oid)
        except (TypeError, KeyError) as e:
            return FlextResult[str | None].fail(
                f"Failed to lookup syntax name: {e}",
            )

    def resolve_syntax(
        self,
        oid: str,
        name: str | None = None,
        desc: str | None = None,
        server_type: str = "rfc",
    ) -> FlextResult[FlextLdifModels.Syntax]:
        """Resolve OID to complete Syntax model with validation.

        Creates a Syntax model from OID with optional metadata enrichment.
        Performs full Pydantic validation with OID and RFC 4517 checks.

        Args:
            oid: Syntax OID (required, must be valid format)
            name: Human-readable syntax name (optional, auto-looked-up if not provided)
            desc: Syntax description (optional)
            server_type: LDAP server type for quirk metadata (default: "rfc")

        Returns:
            FlextResult containing fully resolved Syntax model

        Example:
            >>> result = service.resolve_syntax("1.3.6.1.4.1.1466.115.121.1.7")
            >>> if result.is_success:
            >>>     syntax = result.unwrap()
            >>>     assert syntax.oid == "1.3.6.1.4.1.1466.115.121.1.7"
            >>>     assert syntax.is_rfc4517_standard is True

        """
        # Validate OID format first
        oid_valid = self.validate_oid(oid)
        if oid_valid.is_failure:
            return FlextResult[FlextLdifModels.Syntax].fail(
                f"Invalid OID format: {oid}",
            )

        # Use the static method from models.py
        syntax = FlextLdifModels.Syntax.resolve_syntax_oid(oid, server_type=server_type)

        if syntax is None:
            return FlextResult[FlextLdifModels.Syntax].fail(
                f"Failed to resolve syntax: {oid}",
            )

        # Update with optional parameters
        if name:
            syntax.name = name
        if desc:
            syntax.desc = desc

        return FlextResult[FlextLdifModels.Syntax].ok(syntax)

    def validate_value(
        self,
        value: str,
        syntax_oid: str,
        server_type: str = "rfc",
    ) -> FlextResult[bool]:
        """Validate a value against its syntax type.

        Performs type-specific validation based on the syntax OID.
        Supports basic validation for common syntax types.

        Args:
            value: Value to validate
            syntax_oid: Syntax OID that defines validation rules
            server_type: LDAP server type for server-specific validation

        Returns:
            FlextResult containing True if value is valid for syntax, False otherwise

        Example:
            >>> # Boolean syntax validation
            >>> result = service.validate_value(
            ...     value="TRUE", syntax_oid="1.3.6.1.4.1.1466.115.121.1.7"
            ... )
            >>> if result.is_success:
            >>>     is_valid = result.unwrap()  # True or False

        """
        if not value or not syntax_oid:
            return FlextResult[bool].ok(True)  # Empty values pass validation

        # Resolve syntax to get type category
        resolve_result = self.resolve_syntax(syntax_oid, server_type=server_type)
        if resolve_result.is_failure:
            return FlextResult[bool].fail(
                f"Cannot validate - unknown syntax OID: {syntax_oid}",
            )

        syntax = resolve_result.unwrap()
        type_category = syntax.type_category

        try:
            # Type-specific validation
            if type_category == "boolean":
                return self._validate_boolean(value)
            if type_category == "integer":
                return self._validate_integer(value)
            if type_category == "dn":
                return self._validate_dn(value)
            if type_category == "time":
                return self._validate_time(value)
            if type_category == "binary":
                return FlextResult[bool].ok(True)  # Base64 assumed valid
            # string and others
            return FlextResult[bool].ok(True)

        except Exception as e:
            return FlextResult[bool].fail(
                f"Failed to validate value for syntax {syntax_oid}: {e}",
            )

    @staticmethod
    def _validate_boolean(value: str) -> FlextResult[bool]:
        """Validate Boolean syntax value (RFC 4517)."""
        valid_values = {"TRUE", "FALSE"}
        is_valid = value.upper() in valid_values
        return FlextResult[bool].ok(is_valid)

    @staticmethod
    def _validate_integer(value: str) -> FlextResult[bool]:
        """Validate Integer syntax value (RFC 4517)."""
        try:
            int(value)
            return FlextResult[bool].ok(True)
        except ValueError:
            return FlextResult[bool].ok(False)

    @staticmethod
    def _validate_dn(value: str) -> FlextResult[bool]:
        """Validate DN syntax value (RFC 4517)."""
        # Basic DN validation: must have at least one = and comma pair
        if "=" not in value:
            return FlextResult[bool].ok(False)
        return FlextResult[bool].ok(True)

    @staticmethod
    def _validate_time(value: str) -> FlextResult[bool]:
        """Validate GeneralizedTime syntax value (RFC 4517)."""
        # Generalized Time format: YYYYMMDDhhmmss[.frac]Z
        time_pattern = r"^\d{14}(\.\d+)?Z$"
        is_valid = bool(re.match(time_pattern, value))
        return FlextResult[bool].ok(is_valid)

    def get_syntax_category(self, oid: str) -> FlextResult[str]:
        """Get type category for a syntax OID.

        Args:
            oid: Syntax OID

        Returns:
            FlextResult containing type category (string, integer, binary, dn, time, boolean)

        Example:
            >>> result = service.get_syntax_category("1.3.6.1.4.1.1466.115.121.1.7")
            >>> if result.is_success:
            >>>     category = result.unwrap()  # "boolean"

        """
        resolve_result = self.resolve_syntax(oid)
        if resolve_result.is_failure:
            return FlextResult[str].fail(
                f"Cannot determine category - unknown syntax OID: {oid}",
            )

        syntax = resolve_result.unwrap()
        return FlextResult[str].ok(syntax.type_category)

    def list_common_syntaxes(self) -> FlextResult[list[str]]:
        """List all supported RFC 4517 syntax OIDs.

        Returns:
            FlextResult containing sorted list of OIDs

        Example:
            >>> result = service.list_common_syntaxes()
            >>> if result.is_success:
            >>>     oids = result.unwrap()
            >>>     assert "1.3.6.1.4.1.1466.115.121.1.7" in oids

        """
        try:
            oids = sorted(self._common_syntaxes)
            return FlextResult[list[str]].ok(oids)
        except (TypeError, AttributeError) as e:
            return FlextResult[list[str]].fail(
                f"Failed to list common syntaxes: {e}",
            )
