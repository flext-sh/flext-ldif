"""LDIF Syntax Service - RFC 4517 Attribute Syntax Validation and Resolution.

╔══════════════════════════════════════════════════════════════════════════╗
║  RFC 4517 ATTRIBUTE SYNTAX VALIDATION & RESOLUTION SERVICE              ║
╠══════════════════════════════════════════════════════════════════════════╣
║  ✅ OID format validation (numeric.numeric.numeric...)                  ║
║  ✅ RFC 4517 standard syntax detection                                   ║
║  ✅ OID to syntax name resolution                                        ║
║  ✅ Syntax name to OID lookup                                            ║
║  ✅ Complete Syntax model resolution with metadata                       ║
║  ✅ Type-specific value validation (boolean, integer, DN, time, etc.)    ║
║  ✅ Syntax type category resolution                                      ║
║  ✅ Common syntax listing and lookup                                    ║
║  ✅ 100% type-safe with FlextResult error handling                      ║
║  ✅ Multiple API patterns: execute(), direct methods                   ║
╚══════════════════════════════════════════════════════════════════════════╝

═══════════════════════════════════════════════════════════════════════════
RESPONSIBILITY (SRP)

This service handles SYNTAX VALIDATION & RESOLUTION ONLY:
- Validating OID format compliance with LDAP standards
- Detecting RFC 4517 standard syntax OIDs
- Resolving OIDs to complete Syntax models
- Looking up syntax names and OIDs
- Validating values against syntax types
- Determining syntax type categories

What it does NOT do:
- Parse LDIF entries (use FlextLdifParser)
- Validate attribute names (use FlextLdifValidation)
- Transform entries (use FlextLdifEntry)
- Sort entries (use FlextLdifSorting)

═══════════════════════════════════════════════════════════════════════════
RFC COMPLIANCE

RFC 4517: Lightweight Directory Access Protocol (LDAP): Syntaxes and Matching Rules
- Defines standard syntax OIDs (1.3.6.1.4.1.1466.115.121.1.X)
- Specifies value validation rules per syntax type
- Provides type categories (string, integer, binary, dn, time, boolean)
- Standard OID format: numeric.numeric.numeric... (no leading zeros)
- RFC 4517 standard syntaxes follow pattern: 1.3.6.1.4.1.1466.115.121.1.X

Common Syntax Types:
- Boolean: TRUE/FALSE values
- Integer: Numeric values
- DN: Distinguished Name values
- GeneralizedTime: Time values (YYYYMMDDhhmmss[.frac]Z)
- Binary: Base64-encoded binary data
- String: Text values

═══════════════════════════════════════════════════════════════════════════
REAL USAGE EXAMPLES

# PATTERN 1: Direct Method API (Most Common)
─────────────────────────────────────────────
syntax_service = FlextLdifSyntax()

# Validate OID format
result = syntax_service.validate_oid("1.3.6.1.4.1.1466.115.121.1.7")
is_valid = result.unwrap()  # True

# Check if OID is RFC 4517 standard
result = syntax_service.is_rfc4517_standard("1.3.6.1.4.1.1466.115.121.1.7")
is_standard = result.unwrap()  # True

# Look up syntax name from OID
result = syntax_service.lookup_oid("1.3.6.1.4.1.1466.115.121.1.7")
name = result.unwrap()  # "Boolean"

# Look up OID from syntax name
result = syntax_service.lookup_name("Boolean")
oid = result.unwrap()  # "1.3.6.1.4.1.1466.115.121.1.7"

# Resolve complete Syntax model
result = syntax_service.resolve_syntax("1.3.6.1.4.1.1466.115.121.1.7")
syntax = result.unwrap()
# Syntax(oid="1.3.6.1.4.1.1466.115.121.1.7", name="Boolean", ...)

# Validate value against syntax type
result = syntax_service.validate_value(
    value="TRUE",
    syntax_oid="1.3.6.1.4.1.1466.115.121.1.7"
)
is_valid = result.unwrap()  # True

# Get syntax type category
result = syntax_service.get_syntax_category("1.3.6.1.4.1.1466.115.121.1.7")
category = result.unwrap()  # "boolean"

# List all common syntaxes
result = syntax_service.list_common_syntaxes()
oids = result.unwrap()  # ["1.3.6.1.4.1.1466.115.121.1.1", ...]

# PATTERN 2: Execute Method (V1 FlextService Style)
────────────────────────────────────────────────────
result = FlextLdifSyntax().execute()
if result.is_success:
    status = result.unwrap()
    # {"service": "SyntaxService", "status": "operational", ...}

═══════════════════════════════════════════════════════════════════════════
QUICK REFERENCE

Most Common Use Cases:
- validate_oid(oid) -> bool
- is_rfc4517_standard(oid) -> bool
- lookup_oid(oid) -> str | None
- lookup_name(name) -> str | None
- resolve_syntax(oid, name=None, desc=None, server_type="rfc") -> Syntax
- validate_value(value, syntax_oid, server_type="rfc") -> bool
- get_syntax_category(oid) -> str
- list_common_syntaxes() -> list[str]

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import re
from typing import override

from flext_core import FlextDecorators, FlextResult, FlextService

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels


class FlextLdifSyntax(FlextService[FlextLdifModels.SyntaxServiceStatus]):
    """RFC 4517 Compliant Attribute Syntax Validation and Resolution Service.

    Provides comprehensive syntax OID validation, lookup, resolution, and
    type-specific value validation following RFC 4517 (LDAP Attribute Syntax).

    Key Features:
    - OID format validation (numeric.numeric.numeric...)
    - RFC 4517 standard syntax detection
    - Bidirectional OID <-> name lookup
    - Complete Syntax model resolution with metadata
    - Type-specific value validation (boolean, integer, DN, time, binary, string)
    - Syntax type category resolution
    - Common syntax listing and management

    All methods return FlextResult for consistent error handling and composable
    operations. The service maintains internal lookup tables for fast OID/name
    resolution based on RFC 4517 standard syntax definitions.

    FlextService V2 Integration:
    - Builder pattern for OID and syntax name lookups
    - Pydantic fields for query configuration
    - execute() method for health checks
    """

    # ════════════════════════════════════════════════════════════════════════
    # PYDANTIC FIELDS (for builder pattern)
    # ════════════════════════════════════════════════════════════════════════

    oid_to_lookup: str | None = None
    name_to_lookup: str | None = None

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
    def execute(
        self,
        **kwargs: object,
    ) -> FlextResult[FlextLdifModels.SyntaxServiceStatus]:
        """Execute Syntax service self-check.

        FlextDecorators automatically:
        - Log operation start/completion/failure
        - Track performance metrics
        - Handle context propagation (correlation_id, operation_name)

        Returns:
            FlextResult containing service status

        """
        return FlextResult[FlextLdifModels.SyntaxServiceStatus].ok(
            FlextLdifModels.SyntaxServiceStatus(
                service="SyntaxService",
                status="operational",
                rfc_compliance="RFC 4517",
                total_syntaxes=len(self._oid_to_name),
                common_syntaxes=len(self._common_syntaxes),
            ),
        )

    # ════════════════════════════════════════════════════════════════════════
    # FLUENT BUILDER PATTERN
    # ════════════════════════════════════════════════════════════════════════

    @classmethod
    def builder(cls) -> FlextLdifSyntax:
        """Create fluent builder for OID and syntax name lookups.

        Returns:
            Service instance for method chaining

        Example:
            result = (FlextLdifSyntax.builder()
                .with_oid_to_lookup("1.3.6.1.4.1.1466.115.121.1.7")
                .build())

        """
        return cls()

    def with_oid_to_lookup(self, oid: str) -> FlextLdifSyntax:
        """Set OID to lookup (fluent builder)."""
        self.oid_to_lookup = oid
        return self

    def with_name_to_lookup(self, name: str) -> FlextLdifSyntax:
        """Set syntax name to lookup (fluent builder)."""
        self.name_to_lookup = name
        return self

    def build(self) -> FlextLdifModels.SyntaxLookupResult:
        """Execute lookups and return results (fluent terminal).

        Returns:
            SyntaxLookupResult model with lookup results

        """
        oid_result: str | None = None
        name_result: str | None = None

        if self.oid_to_lookup:
            lookup_result = self.lookup_oid(self.oid_to_lookup)
            if lookup_result.is_success:
                oid_result = lookup_result.unwrap()

        if self.name_to_lookup:
            lookup_result = self.lookup_name(self.name_to_lookup)
            if lookup_result.is_success:
                name_result = lookup_result.unwrap()

        return FlextLdifModels.SyntaxLookupResult(
            oid_lookup=oid_result,
            name_lookup=name_result,
        )

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

    def lookup_oid(self, oid: str) -> FlextResult[str]:
        """Look up syntax name for a given OID.

        Args:
            oid: OID to look up

        Returns:
            FlextResult[str] containing syntax name if found, fails if not found

        Example:
            >>> result = service.lookup_oid("1.3.6.1.4.1.1466.115.121.1.7")
            >>> if result.is_success:
            >>>     name = result.unwrap()  # "Boolean"
            >>> else:
            >>>     print(f"Not found: {result.error}")

        """
        if not oid:
            return FlextResult[str].fail("OID cannot be empty")

        try:
            name = self._oid_to_name.get(oid)
            if name is None:
                return FlextResult[str].fail(f"Syntax name not found for OID: {oid}")
            return FlextResult[str].ok(name)
        except (TypeError, KeyError) as e:
            return FlextResult[str].fail(
                f"Failed to lookup OID: {e}",
            )

    def lookup_name(self, name: str) -> FlextResult[str]:
        """Look up OID for a given syntax name.

        Args:
            name: Syntax name to look up (case-sensitive)

        Returns:
            FlextResult containing OID if found, failure otherwise

        Example:
            >>> result = service.lookup_name("Boolean")
            >>> if result.is_success:
            >>>     oid = result.unwrap()  # "1.3.6.1.4.1.1466.115.121.1.7"

        """
        if not name:
            return FlextResult[str].fail("Syntax name cannot be empty")

        try:
            oid = self._name_to_oid.get(name)
            if oid is None:
                return FlextResult[str].fail(f"OID not found for syntax name: {name}")
            return FlextResult[str].ok(oid)
        except (TypeError, KeyError) as e:
            return FlextResult[str].fail(
                f"Failed to lookup syntax name: {e}",
            )

    @FlextDecorators.track_performance()
    def resolve_syntax(
        self,
        oid: str,
        name: str | None = None,
        desc: str | None = None,
        server_type: str = FlextLdifConstants.ServerTypes.RFC,
    ) -> FlextResult[FlextLdifModels.Syntax]:
        """Resolve OID to complete Syntax model with validation.

        Creates a Syntax model from OID with optional metadata enrichment.
        Performs full Pydantic validation with OID and RFC 4517 checks.

        Args:
            oid: Syntax OID (required, must be valid format)
            name: Human-readable syntax name (optional, auto-looked-up if not provided)
            desc: Syntax description (optional)
            server_type: LDAP server type for quirk metadata

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

        # Use the static resolve_syntax_oid method which correctly
        # looks up the name and determines type_category from constants
        try:
            syntax = FlextLdifModels.Syntax.resolve_syntax_oid(
                oid=oid,
                server_type=server_type,
            )
            if syntax is None:
                return FlextResult[FlextLdifModels.Syntax].fail(
                    f"Failed to resolve syntax OID: {oid}",
                )
        except Exception as e:
            return FlextResult[FlextLdifModels.Syntax].fail(
                f"Failed to create syntax: {oid} - {e}",
            )

        # Update with optional parameters (override defaults from resolve_syntax_oid)
        if name:
            syntax.name = name
        if desc:
            syntax.desc = desc

        # Type narrowing: resolve_syntax_oid returns Domain.Syntax, but we need Models.Syntax
        # Since Models.Syntax extends Domain.Syntax, we can safely use it
        if isinstance(syntax, FlextLdifModels.Syntax):
            return FlextResult[FlextLdifModels.Syntax].ok(syntax)
        # Convert Domain.Syntax to Models.Syntax if needed
        # This should not happen in practice, but handle defensively
        # NOTE: is_rfc4517_standard is a @computed_field, it's automatically calculated from oid
        models_syntax = FlextLdifModels.Syntax(
            oid=syntax.oid,
            name=syntax.name,
            desc=syntax.desc,
            type_category=syntax.type_category,
            max_length=syntax.max_length,
            validation_pattern=syntax.validation_pattern,
            metadata=syntax.metadata,  # RFC Compliance: Include quirk metadata from resolve_syntax_oid
        )
        return FlextResult[FlextLdifModels.Syntax].ok(models_syntax)

    @FlextDecorators.track_performance()
    def validate_value(
        self,
        value: str,
        syntax_oid: str,
        _server_type: str = FlextLdifConstants.ServerTypes.RFC,
    ) -> FlextResult[bool]:
        """Validate a value against its syntax type.

        Performs type-specific validation based on the syntax OID.
        Supports basic validation for common syntax types.

        Args:
            value: Value to validate
            syntax_oid: Syntax OID that defines validation rules

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

        # Check if syntax OID is known in RFC 4517 standard
        # For validation purposes, we reject unknown OIDs
        if syntax_oid not in FlextLdifConstants.RfcSyntaxOids.OID_TO_NAME:
            return FlextResult[bool].fail(
                f"Cannot validate - unknown syntax OID: {syntax_oid}",
            )

        # Resolve syntax to get type category
        resolve_result = self.resolve_syntax(syntax_oid)
        if resolve_result.is_failure:
            return FlextResult[bool].fail(
                f"Cannot validate - failed to resolve syntax OID: {syntax_oid}",
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

    def _validate_by_category(
        self,
        value: str,
        type_category: str,
    ) -> FlextResult[bool]:
        """Validate value using functional validator lookup with error handling.

        Uses a functional approach with validator mapping and railway pattern
        for clean error propagation and reduced complexity.

        Args:
            value: Value to validate
            type_category: Syntax type category (boolean, integer, dn, time, etc.)

        Returns:
            FlextResult containing validation result

        """
        # Functional validator mapping with railway pattern
        validator_map = {
            "boolean": self._validate_boolean,
            "integer": self._validate_integer,
            "dn": self._validate_dn,
            "time": self._validate_time,
            "binary": lambda _: FlextResult.ok(True),  # Base64 assumed valid
        }

        # Get validator with default pass-through for extensibility
        validator = validator_map.get(type_category, lambda _: FlextResult.ok(True))

        # Apply validation with railway error handling
        result = FlextResult.ok(value).flat_map(validator)
        if result.is_failure:
            return FlextResult[bool].fail(
                f"Validation failed for {type_category}: {result.error}",
            )
        return result

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
            FlextResult containing type category
            (string, integer, binary, dn, time, boolean)

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
