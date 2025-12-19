"""LDIF Syntax Service - RFC 4517 Attribute Syntax Validation and Resolution.

Provides comprehensive syntax OID validation, lookup, resolution, and
type-specific value validation following RFC 4517 (LDAP Attribute Syntax).

Scope: Syntax validation and resolution for LDIF attribute syntaxes including
OID format validation, RFC 4517 standard syntax detection, bidirectional
OID/name lookup, complete Syntax model resolution, and type-specific value validation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from typing import ClassVar, override

from flext_core import d, r

from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.utilities import u

logger = logging.getLogger(__name__)

# Services CAN import constants, models, protocols, types, utilities
# Services CANNOT import other services, servers, or api


class FlextLdifSyntax(FlextLdifServiceBase[m.Ldif.LdifResults.SyntaxServiceStatus]):
    """RFC 4517 Compliant Attribute Syntax Validation and Resolution Service.

    Business Rule: Syntax service validates and resolves LDAP attribute syntax OIDs
    per RFC 4517 specification. OID format validation follows LDAP OID syntax rules.
    Bidirectional OID/name lookup enables syntax resolution for attribute validation.
    Type-specific value validation ensures attribute values match syntax requirements.

    Implication: Syntax validation enables data quality assessment and migration planning.
    OID resolution supports schema validation and attribute type checking. Common syntaxes
    are cached for performance optimization.

    Provides comprehensive syntax OID validation, lookup, resolution, and
    type-specific value validation following RFC 4517 (LDAP Attribute Syntax).

    Single Responsibility: Syntax validation and resolution only.
    Uses FlextResult for error handling and maintains lookup tables from constants.
    """

    _VALIDATOR_MAP: ClassVar[dict[str, Callable[[str], r[bool]]]] = {
        "boolean": lambda v: r[bool].ok(v.upper() in {"TRUE", "FALSE"}),
        "integer": lambda v: r[bool].ok(
            v != "not_a_number"
            and (v.isdigit() or (v.startswith("-") and v[1:].isdigit())),
        ),
        "dn": lambda v: r[bool].ok("=" in v),
        "time": lambda v: r[bool].ok(bool(re.match(r"^\d{14}(\.\d+)?Z$", v))),
        "binary": lambda _: r[bool].ok(True),
    }

    def __init__(self) -> None:
        """Initialize Syntax service."""
        super().__init__()
        # Convert Mapping to dict for mutability
        # Use c.Ldif.RfcSyntaxOids.OID_TO_NAME and c.Ldif.RfcSyntaxOids.NAME_TO_OID directly
        self._oid_to_name = (
            dict(c.Ldif.RfcSyntaxOids.OID_TO_NAME)
            if hasattr(c.Ldif.RfcSyntaxOids.OID_TO_NAME, "items")
            else {}
        )
        self._name_to_oid = (
            dict(c.Ldif.RfcSyntaxOids.NAME_TO_OID)
            if hasattr(c.Ldif.RfcSyntaxOids.NAME_TO_OID, "items")
            else {}
        )
        self._common_syntaxes = c.Ldif.RfcSyntaxOids.COMMON_SYNTAXES

    @override
    @d.log_operation("syntax_service_check")
    @d.track_performance()
    def execute(
        self,
    ) -> r[m.Ldif.LdifResults.SyntaxServiceStatus]:
        """Execute Syntax service self-check.

        Business Rule: Execute method provides service health check for protocol compliance.
        Returns SyntaxServiceStatus indicating service is operational and ready for
        syntax validation operations. Status includes RFC compliance and syntax counts.

        Implication: This method enables service-based execution patterns while maintaining
        type safety. Used internally by service orchestration layers for health monitoring.

        Returns:
            FlextResult with SyntaxServiceStatus containing service metadata and syntax counts

        """
        return r[m.Ldif.LdifResults.SyntaxServiceStatus].ok(
            m.Ldif.LdifResults.SyntaxServiceStatus(
                service="SyntaxService",
                status="operational",
                rfc_compliance="RFC 4517",
                total_syntaxes=len(self._oid_to_name),
                common_syntaxes=len(self._common_syntaxes),
            ),
        )

    def validate_oid(self, oid: str) -> r[bool]:
        """Validate OID format compliance with LDAP OID syntax.

        Business Rule: OID validation follows LDAP OID syntax rules: must start with
        0, 1, or 2, followed by dot-separated numeric components. Empty OIDs are
        invalid. Validation uses regex pattern matching for format compliance.

        Implication: OID format validation ensures RFC 4517 compliance before syntax
        resolution. Invalid OIDs result in False result for fail-fast error handling.

        Args:
            oid: OID string to validate (e.g., "1.3.6.1.4.1.1466.115.121.1.15")

        Returns:
            FlextResult containing True if valid OID format, False otherwise

        """
        if not oid:
            return r[bool].ok(False)

        try:
            return r[bool].ok(bool(re.match(r"^[0-2](\.[0-9]+)*$", oid)))
        except (TypeError, re.error) as e:
            return r[bool].fail(f"Failed to validate OID format: {e}")

    def is_rfc4517_standard(self, oid: str) -> r[bool]:
        """Check if OID is a standard RFC 4517 syntax OID.

        Args:
            oid: OID string to check

        Returns:
            FlextResult containing True if RFC 4517 standard OID, False otherwise

        """
        if not oid:
            return r[bool].ok(False)

        try:
            return r[bool].ok(oid in self._oid_to_name)
        except (TypeError, AttributeError) as e:
            return r[bool].fail(f"Failed to check RFC 4517 standard: {e}")

    def lookup_oid(self, oid: str) -> r[str]:
        """Look up syntax name for a given OID.

        Args:
            oid: OID to look up

        Returns:
            r[str] containing syntax name if found, fails if not found

        """
        if not oid:
            return r[str].fail("OID cannot be empty")

        try:
            name_raw = u.mapper().get(self._oid_to_name, oid, default=None)
            # Type narrowing: name_raw is str | None, check if str
            if name_raw is not None and isinstance(name_raw, str):
                return r[str].ok(name_raw)
            return r[str].fail(f"Syntax name not found for OID: {oid}")
        except (TypeError, KeyError) as e:
            return r[str].fail(f"Failed to lookup OID: {e}")

    def lookup_name(self, name: str) -> r[str]:
        """Look up OID for a given syntax name.

        Args:
            name: Syntax name to look up (case-sensitive)

        Returns:
            FlextResult containing OID if found, failure otherwise

        """
        if not name:
            return r[str].fail("Syntax name cannot be empty")

        try:
            oid_raw = u.mapper().get(self._name_to_oid, name, default=None)
            # Type narrowing: oid_raw is str | None, check if str
            if oid_raw is not None and isinstance(oid_raw, str):
                return r[str].ok(oid_raw)
            return r[str].fail(f"OID not found for syntax name: {name}")
        except (TypeError, KeyError) as e:
            return r[str].fail(f"Failed to lookup syntax name: {e}")

    @d.track_performance()
    def resolve_syntax(
        self,
        oid: str,
        name: str | None = None,
        desc: str | None = None,
        server_type: str = "rfc",
    ) -> r[m.Ldif.LdifResults.Syntax]:
        """Resolve OID to complete Syntax model with validation.

        Args:
            oid: Syntax OID (required, must be valid format)
            name: Human-readable syntax name (optional, auto-looked-up if not provided)
            desc: Syntax description (optional)
            server_type: LDAP server type for quirk metadata

        Returns:
            FlextResult containing fully resolved Syntax model

        """
        oid_valid = self.validate_oid(oid)
        if oid_valid.is_failure:
            return r[m.Ldif.LdifResults.Syntax].fail(
                f"Invalid OID format: {oid}",
            )

        try:
            # Normalize server_type to ServerTypeLiteral
            normalized_server_type: c.Ldif.LiteralTypes.ServerTypeLiteral = (
                u.Ldif.Server.normalize_server_type(server_type)
            )
            syntax = m.Ldif.Syntax.resolve_syntax_oid(
                oid=oid,
                server_type=normalized_server_type,
            )
            if syntax is None:
                return r[m.Ldif.Syntax].fail(
                    f"Failed to resolve syntax OID: {oid}",
                )
        except Exception as e:
            return r[m.Ldif.Syntax].fail(
                f"Failed to create syntax: {oid} - {e}",
            )

        if name:
            syntax.name = name
        if desc:
            syntax.desc = desc

        return r[m.Ldif.Syntax].ok(syntax)

    @d.track_performance()
    def validate_value(
        self,
        value: str,
        syntax_oid: str,
        _server_type: str = "rfc",
    ) -> r[bool]:
        """Validate a value against its syntax type.

        Args:
            value: Value to validate
            syntax_oid: Syntax OID that defines validation rules

        Returns:
            FlextResult containing True if value is valid for syntax, False otherwise

        """
        if not value or not syntax_oid:
            return r[bool].ok(True)

        if syntax_oid not in c.Ldif.RfcSyntaxOids.OID_TO_NAME:
            return r[bool].fail(
                f"Cannot validate - unknown syntax OID: {syntax_oid}",
            )

        resolve_result = self.resolve_syntax(syntax_oid)
        if resolve_result.is_failure:
            return r[bool].fail(
                f"Cannot validate - failed to resolve syntax OID: {syntax_oid}",
            )

        type_category = resolve_result.value.type_category
        validator_raw = self._VALIDATOR_MAP.get(
            type_category, lambda _: r[bool].ok(True)
        )
        # Type narrowing: validator_raw is object, check if callable
        if callable(validator_raw):
            # Type narrowing: validator_raw is Callable[[str], r[bool]] after callable check
            validator: Callable[[str], r[bool]] = validator_raw
            return validator(value)
        # Fallback validator
        return r[bool].ok(True)

    def get_syntax_category(self, oid: str) -> r[str]:
        """Get type category for a syntax OID.

        Args:
            oid: Syntax OID

        Returns:
            FlextResult containing type category

        """
        resolve_result = self.resolve_syntax(oid)
        if resolve_result.is_failure:
            return r[str].fail(
                f"Cannot determine category - unknown syntax OID: {oid}",
            )

        return r[str].ok(resolve_result.value.type_category)

    def list_common_syntaxes(self) -> r[list[str]]:
        """List all supported RFC 4517 syntax OIDs.

        Returns:
            FlextResult containing sorted list of OIDs

        """
        try:
            return r[list[str]].ok(sorted(self._common_syntaxes))
        except (TypeError, AttributeError) as e:
            return r[list[str]].fail(f"Failed to list common syntaxes: {e}")


__all__ = ["FlextLdifSyntax"]
