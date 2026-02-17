"""LDIF Syntax Service - RFC 4517 Attribute Syntax Validation and Resolution."""

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


class FlextLdifSyntax(FlextLdifServiceBase[m.Ldif.LdifResults.SyntaxServiceStatus]):
    """RFC 4517 Compliant Attribute Syntax Validation and Resolution Service."""

    _VALIDATOR_MAP: ClassVar[dict[str, Callable[[str], r[bool]]]] = {
        "boolean": lambda v: r[bool].ok(v.upper() in {"TRUE", "FALSE"}),
        "integer": lambda v: r[bool].ok(
            v != "not_a_number"
            and (v.isdigit() or (v.startswith("-") and v[1:].isdigit())),
        ),
        "dn": lambda v: r[bool].ok("=" in v),
        "time": lambda v: r[bool].ok(bool(re.match(r"^\d{14}(\.\d+)?Z$", v))),
        "binary": lambda _: r[bool].ok(value=True),
    }

    def __init__(self) -> None:
        """Initialize Syntax service."""
        super().__init__()

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
        """Execute Syntax service self-check."""
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
        """Validate OID format compliance with LDAP OID syntax."""
        if not oid:
            return r[bool].ok(False)

        try:
            return r[bool].ok(bool(re.match(r"^[0-2](\.[0-9]+)*$", oid)))
        except (TypeError, re.error) as e:
            return r[bool].fail(f"Failed to validate OID format: {e}")

    def is_rfc4517_standard(self, oid: str) -> r[bool]:
        """Check if OID is a standard RFC 4517 syntax OID."""
        if not oid:
            return r[bool].ok(False)

        try:
            return r[bool].ok(oid in self._oid_to_name)
        except (TypeError, AttributeError) as e:
            return r[bool].fail(f"Failed to check RFC 4517 standard: {e}")

    def lookup_oid(self, oid: str) -> r[str]:
        """Look up syntax name for a given OID."""
        if not oid:
            return r[str].fail("OID cannot be empty")

        try:
            name_raw = u.mapper().get(self._oid_to_name, oid, default="")

            if name_raw:
                return r[str].ok(name_raw)
            return r[str].fail(f"Syntax name not found for OID: {oid}")
        except (TypeError, KeyError) as e:
            return r[str].fail(f"Failed to lookup OID: {e}")

    def lookup_name(self, name: str) -> r[str]:
        """Look up OID for a given syntax name."""
        if not name:
            return r[str].fail("Syntax name cannot be empty")

        try:
            oid_raw = u.mapper().get(self._name_to_oid, name, default="")

            if oid_raw:
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
        """Resolve OID to complete Syntax model with validation."""
        oid_valid = self.validate_oid(oid)
        if oid_valid.is_failure:
            return r[m.Ldif.LdifResults.Syntax].fail(
                f"Invalid OID format: {oid}",
            )

        try:
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
        """Validate a value against its syntax type."""
        if not value or not syntax_oid:
            return r[bool].ok(value=True)

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
            type_category,
            lambda _: r[bool].ok(value=True),
        )

        if callable(validator_raw):
            validator: Callable[[str], r[bool]] = validator_raw
            return validator(value)

        return r[bool].ok(value=True)

    def get_syntax_category(self, oid: str) -> r[str]:
        """Get type category for a syntax OID."""
        resolve_result = self.resolve_syntax(oid)
        if resolve_result.is_failure:
            return r[str].fail(
                f"Cannot determine category - unknown syntax OID: {oid}",
            )

        return r[str].ok(resolve_result.value.type_category)

    def list_common_syntaxes(self) -> r[list[str]]:
        """List all supported RFC 4517 syntax OIDs."""
        try:
            return r[list[str]].ok(sorted(self._common_syntaxes))
        except (TypeError, AttributeError) as e:
            return r[list[str]].fail(f"Failed to list common syntaxes: {e}")


__all__ = ["FlextLdifSyntax"]
