"""RFC 4512 Compliant Server Quirks - Base LDAP Schema/ACL/Entry Implementation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides RFC-compliant baseline implementations for LDAP directory operations.
All server-specific quirks (OID, OUD, OpenLDAP, etc.) extend this RFC base.

Architecture:
    - RFC baseline: Strict RFC 2849/4512 compliance
    - Server quirks: Extend RFC with server-specific enhancements
    - No cross-server dependencies: Each server is isolated
    - Generic conversions: All via RFC intermediate format

References:
    - RFC 2849: LDIF Format Specification
    - RFC 4512: LDAP Directory Information Models

"""

from __future__ import annotations

from typing import Self, overload

from flext_core import FlextLogger, FlextResult, FlextTypes, t

from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.protocols import p
from flext_ldif.servers._base.acl import FlextLdifServersBaseSchemaAcl
from flext_ldif.servers.base import FlextLdifServersBase

logger = FlextLogger(__name__)


# TypedDicts moved to typings.py - import from there


class FlextLdifServersRfcAcl(FlextLdifServersBase.Acl):
    r"""LDAP ACL Quirk - Base Implementation.

    Note: LDAP Access Control is NOT standardized in a single RFC.
    RFC 2820 defines requirements, but implementations vary by vendor:
    - OpenLDAP: Uses "olcAccess" with complex syntax
    - Oracle OID: Uses "orclaci" attribute
    - Oracle OUD: Uses "aci" attribute with OpenDS/DSEE syntax
    - Active Directory: Uses ACE/ACL security descriptors

    This base implementation provides common ACL parsing primitives
    that server-specific quirks can extend with vendor-specific parsing.

    Common ACL Concepts (RFC 2820 Requirements):
    =============================================
    - Subject: Who the ACL applies to (user, group, role)
    - Target: What resource is being protected (entry, attribute)
    - Permissions: What operations are allowed/denied (read, write, etc.)

    """

    def can_handle_acl(self, acl_line: str | m.Ldif.Acl) -> bool:
        """Check if this quirk can handle the ACL definition.

        RFC quirk handles all ACLs as it's the baseline implementation.

        Args:
            acl_line: ACL definition line string or Acl model

        Returns:
            True (RFC handles all ACLs)

        """
        _ = acl_line  # Unused - RFC handles all ACLs
        return True

    def _supports_feature(self, feature_id: str) -> bool:
        """Check if this server supports a specific feature.

        Delegates to base class implementation.
        """
        return super()._supports_feature(feature_id)

    def _normalize_permission(
        self,
        permission: str,
        _metadata: dict[str, t.MetadataAttributeValue],
    ) -> tuple[str, str | None]:
        """Normalize a server-specific permission to RFC standard.

        Override to convert server-specific permissions to RFC equivalents.
        Returns (rfc_permission, feature_id) where feature_id is set for
        vendor-specific permissions that need metadata preservation.

        Args:
            permission: Server-specific permission string
            _metadata: Metadata dict to store original value (unused in base)

        Returns:
            Tuple of (normalized_permission, feature_id or None)

        """
        # RFC implementation: permissions are already RFC-compliant
        return permission, None

    def _denormalize_permission(
        self,
        permission: str,
        _feature_id: str | None,
        _metadata: dict[str, t.MetadataAttributeValue],
    ) -> str:
        """Convert RFC permission back to server-specific format.

        Override to convert RFC permissions to server-specific equivalents.
        Uses feature_id and metadata to restore original vendor values.

        Args:
            permission: RFC-normalized permission
            _feature_id: Feature ID if vendor-specific (unused in base)
            _metadata: Metadata dict with original values (unused in base)

        Returns:
            Server-specific permission string.

        """
        # RFC implementation: keep RFC permission as-is
        return permission

    def _get_feature_fallback(self, feature_id: str) -> str | None:
        """Get RFC fallback value for unsupported vendor feature.

        Delegates to base class implementation.
        """
        return super()._get_feature_fallback(feature_id)

    def _preserve_unsupported_feature(
        self,
        feature_id: str,
        original_value: str,
        metadata: dict[str, t.MetadataAttributeValue],
    ) -> None:
        """Preserve unsupported feature in metadata for round-trip.

        Called when a feature cannot be translated. Stores the original
        value in metadata so it can be restored if converting back.

        Args:
            feature_id: Feature ID that couldn't be translated
            original_value: Original server-specific value
            metadata: Metadata dict to store preservation info

        """
        meta_key = c.Ldif.FeatureCapabilities.META_UNSUPPORTED_FEATURES
        if meta_key not in metadata:
            metadata[meta_key] = {}
        unsupported = metadata[meta_key]
        if isinstance(unsupported, dict):
            unsupported[feature_id] = original_value

    def _parse_acl(self, acl_line: str) -> FlextResult[m.Ldif.Acl]:
        """Parse RFC-compliant ACL line (implements abstract method).

        Args:
            acl_line: The raw ACL string from the LDIF.

        Returns:
            A FlextResult containing the Acl model.

        """
        # Type guard: ensure acl_line is a string
        if not isinstance(acl_line, str):
            return FlextResult[m.Ldif.Acl].fail(
                f"ACL line must be a string, got {type(acl_line).__name__}",
            )
        if not acl_line or not acl_line.strip():
            return FlextResult.fail("ACL line must be a non-empty string.")

        # Get server type from the actual server class (not hardcoded "rfc")
        server_type_value = self._get_server_type()

        # RFC passthrough: store the raw line in the model.
        # server_type_value is already the correct type from _get_server_type()
        acl_model = m.Ldif.Acl(
            raw_acl=acl_line,
            server_type=server_type_value,
            metadata=m.QuirkMetadata(
                quirk_type=server_type_value,
                extensions=m.DynamicMetadata(**{
                    c.Ldif.MetadataKeys.ACL_ORIGINAL_FORMAT: acl_line,
                }),
            ),
        )
        return FlextResult.ok(acl_model)

    # parse_acl() method is redundant - parse() already delegates to _parse_acl()
    # Removed to use base.py.parse() which already handles this

    # create_metadata(), convert_rfc_acl_to_aci(), format_acl_value()
    # are now in base.py - these methods delegate to parent without RFC-specific logic

    def _write_acl(self, acl_data: m.Ldif.Acl) -> FlextResult[str]:
        """Write ACL to RFC-compliant string format (internal).

        RFC implementation of ACL writing using raw_acl or name fallback.
        """
        # Use raw_acl if available and non-empty
        if (
            acl_data.raw_acl
            and isinstance(acl_data.raw_acl, str)
            and acl_data.raw_acl.strip()
        ):
            return FlextResult[str].ok(acl_data.raw_acl)
        # If raw_acl is empty but name exists, return minimal ACL with name
        if acl_data.name and isinstance(acl_data.name, str) and acl_data.name.strip():
            return FlextResult[str].ok(f"{acl_data.name}:")
        # No valid data to write
        return FlextResult[str].fail("ACL has no raw_acl or name to write")

    def can_handle_attribute(
        self,
        attribute: m.Ldif.SchemaAttribute,
    ) -> bool:
        """Check if quirk handles schema attributes.

        ACL quirks don't handle schema attributes - that's handled by Schema quirks.

        Args:
            attribute: SchemaAttribute model

        Returns:
            False - ACL quirks don't handle attributes

        """
        _ = attribute  # Unused - ACL doesn't handle attributes
        return False

    def can_handle_objectclass(
        self,
        objectclass: m.Ldif.SchemaObjectClass,
    ) -> bool:
        """Check if quirk handles objectclasses.

        ACL quirks don't handle objectclasses - that's handled by Schema quirks.

        Args:
            objectclass: SchemaObjectClass model

        Returns:
            False - ACL quirks don't handle objectclasses

        """
        _ = objectclass  # Unused - ACL doesn't handle objectclasses
        return False

    # execute() is now in base.py (via parent FlextService)
    # This class only provides RFC-specific implementations of:
    # - _parse_acl(), _write_acl()

    @overload
    def __call__(
        self,
        data: str,
        *,
        operation: c.Ldif.LiteralTypes.ParseOperationLiteral | None = None,
    ) -> m.Ldif.Acl: ...

    @overload
    def __call__(
        self,
        data: m.Ldif.Acl,
        *,
        operation: c.Ldif.LiteralTypes.WriteOperationLiteral | None = None,
    ) -> str: ...

    @overload
    def __call__(
        self,
        data: str | m.Ldif.Acl | None = None,
        *,
        operation: c.Ldif.LiteralTypes.ParseWriteOperationLiteral | None = None,
    ) -> m.Ldif.Acl | str: ...

    def __call__(
        self,
        data: str | m.Ldif.Acl | None = None,
        *,
        operation: c.Ldif.LiteralTypes.ParseWriteOperationLiteral | None = None,
    ) -> m.Ldif.Acl | str:
        """Callable interface - automatic polymorphic processor.

        Pass ACL line string for parsing or Acl model for writing.
        Type auto-detection handles routing automatically.
        """
        result = self.execute(data=data, operation=operation)
        return result.unwrap()

    def __new__(
        cls,
        _acl_service: p.Ldif.Services.HasParseMethodProtocol | None = None,
        parent_quirk: p.Ldif.Quirks.ParentQuirkProtocol | None = None,
        **kwargs: dict[str, str | int | float | bool | list[str] | None],
    ) -> Self:
        """Override __new__ to support auto-execute and processor instantiation."""
        instance = super().__new__(cls)
        # Remove auto-execute kwargs before passing to __init__
        # Also filter parent_quirk to avoid passing it twice
        auto_execute_kwargs = {"data", "operation", "parent_quirk", "_parent_quirk"}
        _ = {
            k: v for k, v in kwargs.items() if k not in auto_execute_kwargs
        }  # Filtered
        # Use explicit parent_quirk parameter or fallback to kwargs (_parent_quirk)
        # Business Rule: parent_quirk must satisfy ParentQuirkProtocol
        parent_quirk_raw = (
            parent_quirk if parent_quirk is not None else kwargs.get("_parent_quirk")
        )
        parent_quirk_value: p.Ldif.Quirks.ParentQuirkProtocol | None = (
            parent_quirk_raw
            if isinstance(parent_quirk_raw, p.Ldif.Quirks.ParentQuirkProtocol)
            else None
        )
        # Initialize using super() to avoid mypy error about accessing
        # __init__ on instance
        # Use FlextLdifServersBase.Acl as the base class for super()
        # Type narrowing: instance is Self (Acl subclass)
        # Guard clause: should always pass for valid Acl subclasses
        if not isinstance(instance, FlextLdifServersRfcAcl):
            # Unreachable for valid Acl subclasses, but needed for type safety
            error_msg = f"Invalid instance type: {type(instance)}"
            raise TypeError(error_msg)
        acl_instance: Self = instance  # Now properly narrowed
        # Store _parent_quirk after instance creation using object.__setattr__
        # Note: __init__ will be called automatically by Python after __new__ returns
        if parent_quirk_value is not None:
            object.__setattr__(acl_instance, "_parent_quirk", parent_quirk_value)

        if cls.auto_execute:
            # Type-safe extraction of kwargs
            data_raw = kwargs.get("data")
            data: str | m.Ldif.Acl | None = None
            if isinstance(data_raw, (str, m.Ldif.Acl)):
                data = data_raw
            op_raw = kwargs.get("operation")
            op: c.Ldif.LiteralTypes.ParseWriteOperationLiteral | None = None
            if isinstance(op_raw, str) and op_raw == "parse":
                op = "parse"
            elif isinstance(op_raw, str) and op_raw == "write":
                op = "write"
            # Type narrowing: instance is Self (Acl subclass)
            # Use acl_instance from above
            result = acl_instance.execute(data=data, operation=op)
            unwrapped: m.Ldif.Acl | str = result.unwrap()
            if isinstance(unwrapped, cls):
                return unwrapped
            return instance

        return instance

    def __init__(
        self,
        acl_service: p.Ldif.Services.HasParseMethodProtocol | None = None,
        parent_quirk: p.Ldif.Quirks.ParentQuirkProtocol | None = None,
        **kwargs: FlextTypes.GeneralValueType,
    ) -> None:
        """Initialize RFC ACL quirk service.

        Args:
            acl_service: Injected FlextLdifAcl service (optional)
            parent_quirk: Reference to parent quirk (optional)
            **kwargs: Passed to parent class

        """
        # Business Rule: Filter parent_quirk from kwargs to avoid type errors
        # Implication: parent_quirk is handled separately, not via Pydantic fields
        filtered_kwargs: dict[str, FlextTypes.GeneralValueType] = {
            k: v
            for k, v in kwargs.items()
            if k not in {"_parent_quirk", "parent_quirk"}
        }
        # Business Rule: Call parent Acl.__init__ which accepts acl_service and _parent_quirk
        # acl_service is already compatible with HasParseMethodProtocol
        acl_service_typed: p.Ldif.Services.HasParseMethodProtocol | None = (
            acl_service if acl_service is not None else None
        )
        # Call base class __init__ directly to avoid mypy inference issues through nested class
        FlextLdifServersBaseSchemaAcl.__init__(
            self,
            acl_service=acl_service_typed,
            _parent_quirk=None,  # Pass None, we handle parent_quirk separately
            **filtered_kwargs,
        )
        # Store _parent_quirk after initialization using object.__setattr__
        if parent_quirk is not None:
            object.__setattr__(self, "_parent_quirk", parent_quirk)

    # parse() method inherited from base.py.Acl - delegates to _parse_acl()

    # write() method inherited from base.py.Acl - delegates to _write_acl()
