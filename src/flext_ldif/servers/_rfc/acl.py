"""RFC 4512 Compliant Server Servers - Base LDAP Schema/ACL/Entry Implementation.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Self, cast, overload, override

from flext_ldif import c, m, p, r, t, u
from flext_ldif.servers._base import (
    FlextLdifServerMethodsMixin,
    FlextLdifServersBaseSchemaAcl,
)


class FlextLdifServersRfcAcl(FlextLdifServersBaseSchemaAcl):
    """LDAP ACL Server - Base Implementation."""

    def __new__(
        cls,
        acl_service: p.Ldif.AclServer | None = None,
        parent_server: Self | None = None,
        **kwargs: t.Ldif.Scalar | m.Ldif.Acl,
    ) -> Self:
        """Override __new__ to support auto-execute and processor instantiation."""
        _ = acl_service
        instance: Self = super().__new__(cls)
        auto_execute_kwargs = {"data", "operation", "parent_server", "_parent_server"}
        _ = {k: v for k, v in kwargs.items() if k not in auto_execute_kwargs}
        parent_server_raw = (
            parent_server if parent_server is not None else kwargs.get("_parent_server")
        )
        parent_server_value: Self | None = (
            parent_server_raw if isinstance(parent_server_raw, cls) else None
        )
        acl_instance: Self = instance
        if parent_server_value is not None:
            object.__setattr__(acl_instance, "parent_server", parent_server_value)
        if cls.auto_execute:
            data_raw = kwargs.get("data")
            data: str | m.Ldif.Acl | None = (
                data_raw if isinstance(data_raw, str) else None
            )
            op_raw = kwargs.get("operation")
            op: str | None = None
            if isinstance(op_raw, str) and op_raw == "parse":
                op = "parse"
            elif isinstance(op_raw, str) and op_raw == "write":
                op = "write"
            acl_instance.execute(data=data, operation=op)
        return instance

    def __init__(
        self,
        acl_service: p.Ldif.AclServer | None = None,
        parent_server: Self | None = None,
        **kwargs: t.Ldif.Scalar | m.Ldif.Acl,
    ) -> None:
        """Initialize RFC ACL server service."""
        _ = kwargs
        acl_service_typed: p.Ldif.AclServer | None = (
            acl_service if acl_service is not None else None
        )
        FlextLdifServersBaseSchemaAcl.__init__(
            self,
            acl_service=acl_service_typed,
            _parent_server=None,
        )
        if parent_server is not None:
            object.__setattr__(self, "parent_server", parent_server)

    @overload
    def __call__(
        self,
        *,
        server: p.Ldif.ServerRegistry | None = None,
        settings: p.Ldif.Settings | None = None,
        **fields: t.JsonValue,
    ) -> Self: ...

    @overload
    def __call__(self, data: str, *, operation: str | None = None) -> m.Ldif.Acl: ...

    @overload
    def __call__(self, data: m.Ldif.Acl, *, operation: str | None = None) -> str: ...

    @overload
    def __call__(
        self,
        data: str | m.Ldif.Acl | None = None,
        *,
        operation: str | None = None,
    ) -> m.Ldif.Acl | str: ...

    def __call__(
        self,
        data: t.JsonValue | m.Ldif.Acl | None = None,
        operation: t.JsonValue | None = None,
        server: p.Ldif.ServerRegistry | None = None,
        settings: p.Ldif.Settings | None = None,
        **fields: t.JsonValue,
    ) -> Self | m.Ldif.Acl | str:
        """Polymorphic callable interface for parse and write operations.

        When neither server nor settings is supplied, parses ACL text or
        serializes an ACL model according to the given data and operation.

        Args:
            data: ACL text to parse or ACL model to serialize.
            operation: Explicit operation name; inferred from data when None.
            server: Optional server registry for the configured builder path.
            settings: Optional settings for the configured builder path.
            **fields: Additional processor fields.

        Returns:
            A configured processor, the parsed ACL, or the serialized text.

        """
        processor_fields: t.MutableMappingKV[str, t.JsonValue | m.Ldif.Acl | None] = (
            dict(fields)
        )
        processor_fields["data"] = data
        processor_fields["operation"] = operation
        configured = FlextLdifServerMethodsMixin.dispatch_builder(
            super().__call__,
            processor_fields,
            frozenset({"data", "operation"}),
            server,
            settings,
        )
        if configured is not None:
            return cast("Self", configured)
        data_raw = processor_fields.get("data")
        narrowed_data = (
            data_raw
            if isinstance(data_raw, (str, m.Ldif.Acl)) or data_raw is None
            else None
        )
        operation_raw = processor_fields.get("operation")
        # Why: "operation" never actually carries an Acl value (only "data"
        # does); narrow the dict-value union before _narrow_operation, which
        # accepts t.JsonValue | None and does not accept m.Ldif.Acl.
        narrowed_operation = self._narrow_operation(
            None if isinstance(operation_raw, m.Ldif.Acl) else operation_raw,
        )
        result = self.execute(data=narrowed_data, operation=narrowed_operation)
        if isinstance(result.value, str):
            return result.value
        acl: m.Ldif.Acl = m.Ldif.Acl.model_validate(result.value)
        return acl

    @override
    def resolve_acl_attributes(self) -> t.MutableSequenceOf[str]:
        """Return the RFC ACL attribute names.

        Returns:
            The RFC-defined ACL attribute names.

        """
        return list(c.Ldif.RFC_ACL_ATTRIBUTES)

    @override
    def can_handle_acl(self, acl_line: str | m.Ldif.Acl) -> bool:
        """Accept any ACL definition in RFC form.

        Args:
            acl_line: Raw ACL line text or a parsed ACL.

        Returns:
            True; the RFC server handles every ACL definition.

        """
        _ = acl_line
        return True

    @override
    def can_handle_attribute(self, attribute: m.Ldif.SchemaAttribute) -> bool:
        """Decline schema attribute handling for the ACL server.

        Args:
            attribute: Attribute to check.

        Returns:
            False; schema attributes belong to the schema server.

        """
        _ = attribute
        return False

    @override
    def can_handle_objectclass(self, objectclass: m.Ldif.SchemaObjectClass) -> bool:
        """Decline objectClass handling for the ACL server.

        Args:
            objectclass: ObjectClass to check.

        Returns:
            False; objectClasses belong to the schema server.

        """
        _ = objectclass
        return False

    @staticmethod
    def _denormalize_permission(
        permission: str,
        _feature_id: str | None,
        _metadata: t.MutableJsonMapping,
    ) -> str:
        """Return the RFC permission unchanged.

        Args:
            permission: RFC permission name.
            _feature_id: Unused feature identifier.
            _metadata: Unused metadata extensions.

        Returns:
            The permission name in RFC form.

        """
        return permission

    @override
    def _get_feature_fallback(self, _feature_id: str) -> str | None:
        """Return the RFC fallback value for an unsupported vendor feature.

        Args:
            _feature_id: Identifier of the unsupported feature.

        Returns:
            None; the RFC server provides no vendor feature fallback.

        """
        return None

    @staticmethod
    def _normalize_permission(
        permission: str,
        _metadata: t.MutableJsonMapping,
    ) -> tuple[str, str | None]:
        """Normalize a server-specific permission to RFC standard.

        Args:
            permission: Permission name in server-specific form.
            _metadata: Unused metadata extensions.

        Returns:
            Pair of the RFC permission name and its optional feature id.

        """
        return (permission, None)

    @override
    def _parse_acl(self, acl_line: str) -> p.Result[m.Ldif.Acl]:
        """Parse an RFC-compliant ACL line.

        Wraps the raw line in an ACL model that preserves the original text.

        Args:
            acl_line: Raw ACL line text.

        Returns:
            Result carrying the parsed ACL, or a failure.

        """
        if not acl_line or not acl_line.strip():
            return r[m.Ldif.Acl].fail("ACL line must be a non-empty string.")
        server_type_str = self._get_server_type()
        server_type_value = u.Ldif.normalize_server_type(server_type_str)
        # mro-wgwh.5 (agent: kimi-coder) — model_construct bypass removed: plain
        # mapping validated by the ServerMetadata boundary.
        acl_model = m.Ldif.Acl(
            raw_acl=acl_line,
            server_type=server_type_value,
            metadata=m.Ldif.ServerMetadata(
                server_type=server_type_value,
                extensions={"original_format": acl_line},
            ),
        )
        return r[m.Ldif.Acl].ok(acl_model)

    @staticmethod
    def _preserve_unsupported_feature(
        feature_id: str,
        original_value: str,
        metadata: t.MutableJsonMapping,
    ) -> None:
        """Preserve unsupported feature in metadata for round-trip."""
        base_key = "unsupported_feature"
        metadata[f"{base_key}_{feature_id}"] = original_value

    @override
    def _supports_feature(self, _feature_id: str) -> bool:
        """Report whether a vendor feature is supported.

        Args:
            _feature_id: Identifier of the feature to check.

        Returns:
            False; the RFC server supports no vendor-specific features.

        """
        return False

    @override
    def _write_acl(self, acl_data: m.Ldif.Acl) -> p.Result[str]:
        """Write an ACL to RFC-compliant string format.

        Emits the preserved raw line when present, otherwise a bare
        attribute-name line.

        Args:
            acl_data: ACL to serialize.

        Returns:
            Result carrying the ACL text, or a failure.

        """
        if acl_data.raw_acl and acl_data.raw_acl.strip():
            return r[str].ok(acl_data.raw_acl)
        if acl_data.name and u.string_non_empty(acl_data.name):
            return r[str].ok(f"{acl_data.name}:")
        return r[str].fail("ACL has no raw_acl or name to write")


__all__: list[str] = ["FlextLdifServersRfcAcl"]
