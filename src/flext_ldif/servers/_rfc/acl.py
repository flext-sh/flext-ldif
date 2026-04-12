"""RFC 4512 Compliant Server Quirks - Base LDAP Schema/ACL/Entry Implementation."""

from __future__ import annotations

from typing import Self, overload, override

from flext_core import r
from flext_ldif import m, p, t, u
from flext_ldif.servers._base.acl import FlextLdifServersBaseSchemaAcl
from flext_ldif.servers.base import FlextLdifServersBase

logger = u.fetch_logger(__name__)


class FlextLdifServersRfcAcl(FlextLdifServersBase.Acl):
    """LDAP ACL Quirk - Base Implementation."""

    def __new__(
        cls,
        acl_service: p.Ldif.AclQuirk | None = None,
        parent_quirk: Self | None = None,
        **kwargs: t.Scalar,
    ) -> Self:
        """Override __new__ to support auto-execute and processor instantiation."""
        _ = acl_service
        instance = super().__new__(cls)
        auto_execute_kwargs = {"data", "operation", "parent_quirk", "_parent_quirk"}
        _ = {k: v for k, v in kwargs.items() if k not in auto_execute_kwargs}
        parent_quirk_raw = (
            parent_quirk if parent_quirk is not None else kwargs.get("_parent_quirk")
        )
        parent_quirk_value: Self | None = (
            parent_quirk_raw if isinstance(parent_quirk_raw, cls) else None
        )
        acl_instance: Self = instance
        if parent_quirk_value is not None:
            object.__setattr__(acl_instance, "_parent_quirk", parent_quirk_value)
        if cls.auto_execute:
            data_raw = kwargs.get("data")
            data = instance._coerce_acl_data(data_raw)
            op_raw = kwargs.get("operation")
            op: str | None = None
            if isinstance(op_raw, str) and op_raw == "parse":
                op = "parse"
            elif isinstance(op_raw, str) and op_raw == "write":
                op = "write"
            result = acl_instance.execute(data=data, operation=op)
            unwrapped: m.Ldif.Acl | str = result.value
            if isinstance(unwrapped, cls):
                return unwrapped
            return instance
        return instance

    def __init__(
        self,
        acl_service: p.Ldif.AclQuirk | None = None,
        parent_quirk: Self | None = None,
        **kwargs: t.Scalar,
    ) -> None:
        """Initialize RFC ACL quirk service."""
        _ = kwargs
        acl_service_typed: p.Ldif.AclQuirk | None = (
            acl_service if acl_service is not None else None
        )
        FlextLdifServersBaseSchemaAcl.__init__(
            self,
            acl_service=acl_service_typed,
            _parent_quirk=None,
        )
        if parent_quirk is not None:
            object.__setattr__(self, "_parent_quirk", parent_quirk)

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
        data: str | m.Ldif.Acl | None = None,
        *,
        operation: str | None = None,
    ) -> m.Ldif.Acl | str:
        """Callable interface - automatic polymorphic processor."""
        result = self.execute(data=data, operation=operation)
        return result.value

    @override
    def can_handle_acl(self, acl_line: str | m.Ldif.Acl) -> bool:
        """Check if this quirk can handle the ACL definition."""
        _ = acl_line
        return True

    @override
    def can_handle_attribute(self, attribute: m.Ldif.SchemaAttribute) -> bool:
        """Check if quirk handles schema attributes."""
        _ = attribute
        return False

    @override
    def can_handle_objectclass(self, objectclass: m.Ldif.SchemaObjectClass) -> bool:
        """Check if quirk handles objectclasses."""
        _ = objectclass
        return False

    def _denormalize_permission(
        self,
        permission: str,
        _feature_id: str | None,
        _metadata: t.MutableRecursiveContainerMapping,
    ) -> str:
        """Convert RFC permission back to server-specific format."""
        return permission

    @override
    def _get_feature_fallback(self, _feature_id: str) -> str | None:
        """Get RFC fallback value for unsupported vendor feature."""
        return super()._get_feature_fallback(_feature_id)

    def _normalize_permission(
        self,
        permission: str,
        _metadata: t.MutableRecursiveContainerMapping,
    ) -> tuple[str, str | None]:
        """Normalize a server-specific permission to RFC standard."""
        return (permission, None)

    @override
    def _parse_acl(self, acl_line: str) -> r[m.Ldif.Acl]:
        """Parse RFC-compliant ACL line (implements abstract method)."""
        if not acl_line or not acl_line.strip():
            return r[m.Ldif.Acl].fail("ACL line must be a non-empty string.")
        server_type_str = self._get_server_type()
        server_type_value = u.Ldif.normalize_server_type(server_type_str)
        extensions_meta = m.Ldif.DynamicMetadata.model_construct(
            _fields_set={"original_format"},
            original_format=acl_line,
        )
        acl_model = m.Ldif.Acl(
            raw_acl=acl_line,
            server_type=server_type_value,
            metadata=m.Ldif.QuirkMetadata(
                quirk_type=server_type_value,
                extensions=extensions_meta,
            ),
        )
        return r[m.Ldif.Acl].ok(acl_model)

    def _preserve_unsupported_feature(
        self,
        feature_id: str,
        original_value: str,
        metadata: m.Ldif.DynamicMetadata,
    ) -> None:
        """Preserve unsupported feature in metadata for round-trip."""
        base_key = "unsupported_feature"
        metadata[f"{base_key}_{feature_id}"] = original_value

    @override
    def _supports_feature(self, _feature_id: str) -> bool:
        """Check if this server supports a specific feature."""
        return super()._supports_feature(_feature_id)

    @override
    def _write_acl(self, acl_data: m.Ldif.Acl) -> r[str]:
        """Write ACL to RFC-compliant string format (internal)."""
        if acl_data.raw_acl and acl_data.raw_acl.strip():
            return r[str].ok(acl_data.raw_acl)
        if acl_data.name and u.string_non_empty(acl_data.name):
            return r[str].ok(f"{acl_data.name}:")
        return r[str].fail("ACL has no raw_acl or name to write")
