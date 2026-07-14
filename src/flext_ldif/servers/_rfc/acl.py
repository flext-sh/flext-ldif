"""RFC 4512 Compliant Server Servers - Base LDAP Schema/ACL/Entry Implementation."""

from __future__ import annotations

from typing import Self, overload, override

from flext_ldif import m, p, r, t, u
from flext_ldif.servers._base.acl import FlextLdifServersBaseSchemaAcl
from flext_ldif.servers.base import FlextLdifServersBase


class FlextLdifServersRfcAcl(FlextLdifServersBase.Acl):
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
            object.__setattr__(acl_instance, "_parent_server", parent_server_value)
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
            object.__setattr__(self, "_parent_server", parent_server)

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
        *,
        operation: t.JsonValue | None = None,
    ) -> m.Ldif.Acl | str:
        """Callable interface - automatic polymorphic processor."""
        narrowed_data = (
            data if isinstance(data, (str, m.Ldif.Acl)) or data is None else None
        )
        narrowed_operation = operation if isinstance(operation, str) else None
        result = self.execute(data=narrowed_data, operation=narrowed_operation)
        if isinstance(result.value, str):
            return result.value
        acl: m.Ldif.Acl = m.Ldif.Acl.model_validate(result.value)
        return acl

    @override
    def can_handle_acl(self, acl_line: str | m.Ldif.Acl) -> bool:
        """Check if this server can handle the ACL definition."""
        _ = acl_line
        return True

    @override
    def can_handle_attribute(self, attribute: m.Ldif.SchemaAttribute) -> bool:
        """Check if server handles schema attributes."""
        _ = attribute
        return False

    @override
    def can_handle_objectclass(self, objectclass: m.Ldif.SchemaObjectClass) -> bool:
        """Check if server handles objectclasses."""
        _ = objectclass
        return False

    def _denormalize_permission(
        self,
        permission: str,
        _feature_id: str | None,
        _metadata: t.MutableJsonMapping,
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
        _metadata: t.MutableJsonMapping,
    ) -> tuple[str, str | None]:
        """Normalize a server-specific permission to RFC standard."""
        return (permission, None)

    @override
    def _parse_acl(self, acl_line: str) -> p.Result[m.Ldif.Acl]:
        """Parse RFC-compliant ACL line (implements abstract method)."""
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

    def _preserve_unsupported_feature(
        self,
        feature_id: str,
        original_value: str,
        metadata: t.MutableJsonMapping,
    ) -> None:
        """Preserve unsupported feature in metadata for round-trip."""
        base_key = "unsupported_feature"
        metadata[f"{base_key}_{feature_id}"] = original_value

    @override
    def _supports_feature(self, _feature_id: str) -> bool:
        """Check if this server supports a specific feature."""
        return super()._supports_feature(_feature_id)

    @override
    def _write_acl(self, acl_data: m.Ldif.Acl) -> p.Result[str]:
        """Write ACL to RFC-compliant string format (internal)."""
        if acl_data.raw_acl and acl_data.raw_acl.strip():
            return r[str].ok(acl_data.raw_acl)
        if acl_data.name and u.string_non_empty(acl_data.name):
            return r[str].ok(f"{acl_data.name}:")
        return r[str].fail("ACL has no raw_acl or name to write")
