"""Base server mixins for LDIF server implementations."""

from __future__ import annotations

from flext_ldif import c, p, u


class FlextLdifServerMethodsMixin:
    """Common server methods shared by schema, ACL, and entry servers."""

    @staticmethod
    def get_parent_server_from_instance(
        instance: FlextLdifServerMethodsMixin,
    ) -> p.Ldif.ServerServer | None:
        """Get the effective parent server when available."""
        parent_raw: p.Ldif.ServerServer | None = getattr(
            instance,
            "_parent_server",
            None,
        )
        if (
            parent_raw is not None
            and getattr(parent_raw, "_parent_server", None) is not None
        ):
            return parent_raw
        return None

    @staticmethod
    def get_priority_from_parent(parent: p.Ldif.ServerServer | None) -> int:
        """Resolve priority from the parent server Constants class."""
        if parent is None:
            return 100
        constants_attr = getattr(parent, "Constants", None)
        if constants_attr is None:
            return 100
        priority_raw = getattr(constants_attr, "PRIORITY", 100)
        if isinstance(priority_raw, int):
            return priority_raw
        return 100

    @staticmethod
    def get_server_type_from_utilities(
        server_class: type,
    ) -> c.Ldif.ServerTypes:
        """Infer the server type from the namespace."""
        resolved: c.Ldif.ServerTypes = u.Ldif.get_parent_server_type(server_class)
        return resolved

    def _get_parent_server_safe(self) -> p.Ldif.ServerServer | None:
        """Get the effective parent server safely."""
        return FlextLdifServerMethodsMixin.get_parent_server_from_instance(self)

    def _get_priority(self) -> int:
        """Get server priority from the parent Constants class."""
        return FlextLdifServerMethodsMixin.get_priority_from_parent(
            self._get_parent_server_safe(),
        )

    def _get_server_type(self) -> c.Ldif.ServerTypes:
        """Resolve server type for the current server class."""
        return FlextLdifServerMethodsMixin.get_server_type_from_utilities(type(self))


__all__: list[str] = ["FlextLdifServerMethodsMixin"]
