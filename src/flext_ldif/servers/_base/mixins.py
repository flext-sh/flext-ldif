"""Base quirk mixins for LDIF server implementations."""

from __future__ import annotations

from flext_ldif import c, p, u


class FlextLdifQuirkMethodsMixin:
    """Common quirk methods shared by schema, ACL, and entry servers."""

    @staticmethod
    def get_parent_quirk_from_instance(
        instance: FlextLdifQuirkMethodsMixin,
    ) -> p.Ldif.SchemaQuirk | None:
        """Get the effective parent quirk when available."""
        parent_raw: p.Ldif.SchemaQuirk | None = getattr(instance, "_parent_quirk", None)
        if (
            parent_raw is not None
            and getattr(parent_raw, "_parent_quirk", None) is not None
        ):
            return parent_raw
        return None

    @staticmethod
    def get_priority_from_parent(parent: p.Ldif.SchemaQuirk | None) -> int:
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
        quirk_class: type,
    ) -> c.Ldif.ServerTypeLiteral:
        """Infer the server type from the utilities namespace."""
        return u.Ldif.get_parent_server_type(quirk_class)

    def _get_parent_quirk_safe(self) -> p.Ldif.SchemaQuirk | None:
        """Get the effective parent quirk safely."""
        return FlextLdifQuirkMethodsMixin.get_parent_quirk_from_instance(self)

    def _get_priority(self) -> int:
        """Get server priority from the parent Constants class."""
        return FlextLdifQuirkMethodsMixin.get_priority_from_parent(
            self._get_parent_quirk_safe(),
        )

    def _get_server_type(self) -> c.Ldif.ServerTypeLiteral:
        """Resolve server type for the current quirk class."""
        return FlextLdifQuirkMethodsMixin.get_server_type_from_utilities(type(self))


__all__: list[str] = ["FlextLdifQuirkMethodsMixin"]
