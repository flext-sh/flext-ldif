"""Base server MRO-based server type and priority resolution.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import u


class FlextLdifServersBaseMroMixin:
    """Resolve server type/priority from family Constants through the MRO."""

    def _get_server_type(self) -> str:
        """Get server_type from parent class Constants via MRO traversal.

        Returns:
            The resulting ``str``.
        """
        return self._get_server_type_from_mro(type(self))

    @classmethod
    def _get_priority_from_mro(cls, server_class: type) -> int:
        """Get priority from parent class Constants via MRO traversal.

        Returns:
            The resulting ``int``.

        Raises:
            AttributeError: If Cannot find PRIORITY in Constants for server class.
        """
        for mro_cls in server_class.__mro__:
            if not mro_cls.__name__.startswith(
                "FlextLdifServers",
            ) or mro_cls.__name__.endswith(("Schema", "Acl", "Entry")):
                continue
            priority = getattr(getattr(mro_cls, "Constants", None), "PRIORITY", None)
            if isinstance(priority, int):
                return priority
        msg = (
            f"Cannot find PRIORITY in Constants for server class: "
            f"{server_class.__name__}"
        )
        raise AttributeError(msg)

    @classmethod
    def _get_server_type_from_mro(cls, server_class: type) -> str:
        """Get server_type from parent class Constants via MRO traversal.

        Returns:
            The resulting ``str``.

        Raises:
            AttributeError: If Cannot find SERVER_TYPE in Constants for server class.
        """
        for mro_cls in server_class.__mro__:
            if not mro_cls.__name__.startswith(
                "FlextLdifServers",
            ) or mro_cls.__name__.endswith(("Schema", "Acl", "Entry")):
                continue
            server_type = getattr(
                getattr(mro_cls, "Constants", None),
                "SERVER_TYPE",
                None,
            )
            if isinstance(server_type, str) and server_type:
                normalized: str = u.Ldif.normalize_server_type(server_type)
                return normalized
        msg = (
            f"Cannot find SERVER_TYPE in Constants for server class: "
            f"{server_class.__name__}"
        )
        raise AttributeError(msg)


__all__: list[str] = ["FlextLdifServersBaseMroMixin"]
