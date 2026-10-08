"""LDIF server type resolution utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import sys
from typing import TypeIs

from flext_core import r
from flext_ldif import c, p, t


class FlextLdifServerTypeResolution:
    """Resolve ``ServerTypes`` from server class naming and Constants."""

    @staticmethod
    def _is_valid_server_type(value: str) -> TypeIs[c.Ldif.ServerTypes]:
        return value in c.Ldif.VALID_SERVER_TYPES

    @staticmethod
    def _extract_server_name(name_without_prefix: str) -> p.Result[str]:
        """Extract server name from class name suffix.

        Returns:
            The resulting ``p.Result[str]``.
        """
        for suffix in c.Ldif.CLASS_SUFFIXES:
            if name_without_prefix.endswith(suffix):
                server_name = name_without_prefix[: -len(suffix)]
                if server_name:
                    return r[str].ok(server_name)
                return r[str].fail("Server name is empty after suffix extraction")
        return r[str].fail("Class name does not contain a supported server suffix")

    @staticmethod
    def extract_server_type_from_constants(
        cls_with_constants: type | None,
    ) -> c.Ldif.ServerTypes | None:
        """Extract server type from a class's Constants.SERVER_TYPE.

        Returns:
            The resulting ``c.Ldif.ServerTypes | None``.
        """
        if cls_with_constants is None:
            return None
        constants_obj: type | None = vars(cls_with_constants).get("Constants")
        if not isinstance(constants_obj, type):
            return None
        server_type_raw = getattr(constants_obj, "SERVER_TYPE", None)
        if (
            server_type_raw is not None
            and FlextLdifServerTypeResolution._is_valid_server_type(server_type_raw)
        ):
            return c.Ldif.ServerTypes(server_type_raw)
        return None

    @staticmethod
    def _get_type_from_independent_class(target_cls: type) -> c.Ldif.ServerTypes | None:
        """Extract server type from independent class naming pattern.

        Returns:
            The resulting ``c.Ldif.ServerTypes | None``.
        """
        class_name = target_cls.__name__
        if not class_name.startswith("FlextLdifServers"):
            return None
        name_without_prefix = class_name[len("FlextLdifServers") :]
        extract_result = FlextLdifServerTypeResolution._extract_server_name(
            name_without_prefix,
        )
        if extract_result.success:
            server_type_lower = extract_result.value.lower()
            if FlextLdifServerTypeResolution._is_valid_server_type(server_type_lower):
                return c.Ldif.ServerTypes(server_type_lower)
        return None

    @staticmethod
    def _resolve_parent_class(target_cls: type) -> type | None:
        """Walk the qualname chain to the enclosing parent class.

        Returns:
            The resulting ``type | None``.
        """
        qualname_parts = target_cls.__qualname__.split(".")
        if len(qualname_parts) <= 1:
            return None
        parent_module = sys.modules.get(target_cls.__module__)
        if not parent_module:
            return None
        parent_obj: type | None = vars(parent_module).get(qualname_parts[0])
        for part in qualname_parts[1:-1]:
            if isinstance(parent_obj, type):
                parent_obj = vars(parent_obj).get(part)
        return parent_obj if isinstance(parent_obj, type) else None

    @staticmethod
    def _server_type_from_parent(target_cls: type) -> c.Ldif.ServerTypes | None:
        """Extract server type from the enclosing parent class Constants.

        Returns:
            The resulting ``c.Ldif.ServerTypes | None``.
        """
        parent_obj = FlextLdifServerTypeResolution._resolve_parent_class(target_cls)
        if parent_obj is not None:
            return FlextLdifServerTypeResolution.extract_server_type_from_constants(
                parent_obj,
            )
        return None

    @staticmethod
    def _server_type_from_mro(target_cls: type) -> c.Ldif.ServerTypes | None:
        """Extract server type from any class in the MRO Constants.

        Returns:
            The resulting ``c.Ldif.ServerTypes | None``.
        """
        for mro_cls in target_cls.__mro__:
            result = FlextLdifServerTypeResolution.extract_server_type_from_constants(
                mro_cls,
            )
            if result is not None:
                return result
        return None

    @staticmethod
    def _get_type_from_nested_class(target_cls: type) -> c.Ldif.ServerTypes | None:
        """Extract server type from nested class via parent's Constants.

        Returns:
            The resulting ``c.Ldif.ServerTypes | None``.
        """
        from_parent = FlextLdifServerTypeResolution._server_type_from_parent(target_cls)
        if from_parent is not None:
            return from_parent
        return FlextLdifServerTypeResolution._server_type_from_mro(target_cls)

    @staticmethod
    def resolve_parent_server_type(
        nested_class_instance_or_type: type | t.JsonValue,
    ) -> c.Ldif.ServerTypes:
        """Get server_type from parent server class via __qualname__.

        Returns:
            The resulting ``c.Ldif.ServerTypes``.

        Raises:
            AttributeError: Always.
        """
        cls = (
            nested_class_instance_or_type
            if isinstance(nested_class_instance_or_type, type)
            else nested_class_instance_or_type.__class__
        )
        server_type = FlextLdifServerTypeResolution._get_type_from_nested_class(cls)
        if server_type:
            return server_type
        server_type = FlextLdifServerTypeResolution._get_type_from_independent_class(
            cls,
        )
        if server_type:
            return server_type
        msg = f"{cls.__name__} nested class must have parent with Constants.SERVER_TYPE"
        raise AttributeError(msg)


__all__: list[str] = ["FlextLdifServerTypeResolution"]
