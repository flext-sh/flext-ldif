"""Lazy ``Ldif``-tree metaclass for the LDIF utilities facade.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import cast


class FlextLdifUtilitiesLazyMeta(type):
    """Assemble ``Ldif`` on first class-level access."""

    def __getattr__(cls, name: str) -> type:
        """Assemble and return the ``Ldif`` tree on first class-level access.

        Returns:
            The resulting ``type``.

        Raises:
            AttributeError: If type object.
        """
        if name == "Ldif":
            build_tree = cls.build_ldif_tree
            return cast("type", build_tree())
        msg = f"type object {cls.__name__!r} has no attribute {name!r}"
        raise AttributeError(msg)
