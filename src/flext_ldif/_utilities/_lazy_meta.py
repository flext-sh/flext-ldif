"""Lazy ``Ldif``-tree metaclass for the LDIF utilities facade.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import cast


class FlextLdifUtilitiesLazyMeta(type):
    """Assemble ``Ldif`` on first class-level access."""

    def __getattr__(cls, name: str):
        """Assemble and return the ``Ldif`` tree on first class-level access.

        For all other attributes, delegate to the normal MRO to allow access
        to inherited classmethods (e.g., TypeAdapter factories from flext-core).

        Returns:
            The resulting ``type`` for ``Ldif``, or the inherited attribute.

        Raises:
            AttributeError: If attribute not found in MRO.
        """
        if name == "Ldif":
            build_tree = cls.build_ldif_tree
            return cast("type", build_tree())
        return super().__getattr__(name)
