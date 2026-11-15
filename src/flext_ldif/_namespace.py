"""Lazy class-level namespace attribute for the LDIF utilities facade.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Protocol


class FlextLdifLazyNamespace:
    """Assemble the ``Ldif`` tree on first access through the owning class.

    A real class outside the facade MRO (root ADR-018 stand-in composition
    law, rule 5): the facade part holds one instance as a class attribute, so
    no part defines a dunder and the facade needs no metaclass.
    """

    class Builder(Protocol):
        """The owner contract: it builds the ``Ldif`` namespace class."""

        @staticmethod
        def build_ldif_tree() -> type:
            """Return the assembled ``Ldif`` namespace class."""
            ...

    def __get__(self, instance: object, owner: type[Builder]) -> type:
        """Return the ``Ldif`` namespace class of the owning facade.

        Returns:
            The assembled, cached ``Ldif`` utility namespace class.

        """
        return owner.build_ldif_tree()


__all__: list[str] = ["FlextLdifLazyNamespace"]
