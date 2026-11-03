# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/composite
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableSequence
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_cli import FlextCliProtocols

if TYPE_CHECKING:
    from flext_ldif import t


class FlextLdifProtocolsComposite:
    """Own the structural contracts declared by its model source."""

    @runtime_checkable
    class Stats(FlextCliProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def total_entries(self) -> t.NonNegativeInt:
            """Structural member projected from the owning model."""
            ...

        @property
        def successful(self) -> t.NonNegativeInt:
            """Structural member projected from the owning model."""
            ...

        @property
        def failed(self) -> t.NonNegativeInt:
            """Structural member projected from the owning model."""
            ...

    @runtime_checkable
    class OidAclMetadataConfig(FlextCliProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def acl_line(self) -> str:
            """Structural member projected from the owning model."""
            ...

        @property
        def oid_subject_type(self) -> str:
            """Structural member projected from the owning model."""
            ...

        @property
        def rfc_subject_type(self) -> str:
            """Structural member projected from the owning model."""
            ...

        @property
        def oid_subject_value(self) -> str:
            """Structural member projected from the owning model."""
            ...

        @property
        def perms_dict(self) -> t.MutableBoolMapping:
            """Structural member projected from the owning model."""
            ...

        @property
        def target_dn(self) -> str:
            """Structural member projected from the owning model."""
            ...

        target_attrs: MutableSequence[str]

        @property
        def acl_filter(self) -> str:
            """Structural member projected from the owning model."""
            ...

        @property
        def acl_constraint(self) -> str:
            """Structural member projected from the owning model."""
            ...

        @property
        def bindmode(self) -> str:
            """Structural member projected from the owning model."""
            ...

        @property
        def deny_group_override(self) -> bool:
            """Structural member projected from the owning model."""
            ...

        @property
        def append_to_all(self) -> bool:
            """Structural member projected from the owning model."""
            ...

        @property
        def bind_ip_filter(self) -> str:
            """Structural member projected from the owning model."""
            ...

        @property
        def constrain_to_added_object(self) -> str:
            """Structural member projected from the owning model."""
            ...


__all__: list[str] = [
    "FlextLdifProtocolsComposite",
]
