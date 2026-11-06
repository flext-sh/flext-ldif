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
    class Stats(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        total_entries: t.NonNegativeInt
        successful: t.NonNegativeInt
        failed: t.NonNegativeInt

    @runtime_checkable
    class OidAclMetadataConfig(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        acl_line: str
        oid_subject_type: str
        rfc_subject_type: str
        oid_subject_value: str
        perms_dict: t.MutableBoolMapping
        target_dn: str
        target_attrs: MutableSequence[str]
        acl_filter: str
        acl_constraint: str
        bindmode: str
        deny_group_override: bool
        append_to_all: bool
        bind_ip_filter: str
        constrain_to_added_object: str


__all__: list[str] = [
    "FlextLdifProtocolsComposite",
]
