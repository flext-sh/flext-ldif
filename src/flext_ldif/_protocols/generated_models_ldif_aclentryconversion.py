# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contract.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/generated_models_ldif_aclentryconversion
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from flext_ldif._protocols import FlextLdifProtocolsValues


class FlextLdifLdifProtocolsGeneratedModelsAclEntryConversion:
    """Own the structural model contract declared by this module."""

    @runtime_checkable
    class AclEntryConversion(Protocol):
        """Structural data contract projected from the owning model."""

        rules: tuple[FlextLdifProtocolsValues.AciRule, ...]
        oracle_internal_skip: bool


__all__: list[str] = [
    "FlextLdifLdifProtocolsGeneratedModelsAclEntryConversion",
]
