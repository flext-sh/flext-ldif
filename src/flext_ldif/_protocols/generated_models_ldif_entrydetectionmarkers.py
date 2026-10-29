# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contract.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/generated_models_ldif_entrydetectionmarkers
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


class FlextLdifLdifProtocolsGeneratedModelsEntryDetectionMarkers:
    """Own the structural model contract declared by this module."""

    @runtime_checkable
    class EntryDetectionMarkers(Protocol):
        """Structural data contract projected from the owning model."""

        dn_markers: frozenset[str]
        objectclass_names: frozenset[str]
        attribute_names: frozenset[str]
        attribute_prefixes: frozenset[str]


__all__: list[str] = [
    "FlextLdifLdifProtocolsGeneratedModelsEntryDetectionMarkers",
]
