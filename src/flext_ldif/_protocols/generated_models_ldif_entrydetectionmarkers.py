"""Generated models ldif entrydetectionmarkers module.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/generated_models_ldif_entrydetectionmarkers
SPDX-License-Identifier: MIT
"""

# AUTO-GENERATED FILE — Regenerate with: make gen
from __future__ import annotations

from typing import Protocol, runtime_checkable


class FlextLdifLdifProtocolsGeneratedModelsEntryDetectionMarkers:
    @runtime_checkable
    class EntryDetectionMarkers(Protocol):
        dn_markers: frozenset[str]
        objectclass_names: frozenset[str]
        attribute_names: frozenset[str]
        attribute_prefixes: frozenset[str]


__all__ = ["FlextLdifLdifProtocolsGeneratedModelsEntryDetectionMarkers"]
