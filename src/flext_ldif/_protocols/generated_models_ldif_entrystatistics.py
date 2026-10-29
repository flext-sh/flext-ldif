# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contract.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/generated_models_ldif_entrystatistics
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import (
        MutableMapping as collections_abc_MutableMapping,
        MutableSequence as collections_abc_MutableSequence,
    )

    from flext_ldif._protocols import FlextLdifProtocolsBase


class FlextLdifLdifProtocolsGeneratedModelsEntryStatistics:
    """Own the structural model contract declared by this module."""

    @runtime_checkable
    class EntryStatistics(Protocol):
        """Structural data contract projected from the owning model."""

        was_parsed: bool
        was_validated: bool
        was_filtered: bool
        was_written: bool
        was_rejected: bool
        rejection_category: str | None
        rejection_reason: str | None
        attributes_added: collections_abc_MutableSequence[str]
        attributes_removed: collections_abc_MutableSequence[str]
        attributes_modified: collections_abc_MutableSequence[str]
        attributes_filtered: collections_abc_MutableSequence[str]
        objectclasses_original: collections_abc_MutableSequence[str]
        objectclasses_final: collections_abc_MutableSequence[str]
        servers_applied: collections_abc_MutableSequence[str]
        server_transformations: int
        dn_statistics: FlextLdifProtocolsBase.DNStatistics | None
        filters_applied: collections_abc_MutableSequence[str]
        filter_results: collections_abc_MutableMapping[str, bool]
        errors: collections_abc_MutableSequence[str]
        warnings: collections_abc_MutableSequence[str]
        category_assigned: str | None
        category_confidence: float


__all__: list[str] = [
    "FlextLdifLdifProtocolsGeneratedModelsEntryStatistics",
]
