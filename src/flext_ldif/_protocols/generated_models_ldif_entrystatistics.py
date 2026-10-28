"""Generated models ldif entrystatistics module.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/generated_models_ldif_entrystatistics
SPDX-License-Identifier: MIT
"""

# AUTO-GENERATED FILE — Regenerate with: make gen
from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import MutableMapping as collections_abc_MutableMapping

    from flext_ldif import t as flext_ldif_t
    from flext_ldif._protocols import FlextLdifProtocolsBase


class FlextLdifProtocolsModelsLdifGeneratedEntryStatistics:
    @runtime_checkable
    class EntryStatistics(Protocol):
        was_parsed: bool
        was_validated: bool
        was_filtered: bool
        was_written: bool
        was_rejected: bool
        rejection_category: str | None
        rejection_reason: str | None
        attributes_added: flext_ldif_t.MutableSequence[str]
        attributes_removed: flext_ldif_t.MutableSequence[str]
        attributes_modified: flext_ldif_t.MutableSequence[str]
        attributes_filtered: flext_ldif_t.MutableSequence[str]
        objectclasses_original: flext_ldif_t.MutableSequence[str]
        objectclasses_final: flext_ldif_t.MutableSequence[str]
        servers_applied: flext_ldif_t.MutableSequence[str]
        server_transformations: int
        dn_statistics: FlextLdifProtocolsBase.DNStatistics | None
        filters_applied: flext_ldif_t.MutableSequence[str]
        filter_results: collections_abc_MutableMapping[str, bool]
        errors: flext_ldif_t.MutableSequence[str]
        warnings: flext_ldif_t.MutableSequence[str]
        category_assigned: str | None
        category_confidence: float


__all__ = ["FlextLdifProtocolsModelsLdifGeneratedEntryStatistics"]
