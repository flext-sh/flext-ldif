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
