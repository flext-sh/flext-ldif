# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/processing
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Literal, Protocol, runtime_checkable

from flext_cli import FlextCliProtocols

if TYPE_CHECKING:
    from flext_ldif import t
    from flext_ldif._protocols import FlextLdifProtocolsDomainEntry
    from flext_ldif._protocols._settings import FlextLdifProtocolsSettingsProcessing


class FlextLdifProtocolsProcessing:
    """Own the structural contracts declared by its model source."""

    @runtime_checkable
    class ProcessingPipelineOptions(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def transform_config(
            self,
        ) -> FlextLdifProtocolsSettingsProcessing.TransformConfig | None:
            """Transformation configuration for the ordered entry pipeline."""
            ...

        @property
        def entries_input(self) -> Sequence[FlextLdifProtocolsDomainEntry.Entry] | None:
            """Entry batch supplied to the processing pipeline."""
            ...

    @runtime_checkable
    class ProcessingResult(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        dn: str
        attributes: t.MutableStrSequenceMapping

    @runtime_checkable
    class ProcessEntriesOptions(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        processor_name: Literal["transform", "validate"]
        parallel: bool
        batch_size: int
        max_workers: int


__all__: list[str] = [
    "FlextLdifProtocolsProcessing",
]
