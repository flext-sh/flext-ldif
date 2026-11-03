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
    from flext_ldif._protocols import FlextLdifProtocolsValues


class FlextLdifProtocolsProcessing:
    """Own the structural contracts declared by its model source."""

    @runtime_checkable
    class ProcessingPipelineOptions(FlextCliProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def transform_config(self) -> FlextLdifProtocolsValues.TransformConfig | None:
            """Transformation configuration for the ordered entry pipeline."""
            ...

        @property
        def entries_input(self) -> Sequence[FlextLdifProtocolsValues.Entry] | None:
            """Entry batch supplied to the processing pipeline."""
            ...

    @runtime_checkable
    class ProcessingResult(FlextCliProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def dn(self) -> str:
            """Distinguished name of the processed entry."""
            ...

        @property
        def attributes(self) -> t.MutableStrSequenceMapping:
            """LDAP attributes as name -> list of values."""
            ...

    @runtime_checkable
    class ProcessEntriesOptions(FlextCliProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def processor_name(self) -> Literal["transform", "validate"]:
            """Canonical processor name for entry handling."""
            ...

        @property
        def parallel(self) -> bool:
            """Enable thread-pool execution mode."""
            ...

        @property
        def batch_size(self) -> int:
            """Batch size for sequential processing."""
            ...

        @property
        def max_workers(self) -> int:
            """Maximum thread workers for parallel mode."""
            ...


__all__: list[str] = [
    "FlextLdifProtocolsProcessing",
]
