"""Processing Models - Type-safe processing results.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Annotated, Literal

from flext_cli import m

from flext_ldif import t
from flext_ldif._models import (
    FlextLdifModelsDomainsEntries,
    FlextLdifModelsSettingsProcessing,
)


class FlextLdifModelsProcessing:
    """Processing model namespace."""

    class ProcessingPipelineOptions(m.ArbitraryTypesModel):
        """Owned input batch and optional transformation configuration."""

        transform_config: FlextLdifModelsSettingsProcessing.TransformConfig | None = (
            m.Field(
                default=None,
                exclude=True,
                description=(
                    "Transformation configuration for the ordered entry pipeline"
                ),
            )
        )
        entries_input: t.SequenceOf[FlextLdifModelsDomainsEntries.Entry] | None = (
            m.Field(
                default=None,
                exclude=True,
                description="Entry batch supplied to the processing pipeline",
            )
        )

    class ProcessingResult(m.StrictModel):
        """Result of entry processing (transform or validate operation)."""

        dn: Annotated[
            str,
            m.Field(..., description="Distinguished name of the processed entry"),
        ]
        attributes: Annotated[
            t.MutableStrSequenceMapping,
            m.Field(..., description="LDAP attributes as name -> list of values"),
        ]

    class ProcessEntriesOptions(m.StrictModel):
        """Validated options for batch/parallel entry processing."""

        processor_name: Annotated[
            Literal["transform", "validate"],
            m.Field(description="Canonical processor name for entry handling."),
        ]
        parallel: Annotated[
            bool,
            m.Field(description="Enable thread-pool execution mode."),
        ] = False
        batch_size: Annotated[
            int,
            m.Field(ge=1, description="Batch size for sequential processing."),
        ] = 100
        max_workers: Annotated[
            int,
            m.Field(ge=1, description="Maximum thread workers for parallel mode."),
        ] = 4


__all__: list[str] = ["FlextLdifModelsProcessing"]
