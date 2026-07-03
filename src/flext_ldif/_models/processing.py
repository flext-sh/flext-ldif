"""Processing Models - Type-safe processing results."""

from __future__ import annotations

from typing import Annotated, Literal

from flext_core import m
from flext_core.utilities import FlextUtilities as u
from flext_ldif import t


class FlextLdifModelsProcessing:
    """Processing model namespace."""

    class ProcessingResult(m.StrictModel):
        """Result of entry processing (transform or validate operation)."""

        dn: Annotated[
            str,
            u.Field(..., description="Distinguished name of the processed entry"),
        ]
        attributes: Annotated[
            t.MutableStrSequenceMapping,
            u.Field(..., description="LDAP attributes as name -> list of values"),
        ]

    class ProcessEntriesOptions(m.StrictModel):
        """Validated options for batch/parallel entry processing."""

        processor_name: Annotated[
            Literal["transform", "validate"],
            u.Field(description="Canonical processor name for entry handling."),
        ]
        parallel: Annotated[
            bool,
            u.Field(description="Enable thread-pool execution mode."),
        ] = False
        batch_size: Annotated[
            int,
            u.Field(ge=1, description="Batch size for sequential processing."),
        ] = 100
        max_workers: Annotated[
            int,
            u.Field(ge=1, description="Maximum thread workers for parallel mode."),
        ] = 4
