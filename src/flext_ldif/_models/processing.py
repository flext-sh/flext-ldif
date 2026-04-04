"""Processing Models - Type-safe processing results."""

from __future__ import annotations

from typing import Annotated

from pydantic import Field

from flext_core import m
from flext_ldif import FlextLdifTypes as t


class FlextLdifModelsProcessing:
    """Processing model namespace."""

    class ProcessingResult(m.StrictModel):
        """Result of entry processing (transform or validate operation)."""

        dn: Annotated[
            str,
            Field(..., description="Distinguished name of the processed entry"),
        ]
        attributes: Annotated[
            t.MutableStrSequenceMapping,
            Field(..., description="LDAP attributes as name -> list of values"),
        ]
