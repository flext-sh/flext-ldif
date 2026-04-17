"""Processing Models - Type-safe processing results."""

from __future__ import annotations

from typing import Annotated

from flext_cli import m, u
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
