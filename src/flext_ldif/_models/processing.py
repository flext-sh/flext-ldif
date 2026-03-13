"""Processing Models - Type-safe processing results."""

from __future__ import annotations

from pydantic import ConfigDict, Field

from flext_ldif._models.base import FlextLdifModelsBase


class FlextLdifModelsProcessing:
    """Processing model namespace."""

    class ProcessingResult(FlextLdifModelsBase):
        """Result of entry processing (transform or validate operation)."""

        model_config = ConfigDict(frozen=False, validate_assignment=True)
        dn: Annotated[
            str, Field(..., description="Distinguished name of the processed entry")
        ]
        attributes: Annotated[
            dict[str, list[str]],
            Field(..., description="LDAP attributes as name -> list of values"),
        ]
