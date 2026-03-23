"""Processing Models - Type-safe processing results."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Annotated, ClassVar

from pydantic import ConfigDict, Field

from flext_ldif import FlextLdifModelsBases


class FlextLdifModelsProcessing:
    """Processing model namespace."""

    class ProcessingResult(FlextLdifModelsBases.Base):
        """Result of entry processing (transform or validate operation)."""

        model_config: ClassVar[ConfigDict] = ConfigDict(
            frozen=False, validate_assignment=True
        )
        dn: Annotated[
            str,
            Field(..., description="Distinguished name of the processed entry"),
        ]
        attributes: Annotated[
            Mapping[str, Sequence[str]],
            Field(..., description="LDAP attributes as name -> list of values"),
        ]
