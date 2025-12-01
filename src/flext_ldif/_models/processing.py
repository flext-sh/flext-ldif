"""Processing Models - Type-safe processing results.

Provides typed models for processing service results, replacing generic
dict[str, object] returns with proper Pydantic models.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pydantic import ConfigDict, Field

from flext_ldif._models.base import FlextLdifModelsBase


class ProcessingResult(FlextLdifModelsBase):
    """Result of entry processing (transform or validate operation).

    Replaces dict[str, object] returns from processing service to provide
    type-safe structured results matching EntryProtocol contract.

    Attributes:
        dn: Distinguished name of the processed entry
        attributes: LDAP attributes (name -> list of values)

    Example:
        >>> result = ProcessingResult(
        ...     dn="cn=test,dc=example,dc=com",
        ...     attributes={"cn": ["test"], "objectClass": ["person"]},
        ... )
        >>> result.dn
        'cn=test,dc=example,dc=com'

    """

    model_config = ConfigDict(frozen=False, validate_assignment=True)

    dn: str = Field(
        ...,
        description="Distinguished name of the processed entry",
    )

    attributes: dict[str, list[str]] = Field(
        ...,
        description="LDAP attributes as name -> list of values",
    )
