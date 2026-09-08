"""Schema utilities facade for FLEXT-LDIF.

Composed from focused MRO mixins; public API remains ``FlextLdifUtilitiesSchema``.
"""

from __future__ import annotations

from .schema_build import FlextLdifUtilitiesSchemaBuild
from .schema_extract import FlextLdifUtilitiesSchemaExtract
from .schema_format import FlextLdifUtilitiesSchemaFormat
from .schema_normalize import FlextLdifUtilitiesSchemaNormalize
from .schema_parse import FlextLdifUtilitiesSchemaParse


class FlextLdifUtilitiesSchema(
    FlextLdifUtilitiesSchemaFormat,
    FlextLdifUtilitiesSchemaExtract,
    FlextLdifUtilitiesSchemaNormalize,
    FlextLdifUtilitiesSchemaBuild,
    FlextLdifUtilitiesSchemaParse,
):
    """Generic schema-definition normalization utilities."""


__all__: list[str] = ["FlextLdifUtilitiesSchema"]
