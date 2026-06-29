"""Schema utilities facade for FLEXT-LDIF.

Composed from focused MRO mixins; public API remains ``FlextLdifUtilitiesSchema``.
"""

from __future__ import annotations

from flext_ldif._utilities.schema_build import FlextLdifUtilitiesSchemaBuild
from flext_ldif._utilities.schema_extract import FlextLdifUtilitiesSchemaExtract
from flext_ldif._utilities.schema_format import FlextLdifUtilitiesSchemaFormat
from flext_ldif._utilities.schema_normalize import FlextLdifUtilitiesSchemaNormalize
from flext_ldif._utilities.schema_parse import FlextLdifUtilitiesSchemaParse


class FlextLdifUtilitiesSchema(
    FlextLdifUtilitiesSchemaFormat,
    FlextLdifUtilitiesSchemaExtract,
    FlextLdifUtilitiesSchemaNormalize,
    FlextLdifUtilitiesSchemaBuild,
    FlextLdifUtilitiesSchemaParse,
):
    """Generic schema-definition normalization utilities."""


__all__: list[str] = ["FlextLdifUtilitiesSchema"]
