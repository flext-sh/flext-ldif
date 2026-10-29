# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contract.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/generated_models_ldif_servermetadata
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import (
        MutableMapping as collections_abc_MutableMapping,
        MutableSequence as collections_abc_MutableSequence,
    )

    import pydantic

    from flext_ldif import c as flext_ldif_c
    from flext_ldif._protocols import (
        FlextLdifLdifProtocolsGeneratedModelsAclEntryConversion,
        FlextLdifLdifProtocolsGeneratedModelsEntryStatistics,
        FlextLdifLdifProtocolsGeneratedModelsValidationMetadata,
        FlextLdifProtocolsBase,
    )


class FlextLdifLdifProtocolsGeneratedModelsServerMetadata:
    """Own the structural model contract declared by this module."""

    @runtime_checkable
    class ServerMetadata(Protocol):
        """Structural data contract projected from the owning model."""

        server_type: flext_ldif_c.Ldif.ServerTypes
        extensions: collections_abc_MutableMapping[str, pydantic.JsonValue]
        rfc_violations: collections_abc_MutableSequence[str]
        rfc_warnings: collections_abc_MutableSequence[str]
        conversion_notes: collections_abc_MutableMapping[str, pydantic.JsonValue]
        attribute_transformations: collections_abc_MutableMapping[
            str,
            FlextLdifProtocolsBase.AttributeTransformation,
        ]
        server_specific_data: collections_abc_MutableMapping[str, pydantic.JsonValue]
        original_server_type: flext_ldif_c.Ldif.ServerTypes | None
        target_server_type: flext_ldif_c.Ldif.ServerTypes | None
        acls: collections_abc_MutableSequence[str]
        objectclasses: collections_abc_MutableSequence[str]
        validation_results: (
            FlextLdifLdifProtocolsGeneratedModelsValidationMetadata.ValidationMetadata
            | None
        )
        processing_stats: (
            FlextLdifLdifProtocolsGeneratedModelsEntryStatistics.EntryStatistics | None
        )
        write_options: FlextLdifProtocolsBase.WriteOptions | None
        removed_attributes: collections_abc_MutableMapping[str, pydantic.JsonValue]
        original_format_details: FlextLdifProtocolsBase.FormatDetails | None
        schema_format_details: FlextLdifProtocolsBase.SchemaFormatDetails | None
        acl_conversion: (
            FlextLdifLdifProtocolsGeneratedModelsAclEntryConversion.AclEntryConversion
            | None
        )
        soft_delete_markers: collections_abc_MutableSequence[str]
        original_attribute_case: collections_abc_MutableMapping[str, pydantic.JsonValue]
        schema_servers_applied: collections_abc_MutableSequence[str]
        boolean_conversions: collections_abc_MutableMapping[str, pydantic.JsonValue]
        minimal_differences: collections_abc_MutableMapping[str, pydantic.JsonValue]
        original_strings: collections_abc_MutableMapping[str, pydantic.JsonValue]
        conversion_history: collections_abc_MutableSequence[
            collections_abc_MutableMapping[str, str]
        ]


__all__: list[str] = [
    "FlextLdifLdifProtocolsGeneratedModelsServerMetadata",
]
