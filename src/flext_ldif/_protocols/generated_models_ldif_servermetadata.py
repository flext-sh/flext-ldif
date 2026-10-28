# AUTO-GENERATED FILE — Regenerate with: make gen
from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import MutableMapping as collections_abc_MutableMapping

    import pydantic

    from flext_ldif import c as flext_ldif_c, t as flext_ldif_t
    from flext_ldif._protocols import (
        FlextLdifLdifProtocolsGeneratedModelsAclEntryConversion,
        FlextLdifLdifProtocolsGeneratedModelsEntryStatistics,
        FlextLdifLdifProtocolsGeneratedModelsValidationMetadata,
        FlextLdifProtocolsBase,
    )


class FlextLdifLdifProtocolsGeneratedModelsServerMetadata:
    @runtime_checkable
    class ServerMetadata(Protocol):
        server_type: flext_ldif_c.Ldif.ServerTypes
        extensions: collections_abc_MutableMapping[str, pydantic.JsonValue]
        rfc_violations: flext_ldif_t.MutableSequenceOf[str]
        rfc_warnings: flext_ldif_t.MutableSequenceOf[str]
        conversion_notes: collections_abc_MutableMapping[str, pydantic.JsonValue]
        attribute_transformations: collections_abc_MutableMapping[
            str,
            FlextLdifProtocolsBase.AttributeTransformation,
        ]
        server_specific_data: collections_abc_MutableMapping[str, pydantic.JsonValue]
        original_server_type: flext_ldif_c.Ldif.ServerTypes | None
        target_server_type: flext_ldif_c.Ldif.ServerTypes | None
        acls: flext_ldif_t.MutableSequenceOf[str]
        objectclasses: flext_ldif_t.MutableSequenceOf[str]
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
        soft_delete_markers: flext_ldif_t.MutableSequenceOf[str]
        original_attribute_case: collections_abc_MutableMapping[str, pydantic.JsonValue]
        schema_servers_applied: flext_ldif_t.MutableSequenceOf[str]
        boolean_conversions: collections_abc_MutableMapping[str, pydantic.JsonValue]
        minimal_differences: collections_abc_MutableMapping[str, pydantic.JsonValue]
        original_strings: collections_abc_MutableMapping[str, pydantic.JsonValue]
        conversion_history: flext_ldif_t.MutableSequenceOf[
            collections_abc_MutableMapping[str, str]
        ]


__all__ = ["FlextLdifLdifProtocolsGeneratedModelsServerMetadata"]
