"""Domain models for LDIF metadata.

Namespace mixin extracted from domain_entries.py containing
ValidationMetadata, WriteOptions, FormatDetails, SchemaFormatDetails,
and QuirkMetadata inner classes.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import MutableMapping, MutableSequence
from typing import Annotated, Self

from pydantic import BaseModel, Field, field_validator

from flext_core import m
from flext_ldif import (
    FlextLdifModelsDomainAttributes,
    FlextLdifModelsMetadata,
    FlextLdifShared,
    c,
    t,
)


class FlextLdifModelsDomainMetadata:
    """Namespace mixin for LDIF metadata domain models."""

    class ValidationMetadata(m.FrozenModel):
        """Validation results and error tracking metadata.

        Composed model for QuirkMetadata.validation_results field.
        """

        rfc_violations: Annotated[
            MutableSequence[str],
            Field(
                description="RFC violations detected during validation",
            ),
        ]
        errors: Annotated[
            MutableSequence[str],
            Field(description="Validation errors that occurred"),
        ]
        warnings: Annotated[
            MutableSequence[str],
            Field(description="Non-fatal validation warnings"),
        ]
        context: Annotated[
            t.MutableStrMapping,
            Field(description="Validation context information"),
        ]
        server_specific_violations: Annotated[
            MutableSequence[str],
            Field(
                description="Server-specific validation violations",
            ),
        ]
        validation_server_type: Annotated[
            c.Ldif.ServerTypeLiteral | None,
            Field(description="Server type used for validation"),
        ] = None

    class WriteOptions(m.FrozenModel):
        """LDIF writing configuration options.

        Composed model for QuirkMetadata.write_options field.
        """

        format: Annotated[
            str | None,
            Field(
                description="LDIF format variant (rfc2849, extended, etc.)",
            ),
        ] = None
        base_dn: Annotated[
            str | None,
            Field(description="Base DN for relative DN conversions"),
        ] = None
        hidden_attrs: Annotated[
            MutableSequence[str],
            Field(
                description="Attributes to exclude from output",
            ),
        ] = Field(default_factory=list)
        sort_entries: Annotated[
            bool,
            Field(description="Whether to sort entries in output"),
        ] = False
        include_comments: Annotated[
            bool,
            Field(description="Whether to include comment lines"),
        ] = False
        base64_encode_binary: Annotated[
            bool,
            Field(
                description="Whether to base64 encode binary attributes",
            ),
        ] = False

    class FormatDetails(m.FrozenModel):
        """Original formatting details for round-trip preservation.

        Composed model for QuirkMetadata.original_format_details field.
        """

        dn_line: Annotated[
            str | None,
            Field(description="Original DN line formatting"),
        ] = None
        syntax: Annotated[
            str | None,
            Field(description="Original attribute syntax information"),
        ] = None
        encoding: Annotated[
            c.Ldif.EncodingLiteral | None,
            Field(description="Original encoding (utf-8, etc.)"),
        ] = None
        spacing: Annotated[
            str | None,
            Field(description="Original spacing/indentation"),
        ] = None
        trailing_info: Annotated[
            str | None,
            Field(description="Trailing comments or metadata"),
        ] = None

    class SchemaFormatDetails(m.FrozenModel):
        """Schema formatting details for perfect round-trip conversion.

        Composed model for QuirkMetadata.schema_format_details field.
        """

        original_string_complete: Annotated[
            str | None,
            Field(
                description="Complete original schema definition string for perfect round-trip",
            ),
        ] = None
        quotes: Annotated[
            str | None,
            Field(description="Quoting style used in schema definition"),
        ] = None
        spacing: Annotated[
            str | None,
            Field(description="Spacing around schema fields"),
        ] = None
        field_order: Annotated[
            MutableSequence[str],
            Field(
                description="Original order of schema fields",
            ),
        ] = Field(default_factory=list)
        x_origin: Annotated[
            str | None,
            Field(description="X-ORIGIN value from schema"),
        ] = None
        x_ordered: Annotated[
            MutableSequence[str],
            Field(
                description="X-ORDERED field values",
            ),
        ] = Field(default_factory=list)
        extensions: Annotated[
            FlextLdifModelsMetadata.DynamicMetadata,
            Field(
                description="Non-standard schema extensions",
            ),
        ] = Field(default_factory=FlextLdifModelsMetadata.DynamicMetadata)

    class QuirkMetadata(m.DynamicModel):
        """Universal metadata container for quirk-specific data preservation.

        Used to store server-specific quirks, transformations, and metadata
        that needs to be preserved during LDIF processing operations.

        Extended with RFC compliance tracking, conversion history, and
        server-specific data preservation for complete audit trails.

        Attributes:
            quirk_type: Type of quirk this metadata represents
            extensions: Extensible metadata storage for quirk-specific data

            # RFC Compliance Tracking (Phase 1: Enhanced Validation)
            rfc_violations: List of RFC violations detected in entry/attribute
            rfc_warnings: List of non-fatal RFC warnings

            # Conversion Tracking (Phase 1: Audit Trail)
            conversion_notes: Map of conversion operation → description
            attribute_transformations: Detailed attribute transformation records

            # Server-Specific Data (Phase 1: Round-trip Support)
            server_specific_data: Preservation of server-proprietary data
            original_server_type: Source server type (oid, oud, etc.)
            target_server_type: Target server type (oid, oud, etc.)

        """

        quirk_type: Annotated[
            c.Ldif.ServerTypes | c.Ldif.ServerTypeLiteral,
            Field(
                ...,
                description="Type of quirk this metadata represents (ServerTypes enum or literal)",
            ),
        ]
        extensions: Annotated[
            FlextLdifModelsMetadata.DynamicMetadata,
            Field(
                description="Extensible metadata storage for quirk-specific data (server-injected validation rules, unconverted attributes, etc.)",
            ),
        ] = Field(default_factory=FlextLdifModelsMetadata.DynamicMetadata)
        rfc_violations: Annotated[
            MutableSequence[str],
            Field(
                description="RFC violations detected (e.g., 'RFC 2849 §2: DN required')",
            ),
        ] = Field(default_factory=list)
        rfc_warnings: Annotated[
            MutableSequence[str],
            Field(
                description="Non-fatal RFC warnings (e.g., unusual but valid formatting)",
            ),
        ] = Field(default_factory=list)
        conversion_notes: Annotated[
            FlextLdifModelsMetadata.DynamicMetadata,
            Field(
                description="Map of conversion operation name → human-readable description",
            ),
        ] = Field(default_factory=FlextLdifModelsMetadata.DynamicMetadata)
        attribute_transformations: MutableMapping[
            str,
            FlextLdifModelsDomainAttributes.AttributeTransformation,
        ] = Field(
            default_factory=dict,
            description="Detailed transformation records keyed by original attribute name",
        )
        server_specific_data: Annotated[
            FlextLdifModelsMetadata.EntryMetadata,
            Field(
                description="Preservation of server-proprietary data for round-trip conversions",
            ),
        ] = Field(default_factory=FlextLdifModelsMetadata.EntryMetadata)
        original_server_type: Annotated[
            c.Ldif.ServerTypeLiteral | None,
            Field(
                description="Source LDAP server type (e.g., 'oid', 'oud', 'ad', 'openldap')",
            ),
        ] = None
        target_server_type: Annotated[
            c.Ldif.ServerTypeLiteral | None,
            Field(
                description="Target LDAP server type (e.g., 'oid', 'oud', 'ad', 'openldap')",
            ),
        ] = None
        acls: Annotated[
            MutableSequence[str],
            Field(
                description="Access Control Lists extracted from entry attributes during parsing",
            ),
        ] = Field(default_factory=list)
        objectclasses: Annotated[
            MutableSequence[str],
            Field(
                description="ObjectClass definitions for schema validation (not RFC LDIF data)",
            ),
        ] = Field(default_factory=list)
        validation_results: FlextLdifModelsDomainMetadata.ValidationMetadata | None = (
            Field(
                default=None,
                description="Validation results with RFC violations, errors, warnings, and context",
            )
        )
        processing_stats: BaseModel | None = Field(
            default=None,
            description="Complete statistics tracking for entry transformations (accepts EntryStatistics)",
        )
        write_options: FlextLdifModelsDomainMetadata.WriteOptions | None = Field(
            default=None,
            description="Writer configuration including format, base DN, hidden attributes, sorting, and comments",
        )
        removed_attributes: Annotated[
            FlextLdifModelsMetadata.DynamicMetadata,
            Field(
                description="Attributes removed during conversion (was entry_metadata.removed_attributes_with_values)",
            ),
        ] = Field(default_factory=FlextLdifModelsMetadata.DynamicMetadata)
        original_format_details: FlextLdifModelsDomainMetadata.FormatDetails | None = (
            Field(
                default=None,
                description="Original formatting details for round-trip preservation (DN line, syntax, encoding, spacing)",
            )
        )
        schema_format_details: (
            FlextLdifModelsDomainMetadata.SchemaFormatDetails | None
        ) = Field(
            default=None,
            description="Schema formatting details for round-trip preservation",
        )
        soft_delete_markers: Annotated[
            MutableSequence[str],
            Field(
                description="Attributes soft-deleted during conversion (can be restored). Different from removed_attributes: these are intentionally hidden for target server but preserved for reverse conversion.",
            ),
        ] = Field(default_factory=list)
        original_attribute_case: Annotated[
            FlextLdifModelsMetadata.DynamicMetadata,
            Field(
                description="Original case of attribute names: {'objectclass': 'objectClass', 'cn': 'CN'}. Used to restore original case during reverse conversion.",
            ),
        ] = Field(default_factory=FlextLdifModelsMetadata.DynamicMetadata)
        schema_quirks_applied: Annotated[
            MutableSequence[str],
            Field(
                description="List of schema quirks applied during parsing: ['matching_rule_normalization', 'syntax_oid_conversion', 'schema_dn_quirk']",
            ),
        ] = Field(default_factory=list)
        boolean_conversions: Annotated[
            FlextLdifModelsMetadata.DynamicMetadata,
            Field(
                description="Boolean conversion tracking: {'orcldasisenabled': {'original': '1', 'converted': 'TRUE', 'format': 'OID->RFC'}}",
            ),
        ] = Field(default_factory=FlextLdifModelsMetadata.DynamicMetadata)
        minimal_differences: Annotated[
            FlextLdifModelsMetadata.DynamicMetadata,
            Field(
                description="Complete minimal differences tracking for zero data loss: {'dn': {'has_differences': True, 'original': 'cn=test, dc=example', 'converted': 'cn=test,dc=example', 'differences': [...], 'spacing_changes': {...}, 'case_changes': [...], 'punctuation_changes': [...], 'original_length': 20, 'converted_length': 19}, 'attribute_cn': {'has_differences': False, ...}, 'schema_attr_uid': {'has_differences': True, 'original': \"attributetypes: ( 0.9.2342... NAME 'uid' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15{256}' )  \", 'converted': 'attributeTypes: ( 0.9.2342... NAME uid SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )', 'differences': [...], 'syntax_quotes_removed': True, 'trailing_spaces_removed': True, ...}}",
            ),
        ] = Field(default_factory=FlextLdifModelsMetadata.DynamicMetadata)
        original_strings: Annotated[
            FlextLdifModelsMetadata.DynamicMetadata,
            Field(
                description="Complete preservation of original strings before ANY conversion: {'dn_original': 'cn=test, dc=example;', 'attribute_cn_original': 'CN', 'schema_attr_uid_original': \"attributetypes: ( 0.9.2342... NAME 'uid' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15{256}' )  \", 'acl_original': 'orclaci: { ... }', 'entry_original_ldif': 'dn: cn=test\\ncn: test\\n'}",
            ),
        ] = Field(default_factory=FlextLdifModelsMetadata.DynamicMetadata)
        conversion_history: Annotated[
            MutableSequence[t.MutableStrMapping],
            Field(
                description="Complete conversion history for audit trail: [{'step': 'parse_oid_entry', 'timestamp': '2025-01-01T00:00:00Z', 'original': {...}, 'converted': {...}, 'differences': {...}, 'server_type': 'oid', 'operation': 'parse'}, {'step': 'normalize_to_rfc', 'timestamp': '2025-01-01T00:00:01Z', 'original': {...}, 'converted': {...}, 'differences': {...}, 'server_type': 'rfc', 'operation': 'normalize'}, ...]",
            ),
        ] = Field(default_factory=lambda: list[t.MutableStrMapping]())

        @field_validator("quirk_type", mode="before")
        @classmethod
        def _coerce_quirk_type(
            cls,
            value: c.Ldif.ServerTypes | str,
        ) -> c.Ldif.ServerTypes:
            """Normalize string server types into canonical enum values."""
            if isinstance(value, c.Ldif.ServerTypes):
                return value
            return FlextLdifShared.normalize_server_type(value)

        @classmethod
        def create_for(
            cls,
            quirk_type: str | c.Ldif.ServerTypeLiteral | None = None,
            extensions: FlextLdifModelsMetadata.DynamicMetadata
            | t.MutableRecursiveContainerMapping
            | None = None,
        ) -> Self:
            """Factory method to create QuirkMetadata with extensions.

            Args:
                quirk_type: Quirk type identifier. Defaults to RFC if not provided.
                extensions: Extensions as DynamicMetadata or dict. Defaults to empty if not provided.

            Returns:
                QuirkMetadata instance with defaults from Constants.

            """
            default_quirk_type: c.Ldif.ServerTypes = (
                FlextLdifShared.normalize_server_type(quirk_type)
                if quirk_type is not None
                else c.Ldif.ServerTypes.RFC
            )
            extensions_model: FlextLdifModelsMetadata.DynamicMetadata
            if extensions is None:
                extensions_model = FlextLdifModelsMetadata.DynamicMetadata()
            elif isinstance(extensions, FlextLdifModelsMetadata.DynamicMetadata):
                extensions_model = extensions
            else:
                extensions_model = FlextLdifModelsMetadata.DynamicMetadata.from_dict(
                    extensions,
                )
            return cls.model_validate({
                "quirk_type": default_quirk_type,
                "extensions": extensions_model,
            })

        def add_conversion_note(self, operation: str, description: str) -> Self:
            """Add a conversion note to the audit trail.

            Args:
                operation: Operation identifier (e.g., "oid_to_oud", "schema_normalize")
                description: Human-readable description of the operation

            Returns:
                Self for method chaining

            Example:
                >>> metadata.add_conversion_note(
                ...     operation="oid_to_rfc",
                ...     description="Converted OID ACL format to RFC 4515 filter",
                ... )

            """
            self.conversion_notes[operation] = description
            return self


__all__: list[str] = ["FlextLdifModelsDomainMetadata"]
