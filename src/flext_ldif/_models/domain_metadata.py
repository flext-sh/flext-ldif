"""Domain models for LDIF metadata.

Namespace mixin extracted from domain_entries.py containing
ValidationMetadata, WriteOptions, FormatDetails, SchemaFormatDetails,
and QuirkMetadata inner classes.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import (
    MutableMapping,
    MutableSequence,
)
from typing import Annotated, Self

from flext_cli import m, u

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
            u.Field(
                description="RFC violations detected during validation",
            ),
        ]
        errors: Annotated[
            MutableSequence[str],
            u.Field(description="Validation errors that occurred"),
        ]
        warnings: Annotated[
            MutableSequence[str],
            u.Field(description="Non-fatal validation warnings"),
        ]
        context: Annotated[
            t.MutableStrMapping,
            u.Field(description="Validation context information"),
        ]
        server_specific_violations: Annotated[
            MutableSequence[str],
            u.Field(
                description="Server-specific validation violations",
            ),
        ]
        validation_server_type: Annotated[
            c.Ldif.ServerTypes | None,
            u.Field(description="Server type used for validation"),
        ] = None

    class WriteOptions(m.FrozenModel):
        """LDIF writing configuration options.

        Composed model for QuirkMetadata.write_options field.
        """

        format: Annotated[
            str | None,
            u.Field(
                description="LDIF format variant (rfc2849, extended, etc.)",
            ),
        ] = None
        base_dn: Annotated[
            str | None,
            u.Field(description="Base DN for relative DN conversions"),
        ] = None
        hidden_attrs: Annotated[
            MutableSequence[str],
            u.Field(
                description="Attributes to exclude from output",
            ),
        ] = u.Field(default_factory=list)
        sort_entries: Annotated[
            bool,
            u.Field(description="Whether to sort entries in output"),
        ] = False
        include_comments: Annotated[
            bool,
            u.Field(description="Whether to include comment lines"),
        ] = False
        base64_encode_binary: Annotated[
            bool,
            u.Field(
                description="Whether to base64 encode binary attributes",
            ),
        ] = False

    class FormatDetails(m.FrozenModel):
        """Original formatting details for round-trip preservation.

        Composed model for QuirkMetadata.original_format_details field.
        """

        dn_line: Annotated[
            str | None,
            u.Field(description="Original DN line formatting"),
        ] = None
        syntax: Annotated[
            str | None,
            u.Field(description="Original attribute syntax information"),
        ] = None
        encoding: Annotated[
            c.Ldif.Encoding | None,
            u.Field(description="Original encoding (utf-8, etc.)"),
        ] = None
        spacing: Annotated[
            str | None,
            u.Field(description="Original spacing/indentation"),
        ] = None
        trailing_info: Annotated[
            str | None,
            u.Field(description="Trailing comments or metadata"),
        ] = None

    class SchemaFormatDetails(m.FrozenModel):
        """Schema formatting details for perfect round-trip conversion.

        Composed model for QuirkMetadata.schema_format_details field.
        """

        original_string_complete: Annotated[
            str | None,
            u.Field(
                description="Complete original schema definition string for perfect round-trip",
            ),
        ] = None
        quotes: Annotated[
            str | None,
            u.Field(description="Quoting style used in schema definition"),
        ] = None
        spacing: Annotated[
            str | None,
            u.Field(description="Spacing around schema fields"),
        ] = None
        field_order: Annotated[
            MutableSequence[str],
            u.Field(
                description="Original order of schema fields",
            ),
        ] = u.Field(default_factory=list)
        x_origin: Annotated[
            str | None,
            u.Field(description="X-ORIGIN value from schema"),
        ] = None
        x_ordered: Annotated[
            MutableSequence[str],
            u.Field(
                description="X-ORDERED field values",
            ),
        ] = u.Field(default_factory=list)
        extensions: Annotated[
            FlextLdifModelsMetadata.DynamicMetadata,
            u.Field(
                description="Non-standard schema extensions",
            ),
        ] = u.Field(default_factory=FlextLdifModelsMetadata.DynamicMetadata)

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
            c.Ldif.ServerTypes,
            u.Field(
                ...,
                description="Type of quirk this metadata represents (ServerTypes enum or literal)",
            ),
        ]
        extensions: Annotated[
            FlextLdifModelsMetadata.DynamicMetadata,
            u.Field(
                description="Extensible metadata storage for quirk-specific data (server-injected validation rules, unconverted attributes, etc.)",
            ),
        ] = u.Field(default_factory=FlextLdifModelsMetadata.DynamicMetadata)
        rfc_violations: Annotated[
            MutableSequence[str],
            u.Field(
                description="RFC violations detected (e.g., 'RFC 2849 §2: DN required')",
            ),
        ] = u.Field(default_factory=list)
        rfc_warnings: Annotated[
            MutableSequence[str],
            u.Field(
                description="Non-fatal RFC warnings (e.g., unusual but valid formatting)",
            ),
        ] = u.Field(default_factory=list)
        conversion_notes: Annotated[
            FlextLdifModelsMetadata.DynamicMetadata,
            u.Field(
                description="Map of conversion operation name → human-readable description",
            ),
        ] = u.Field(default_factory=FlextLdifModelsMetadata.DynamicMetadata)
        attribute_transformations: Annotated[
            MutableMapping[
                str,
                FlextLdifModelsDomainAttributes.AttributeTransformation,
            ],
            u.Field(
                description="Per-attribute transformation audit trail captured during conversion.",
            ),
        ] = u.Field(default_factory=dict)
        server_specific_data: Annotated[
            FlextLdifModelsMetadata.EntryMetadata,
            u.Field(
                description="Preservation of server-proprietary data for round-trip conversions",
            ),
        ] = u.Field(default_factory=FlextLdifModelsMetadata.EntryMetadata)
        original_server_type: Annotated[
            c.Ldif.ServerTypes | None,
            u.Field(
                description="Source LDAP server type (e.g., 'oid', 'oud', 'ad', 'openldap')",
            ),
        ] = None
        target_server_type: Annotated[
            c.Ldif.ServerTypes | None,
            u.Field(
                description="Target LDAP server type (e.g., 'oid', 'oud', 'ad', 'openldap')",
            ),
        ] = None
        acls: Annotated[
            MutableSequence[str],
            u.Field(
                description="Access Control Lists extracted from entry attributes during parsing",
            ),
        ] = u.Field(default_factory=list)
        objectclasses: Annotated[
            MutableSequence[str],
            u.Field(
                description="ObjectClass definitions for schema validation (not RFC LDIF data)",
            ),
        ] = u.Field(default_factory=list)
        validation_results: Annotated[
            FlextLdifModelsDomainMetadata.ValidationMetadata | None,
            u.Field(
                description="Validation results with RFC violations, errors, warnings, and context",
            ),
        ] = None
        processing_stats: Annotated[
            m.BaseModel | None,
            u.Field(
                description="Complete statistics tracking for entry transformations (accepts EntryStatistics)",
            ),
        ] = None
        write_options: Annotated[
            FlextLdifModelsDomainMetadata.WriteOptions | None,
            u.Field(
                description="Writer configuration including format, base DN, hidden attributes, sorting, and comments",
            ),
        ] = None
        removed_attributes: Annotated[
            FlextLdifModelsMetadata.DynamicMetadata,
            u.Field(
                description="Attributes removed during conversion (was entry_metadata.removed_attributes_with_values)",
            ),
        ] = u.Field(default_factory=FlextLdifModelsMetadata.DynamicMetadata)
        original_format_details: Annotated[
            FlextLdifModelsDomainMetadata.FormatDetails | None,
            u.Field(
                description="Original formatting details for round-trip preservation (DN line, syntax, encoding, spacing)",
            ),
        ] = None
        schema_format_details: Annotated[
            (FlextLdifModelsDomainMetadata.SchemaFormatDetails | None),
            u.Field(
                description="Schema formatting details for round-trip preservation",
            ),
        ] = None
        soft_delete_markers: Annotated[
            MutableSequence[str],
            u.Field(
                description="Attributes soft-deleted during conversion (can be restored). Different from removed_attributes: these are intentionally hidden for target server but preserved for reverse conversion.",
            ),
        ] = u.Field(default_factory=list)
        original_attribute_case: Annotated[
            FlextLdifModelsMetadata.DynamicMetadata,
            u.Field(
                description="Original case of attribute names: {'objectclass': 'objectClass', 'cn': 'CN'}. Used to restore original case during reverse conversion.",
            ),
        ] = u.Field(default_factory=FlextLdifModelsMetadata.DynamicMetadata)
        schema_quirks_applied: Annotated[
            MutableSequence[str],
            u.Field(
                description="List of schema quirks applied during parsing: ['matching_rule_normalization', 'syntax_oid_conversion', 'schema_dn_quirk']",
            ),
        ] = u.Field(default_factory=list)
        boolean_conversions: Annotated[
            FlextLdifModelsMetadata.DynamicMetadata,
            u.Field(
                description="Boolean conversion tracking: {'orcldasisenabled': {'original': '1', 'converted': 'TRUE', 'format': 'OID->RFC'}}",
            ),
        ] = u.Field(default_factory=FlextLdifModelsMetadata.DynamicMetadata)
        minimal_differences: Annotated[
            FlextLdifModelsMetadata.DynamicMetadata,
            u.Field(
                description="Complete minimal differences tracking for zero data loss: {'dn': {'has_differences': True, 'original': 'cn=test, dc=example', 'converted': 'cn=test,dc=example', 'differences': [...], 'spacing_changes': {...}, 'case_changes': [...], 'punctuation_changes': [...], 'original_length': 20, 'converted_length': 19}, 'attribute_cn': {'has_differences': False, ...}, 'schema_attr_uid': {'has_differences': True, 'original': \"attributetypes: ( 0.9.2342... NAME 'uid' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15{256}' )  \", 'converted': 'attributeTypes: ( 0.9.2342... NAME uid SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )', 'differences': [...], 'syntax_quotes_removed': True, 'trailing_spaces_removed': True, ...}}",
            ),
        ] = u.Field(default_factory=FlextLdifModelsMetadata.DynamicMetadata)
        original_strings: Annotated[
            FlextLdifModelsMetadata.DynamicMetadata,
            u.Field(
                description="Complete preservation of original strings before ANY conversion: {'dn_original': 'cn=test, dc=example;', 'attribute_cn_original': 'CN', 'schema_attr_uid_original': \"attributetypes: ( 0.9.2342... NAME 'uid' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15{256}' )  \", 'acl_original': 'orclaci: { ... }', 'entry_original_ldif': 'dn: cn=test\\ncn: test\\n'}",
            ),
        ] = u.Field(default_factory=FlextLdifModelsMetadata.DynamicMetadata)
        conversion_history: Annotated[
            MutableSequence[t.MutableStrMapping],
            u.Field(
                description="Complete conversion history for audit trail: [{'step': 'parse_oid_entry', 'timestamp': '2025-01-01T00:00:00Z', 'original': {...}, 'converted': {...}, 'differences': {...}, 'server_type': 'oid', 'operation': 'parse'}, {'step': 'normalize_to_rfc', 'timestamp': '2025-01-01T00:00:01Z', 'original': {...}, 'converted': {...}, 'differences': {...}, 'server_type': 'rfc', 'operation': 'normalize'}, ...]",
            ),
        ] = u.Field(default_factory=lambda: list[t.MutableStrMapping]())

        @u.field_validator("quirk_type", mode="before")
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
            quirk_type: str | c.Ldif.ServerTypes | None = None,
            extensions: FlextLdifModelsMetadata.DynamicMetadata
            | t.Ldif.MetadataInputMapping
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
            validated: Self = cls.model_validate({
                "quirk_type": default_quirk_type,
                "extensions": extensions_model,
            })
            return validated

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
