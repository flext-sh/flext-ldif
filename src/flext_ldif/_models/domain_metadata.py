"""Domain models for LDIF metadata.

Namespace mixin extracted from domain_entries.py containing
ValidationMetadata, WriteOptions, FormatDetails, SchemaFormatDetails,
and ServerMetadata inner classes.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import MutableMapping
from typing import Annotated, ClassVar

from flext_core import m

from flext_ldif import FlextLdifShared, c, t
from flext_ldif._models import (
    FlextLdifModelsAclConvert,
    FlextLdifModelsDomainAttributes,
    FlextLdifModelsDomainEntryStatistics,
)


class FlextLdifModelsDomainMetadata:
    """Namespace mixin for LDIF metadata domain models."""

    class CommentedAttributeValues(m.RootModel[t.StrSequenceMapping]):
        """Original text values retained by attribute name for LDIF comments."""

        model_config: ClassVar[m.ConfigDict] = m.ConfigDict(strict=True, frozen=True)
        root: Annotated[
            t.StrSequenceMapping,
            m.Field(description="Original comment values indexed by attribute name"),
        ]

    class ValidationMetadata(m.FrozenModel):
        """Validation results and error tracking metadata.

        Composed model for ServerMetadata.validation_results field.
        """

        rfc_violations: Annotated[
            t.MutableSequenceOf[str],
            m.Field(description="RFC violations detected during validation"),
        ]
        errors: Annotated[
            t.MutableSequenceOf[str],
            m.Field(description="Validation errors that occurred"),
        ]
        warnings: Annotated[
            t.MutableSequenceOf[str],
            m.Field(description="Non-fatal validation warnings"),
        ]
        context: Annotated[
            t.MutableStrMapping,
            m.Field(description="Validation context information"),
        ]
        server_specific_violations: Annotated[
            t.MutableSequenceOf[str],
            m.Field(description="Server-specific validation violations"),
        ]
        validation_server_type: Annotated[
            c.Ldif.ServerTypes | None,
            m.Field(description="Server type used for validation"),
        ] = None

    class WriteOptions(m.FrozenModel):
        """LDIF writing configuration options.

        Composed model for ServerMetadata.write_options field.
        """

        format: Annotated[
            str | None,
            m.Field(description="LDIF format variant (rfc2849, extended, etc.)"),
        ] = None
        base_dn: Annotated[
            str | None,
            m.Field(description="Base DN for relative DN conversions"),
        ] = None
        hidden_attrs: Annotated[
            t.MutableSequenceOf[str],
            m.Field(description="Attributes to exclude from output"),
        ] = m.Field(default_factory=list[str])
        sort_entries: Annotated[
            bool,
            m.Field(description="Whether to sort entries in output"),
        ] = False
        include_comments: Annotated[
            bool,
            m.Field(description="Whether to include comment lines"),
        ] = False
        base64_encode_binary: Annotated[
            bool,
            m.Field(description="Whether to base64 encode binary attributes"),
        ] = False

    class FormatDetails(m.FrozenModel):
        """Original formatting details for round-trip preservation.

        Composed model for ServerMetadata.original_format_details field.
        """

        dn_line: Annotated[
            str | None,
            m.Field(description="Original DN line formatting"),
        ] = None
        syntax: Annotated[
            str | None,
            m.Field(description="Original attribute syntax information"),
        ] = None
        encoding: Annotated[
            c.Ldif.Encoding | None,
            m.Field(description="Original encoding (utf-8, etc.)"),
        ] = None
        spacing: Annotated[
            str | None,
            m.Field(description="Original spacing/indentation"),
        ] = None
        trailing_info: Annotated[
            str | None,
            m.Field(description="Trailing comments or metadata"),
        ] = None

    class SchemaFormatDetails(m.FrozenModel):
        """Schema formatting details for perfect round-trip conversion.

        Composed model for ServerMetadata.schema_format_details field.
        """

        original_string_complete: Annotated[
            str | None,
            m.Field(
                description="Complete original schema definition string for perfect "
                "round-trip",
            ),
        ] = None
        quotes: Annotated[
            str | None,
            m.Field(description="Quoting style used in schema definition"),
        ] = None
        spacing: Annotated[
            str | None,
            m.Field(description="Spacing around schema fields"),
        ] = None
        field_order: Annotated[
            t.MutableSequenceOf[str],
            m.Field(description="Original order of schema fields"),
        ] = m.Field(default_factory=list[str])
        name_values: Annotated[
            t.MutableSequenceOf[str],
            m.Field(description="Primary schema name followed by its declared aliases"),
        ] = m.Field(default_factory=list[str])
        x_origin: Annotated[
            str | None,
            m.Field(description="X-ORIGIN value from schema"),
        ] = None
        x_ordered: Annotated[
            t.MutableSequenceOf[str],
            m.Field(description="X-ORDERED field values"),
        ] = m.Field(default_factory=list[str])
        extensions: Annotated[
            t.MutableJsonMapping,
            m.Field(description="Non-standard schema extensions"),
        ] = m.Field(default_factory=dict)

    class ServerMetadata(m.DynamicModel):
        """Universal metadata container for server-specific data preservation.

        Used to store server-specific servers, transformations, and metadata
        that needs to be preserved during LDIF processing operations.

        Extended with RFC compliance tracking, conversion history, and
        server-specific data preservation for complete audit trails.

        Attributes:
            server_type: Type of server this metadata represents
            extensions: Extensible metadata storage for server-specific data

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

        server_type: Annotated[
            c.Ldif.ServerTypes,
            m.Field(
                description="Type of server this metadata represents (ServerTypes enum "
                "or literal)",
            ),
        ]
        extensions: Annotated[
            t.MutableJsonMapping,
            m.Field(
                description="Extensible metadata storage for server-specific data "
                "(server-injected validation rules, unconverted attributes, etc.)",
            ),
        ] = m.Field(default_factory=dict)
        rfc_violations: Annotated[
            t.MutableSequenceOf[str],
            m.Field(
                description="RFC violations detected (e.g., 'RFC 2849 §2: DN "
                "required')",
            ),
        ] = m.Field(default_factory=list[str])
        rfc_warnings: Annotated[
            t.MutableSequenceOf[str],
            m.Field(
                description="Non-fatal RFC warnings (e.g., unusual but valid "
                "formatting)",
            ),
        ] = m.Field(default_factory=list[str])
        # mro-wgwh.5 (agent: kimi) — U17: open-ended metadata containers are plain
        # t.MutableJsonMapping fields; the DynamicMetadata/EntryMetadata model wrappers
        # (getters/dump/helpers on declaration-only facets) are removed in this wave.
        # mro-wgwh.5 (agent: kimi-coder) — W2b.2: extensions is t.MutableJsonMapping;
        # create_for factory moved to u.Ldif.server_metadata_for (U17).
        conversion_notes: Annotated[
            t.MutableJsonMapping,
            m.Field(
                description="Map of conversion operation name → human-readable "
                "description",
            ),
        ] = m.Field(default_factory=dict)
        attribute_transformations: Annotated[
            MutableMapping[
                str,
                FlextLdifModelsDomainAttributes.AttributeTransformation,
            ],
            m.Field(
                description="Per-attribute transformation audit trail captured during "
                "conversion.",
            ),
        ] = m.Field(
            default_factory=dict[
                str,
                FlextLdifModelsDomainAttributes.AttributeTransformation,
            ],
        )
        server_specific_data: Annotated[
            t.MutableJsonMapping,
            m.Field(
                description="Preservation of server-proprietary data for round-trip "
                "conversions",
            ),
        ] = m.Field(default_factory=dict)
        original_server_type: Annotated[
            c.Ldif.ServerTypes | None,
            m.Field(
                description="Source LDAP server type (e.g., 'oid', 'oud', 'ad', "
                "'openldap')",
            ),
        ] = None
        target_server_type: Annotated[
            c.Ldif.ServerTypes | None,
            m.Field(
                description="Target LDAP server type (e.g., 'oid', 'oud', 'ad', "
                "'openldap')",
            ),
        ] = None
        acls: Annotated[
            t.MutableSequenceOf[str],
            m.Field(
                description="Access Control Lists extracted from entry attributes "
                "during parsing",
            ),
        ] = m.Field(default_factory=list[str])
        objectclasses: Annotated[
            t.MutableSequenceOf[str],
            m.Field(
                description="ObjectClass definitions for schema validation (not RFC "
                "LDIF data)",
            ),
        ] = m.Field(default_factory=list[str])
        validation_results: Annotated[
            FlextLdifModelsDomainMetadata.ValidationMetadata | None,
            m.Field(
                description="Validation results with RFC violations, errors, warnings, "
                "and context",
            ),
        ] = None
        processing_stats: Annotated[
            FlextLdifModelsDomainEntryStatistics.EntryStatistics | None,
            m.Field(
                description="Complete statistics tracking for entry transformations",
            ),
        ] = None
        write_options: Annotated[
            FlextLdifModelsDomainMetadata.WriteOptions | None,
            m.Field(
                description="Writer configuration including format, base DN, hidden "
                "attributes, sorting, and comments",
            ),
        ] = None
        removed_attributes: Annotated[
            t.MutableJsonMapping,
            m.Field(
                description="Attributes removed during conversion (was "
                "entry_metadata.removed_attributes_with_values)",
            ),
        ] = m.Field(default_factory=dict)
        original_format_details: Annotated[
            FlextLdifModelsDomainMetadata.FormatDetails | None,
            m.Field(
                description="Original formatting details for round-trip preservation "
                "(DN line, syntax, encoding, spacing)",
            ),
        ] = None
        schema_format_details: Annotated[
            (FlextLdifModelsDomainMetadata.SchemaFormatDetails | None),
            m.Field(
                description="Schema formatting details for round-trip preservation",
            ),
        ] = None
        acl_conversion: Annotated[
            FlextLdifModelsAclConvert.AclEntryConversion | None,
            m.Field(
                description="Typed OID→OUD ACL conversion outcome of this entry",
            ),
        ] = None
        soft_delete_markers: Annotated[
            t.MutableSequenceOf[str],
            m.Field(
                description="Attributes soft-deleted during conversion (can be "
                "restored). Different from removed_attributes: these are "
                "intentionally hidden for target server but preserved for "
                "reverse conversion.",
            ),
        ] = m.Field(default_factory=list[str])
        original_attribute_case: Annotated[
            t.MutableJsonMapping,
            m.Field(
                description="Original case of attribute names: {'objectclass': "
                "'objectClass', 'cn': 'CN'}. Used to restore original case during "
                "reverse conversion.",
            ),
        ] = m.Field(default_factory=dict)
        schema_servers_applied: Annotated[
            t.MutableSequenceOf[str],
            m.Field(
                description="List of schema servers applied during parsing: "
                "['matching_rule_normalization', 'syntax_oid_conversion', "
                "'schema_dn_server']",
            ),
        ] = m.Field(default_factory=list[str])
        boolean_conversions: Annotated[
            t.MutableJsonMapping,
            m.Field(
                description="Boolean conversion tracking: {'orcldasisenabled': "
                "{'original': '1', 'converted': 'TRUE', 'format': 'OID->RFC'}}",
            ),
        ] = m.Field(default_factory=dict)
        minimal_differences: Annotated[
            t.MutableJsonMapping,
            m.Field(
                description=(
                    "Complete minimal differences tracking for zero data loss: "
                    "{'dn': {'has_differences': True, 'original': 'cn=test, "
                    "dc=example', 'converted': 'cn=test,dc=example', "
                    "'differences': [...], 'spacing_changes': {...}, "
                    "'case_changes': [...], 'punctuation_changes': [...], "
                    "'original_length': 20, 'converted_length': 19}, "
                    "'attribute_cn': {'has_differences': False, ...}, "
                    "'schema_attr_uid': {'has_differences': True, 'original': "
                    "\"attributetypes: ( 0.9.2342... NAME 'uid' SYNTAX "
                    "'1.3.6.1.4.1.1466.115.121.1.15{256}' )  \", "
                    "'converted': 'attributeTypes: ( 0.9.2342... NAME uid SYNTAX "
                    "1.3.6.1.4.1.1466.115.121.1.15{256} )', 'differences': "
                    "[...], 'syntax_quotes_removed': True, "
                    "'trailing_spaces_removed': True, ...}}"
                ),
            ),
        ] = m.Field(default_factory=dict)
        original_strings: Annotated[
            t.MutableJsonMapping,
            m.Field(
                description=(
                    "Complete preservation of original strings before ANY "
                    "conversion: {'dn_original': 'cn=test, dc=example;', "
                    "'attribute_cn_original': 'CN', "
                    "'schema_attr_uid_original': "
                    "\"attributetypes: ( 0.9.2342... NAME 'uid' SYNTAX "
                    "'1.3.6.1.4.1.1466.115.121.1.15{256}' )  \", "
                    "'acl_original': 'orclaci: { ... }', "
                    "'entry_original_ldif': 'dn: cn=test\\ncn: test\\n'}"
                ),
            ),
        ] = m.Field(default_factory=dict)
        conversion_history: Annotated[
            t.MutableSequenceOf[t.MutableStrMapping],
            m.Field(
                default_factory=list[t.MutableStrMapping],
                description=(
                    "Complete conversion history for audit trail: [{'step': "
                    "'parse_oid_entry', 'timestamp': '2025-01-01T00:00:00Z', "
                    "'original': {...}, 'converted': {...}, 'differences': "
                    "{...}, 'server_type': 'oid', 'operation': 'parse'}, "
                    "{'step': 'normalize_to_rfc', "
                    "'timestamp': '2025-01-01T00:00:01Z', 'original': {...}, "
                    "'converted': {...}, 'differences': {...}, "
                    "'server_type': 'rfc', 'operation': 'normalize'}, ...]"
                ),
            ),
        ] = m.Field(default_factory=list[t.MutableStrMapping])

        @m.field_validator("server_type", mode="before")
        @classmethod
        def _coerce_server_type(
            cls,
            value: c.Ldif.ServerTypes | str,
        ) -> c.Ldif.ServerTypes:
            """Normalize string server types into canonical enum values.

            Returns:
                The resulting ``c.Ldif.ServerTypes``.

            """
            if isinstance(value, c.Ldif.ServerTypes):
                return value
            return FlextLdifShared.normalize_server_type(value)


__all__: list[str] = ["FlextLdifModelsDomainMetadata"]
