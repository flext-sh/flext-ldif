# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/domain_metadata
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, MutableSequence
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_cli import FlextCliProtocols

if TYPE_CHECKING:
    from flext_ldif import t
    from flext_ldif._constants import FlextLdifConstantsBaseParts
    from flext_ldif._protocols import (
        FlextLdifLdifProtocolsGeneratedModelsAclEntryConversion,
        FlextLdifLdifProtocolsGeneratedModelsEntryStatistics,
        FlextLdifLdifProtocolsGeneratedModelsValidationMetadata,
        FlextLdifProtocolsBase,
    )


class FlextLdifProtocolsDomainMetadata:
    """Own the structural contracts declared by its model source."""

    @runtime_checkable
    class CommentedAttributeValues(FlextCliProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def root(self) -> t.StrSequenceMapping:
            """Structural member projected from the owning model."""
            ...

    @runtime_checkable
    class ValidationMetadata(FlextCliProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def rfc_violations(self) -> MutableSequence[str]:
            """RFC violations detected during validation."""
            ...

        @property
        def errors(self) -> MutableSequence[str]:
            """Validation errors that occurred."""
            ...

        @property
        def warnings(self) -> MutableSequence[str]:
            """Non-fatal validation warnings."""
            ...

        @property
        def context(self) -> t.MutableStrMapping:
            """Validation context information."""
            ...

        @property
        def server_specific_violations(self) -> MutableSequence[str]:
            """Server-specific validation violations."""
            ...

        @property
        def validation_server_type(
            self,
        ) -> FlextLdifConstantsBaseParts.FlextLdifConstantsEnums.ServerTypes | None:
            """Server type used for validation."""
            ...

    @runtime_checkable
    class WriteOptions(FlextCliProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def format(self) -> str | None:
            """LDIF format variant (rfc2849, extended, etc.)."""
            ...

        @property
        def base_dn(self) -> str | None:
            """Base DN for relative DN conversions."""
            ...

        @property
        def hidden_attrs(self) -> MutableSequence[str]:
            """Attributes to exclude from output."""
            ...

        @property
        def sort_entries(self) -> bool:
            """Whether to sort entries in output."""
            ...

        @property
        def include_comments(self) -> bool:
            """Whether to include comment lines."""
            ...

        @property
        def base64_encode_binary(self) -> bool:
            """Whether to base64 encode binary attributes."""
            ...

    @runtime_checkable
    class FormatDetails(FlextCliProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def dn_line(self) -> str | None:
            """Original DN line formatting."""
            ...

        @property
        def syntax(self) -> str | None:
            """Original attribute syntax information."""
            ...

        @property
        def encoding(
            self,
        ) -> FlextLdifConstantsBaseParts.FlextLdifConstantsEnums.Encoding | None:
            """Original encoding (utf-8, etc.)."""
            ...

        @property
        def spacing(self) -> str | None:
            """Original spacing/indentation."""
            ...

        @property
        def trailing_info(self) -> str | None:
            """Trailing comments or metadata."""
            ...

    @runtime_checkable
    class SchemaFormatDetails(FlextCliProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def original_string_complete(self) -> str | None:
            """Complete original schema definition string for perfect round-trip."""
            ...

        @property
        def quotes(self) -> str | None:
            """Quoting style used in schema definition."""
            ...

        @property
        def spacing(self) -> str | None:
            """Spacing around schema fields."""
            ...

        @property
        def field_order(self) -> MutableSequence[str]:
            """Original order of schema fields."""
            ...

        @property
        def name_values(self) -> MutableSequence[str]:
            """Primary schema name followed by its declared aliases."""
            ...

        @property
        def x_origin(self) -> str | None:
            """X-ORIGIN value from schema."""
            ...

        @property
        def x_ordered(self) -> MutableSequence[str]:
            """X-ORDERED field values."""
            ...

        @property
        def extensions(self) -> t.MutableJsonMapping:
            """Non-standard schema extensions."""
            ...

    @runtime_checkable
    class ServerMetadata(FlextCliProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def server_type(
            self,
        ) -> FlextLdifConstantsBaseParts.FlextLdifConstantsEnums.ServerTypes:
            """Structural member projected from the owning model.

            Type of server this metadata represents (ServerTypes enum or literal).
            """
            ...

        @property
        def extensions(self) -> t.MutableJsonMapping:
            """Structural member projected from the owning model.

            Extensible metadata storage for server-specific data (server-injected
            validation rules, unconverted attributes, etc.).
            """
            ...

        @property
        def rfc_violations(self) -> MutableSequence[str]:
            """RFC violations detected (e.g., 'RFC 2849 §2: DN required')."""
            ...

        @property
        def rfc_warnings(self) -> MutableSequence[str]:
            """Non-fatal RFC warnings (e.g., unusual but valid formatting)."""
            ...

        @property
        def conversion_notes(self) -> t.MutableJsonMapping:
            """Map of conversion operation name → human-readable description."""
            ...

        @property
        def attribute_transformations(
            self,
        ) -> Mapping[str, FlextLdifProtocolsBase.AttributeTransformation]:
            """Structural member projected from the owning model.

            Per-attribute transformation audit trail captured during conversion.
            """
            ...

        @property
        def server_specific_data(self) -> t.MutableJsonMapping:
            """Structural member projected from the owning model.

            Preservation of server-proprietary data for round-trip conversions.
            """
            ...

        @property
        def original_server_type(
            self,
        ) -> FlextLdifConstantsBaseParts.FlextLdifConstantsEnums.ServerTypes | None:
            """Source LDAP server type (e.g., 'oid', 'oud', 'ad', 'openldap')."""
            ...

        @property
        def target_server_type(
            self,
        ) -> FlextLdifConstantsBaseParts.FlextLdifConstantsEnums.ServerTypes | None:
            """Target LDAP server type (e.g., 'oid', 'oud', 'ad', 'openldap')."""
            ...

        @property
        def acls(self) -> MutableSequence[str]:
            """Structural member projected from the owning model.

            Access Control Lists extracted from entry attributes during parsing.
            """
            ...

        @property
        def objectclasses(self) -> MutableSequence[str]:
            """ObjectClass definitions for schema validation (not RFC LDIF data)."""
            ...

        @property
        def validation_results(
            self,
        ) -> (
            FlextLdifLdifProtocolsGeneratedModelsValidationMetadata.ValidationMetadata
            | None
        ):
            """Structural member projected from the owning model.

            Validation results with RFC violations, errors, warnings, and context.
            """
            ...

        @property
        def processing_stats(
            self,
        ) -> (
            FlextLdifLdifProtocolsGeneratedModelsEntryStatistics.EntryStatistics | None
        ):
            """Complete statistics tracking for entry transformations."""
            ...

        @property
        def write_options(self) -> FlextLdifProtocolsBase.WriteOptions | None:
            """Structural member projected from the owning model.

            Writer configuration including format, base DN, hidden attributes,
            sorting, and comments.
            """
            ...

        @property
        def removed_attributes(self) -> t.MutableJsonMapping:
            """Structural member projected from the owning model.

            Attributes removed during conversion (was
            entry_metadata.removed_attributes_with_values).
            """
            ...

        @property
        def original_format_details(
            self,
        ) -> FlextLdifProtocolsBase.FormatDetails | None:
            """Structural member projected from the owning model.

            Original formatting details for round-trip preservation (DN line,
            syntax, encoding, spacing).
            """
            ...

        @property
        def schema_format_details(
            self,
        ) -> FlextLdifProtocolsBase.SchemaFormatDetails | None:
            """Schema formatting details for round-trip preservation."""
            ...

        @property
        def acl_conversion(
            self,
        ) -> (
            FlextLdifLdifProtocolsGeneratedModelsAclEntryConversion.AclEntryConversion
            | None
        ):
            """Typed OID→OUD ACL conversion outcome of this entry."""
            ...

        @property
        def soft_delete_markers(self) -> MutableSequence[str]:
            """Structural member projected from the owning model.

            Attributes soft-deleted during conversion (can be restored). Different
            from removed_attributes: these are intentionally hidden for target
            server but preserved for reverse conversion.
            """
            ...

        @property
        def original_attribute_case(self) -> t.MutableJsonMapping:
            """Structural member projected from the owning model.

            Original case of attribute names: {'objectclass': 'objectClass', 'cn':
            'CN'}. Used to restore original case during reverse conversion.
            """
            ...

        @property
        def schema_servers_applied(self) -> MutableSequence[str]:
            """Structural member projected from the owning model.

            List of schema servers applied during parsing:
            ['matching_rule_normalization', 'syntax_oid_conversion',
            'schema_dn_server'].
            """
            ...

        @property
        def boolean_conversions(self) -> t.MutableJsonMapping:
            """Structural member projected from the owning model.

            Boolean conversion tracking: {'orcldasisenabled': {'original': '1',
            'converted': 'TRUE', 'format': 'OID->RFC'}}.
            """
            ...

        @property
        def minimal_differences(self) -> t.MutableJsonMapping:
            """Structural member projected from the owning model.

            Complete minimal differences tracking for zero data loss: {'dn':
            {'has_differences': True, 'original': 'cn=test, dc=example',
            'converted': 'cn=test,dc=example', 'differences': [...],
            'spacing_changes': {...}, 'case_changes': [...], 'punctuation_changes':
            [...], 'original_length': 20, 'converted_length': 19}, 'attribute_cn':
            {'has_differences': False, ...}, 'schema_attr_uid': {'has_differences':
            True, 'original': "attributetypes: ( 0.9.2342... NAME 'uid' SYNTAX
            '1.3.6.1.4.1.1466.115.121.1.15{256}' )  ", 'converted': 'attributeTypes:
            ( 0.9.2342... NAME uid SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )',
            'differences': [...], 'syntax_quotes_removed': True,
            'trailing_spaces_removed': True, ...}}.
            """
            ...

        @property
        def original_strings(self) -> t.MutableJsonMapping:
            r"""Structural member projected from the owning model.

            Complete preservation of original strings before ANY conversion:
            {'dn_original': 'cn=test, dc=example;', 'attribute_cn_original': 'CN',
            'schema_attr_uid_original': "attributetypes: ( 0.9.2342... NAME 'uid'
            SYNTAX '1.3.6.1.4.1.1466.115.121.1.15{256}' )  ", 'acl_original':
            'orclaci: { ... }', 'entry_original_ldif': 'dn: cn=test\\ncn: test\\n'}.
            """
            ...

        @property
        def conversion_history(self) -> MutableSequence[t.MutableStrMapping]:
            """Structural member projected from the owning model.

            Complete conversion history for audit trail: [{'step':
            'parse_oid_entry', 'timestamp': '2025-01-01T00:00:00Z', 'original':
            {...}, 'converted': {...}, 'differences': {...}, 'server_type': 'oid',
            'operation': 'parse'}, {'step': 'normalize_to_rfc', 'timestamp':
            '2025-01-01T00:00:01Z', 'original': {...}, 'converted': {...},
            'differences': {...}, 'server_type': 'rfc', 'operation': 'normalize'},
            ...].
            """
            ...


__all__: list[str] = [
    "FlextLdifProtocolsDomainMetadata",
]
