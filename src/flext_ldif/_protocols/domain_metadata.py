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
        FlextLdifProtocolsAclConvert,
        FlextLdifProtocolsDomainAttributes,
        FlextLdifProtocolsDomainEntryStatistics,
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

        extensions: t.MutableJsonMapping
        rfc_violations: MutableSequence[str]
        rfc_warnings: MutableSequence[str]
        conversion_notes: t.MutableJsonMapping

        @property
        def attribute_transformations(
            self,
        ) -> Mapping[str, FlextLdifProtocolsDomainAttributes.AttributeTransformation]:
            """Structural member projected from the owning model.

            Per-attribute transformation audit trail captured during conversion.
            """
            ...

        server_specific_data: t.MutableJsonMapping

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

        acls: MutableSequence[str]
        objectclasses: MutableSequence[str]

        @property
        def validation_results(
            self,
        ) -> FlextLdifProtocolsDomainMetadata.ValidationMetadata | None:
            """Structural member projected from the owning model.

            Validation results with RFC violations, errors, warnings, and context.
            """
            ...

        @property
        def processing_stats(
            self,
        ) -> FlextLdifProtocolsDomainEntryStatistics.EntryStatistics | None:
            """Complete statistics tracking for entry transformations."""
            ...

        @property
        def write_options(self) -> FlextLdifProtocolsDomainMetadata.WriteOptions | None:
            """Structural member projected from the owning model.

            Writer configuration including format, base DN, hidden attributes,
            sorting, and comments.
            """
            ...

        removed_attributes: t.MutableJsonMapping

        @property
        def original_format_details(
            self,
        ) -> FlextLdifProtocolsDomainMetadata.FormatDetails | None:
            """Structural member projected from the owning model.

            Original formatting details for round-trip preservation (DN line,
            syntax, encoding, spacing).
            """
            ...

        @property
        def schema_format_details(
            self,
        ) -> FlextLdifProtocolsDomainMetadata.SchemaFormatDetails | None:
            """Schema formatting details for round-trip preservation."""
            ...

        @property
        def acl_conversion(
            self,
        ) -> FlextLdifProtocolsAclConvert.AclEntryConversion | None:
            """Typed OID→OUD ACL conversion outcome of this entry."""
            ...

        soft_delete_markers: MutableSequence[str]
        original_attribute_case: t.MutableJsonMapping
        schema_servers_applied: MutableSequence[str]
        boolean_conversions: t.MutableJsonMapping
        minimal_differences: t.MutableJsonMapping
        original_strings: t.MutableJsonMapping
        conversion_history: MutableSequence[t.MutableStrMapping]


__all__: list[str] = [
    "FlextLdifProtocolsDomainMetadata",
]
