"""Base LDIF structural contracts."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar, Literal, Protocol, runtime_checkable

from flext_cli import p, t

if TYPE_CHECKING:
    from collections.abc import (
        Iterator,
        KeysView,
        Mapping,
        MutableMapping,
        Sequence,
        ValuesView,
    )
    from pathlib import Path

    from flext_ldif import c

# NOTE (multi-agent, mro-0ftd.3.7.2): this lowest protocol facet deliberately
# depends only on upstream declarations and constants so no public facade can
# re-enter it while the LDIF protocol namespace is being composed.


@runtime_checkable
class FlextLdifProtocolsBase(Protocol):
    """Base LDIF protocols shared across utilities, services, and servers."""

    @runtime_checkable
    class ValidationService(Protocol):
        """Contract for entry validation helpers."""

        def validate_attribute_name(self, name: str) -> p.Result[bool]:
            """Return whether the attribute name is valid."""
            ...

        def validate_objectclass_name(self, name: str) -> p.Result[bool]:
            """Return whether the objectClass name is valid."""
            ...

    @runtime_checkable
    class ServerDetectionService(Protocol):
        """Contract for LDIF server type detection helpers."""

        def detect_server_type(
            self,
            ldif_path: Path | None = None,
            ldif_content: str | None = None,
            max_lines: int | None = None,
        ) -> p.Result[FlextLdifProtocolsBase.ServerDetectionResult]:
            """Detect LDAP server type from LDIF file or content."""
            ...

    @runtime_checkable
    class ServerDetectionResult(p.BaseModel, Protocol):
        """Detected server type returned by the public detection service."""

        @property
        def detected_server_type(self) -> c.Ldif.ServerTypes:
            """The detected LDAP server type."""
            ...

        @property
        def confidence(self) -> float:
            """The normalized detection confidence."""
            ...

        @property
        def scores(self) -> FlextLdifProtocolsBase.DynamicCounts:
            """The per-server detection scores."""
            ...

        @property
        def patterns_found(self) -> Sequence[str]:
            """The server-identifying patterns found in the input."""
            ...

        @property
        def detection_error(self) -> str | None:
            """The detection error when detection failed."""
            ...

        @property
        def fallback_reason(self) -> str | None:
            """The reason a fallback server type was selected."""
            ...

        @property
        def is_confident(self) -> bool:
            """Whether the confidence meets the detection threshold."""
            ...

    @runtime_checkable
    class CategoryRules(p.BaseModel, Protocol):
        """Validated category-rule capabilities consumed by categorization."""

        @property
        def category_markers(self) -> t.FrozensetMapping:
            """Normalized category markers keyed by category."""
            ...

    @runtime_checkable
    class WhitelistRules(p.BaseModel, Protocol):
        """Validated schema-whitelist capabilities consumed by filtering."""

        @property
        def has_oid_filters(self) -> bool:
            """Whether any schema OID filter is configured."""
            ...

        @property
        def schema_oid_filters(self) -> t.FrozensetMapping:
            """Configured OID filters keyed by schema attribute."""
            ...

    @runtime_checkable
    class MigrateOptions(p.BaseModel, Protocol):
        """Public migration options without a concrete model dependency."""

        @property
        def base_dn(self) -> str | None:
            """The configured base DN."""
            ...

        @property
        def output_filename(self) -> str | None:
            """The configured output filename."""
            ...

        @property
        def forbidden_attributes(self) -> Sequence[str] | None:
            """Attributes excluded from migration."""
            ...

        @property
        def forbidden_objectclasses(self) -> Sequence[str] | None:
            """Object classes excluded from migration."""
            ...

        @property
        def categorization_rules(self) -> FlextLdifProtocolsBase.CategoryRules | None:
            """The validated categorization rules."""
            ...

        @property
        def schema_whitelist_rules(
            self,
        ) -> FlextLdifProtocolsBase.WhitelistRules | None:
            """The validated schema whitelist rules."""
            ...

    @runtime_checkable
    class AclEvaluationResult(Protocol):
        """Outcome of evaluating ACLs against required permissions."""

        @property
        def granted(self) -> bool:
            """Report whether access was granted."""
            ...

        @property
        def matched_acl(self) -> FlextLdifProtocolsBase.Acl | None:
            """The ACL that matched the evaluation."""
            ...

        @property
        def message(self) -> str:
            """The evaluation message."""
            ...

    @runtime_checkable
    class ProcessEntriesOptions(p.BaseModel, Protocol):
        """Validated controls for sequential or parallel entry processing."""

        @property
        def processor_name(self) -> Literal["transform", "validate"]:
            """The selected processor operation."""
            ...

        @property
        def parallel(self) -> bool:
            """Report whether processing may run concurrently."""
            ...

        @property
        def batch_size(self) -> int:
            """The processing batch size."""
            ...

        @property
        def max_workers(self) -> int:
            """The maximum worker count."""
            ...

    @runtime_checkable
    class ProcessingResult(Protocol):
        """Observable result of processing one entry."""

        @property
        def dn(self) -> str:
            """The processed entry DN."""
            ...

        @property
        def attributes(self) -> t.StrSequenceMapping:
            """The processed entry attributes."""
            ...

    @runtime_checkable
    class DynamicCounts(p.BaseModel, Protocol):
        """Read-only count collection exposed by statistics results."""

        def __len__(self) -> int:
            """Return the number of count keys."""
            ...

        def get(self, key: str, default: int | None = None) -> int | None:
            """Return a count by key."""
            ...

        def items(self) -> Sequence[tuple[str, int]]:
            """Return count items."""
            ...

    @runtime_checkable
    class EntriesStatistics(p.BaseModel, Protocol):
        """Aggregate distributions calculated for a batch of entries."""

        @property
        def total_entries(self) -> int:
            """The total entry count."""
            ...

        @property
        def object_class_distribution(self) -> FlextLdifProtocolsBase.DynamicCounts:
            """Counts grouped by object class."""
            ...

        @property
        def server_type_distribution(self) -> FlextLdifProtocolsBase.DynamicCounts:
            """Counts grouped by server type."""
            ...

    @runtime_checkable
    class FlexibleCategories(p.BaseModel, Protocol):
        """Categorized entry groups exposed through protocol-only entry contracts."""

        @property
        def categories(self) -> Mapping[str, Sequence[FlextLdifProtocolsBase.Entry]]:
            """The categorized entries by category."""
            ...

        def __getitem__(self, category: str) -> Sequence[FlextLdifProtocolsBase.Entry]:
            """Return entries in one category."""
            ...

        def __setitem__(
            self, category: str, entries: Sequence[FlextLdifProtocolsBase.Entry]
        ) -> None:
            """Replace entries in one category."""
            ...

        def add_entries(
            self, category: str, entries: Sequence[FlextLdifProtocolsBase.Entry]
        ) -> None:
            """Append validated entries to one category."""
            ...

        def __contains__(self, category: str) -> bool:
            """Report whether a category exists."""
            ...

        def items(self) -> Iterator[tuple[str, Sequence[FlextLdifProtocolsBase.Entry]]]:
            """Iterate category and entry pairs."""
            ...

        def get(
            self,
            category: str,
            default: Sequence[FlextLdifProtocolsBase.Entry] | None = None,
        ) -> Sequence[FlextLdifProtocolsBase.Entry]:
            """Return entries for a category or a default."""
            ...

        def keys(self) -> Iterator[str]:
            """Iterate category names."""
            ...

        def values(self) -> Iterator[Sequence[FlextLdifProtocolsBase.Entry]]:
            """Iterate categorized entry sequences."""
            ...

    @runtime_checkable
    class DNStatistics(p.BaseModel, Protocol):
        """Statistics about DN normalization and validation."""

        original_dn: str
        cleaned_dn: str
        normalized_dn: str

        @property
        def transformations(self) -> t.StrSequence:
            """The ordered normalization operations."""
            ...

        @property
        def validation_warnings(self) -> t.StrSequence:
            """The non-fatal validation findings."""
            ...

        @property
        def validation_errors(self) -> t.StrSequence:
            """The fatal validation findings."""
            ...

        @property
        def was_transformed(self) -> bool:
            """Whether normalization changed the original DN."""
            ...

    @runtime_checkable
    class DN(p.BaseModel, Protocol):
        """Distinguished Name value contract."""

        @property
        def value(self) -> str:
            """The DN string value."""
            ...

    @runtime_checkable
    class Attributes(p.BaseModel, Protocol):
        """Attribute container contract used by entry utilities."""

        @property
        def attributes(self) -> MutableMapping[str, t.MutableSequenceOf[str]]:
            """The underlying attribute mapping."""
            ...

        # NOTE (multi-agent, mro-0ftd.3.7.2): read-only @property members the OUD
        # round-trip restore helper reads (transform.py restore_entry_from_metadata);
        # concrete m.Ldif.Attributes carries these fields (domain_attributes.py:38/44).
        @property
        def attribute_metadata(self) -> Mapping[str, t.MutableAttributeMapping]:
            """Per-attribute metadata (category/hidden status)."""
            ...

        @property
        def metadata(self) -> t.MutableJsonMapping | None:
            """Ordering/format preservation metadata."""
            ...

        def get(
            self, key: str, default: t.MutableSequenceOf[str] | None = None
        ) -> t.MutableSequenceOf[str]:
            """Return attribute values with optional default."""
            ...

        def __getitem__(self, key: str) -> t.MutableSequenceOf[str]:
            """Return attribute values by exact attribute name."""
            ...

        def items(self) -> t.MutableSequenceOf[tuple[str, t.MutableSequenceOf[str]]]:
            """Return attribute items as a list of tuples."""
            ...

        def keys(self) -> KeysView[str]:
            """Return attribute names view."""
            ...

        def values(self) -> ValuesView[t.MutableSequenceOf[str]]:
            """Return attribute value lists view."""
            ...

    @runtime_checkable
    class AttributeTransformation(p.BaseModel, Protocol):
        """Attribute transformation audit record."""

        original_name: str
        target_name: str | None
        original_values: t.MutableSequenceOf[str]
        target_values: t.MutableSequenceOf[str] | None
        transformation_type: c.Ldif.TransformationType
        reason: str

    @runtime_checkable
    class AclPermissions(p.BaseModel, Protocol):
        """ACL permission flag set."""

        @property
        def read(self) -> bool:
            """Whether read is allowed."""
            ...

        @property
        def write(self) -> bool:
            """Whether write is allowed."""
            ...

        @property
        def search(self) -> bool:
            """Whether search is allowed."""
            ...

        @property
        def compare(self) -> bool:
            """Whether compare is allowed."""
            ...

        @property
        def add(self) -> bool:
            """Whether add is allowed."""
            ...

        @property
        def delete(self) -> bool:
            """Whether delete is allowed."""
            ...

        @property
        def self_write(self) -> bool:
            """Whether self-write is allowed."""
            ...

        @property
        def proxy(self) -> bool:
            """Whether proxy access is allowed."""
            ...

        @property
        def browse(self) -> bool:
            """Whether browse access is allowed."""
            ...

        @property
        def auth(self) -> bool:
            """Whether authentication access is allowed."""
            ...

        @property
        def all(self) -> bool:
            """Whether the compound all-permissions flag is set."""
            ...

        @property
        def no_write(self) -> bool:
            """Whether write access is explicitly denied."""
            ...

        @property
        def no_add(self) -> bool:
            """Whether add access is explicitly denied."""
            ...

        @property
        def no_delete(self) -> bool:
            """Whether delete access is explicitly denied."""
            ...

        @property
        def no_browse(self) -> bool:
            """Whether browse access is explicitly denied."""
            ...

        @property
        def no_self_write(self) -> bool:
            """Whether self-write access is explicitly denied."""
            ...

    @runtime_checkable
    class AclTarget(p.BaseModel, Protocol):
        """ACL target descriptor."""

        @property
        def target_dn(self) -> str:
            """The target DN expression."""
            ...

        @property
        def attributes(self) -> t.MutableSequenceOf[str]:
            """The target attribute names."""
            ...

    @runtime_checkable
    class AclSubject(p.BaseModel, Protocol):
        """ACL subject descriptor."""

        @property
        def subject_type(self) -> str:
            """The subject type."""
            ...

        @property
        def subject_value(self) -> str:
            """The subject value."""
            ...

    @runtime_checkable
    class ValidationMetadata(Protocol):
        """Validation result payload stored in metadata."""

        @property
        def rfc_violations(self) -> t.MutableSequenceOf[str]:
            """RFC violations."""
            ...

        @property
        def errors(self) -> t.MutableSequenceOf[str]:
            """The validation errors."""
            ...

        @property
        def warnings(self) -> t.MutableSequenceOf[str]:
            """The validation warnings."""
            ...

        @property
        def context(self) -> t.MutableStrMapping:
            """The validation context."""
            ...

    @runtime_checkable
    class WriteOptions(p.BaseModel, Protocol):
        """Round-trip write options stored inside metadata."""

        @property
        def base_dn(self) -> str | None:
            """The base DN override."""
            ...

    @runtime_checkable
    class WriteFormatOptions(p.BaseModel, Protocol):
        """Formatting options for entry serialization."""

        @property
        def line_width(self) -> int:
            """The line width for folding."""
            ...

        @property
        def sort_attributes(self) -> bool:
            """Whether attributes should be sorted."""
            ...

        @property
        def base64_encode_binary(self) -> bool:
            """Whether binary values should be base64 encoded."""
            ...

        @property
        def include_dn_comments(self) -> bool:
            """Whether DN comments should be emitted."""
            ...

        @property
        def include_version_header(self) -> bool:
            """Whether the LDIF version header should be emitted."""
            ...

        @property
        def acl_attribute_names(self) -> frozenset[str]:
            """ACL attribute names recognized by phase-aware writers."""
            ...

        @property
        def comment_acl_in_non_acl_phases(self) -> bool:
            """Whether ACL attributes become comments outside the ACL phase."""
            ...

        @property
        def include_timestamps(self) -> bool:
            """Whether generation timestamps should be emitted."""
            ...

        @property
        def restore_original_format(self) -> bool:
            """Whether original formatting should be restored."""
            ...

        @property
        def entry_category(self) -> str | None:
            """The migration entry category."""
            ...

        @property
        def fold_long_lines(self) -> bool:
            """Whether long output lines are folded."""
            ...

        @property
        def normalize_attribute_names(self) -> bool:
            """Whether attribute names are normalized."""
            ...

        @property
        def write_empty_values(self) -> bool:
            """Whether empty attribute values are written."""
            ...

        @property
        def write_hidden_attributes_as_comments(self) -> bool:
            """Whether hidden attributes are emitted as comments."""
            ...

        @property
        def write_metadata_as_comments(self) -> bool:
            """Whether entry metadata is emitted as comments."""
            ...

        @property
        def use_original_acl_format_as_name(self) -> bool:
            """Whether the original ACL format supplies the ACI name."""
            ...

        @property
        def ldif_changetype(self) -> str | None:
            """The optional LDIF changetype output mode."""
            ...

        @property
        def ldif_modify_operation(self) -> str:
            """The LDIF modify operation."""
            ...

        @property
        def write_original_entry_as_comment(self) -> bool:
            """Whether the original source entry is emitted as comments."""
            ...

        @property
        def write_removed_attributes_as_comments(self) -> bool:
            """Whether removed attributes are emitted as comments."""
            ...

    @runtime_checkable
    class FormatDetails(Protocol):
        """Original LDIF formatting details."""

        @property
        def dn_line(self) -> str | None:
            """The original DN line representation."""
            ...

    @runtime_checkable
    class SchemaFormatDetails(p.BaseModel, Protocol):
        """Original schema formatting details for round-trip preservation."""

        @property
        def original_string_complete(self) -> str | None:
            """The original schema definition."""
            ...

        @property
        def field_order(self) -> t.MutableSequenceOf[str]:
            """The original field order."""
            ...

        @property
        def extensions(self) -> t.MutableJsonMapping:
            """The schema extensions metadata."""
            ...

    @runtime_checkable
    class MetadataWithWriteOptions(Protocol):
        """Metadata payload that may carry embedded write options."""

        @property
        def write_options(self) -> FlextLdifProtocolsBase.WriteOptions | None:
            """The embedded write options."""
            ...

    @runtime_checkable
    class EntryStatistics(p.BaseModel, Protocol):
        """Entry-level processing and validation statistics."""

        # NOTE (mro-wkii.17.26.19): read-only capabilities keep concrete Pydantic
        # fields covariant while all updates flow through model_copy transitions.
        @property
        def was_parsed(self) -> bool:
            """Whether the entry was parsed successfully."""
            ...

        @property
        def was_validated(self) -> bool:
            """Whether the entry passed validation."""
            ...

        @property
        def was_filtered(self) -> bool:
            """Whether filtering was applied."""
            ...

        @property
        def was_written(self) -> bool:
            """Whether the entry was written."""
            ...

        @property
        def was_rejected(self) -> bool:
            """Whether the entry was rejected."""
            ...

        @property
        def rejection_category(self) -> str | None:
            """The rejection category."""
            ...

        @property
        def rejection_reason(self) -> str | None:
            """The rejection reason."""
            ...

        @property
        def attributes_added(self) -> Sequence[str]:
            """The attribute names added during processing."""
            ...

        @property
        def attributes_removed(self) -> Sequence[str]:
            """The attribute names removed during processing."""
            ...

        @property
        def attributes_modified(self) -> Sequence[str]:
            """The attribute names modified during processing."""
            ...

        @property
        def attributes_filtered(self) -> Sequence[str]:
            """The attribute names removed by filters."""
            ...

        @property
        def servers_applied(self) -> Sequence[str]:
            """The server transformations applied to the entry."""
            ...

        @property
        def dn_statistics(self) -> FlextLdifProtocolsBase.DNStatistics | None:
            """The DN transformation statistics."""
            ...

        @property
        def errors(self) -> Sequence[str]:
            """The processing errors."""
            ...

        @property
        def warnings(self) -> Sequence[str]:
            """The processing warnings."""
            ...

        def mark_filtered(
            self, filter_type: str, *, passed: bool
        ) -> FlextLdifProtocolsBase.EntryStatistics:
            """Return statistics updated with one filter result."""
            ...

        def mark_rejected(
            self, category: str, reason: str
        ) -> FlextLdifProtocolsBase.EntryStatistics:
            """Return statistics updated with rejection details."""
            ...

    @runtime_checkable
    class ServerMetadata(p.BaseModel, Protocol):
        """Server-specific metadata persisted on entries, ACLs, and schema items."""

        @property
        def server_type(self) -> str:
            """The server/server type identifier."""
            ...

        @property
        def extensions(self) -> t.MutableJsonMapping:
            """Server-specific JSON metadata."""
            ...

        # NOTE (multi-agent, mro-0ftd.3.7.2): read-only @property (covariant) so the
        # concrete m.Ldif.ServerMetadata field (a subtype-carrying model) satisfies the
        # contract; a read-write attribute would be invariant and unsatisfiable. New
        # values flow through model_copy(update=...), the Pydantic-2 transition canon.
        @property
        def write_options(self) -> FlextLdifProtocolsBase.WriteOptions | None:
            """The round-trip write options persisted in metadata."""
            ...

        @property
        def attribute_transformations(
            self,
        ) -> Mapping[str, FlextLdifProtocolsBase.AttributeTransformation]:
            """The per-attribute transformation audit trail (read-only view)."""
            ...

        @property
        def schema_format_details(
            self,
        ) -> FlextLdifProtocolsBase.SchemaFormatDetails | None:
            """The schema round-trip formatting details."""
            ...

        # NOTE (multi-agent, mro-0ftd.3.7.2): read-only @property the OUD round-trip
        # restore helper reads to recover original attribute-name casing; concrete
        # m.Ldif.ServerMetadata carries this field (domain_metadata.py:315).
        @property
        def original_attribute_case(self) -> t.MutableJsonMapping:
            """Original attribute-name casing for reverse conversion."""
            ...

        @property
        def original_server_type(self) -> c.Ldif.ServerTypes | None:
            """The source server type before conversion."""
            ...

        @property
        def target_server_type(self) -> c.Ldif.ServerTypes | None:
            """The target server type for conversion."""
            ...

        @property
        def acls(self) -> Sequence[str]:
            """The ACL strings preserved from the source entry."""
            ...

        @property
        def processing_stats(self) -> p.BaseModel | None:
            """The entry processing statistics model."""
            ...

        @property
        def boolean_conversions(self) -> t.MutableJsonMapping:
            """The preserved source and converted boolean values."""
            ...

        @property
        def original_format_details(
            self,
        ) -> FlextLdifProtocolsBase.FormatDetails | None:
            """The original entry formatting details."""
            ...

        @property
        def original_strings(self) -> t.MutableJsonMapping:
            """The complete strings preserved before conversion."""
            ...

        @property
        def removed_attributes(self) -> t.MutableJsonMapping:
            """The source attributes removed during conversion."""
            ...

    @runtime_checkable
    class SchemaElement(p.BaseModel, Protocol):
        """Shared schema-element contract (attributes, objectClasses, syntaxes).

        NOTE (multi-agent, mro-0ftd.3.7.2): mirrors the concrete mb.SchemaElement
        base (domain_schema/_models/base.py) so SchemaModelT can bind to the
        protocol instead of the concrete model.
        """

        @property
        def metadata(self) -> FlextLdifProtocolsBase.ServerMetadata | None:
            """The server-specific schema metadata."""
            ...

        @property
        def has_metadata(self) -> bool:
            """Whether the element carries server metadata."""
            ...

        @property
        def has_server_extensions(self) -> bool:
            """Whether the element carries server-specific extensions."""
            ...

        @property
        def server_type(self) -> str:
            """The server type from metadata, default RFC."""
            ...

    class SchemaAttribute(SchemaElement, Protocol):
        """LDIF schema attribute contract."""

        @property
        def oid(self) -> str:
            """The attribute OID."""
            ...

        @property
        def name(self) -> str:
            """The attribute name."""
            ...

        @property
        def desc(self) -> str | None:
            """The attribute description."""
            ...

        @property
        def sup(self) -> str | None:
            """The superior attribute type."""
            ...

        @property
        def equality(self) -> str | None:
            """The equality matching rule."""
            ...

        @property
        def ordering(self) -> str | None:
            """The ordering matching rule."""
            ...

        @property
        def substr(self) -> str | None:
            """The substring matching rule."""
            ...

        @property
        def syntax(self) -> str | None:
            """The attribute syntax OID."""
            ...

        @property
        def length(self) -> int | None:
            """The maximum value length."""
            ...

        @property
        def usage(self) -> str | None:
            """The RFC attribute usage."""
            ...

        @property
        def single_value(self) -> bool:
            """Whether the attribute is single-valued."""
            ...

        @property
        def collective(self) -> bool:
            """Whether the attribute is collective."""
            ...

        @property
        def no_user_modification(self) -> bool:
            """Whether user modification is forbidden."""
            ...

        @property
        def immutable(self) -> bool:
            """Whether the attribute is immutable."""
            ...

        @property
        def user_modification(self) -> bool:
            """Whether user modification is allowed."""
            ...

        @property
        def obsolete(self) -> bool:
            """Whether the attribute is obsolete."""
            ...

        @property
        def x_origin(self) -> str | None:
            """The server-specific origin extension."""
            ...

        @property
        def x_file_ref(self) -> str | None:
            """The server-specific file-reference extension."""
            ...

        @property
        def x_name(self) -> str | None:
            """The server-specific extended name."""
            ...

        @property
        def x_alias(self) -> str | None:
            """The server-specific alias."""
            ...

        @property
        def x_oid(self) -> str | None:
            """The server-specific extended OID."""
            ...

        # NOTE (multi-agent, mro-0ftd.3.7.2): metadata/model_copy now inherited
        # from the SchemaElement base protocol (DRY).

    @runtime_checkable
    class SchemaObjectClass(SchemaElement, Protocol):
        """LDIF schema objectClass contract."""

        @property
        def oid(self) -> str:
            """The objectClass OID."""
            ...

        @property
        def name(self) -> str:
            """The objectClass name."""
            ...

        # NOTE (multi-agent, mro-0ftd.3.7.2): schema business fields the fix_*
        # normalization helpers read — concrete model domain_schema.py:250/256.
        @property
        def sup(self) -> str | t.MutableSequenceOf[str] | None:
            """The superior object class(es) (RFC 4512 SUP)."""
            ...

        @property
        def kind(self) -> str:
            """The objectClass kind (STRUCTURAL/AUXILIARY/ABSTRACT)."""
            ...

        @property
        def desc(self) -> str | None:
            """The objectClass description."""
            ...

        @property
        def must(self) -> Sequence[str] | None:
            """The required attribute names."""
            ...

        @property
        def may(self) -> Sequence[str] | None:
            """The optional attribute names."""
            ...

        # NOTE (multi-agent, mro-0ftd.3.7.2): metadata/model_copy inherited from
        # the SchemaElement base protocol (DRY); sup/kind stay leaf-specific.

    @runtime_checkable
    class Acl(p.BaseModel, Protocol):
        """ACL model contract."""

        @property
        def name(self) -> str:
            """ACL name."""
            ...

        @property
        def server_type(self) -> str:
            """ACL server type."""
            ...

        @property
        def permissions(self) -> FlextLdifProtocolsBase.AclPermissions | None:
            """ACL permissions."""
            ...

        @property
        def target(self) -> FlextLdifProtocolsBase.AclTarget | None:
            """ACL target specification."""
            ...

        @property
        def subject(self) -> FlextLdifProtocolsBase.AclSubject | None:
            """ACL subject specification."""
            ...

        @property
        def raw_acl(self) -> str:
            """The original ACL string."""
            ...

        # NOTE (multi-agent, mro-0ftd.3.7.2): complete the behavioral contract
        # (§3.2) — concrete model has metadata (domain_acl.py:175) and
        # model_copy via BaseModel; Pydantic-2-way frozen-transition canon.
        @property
        def metadata(self) -> FlextLdifProtocolsBase.ServerMetadata | None:
            """The server-specific ACL metadata."""
            ...

    @runtime_checkable
    class Control(p.BaseModel, Protocol):
        """RFC 2849 control contract attached to an LDIF record."""

        @property
        def control_type(self) -> str:
            """The LDAP control OID or descriptor."""
            ...

        @property
        def criticality(self) -> bool | None:
            """The optional control criticality flag."""
            ...

        @property
        def value(self) -> str | None:
            """The decoded control value."""
            ...

        @property
        def value_origin(self) -> c.Ldif.ValueOrigin | None:
            """The original control-value encoding."""
            ...

        @property
        def raw_value(self) -> str | None:
            """The original serialized control value."""
            ...

    @runtime_checkable
    class ChangeOperationValue(p.BaseModel, Protocol):
        """One decoded value inside an LDIF modify operation."""

        @property
        def value(self) -> str:
            """The decoded operation value."""
            ...

        @property
        def value_origin(self) -> c.Ldif.ValueOrigin:
            """The original value encoding."""
            ...

        @property
        def raw_value(self) -> str | None:
            """The original serialized value."""
            ...

    @runtime_checkable
    class ChangeOperation(p.BaseModel, Protocol):
        """Structured RFC 2849 modify operation."""

        @property
        def operation(self) -> c.Ldif.ChangeOperation:
            """The modify operation kind."""
            ...

        @property
        def attribute(self) -> str:
            """The target attribute name."""
            ...

        @property
        def values(self) -> Sequence[FlextLdifProtocolsBase.ChangeOperationValue]:
            """The decoded values in the modify block."""
            ...

    @runtime_checkable
    class Entry(p.BaseModel, Protocol):
        """Entry model contract used across LDIF services."""

        @property
        def dn(self) -> FlextLdifProtocolsBase.DN | None:
            """The entry DN."""
            ...

        @property
        def dn_str(self) -> str:
            """The entry DN rendered as a string."""
            ...

        @property
        def attributes(self) -> FlextLdifProtocolsBase.Attributes | None:
            """The entry attributes."""
            ...

        @property
        def changetype(self) -> c.Ldif.ChangeType | None:
            """The changetype when present."""
            ...

        @property
        def record_kind(self) -> c.Ldif.RecordKind:
            """Whether the record is content or change."""
            ...

        @property
        def newrdn(self) -> str | None:
            """The newrdn for moddn/modrdn records."""
            ...

        @property
        def deleteoldrdn(self) -> bool | None:
            """The deleteoldrdn for moddn/modrdn records."""
            ...

        @property
        def newsuperior(self) -> str | None:
            """The newsuperior for moddn records."""
            ...

        @property
        def controls(self) -> Sequence[FlextLdifProtocolsBase.Control]:
            """The RFC 2849 controls attached to the record."""
            ...

        @property
        def change_operations(self) -> Sequence[FlextLdifProtocolsBase.ChangeOperation]:
            """The structured modify operations attached to the record."""
            ...

        # NOTE (multi-agent, mro-0ftd.3.7.2): complete the behavioral contract so
        # consumers can annotate payloads as p.Ldif.Entry (§3.2) instead of the
        # concrete m.Ldif.Entry. metadata is a read-only @property (covariant): the
        # concrete m.Ldif.Entry field satisfies it, while a read-write attribute would
        # be invariant and unsatisfiable. Handlers transition via
        # entry.model_copy(update={"metadata": ...}) — the Pydantic-2 frozen-transition
        # canon (works on the mutable DynamicModel too, mirroring SchemaElement/Acl).
        @property
        def metadata(self) -> FlextLdifProtocolsBase.ServerMetadata | None:
            """The server-specific entry metadata."""
            ...

    @runtime_checkable
    class EntryValidationSubject(Protocol):
        """Minimal entry contract used by RFC/server validation helpers."""

        @property
        def attributes(self) -> FlextLdifProtocolsBase.Attributes | None:
            """The entry attributes for validation helpers."""
            ...

        @property
        def changetype(self) -> c.Ldif.ChangeType | None:
            """The entry changetype for validation helpers."""
            ...

    @runtime_checkable
    class EntryWithMetadata(Protocol):
        """Entry-like value that exposes write-capable metadata."""

        @property
        def metadata(self) -> FlextLdifProtocolsBase.MetadataWithWriteOptions | None:
            """The metadata that may carry write options."""
            ...

    @runtime_checkable
    class Statistics(Protocol):
        """Aggregate statistics payload for parse/write/migration flows."""

        @property
        def total_entries(self) -> int:
            """The total processed entries."""
            ...

        @property
        def processed_entries(self) -> int:
            """The successfully processed entries."""
            ...

        @property
        def failed_entries(self) -> int:
            """The failed entry count."""
            ...

        @property
        def rejected_entries(self) -> int:
            """The rejected entry count."""
            ...

        @property
        def events(
            self,
        ) -> t.SequenceOf[
            FlextLdifProtocolsBase.ConversionEvent | FlextLdifProtocolsBase.DnEvent
        ]:
            """The accumulated processing events."""
            ...

    @runtime_checkable
    class Response(Protocol):
        """Canonical LDIF service response payload."""

        @property
        def statistics(self) -> FlextLdifProtocolsBase.Statistics:
            """The pipeline statistics."""
            ...

    @runtime_checkable
    class ParseResponse(Response, Protocol):
        """Parsed LDIF batch response."""

        @property
        def entries(self) -> t.SequenceOf[FlextLdifProtocolsBase.Entry]:
            """The parsed entries."""
            ...

        @property
        def detected_server_type(self) -> str | None:
            """The detected server type."""
            ...

    @runtime_checkable
    class ValidationResult(Protocol):
        """Validation summary contract."""

        @property
        def valid(self) -> bool:
            """The validation outcome."""
            ...

        @property
        def total_entries(self) -> int:
            """The validated entry count."""
            ...

        @property
        def valid_entries(self) -> int:
            """The valid entry count."""
            ...

        @property
        def invalid_entries(self) -> int:
            """The invalid entry count."""
            ...

        @property
        def errors(self) -> t.StrSequence:
            """The validation errors."""
            ...

    @runtime_checkable
    class MigrationPipelineResult(p.BaseModel, Protocol):
        """Migration pipeline result contract."""

        @property
        def entries(self) -> t.SequenceOf[FlextLdifProtocolsBase.Entry]:
            """The migrated entries."""
            ...

        @property
        def stats(self) -> FlextLdifProtocolsBase.Statistics:
            """The migration statistics."""
            ...

        @property
        def output_files(self) -> t.StrSequence:
            """The generated output files."""
            ...

        @property
        def entry_count(self) -> int:
            """The number of migrated entries."""
            ...

        @property
        def is_empty(self) -> bool:
            """Whether the migration produced no schema or entries."""
            ...

        @property
        def output_file_count(self) -> int:
            """The number of generated output files."""
            ...

    @runtime_checkable
    class AclResponse(Response, Protocol):
        """ACL extraction response payload."""

        @property
        def acls(self) -> t.SequenceOf[FlextLdifProtocolsBase.Acl]:
            """The extracted ACLs."""
            ...

    @runtime_checkable
    class WriteResponse(Response, Protocol):
        """Write response payload."""

        @property
        def content(self) -> str | None:
            """The serialized LDIF text."""
            ...

        @property
        def output_path(self) -> str | None:
            """The persisted output path."""
            ...

    @runtime_checkable
    class ConversionEvent(p.DomainEvent, Protocol):
        """Conversion event contract."""

        @property
        def conversion_operation(self) -> str:
            """The conversion operation name."""
            ...

        @property
        def source_format(self) -> str:
            """The source format."""
            ...

        @property
        def target_format(self) -> str:
            """The target format."""
            ...

        @property
        def items_converted(self) -> int:
            """The converted item count."""
            ...

        @property
        def items_failed(self) -> int:
            """The failed item count."""
            ...

        @property
        def error_details(self) -> t.StrSequence | None:
            """The conversion error details."""
            ...

        @property
        def conversion_success_rate(self) -> float:
            """The percentage of converted items."""
            ...

        @property
        def throughput_items_per_sec(self) -> float:
            """The conversion throughput in items per second."""
            ...

    @runtime_checkable
    class DnEvent(p.DomainEvent, Protocol):
        """DN event contract."""

        @property
        def dn_operation(self) -> str:
            """DN operation name."""
            ...

        @property
        def input_dn(self) -> str:
            """The input DN."""
            ...

        @property
        def output_dn(self) -> str | None:
            """The output DN."""
            ...

        validation_result: bool | None

        @property
        def has_output(self) -> bool:
            """Whether the operation produced a DN."""
            ...

        @property
        def component_count(self) -> int:
            """The number of RDN components."""
            ...

    @runtime_checkable
    class DnRegistry(Protocol):
        """DN registry contract used during conversions."""

        def clear(self) -> None:
            """Reset all registered DN state."""
            ...

        def resolve_canonical_dn(self, dn: str) -> str | None:
            """Return canonical DN casing when known."""
            ...

        def register_dn(self, dn: str, *, force: bool = False) -> str:
            """Register and return canonical DN casing."""
            ...

    @runtime_checkable
    class ModelWithValidationMetadata(Protocol):
        """Model exposing validation metadata for helper updates."""

        @property
        def validation_metadata(self) -> p.BaseModel | None:
            """The validated metadata model when one is present."""
            ...

    @runtime_checkable
    class CategorizationService(Protocol):
        """Protocol for LDIF entry categorization services."""

        def categorize_entries(
            self, entries: Sequence[FlextLdifProtocolsBase.Entry]
        ) -> p.Result[FlextLdifProtocolsBase.FlexibleCategories]:
            """Categorize validated entries."""
            ...

        def filter_by_base_dn(
            self, categories: FlextLdifProtocolsBase.FlexibleCategories
        ) -> FlextLdifProtocolsBase.FlexibleCategories:
            """Filter categorized entries by base DN."""
            ...

        def validate_dns(
            self,
            entries: Sequence[FlextLdifProtocolsBase.Entry]
            | FlextLdifProtocolsBase.ParseResponse,
        ) -> p.Result[Sequence[FlextLdifProtocolsBase.Entry]]:
            """Validate and normalize entry DNs."""
            ...

        def filter_schema_by_oids(
            self, schema_entries: Sequence[FlextLdifProtocolsBase.Entry]
        ) -> p.Result[Sequence[FlextLdifProtocolsBase.Entry]]:
            """Filter schema entries by allowed OIDs."""
            ...

    @runtime_checkable
    class ProcessingPipeline(Protocol):
        """Protocol for LDIF processing pipelines."""

        def execute(self) -> p.Result[Sequence[FlextLdifProtocolsBase.Entry]]:
            """Execute the processing pipeline."""
            ...

    @runtime_checkable
    class MigrationPipeline(Protocol):
        """Protocol for LDIF migration pipelines."""

        @property
        def input_dir(self) -> Path | None:
            """The directory containing source LDIF files."""
            ...

        @property
        def output_dir(self) -> Path | None:
            """The directory receiving migrated LDIF files."""
            ...

        @property
        def source_server_type(self) -> str | c.Ldif.ServerTypes | None:
            """The configured source server type."""
            ...

        @property
        def target_server_type(self) -> str | c.Ldif.ServerTypes | None:
            """The configured target server type."""
            ...

        def execute(self) -> p.Result[FlextLdifProtocolsBase.MigrationPipelineResult]:
            """Execute the migration pipeline."""
            ...

        def migrate_entries(
            self, entries: t.MutableSequenceOf[FlextLdifProtocolsBase.Entry]
        ) -> p.Result[t.MutableSequenceOf[FlextLdifProtocolsBase.Entry]]:
            """Migrate validated entries between server formats."""
            ...

        def migrate_file(
            self, input_file: Path, output_file: Path | None = None
        ) -> p.Result[FlextLdifProtocolsBase.MigrationPipelineResult]:
            """Migrate one LDIF file."""
            ...

    @runtime_checkable
    class ServerReference(Protocol):
        """Anything that can identify itself as a server via ``server_type``."""

        server_type: ClassVar[str]

    @runtime_checkable
    class ServerConstants(Protocol):
        """Server constants contract extracted from server namespaces."""

        SERVER_TYPE: str
        PRIORITY: int
        DETECTION_PATTERN: str | t.RegexPattern | None
        DETECTION_WEIGHT: int
        DETECTION_ATTRIBUTES: t.IterableOf[str]
        DETECTION_OID_PATTERN: str | t.RegexPattern | None
        DETECTION_ATTRIBUTE_PREFIXES: t.IterableOf[str] | None
        DETECTION_OBJECTCLASS_NAMES: t.IterableOf[str] | None
        DETECTION_DN_MARKERS: t.IterableOf[str] | None
        ACL_ATTRIBUTE_NAME: str | None
        CATEGORIZATION_PRIORITY: t.StrSequence
        CATEGORY_OBJECTCLASSES: t.FrozensetMapping
        HIERARCHY_PRIORITY_OBJECTCLASSES: frozenset[str]
        CATEGORIZATION_ACL_ATTRIBUTES: frozenset[str]

    @runtime_checkable
    class Predicate[T](Protocol):
        """Predicate function contract."""

        def __call__(self, item: T) -> bool:
            """Return whether the item matches the predicate."""
            ...


__all__: list[str] = ["FlextLdifProtocolsBase"]
