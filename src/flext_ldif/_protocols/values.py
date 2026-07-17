"""Structural contracts for model-backed LDIF values."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Protocol, runtime_checkable

from flext_cli import p, t
from flext_ldif.constants import c


@runtime_checkable
class FlextLdifProtocolsValues(Protocol):
    """Protocol-only view of canonical LDIF Pydantic values."""

    @runtime_checkable
    class AciAllow(p.BaseModel, Protocol):
        """Rendered OUD allow-clause contract."""

        @property
        def subject_type(self) -> str: ...

        @property
        def subject_value(self) -> str: ...

        @property
        def permissions(self) -> t.StrSequence: ...

        @property
        def authmethod(self) -> str: ...

        @property
        def ip(self) -> str: ...

    @runtime_checkable
    class AciLineFormatConfig(p.BaseModel, Protocol):
        """ACI line formatting contract."""

        @property
        def name(self) -> str: ...

        @property
        def target_clause(self) -> str: ...

        @property
        def permissions_clause(self) -> str: ...

        @property
        def bind_rule(self) -> str: ...

        @property
        def aci_prefix(self) -> str: ...

        @property
        def version(self) -> str: ...

    @runtime_checkable
    class AciParserConfig(p.BaseModel, Protocol):
        """Server-specific ACI parsing contract."""

        @property
        def server_type(self) -> c.Ldif.ServerTypes: ...

        @property
        def aci_prefix(self) -> str: ...

        @property
        def version_acl_pattern(self) -> str: ...

        @property
        def targetattr_pattern(self) -> str: ...

        @property
        def default_targetattr(self) -> str: ...

        @property
        def allow_deny_pattern(self) -> str: ...

        @property
        def ops_separator(self) -> str: ...

        @property
        def action_filter(self) -> str | None: ...

        @property
        def bind_patterns(self) -> Mapping[str, str]: ...

        @property
        def permission_map(self) -> Mapping[str, str]: ...

        @property
        def special_subjects(self) -> Mapping[str, tuple[str, str]]: ...

        @property
        def extra_patterns(self) -> Mapping[str, str]: ...

        @property
        def default_name(self) -> str: ...

    @runtime_checkable
    class AciRule(p.BaseModel, Protocol):
        """OUD ACI rule contract."""

        @property
        def targetattr(self) -> str: ...

        @property
        def targetfilter(self) -> str | None: ...

        @property
        def targetscope(self) -> str | None: ...

        @property
        def acl_name(self) -> str: ...

        @property
        def allows(self) -> Sequence[FlextLdifProtocolsValues.AciAllow]: ...

        @property
        def notes(self) -> t.StrSequence: ...

    @runtime_checkable
    class AclMetadataConfig(p.BaseModel, Protocol):
        """ACL metadata-extension contract."""

        @property
        def line_breaks(self) -> t.JsonValueList | None: ...

        @property
        def dn_spaces(self) -> str | None: ...

        @property
        def targetscope(self) -> t.JsonValueList | None: ...

        @property
        def version(self) -> str | None: ...

        @property
        def action_type(self) -> str | None: ...

    @runtime_checkable
    class AclSubjectMatcher(p.BaseModel, Protocol):
        """Compiled OID subject matcher contract."""

        @property
        def pattern(self) -> t.RegexPattern: ...

        @property
        def subj_type(self) -> str: ...

        @property
        def value_group(self) -> int | str: ...

        @property
        def perms_group(self) -> int: ...

    @runtime_checkable
    class AclSubjectMatcherCatalog(p.BaseModel, Protocol):
        """OID matcher catalog contract."""

        @property
        def matchers(self) -> Sequence[FlextLdifProtocolsValues.AclSubjectMatcher]: ...

    @runtime_checkable
    class AclWriteMetadata(p.BaseModel, Protocol):
        """ACL write-format metadata contract."""

        @property
        def original_format(self) -> str | None: ...

        def has_original_format(self) -> bool: ...

    @runtime_checkable
    class ConversionEventConfig(p.BaseModel, Protocol):
        """Conversion-event construction contract."""

        @property
        def conversion_operation(self) -> str: ...

        @property
        def source_format(self) -> str: ...

        @property
        def target_format(self) -> str: ...

        @property
        def items_processed(self) -> int: ...

        @property
        def items_converted(self) -> int: ...

        @property
        def items_failed(self) -> int: ...

        @property
        def conversion_duration_ms(self) -> float: ...

        @property
        def error_details(self) -> Sequence[str] | None: ...

    @runtime_checkable
    class DnEventConfig(p.BaseModel, Protocol):
        """DN-event construction contract."""

        @property
        def dn_operation(self) -> str: ...

        @property
        def input_dn(self) -> str: ...

        @property
        def output_dn(self) -> str | None: ...

        @property
        def operation_duration_ms(self) -> float: ...

        @property
        def validation_result(self) -> bool | None: ...

    @runtime_checkable
    class EntryParseMetadataConfig(p.BaseModel, Protocol):
        """Entry parse-metadata contract."""

        @property
        def server_type(self) -> c.Ldif.ServerTypes: ...

        @property
        def original_entry_dn(self) -> str: ...

        @property
        def cleaned_dn(self) -> str: ...

        @property
        def original_dn_line(self) -> str | None: ...

        @property
        def original_attr_lines(self) -> Sequence[str] | None: ...

        @property
        def dn_was_base64(self) -> bool: ...

        @property
        def original_attribute_case(self) -> Mapping[str, str] | None: ...

    @runtime_checkable
    class LogContextExtras(p.BaseModel, Protocol):
        """Optional structured logging context."""

        @property
        def user_id(self) -> str | None: ...

        @property
        def session_id(self) -> str | None: ...

        @property
        def request_id(self) -> str | None: ...

        @property
        def component(self) -> str | None: ...

        @property
        def correlation_id(self) -> str | None: ...

        @property
        def trace_id(self) -> str | None: ...

    @runtime_checkable
    class OidAclMetadataConfig(p.BaseModel, Protocol):
        """OID ACL metadata parsing contract."""

        @property
        def acl_line(self) -> str: ...

        @property
        def oid_subject_type(self) -> str: ...

        @property
        def rfc_subject_type(self) -> str: ...

        @property
        def oid_subject_value(self) -> str: ...

        @property
        def perms_dict(self) -> Mapping[str, bool]: ...

        @property
        def target_dn(self) -> str: ...

        @property
        def target_attrs(self) -> Sequence[str]: ...

        @property
        def acl_filter(self) -> str: ...

        @property
        def acl_constraint(self) -> str: ...

        @property
        def bindmode(self) -> str: ...

        @property
        def deny_group_override(self) -> bool: ...

        @property
        def append_to_all(self) -> bool: ...

        @property
        def bind_ip_filter(self) -> str: ...

        @property
        def constrain_to_added_object(self) -> str: ...

    @runtime_checkable
    class OidAclRule(p.BaseModel, Protocol):
        """Parsed OID ACL rule contract."""

        @property
        def dn(self) -> str: ...

        @property
        def acl_type(self) -> str: ...

        @property
        def target_type(self) -> str: ...

        @property
        def target_attrs(self) -> str: ...

        @property
        def target_filter(self) -> str | None: ...

        @property
        def subjects(self) -> Sequence[FlextLdifProtocolsValues.OidAclSubject]: ...

    @runtime_checkable
    class OidAclSubject(p.BaseModel, Protocol):
        """Parsed OID ACL subject contract."""

        @property
        def subject_type(self) -> str: ...

        @property
        def value(self) -> str: ...

        @property
        def permissions(self) -> t.StrSequence: ...

        @property
        def bindmode(self) -> str: ...

        @property
        def bindipfilter(self) -> str: ...

        @property
        def added_object_constraint(self) -> str: ...

    @runtime_checkable
    class OidAclSubjectModifiers(p.BaseModel, Protocol):
        """Optional OID subject modifiers."""

        @property
        def bindmode(self) -> str: ...

        @property
        def bindipfilter(self) -> str: ...

        @property
        def added_object_constraint(self) -> str: ...

    @runtime_checkable
    class RdnProcessingConfig(p.BaseModel, Protocol):
        """Mutable RDN-parser state contract."""

        current_attr: str
        current_val: str
        in_value: bool
        pairs: t.MutableStrPairSequence

    @runtime_checkable
    class ServerPatternsConfig(p.BaseModel, Protocol):
        """Server schema-detection patterns contract."""

        @property
        def oid_pattern(self) -> str: ...

        @property
        def dn_patterns(self) -> Sequence[t.StrSequence]: ...

        @property
        def attr_prefixes(self) -> t.StrSequence | frozenset[str]: ...

        @property
        def attr_names(self) -> frozenset[str] | set[str]: ...

        @property
        def keyword_patterns(self) -> t.StrSequence: ...

        @property
        def detection_string(self) -> str | None: ...

        @property
        def name_regex(self) -> str | None: ...

        @property
        def use_prefix_match(self) -> bool: ...

        @property
        def match_definition_text(self) -> bool: ...

    @runtime_checkable
    class DnNormalizationConfig(p.BaseModel, Protocol):
        """DN normalization options."""

        @property
        def case_sensitive(self) -> bool: ...

        @property
        def remove_spaces(self) -> bool: ...

        @property
        def case_fold(self) -> str | None: ...

        @property
        def space_handling(self) -> str | None: ...

        @property
        def escape_handling(self) -> str | None: ...

        @property
        def validate_before(self) -> bool: ...

    @runtime_checkable
    class AttrNormalizationConfig(p.BaseModel, Protocol):
        """Attribute normalization options."""

        @property
        def lowercase_keys(self) -> bool: ...

        @property
        def sort_values(self) -> bool: ...

        @property
        def sort_attributes(self) -> str | None: ...

        @property
        def normalize_whitespace(self) -> bool: ...

        @property
        def case_fold_names(self) -> bool: ...

        @property
        def trim_values(self) -> bool: ...

        @property
        def remove_empty(self) -> bool: ...

    @runtime_checkable
    class ProcessConfig(p.BaseModel, Protocol):
        """Batch-processing configuration contract."""

        @property
        def source_server(self) -> str | None: ...

        @property
        def target_server(self) -> str | None: ...

        @property
        def base_dn(self) -> str: ...

        @property
        def dn_config(
            self,
        ) -> FlextLdifProtocolsValues.DnNormalizationConfig | None: ...

        @property
        def attr_config(
            self,
        ) -> FlextLdifProtocolsValues.AttrNormalizationConfig | None: ...

    @runtime_checkable
    class TransformConfig(p.BaseModel, Protocol):
        """Transformation pipeline configuration contract."""

        @property
        def normalize_dns(self) -> bool: ...

        @property
        def normalize_attrs(self) -> bool: ...

        @property
        def process_config(self) -> FlextLdifProtocolsValues.ProcessConfig | None: ...


__all__: list[str] = ["FlextLdifProtocolsValues"]
