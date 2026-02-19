"""Domain models for LDIF entities."""

from __future__ import annotations

import re
from collections.abc import Callable, KeysView, Mapping, Sequence, ValuesView
from contextlib import suppress
from datetime import datetime
from typing import ClassVar, Self

from flext_core import FlextLogger, FlextResult, FlextUtilities, t
from flext_core._models.base import FlextModelsBase
from flext_core._models.entity import FlextModelsEntity
from pydantic import (
    ConfigDict,
    Field,
    computed_field,
    field_validator,
    model_validator,
)

from flext_ldif._models.base import (
    AclElement,
    FlextLdifModelsBase,
    FrozenIgnoreLdifModel,
    FrozenLdifModel,
    MutableIgnoreLdifModel,
    SchemaElement,
)
from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif._models.validation import ServerValidationRules
from flext_ldif._shared import normalize_server_type
from flext_ldif.constants import c

u = FlextUtilities

logger = FlextLogger(__name__)


class FlextLdifModelsDomains:
    """LDIF domain models container class."""

    class DN(FlextModelsEntity.Value):
        """Distinguished Name value object."""

        model_config = ConfigDict(
            strict=True,
            frozen=True,
            extra="forbid",
            validate_default=True,
            use_enum_values=True,
            str_strip_whitespace=True,
        )

        value: str = Field(
            ...,
        )
        metadata: FlextLdifModelsMetadata.EntryMetadata = Field(
            default_factory=FlextLdifModelsMetadata.EntryMetadata,
        )

        _DN_COMPONENT_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
            r"^[a-zA-Z][a-zA-Z0-9-]*=(?:[^\\,]|\\.)*$",
            re.IGNORECASE,
        )

        @property
        def components(self) -> list[str]:
            """Parse DN into individual RDN components."""
            if not self.value:
                return []

            raw_components = [comp.strip() for comp in self.value.split(",")]

            return [comp for comp in raw_components if comp]

        @property
        def was_base64_encoded(self) -> bool:
            """Check if DN was originally base64-encoded per RFC 2849."""
            if not self.metadata:
                return False
            return getattr(self.metadata, "original_format", None) == "base64"

        def create_statistics(
            self,
            original_dn: str | None = None,
            cleaned_dn: str | None = None,
            transformations: list[str] | None = None,
            flags: FlextLdifModelsDomains.DNStatisticsFlagsModel | None = None,
        ) -> FlextLdifModelsDomains.DNStatistics:
            """Create DNStatistics for this DN with transformation history."""
            final_dn = self.value
            orig_dn = original_dn or final_dn
            clean_dn = cleaned_dn or final_dn

            result_flags = flags or FlextLdifModelsDomains.DNStatisticsFlagsModel()
            if self.metadata:
                if self.was_base64_encoded and result_flags.was_base64_encoded is None:
                    result_flags = result_flags.model_copy(
                        update={"was_base64_encoded": True}
                    )
                if (
                    getattr(self.metadata, "had_utf8_chars", False)
                    and result_flags.had_utf8_chars is None
                ):
                    result_flags = result_flags.model_copy(
                        update={"had_utf8_chars": True}
                    )
                if (
                    getattr(self.metadata, "had_escape_sequences", False)
                    and result_flags.had_escape_sequences is None
                ):
                    result_flags = result_flags.model_copy(
                        update={"had_escape_sequences": True}
                    )

            return FlextLdifModelsDomains.DNStatistics.create_with_transformation(
                original_dn=orig_dn,
                cleaned_dn=clean_dn,
                normalized_dn=final_dn,
                transformations=transformations if transformations is not None else [],
                flags=result_flags,
            )

        @classmethod
        def from_value(cls, dn: str | Self | None) -> Self:
            """Create DN from string or existing instance."""
            if dn is None:
                msg = "dn cannot be None"
                raise ValueError(msg)

            if isinstance(dn, str):
                return cls.model_validate({"value": dn})

            return dn

        def __str__(self) -> str:
            """Return DN value as string for str() conversion."""
            return self.value

    class SchemaAttribute(SchemaElement):
        """LDAP schema attribute definition model (RFC 4512 compliant)."""

        name: str = Field(...)
        oid: str = Field(...)
        desc: str | None = Field(
            default=None,
        )
        sup: str | None = Field(
            default=None,
        )
        equality: str | None = Field(
            default=None,
        )
        ordering: str | None = Field(
            default=None,
        )
        substr: str | None = Field(
            default=None,
        )
        syntax: str | None = Field(
            default=None,
        )
        length: int | None = Field(
            default=None,
        )
        usage: str | None = Field(
            default=None,
        )
        single_value: bool = Field(
            default=False,
        )
        collective: bool = Field(
            default=False,
        )
        no_user_modification: bool = Field(
            default=False,
        )

        immutable: bool = Field(
            default=False,
        )
        user_modification: bool = Field(
            default=True,
        )
        obsolete: bool = Field(
            default=False,
        )
        x_origin: str | None = Field(
            default=None,
        )
        x_file_ref: str | None = Field(
            default=None,
        )
        x_name: str | None = Field(
            default=None,
        )
        x_alias: str | None = Field(
            default=None,
        )
        x_oid: str | None = Field(
            default=None,
        )
        metadata: FlextLdifModelsDomains.QuirkMetadata | None = Field(
            default=None,
        )

        @computed_field
        def has_matching_rules(self) -> bool:
            """Check if attribute has any matching rules defined."""
            return bool(self.equality or self.ordering or self.substr)

        @computed_field
        def syntax_definition(self) -> FlextLdifModelsDomains.Syntax | None:
            """Resolve syntax OID to complete Syntax model using RFC 4517 validation."""
            if not self.syntax:
                return None

            return FlextLdifModelsDomains.Syntax.resolve_syntax_oid(
                self.syntax,
                server_type="rfc",
            )

    class Syntax(SchemaElement):
        """LDAP attribute syntax definition model (RFC 4517 compliant)."""

        oid: str = Field(
            ...,
        )
        name: str | None = Field(
            None,
        )
        desc: str | None = Field(
            None,
        )
        type_category: str = Field(
            default="string",
        )
        is_binary: bool = Field(
            default=False,
        )
        max_length: int | None = Field(
            None,
        )
        case_insensitive: bool = Field(
            default=False,
        )
        allows_multivalued: bool = Field(
            default=True,
        )
        encoding: c.Ldif.LiteralTypes.EncodingLiteral = Field(
            default="utf-8",
        )
        validation_pattern: str | None = Field(
            None,
        )
        metadata: FlextLdifModelsDomains.QuirkMetadata | None = Field(
            default=None,
        )

        @field_validator("oid")
        @classmethod
        def validate_oid(cls, v: str) -> str:
            """Validate that OID is not empty."""
            if not v or not v.strip():
                msg = "OID cannot be empty"
                raise ValueError(msg)
            return v

        @computed_field
        def is_rfc4517_standard(self) -> bool:
            """Check if this is a standard RFC 4517 syntax OID."""
            oid_base = "1.3.6.1.4.1.1466.115.121.1"
            return self.oid.startswith(oid_base)

        @computed_field
        def syntax_oid_suffix(self) -> str | None:
            """Extract the numeric suffix from RFC 4517 OID."""
            oid_base = "1.3.6.1.4.1.1466.115.121.1"
            is_standard = self.oid.startswith(oid_base)
            if not is_standard:
                return None
            parts = self.oid.split(".")
            return parts[-1] if parts else None

        @classmethod
        def resolve_syntax_oid(
            cls,
            oid: str,
            server_type: c.Ldif.LiteralTypes.ServerTypeLiteral = "rfc",
        ) -> Self | None:
            """Resolve a syntax OID to a Syntax model using RFC 4517 validation."""
            if not oid or not oid.strip():
                return None

            try:
                oid_pattern = re.compile(r"^\d+(\.\d+)*$")
                if not oid_pattern.match(oid):
                    return None

                oid_to_name = dict(c.Ldif.RfcSyntaxOids.OID_TO_NAME)

                name = oid_to_name.get(oid)
                type_category = (
                    c.Ldif.RfcSyntaxOids.NAME_TO_TYPE_CATEGORY.get(
                        name,
                        "string",
                    )
                    if name
                    else "string"
                )

                metadata = (
                    FlextLdifModelsDomains.QuirkMetadata(
                        quirk_type=server_type,
                    )
                    if server_type != c.Ldif.ServerTypes.RFC.value
                    else None
                )

                return cls(
                    oid=oid,
                    name=name,
                    desc=None,
                    type_category=type_category,
                    max_length=None,
                    validation_pattern=None,
                    metadata=metadata,
                )

            except Exception:
                return None

    class SchemaObjectClass(SchemaElement):
        """LDAP schema object class definition model (RFC 4512 compliant)."""

        name: str = Field(...)
        oid: str = Field(...)
        desc: str | None = Field(
            default=None,
        )
        sup: str | (list[str] | None) = Field(
            default=None,
        )
        kind: str = Field(
            default="STRUCTURAL",
        )
        must: list[str] | None = Field(
            default=None,
        )
        may: list[str] | None = Field(
            default=None,
        )
        metadata: FlextLdifModelsDomains.QuirkMetadata | None = Field(
            default=None,
        )

        @computed_field
        def is_structural(self) -> bool:
            """Check if this is a structural object class."""
            return self.kind.upper() == "STRUCTURAL"

        @computed_field
        def is_auxiliary(self) -> bool:
            """Check if this is an auxiliary object class."""
            return self.kind.upper() == "AUXILIARY"

        @computed_field
        def is_abstract(self) -> bool:
            """Check if this is an abstract object class."""
            return self.kind.upper() == "ABSTRACT"

        @computed_field
        def total_attributes(self) -> int:
            """Total number of attributes (required + optional)."""
            must_count = len(self.must) if self.must else 0
            may_count = len(self.may) if self.may else 0
            return must_count + may_count

        @computed_field
        def attribute_summary(self) -> dict[str, int]:
            """Get summary of required and optional attributes."""
            must_count = len(self.must) if self.must else 0
            may_count = len(self.may) if self.may else 0
            return {
                "required": must_count,
                "optional": may_count,
                "total": must_count + may_count,
            }

    class Attributes(FlextModelsBase.ArbitraryTypesModel):
        """LDIF attributes container - simplified dict-like interface."""

        model_config = ConfigDict(
            validate_assignment=True,
            extra="forbid",
            use_enum_values=True,
            str_strip_whitespace=True,
        )

        attributes: dict[str, list[str]] = Field(
            default_factory=dict,
        )
        attribute_metadata: dict[str, dict[str, str | list[str]]] = Field(
            default_factory=dict,
        )
        metadata: FlextLdifModelsMetadata.EntryMetadata | None = Field(
            default=None,
        )

        def __len__(self) -> int:
            """Return the number of attributes."""
            return len(self.attributes)

        def __getitem__(self, key: str) -> list[str]:
            """Get attribute values by name (case-sensitive LDAP)."""
            return self.attributes[key]

        def __setitem__(self, key: str, value: list[str]) -> None:
            """Set attribute values by name."""
            self.attributes[key] = value

        def __contains__(self, key: str) -> bool:
            """Check if attribute exists."""
            return key in self.attributes

        def get(self, key: str, default: list[str] | None = None) -> list[str]:
            """Get attribute values with optional default."""
            if default is not None:
                return self.attributes.get(key, default)
            if key in self.attributes:
                return self.attributes[key]

            return []

        def get_values(self, key: str, default: list[str] | None = None) -> list[str]:
            """Get attribute values as a list (same as get())."""
            return self.get(key, default)

        def has_attribute(self, key: str) -> bool:
            """Check if attribute exists."""
            return key in self.attributes

        def iter_attributes(self) -> list[str]:
            """Get list of all attribute names."""
            return list(self.attributes.keys())

        def items(self) -> list[tuple[str, list[str]]]:
            """Get attribute name-values pairs."""
            return list(self.attributes.items())

        def keys(self) -> KeysView[str]:
            """Get attribute names."""
            return self.attributes.keys()

        def values(self) -> ValuesView[list[str]]:
            """Get attribute values lists."""
            return self.attributes.values()

        def add_attribute(self, key: str, values: str | list[str]) -> Self:
            """Add or update an attribute with values."""
            if isinstance(values, str):
                values = [values]

            self.attributes[key] = values
            return self

        def remove_attribute(self, key: str) -> Self:
            """Remove an attribute if it exists."""
            _ = self.attributes.pop(key, None)
            return self

        def to_ldap3(
            self,
            exclude: list[str] | None = None,
        ) -> dict[str, list[str]]:
            """Convert to ldap3-compatible attributes dict."""
            exclude_set = set(exclude if exclude is not None else [])
            return {
                attr_name: values
                for attr_name, values in self.attributes.items()
                if attr_name not in exclude_set
            }

        @classmethod
        def create(
            cls,
            attrs_data: Mapping[
                str,
                str | list[str] | bytes | list[bytes] | int | float | bool | None,
            ],
        ) -> FlextResult[FlextLdifModelsDomains.Attributes]:
            """Create an Attributes instance from data."""
            try:
                normalized_dict: dict[str, list[str]] = {}
                for key, val in attrs_data.items():
                    if isinstance(val, list):
                        normalized_dict[key] = [str(v) for v in val]
                    elif isinstance(val, str):
                        normalized_dict[key] = [val]
                    else:
                        normalized_dict[key] = [str(val)]

                return FlextResult[FlextLdifModelsDomains.Attributes].ok(
                    cls(attributes=normalized_dict),
                )
            except (ValueError, TypeError, AttributeError) as e:
                return FlextResult[FlextLdifModelsDomains.Attributes].fail(
                    f"Failed to create Attributes: {e}",
                )

        def mark_as_deleted(
            self,
            attribute_name: str,
            reason: str,
            deleted_by: str,
        ) -> None:
            """Mark attribute as soft-deleted with audit trail."""
            if attribute_name not in self.attributes:
                msg = f"Attribute '{attribute_name}' not found in attributes"
                raise ValueError(msg)

            def _to_str(value: str) -> str:
                """Convert str to str, handling byte representation if necessary."""
                return value

            self.attribute_metadata[str(attribute_name)] = {
                "status": "deleted",
                "deleted_at": u.Generators.generate_iso_timestamp(),
                "deleted_reason": reason,
                "deleted_by": deleted_by,
                "original_values": [
                    _to_str(v) for v in self.attributes[attribute_name]
                ],
            }

        def get_active_attributes(self) -> dict[str, list[str]]:
            """Get only active attributes (exclude deleted/hidden)."""

            def _to_str(value: str) -> str:
                """Convert str to str, handling byte representation if necessary."""
                return value

            def _convert_values(values: list[str]) -> list[str]:
                """Convert list of str to list of str."""
                return [_to_str(v) for v in values]

            if not self.attribute_metadata:
                return {
                    _to_str(name): _convert_values(values)
                    for name, values in self.attributes.items()
                }

            return {
                _to_str(name): _convert_values(values)
                for name, values in self.attributes.items()
                if self.attribute_metadata.get(str(name), {}).get("status", "active")
                not in {"deleted", "hidden"}
            }

        def get_deleted_attributes(
            self,
        ) -> dict[str, dict[str, str | list[str]]]:
            """Get soft-deleted attributes with their metadata."""
            if not self.attribute_metadata:
                return {}

            return {
                name: meta
                for name, meta in self.attribute_metadata.items()
                if meta.get("status") == "deleted"
            }

    class ErrorDetail(FlextModelsBase.FrozenStrictModel):
        """Error detail information for failed operations."""

        item: str = Field(...)
        error: str = Field(...)
        error_code: str | None = Field(default=None)
        context: FlextLdifModelsMetadata.DynamicMetadata = Field(
            default_factory=FlextLdifModelsMetadata.DynamicMetadata,
        )

    class DnRegistry(FlextLdifModelsBase):
        """Registry for tracking canonical DN case during conversions."""

        model_config = ConfigDict(frozen=False)

        def __init__(self) -> None:
            """Initialize empty DN case registry."""
            super().__init__()
            self._registry: FlextLdifModelsMetadata.DynamicMetadata = (
                FlextLdifModelsMetadata.DynamicMetadata()
            )
            self._case_variants: dict[str, set[str]] = {}

        @staticmethod
        def _normalize_dn(dn: str) -> str:
            """Convert DN to lowercase for case-insensitive dict lookup."""
            return dn.lower().replace(" ", "")

        def register_dn(self, dn: str, *, force: bool = False) -> str:
            """Register DN and return its canonical case."""
            normalized = self._normalize_dn(dn)

            if normalized not in self._case_variants:
                self._case_variants[normalized] = set()
            self._case_variants[normalized].add(dn)

            if normalized not in self._registry or force:
                self._registry[normalized] = dn

            value = self._registry[normalized]
            if isinstance(value, str):
                return value
            return dn

        def get_canonical_dn(self, dn: str) -> str | None:
            """Get canonical case for a DN (case-insensitive lookup)."""
            normalized = self._normalize_dn(dn)
            value = self._registry.get(normalized)
            if isinstance(value, str):
                return value
            return None

        def has_dn(self, dn: str) -> bool:
            """Check if DN is registered (case-insensitive)."""
            normalized = self._normalize_dn(dn)
            return normalized in self._registry

        def get_case_variants(self, dn: str) -> set[str]:
            """Get all case variants seen for a DN."""
            normalized = self._normalize_dn(dn)
            return self._case_variants.get(normalized, set())

        def validate_oud_consistency(self) -> FlextResult[bool]:
            """Validate DN case consistency for server conversion."""
            inconsistencies: list[dict[str, str | int | list[str]]] = []

            for normalized_dn, variants in self._case_variants.items():
                if len(variants) > 1:
                    canonical_value = self._registry.get(normalized_dn)
                    canonical = (
                        str(canonical_value)
                        if canonical_value is not None
                        else normalized_dn
                    )
                    inconsistencies.append(
                        {
                            "normalized_dn": normalized_dn,
                            "canonical_case": canonical,
                            "variants": list(variants),
                            "variant_count": len(variants),
                        },
                    )

            if inconsistencies:
                return FlextResult[bool].ok(False)

            return FlextResult[bool].ok(value=True)

        def normalize_dn_references(
            self,
            data: dict[str, str | list[str] | dict[str, str]],
            dn_fields: list[str] | None = None,
        ) -> FlextResult[dict[str, str | list[str] | dict[str, str]]]:
            """Normalize DN references in data object to canonical case."""
            try:
                if dn_fields is None:
                    dn_fields = ["dn"] + list(
                        c.Ldif.DnValuedAttributes.ALL_DN_VALUED,
                    )

                normalized_data = dict(data)

                for field_name in dn_fields:
                    if field_name not in normalized_data:
                        continue

                    field_value = normalized_data[field_name]

                    if isinstance(field_value, str):
                        normalized_data[field_name] = self._normalize_single_dn(
                            field_value,
                        )
                    elif isinstance(field_value, list):
                        field_value_list = field_value
                        normalized_data[field_name] = self._normalize_dn_list(
                            field_value_list,
                        )

                return FlextResult[dict[str, str | list[str] | dict[str, str]]].ok(
                    normalized_data,
                )

            except Exception as e:
                return FlextResult[dict[str, str | list[str] | dict[str, str]]].fail(
                    f"Failed to normalize DN references: {e}",
                )

        def _normalize_single_dn(self, dn: str) -> str:
            """Normalize a single DN string to canonical case."""
            canonical = self.get_canonical_dn(dn)
            if canonical:
                return canonical

            return self._normalize_dn(dn)

        def _normalize_dn_list(self, dn_list: list[str]) -> list[str]:
            """Normalize a list of DN values."""
            return [self._normalize_single_dn(item) for item in dn_list]

        def clear(self) -> None:
            """Clear all DN registrations."""
            self._registry.clear()
            self._case_variants.clear()

        def get_stats(self) -> dict[str, int]:
            """Get registry statistics."""
            total_variants = sum(
                len(variants) for variants in self._case_variants.values()
            )
            multiple_variants = sum(
                1 for variants in self._case_variants.values() if len(variants) > 1
            )

            return {
                "total_dns": len(self._registry),
                "total_variants": total_variants,
                "dns_with_multiple_variants": multiple_variants,
            }

    class AclPermissions(FlextModelsBase.ArbitraryTypesModel):
        """ACL permissions for LDAP operations."""

        read: bool = Field(default=False)
        write: bool = Field(default=False)
        add: bool = Field(default=False)
        delete: bool = Field(default=False)
        search: bool = Field(default=False)
        compare: bool = Field(default=False)

        self_write: bool = Field(
            default=False,
        )
        proxy: bool = Field(
            default=False,
        )
        browse: bool = Field(
            default=False,
        )
        auth: bool = Field(
            default=False,
        )
        all: bool = Field(
            default=False,
        )

        no_write: bool = Field(default=False)
        no_add: bool = Field(default=False)
        no_delete: bool = Field(
            default=False,
        )
        no_browse: bool = Field(
            default=False,
        )
        no_self_write: bool = Field(
            default=False,
        )

        @staticmethod
        def get_rfc_compliant_permissions(
            perms_dict: dict[str, bool],
        ) -> dict[str, bool]:
            """Filter permissions dict to RFC-compliant fields only."""
            rfc_compliant_keys = {
                "read",
                "write",
                "add",
                "delete",
                "search",
                "compare",
                "self_write",
                "proxy",
                "browse",
                "auth",
                "all",
                "no_write",
                "no_add",
                "no_delete",
                "no_browse",
                "no_self_write",
            }

            return {
                key: value
                for key, value in perms_dict.items()
                if key in rfc_compliant_keys
            }

    class AclTarget(FlextModelsBase.ArbitraryTypesModel):
        """ACL target specification."""

        target_dn: str = Field(...)
        attributes: list[str] = Field(
            default_factory=list,
        )

    class AclSubject(FlextModelsBase.ArbitraryTypesModel):
        """ACL subject specification."""

        subject_type: c.Ldif.LiteralTypes.AclSubjectTypeLiteral = Field(
            ...,
        )
        subject_value: str = Field(...)

    class Acl(AclElement):
        """Universal ACL model for all LDAP server types."""

        name: str = Field(default="")
        target: FlextLdifModelsDomains.AclTarget | None = Field(
            default=None,
        )
        subject: FlextLdifModelsDomains.AclSubject | None = Field(
            default=None,
        )
        permissions: FlextLdifModelsDomains.AclPermissions | None = Field(
            default=None,
        )

        raw_line: str = Field(default="")
        raw_acl: str = Field(default="")

        metadata: FlextLdifModelsDomains.QuirkMetadata | None = Field(
            default=None,
        )

        @model_validator(mode="after")
        def validate_acl_format(self) -> Self:
            """Validate ACL format - capture violations in metadata, DON'T reject."""
            violations: list[str] = []

            valid_server_types: set[str] = {
                "rfc",
                "openldap",
                "openldap2",
                "openldap1",
                "oid",
                "oud",
                "389ds",
                "active_directory",
                "relaxed",
            }

            if self.server_type not in valid_server_types:
                violations.append(
                    f"Invalid server_type '{self.server_type}' - expected one of: {', '.join(sorted(valid_server_types))}",
                )

            acl_is_defined = (
                self.target is not None
                or self.subject is not None
                or self.permissions is not None
            )
            if acl_is_defined and not FlextUtilities.Guards.is_string_non_empty(
                self.raw_acl,
            ):
                violations.append(
                    "ACL is defined (has target/subject/permissions) but raw_acl is empty",
                )

            if violations:
                return self.model_copy(
                    update={"validation_violations": violations},
                )

            return self

        @classmethod
        def get_acl_format(cls) -> str:
            """Get ACL format for this server type."""
            return c.Ldif.AclFormats.DEFAULT_ACL_FORMAT

        def get_acl_type(self) -> str:
            """Get ACL type identifier for this server."""
            short_server_type = c.Ldif.ServerTypesMappings.FROM_LONG.get(
                self.server_type,
                self.server_type,
            )
            return f"{short_server_type}_acl"

    class AclWriteMetadata(FrozenLdifModel):
        """Metadata for ACL write formatting operations."""

        original_format: str | None = Field(
            default=None,
        )
        source_server: str | None = Field(
            default=None,
        )
        name_sanitized: bool = Field(
            default=False,
        )
        original_name_raw: str | None = Field(
            default=None,
        )

        @classmethod
        def from_extensions(
            cls,
            extensions: Mapping[str, t.MetadataAttributeValue] | None,
        ) -> Self:
            """Extract ACL write metadata from QuirkMetadata extensions."""
            if not extensions:
                return cls()

            keys = c.Ldif.MetadataKeys

            original_format = extensions.get(keys.ACL_ORIGINAL_FORMAT)
            source_server = extensions.get(keys.ACL_SOURCE_SERVER)
            name_sanitized = extensions.get(keys.ACL_NAME_SANITIZED, False)
            original_name_raw = extensions.get(keys.ACL_ORIGINAL_NAME_RAW)

            return cls(
                original_format=str(original_format) if original_format else None,
                source_server=str(source_server) if source_server else None,
                name_sanitized=bool(name_sanitized),
                original_name_raw=str(original_name_raw) if original_name_raw else None,
            )

        def has_original_format(self) -> bool:
            """Check if original ACL format is available for name replacement."""
            return self.original_format is not None and len(self.original_format) > 0

    class Entry(FlextModelsEntity.Entry):
        """LDIF entry domain model."""

        model_config = ConfigDict(
            strict=True,
            validate_default=True,
            validate_assignment=True,
            extra="allow",
        )

        dn: FlextLdifModelsDomains.DN | None = Field(
            ...,
        )
        attributes: FlextLdifModelsDomains.Attributes | None = Field(
            ...,
        )

        @field_validator("dn", mode="before")
        @classmethod
        def coerce_dn_from_string(
            cls,
            value: str
            | dict[str, t.GeneralValueType]
            | FlextLdifModelsDomains.DN
            | None,
        ) -> FlextLdifModelsDomains.DN | None:
            """Convert string DN to DN instance."""
            if value is None:
                return None

            if isinstance(value, FlextLdifModelsDomains.DN):
                return value

            if isinstance(value, dict):
                return FlextLdifModelsDomains.DN.model_validate(value)

            if isinstance(value, str):
                return FlextLdifModelsDomains.DN.model_validate({"value": value})

            return FlextLdifModelsDomains.DN.model_validate({"value": ""})

        @field_validator("attributes", mode="before")
        @classmethod
        def coerce_attributes_from_dict(
            cls,
            value: dict[str, list[str]]
            | dict[str, t.GeneralValueType]
            | FlextLdifModelsDomains.Attributes
            | None,
        ) -> FlextLdifModelsDomains.Attributes | None:
            """Convert dict to Attributes instance."""
            if value is None:
                return None

            if isinstance(value, FlextLdifModelsDomains.Attributes):
                return value

            if isinstance(value, dict) and "attributes" in value:
                attrs_data = value.get("attributes", {})
                meta_data = value.get("attribute_metadata", {})
                entry_meta = value.get("metadata")

                typed_attrs: dict[str, list[str]] = {}
                if isinstance(attrs_data, dict):
                    for k, v in attrs_data.items():
                        if isinstance(k, str):
                            if isinstance(v, list):
                                typed_attrs[k] = [str(item) for item in v]
                            else:
                                typed_attrs[k] = [str(v)]

                typed_meta: dict[str, dict[str, str | list[str]]] = {}
                if isinstance(meta_data, dict):
                    for k, v in meta_data.items():
                        if isinstance(k, str) and isinstance(v, dict):
                            nested_dict: dict[str, str | list[str]] = {}
                            for mk, mv in v.items():
                                if isinstance(mk, str):
                                    if isinstance(mv, list):
                                        nested_dict[mk] = [str(item) for item in mv]
                                    elif isinstance(mv, str):
                                        nested_dict[mk] = mv
                                    else:
                                        nested_dict[mk] = str(mv)
                            typed_meta[k] = nested_dict

                return FlextLdifModelsDomains.Attributes(
                    attributes=typed_attrs,
                    attribute_metadata=typed_meta,
                    metadata=entry_meta
                    if isinstance(entry_meta, FlextLdifModelsMetadata.EntryMetadata)
                    else None,
                )

            attrs_dict: dict[str, list[str]] = {}
            for k, v in value.items():
                if isinstance(v, list):
                    attrs_dict[k] = [str(x) for x in v]
                else:
                    attrs_dict[k] = [str(v)]
            return FlextLdifModelsDomains.Attributes(
                attributes=attrs_dict,
            )

        changetype: c.Ldif.LiteralTypes.ChangeTypeLiteral | None = Field(
            default=None,
        )
        metadata: FlextLdifModelsDomains.QuirkMetadata | None = Field(
            default=None,
        )

        @model_validator(mode="before")
        @classmethod
        def ensure_metadata_initialized(
            cls,
            data: dict[str, t.GeneralValueType] | list[t.GeneralValueType],
        ) -> dict[str, t.GeneralValueType] | list[t.GeneralValueType]:
            """Ensure metadata field is always initialized to a QuirkMetadata instance."""
            if not isinstance(data, dict):
                return data

            for dt_field in ("created_at", "updated_at"):
                if dt_field in data and isinstance(data[dt_field], str):
                    with suppress(ValueError):
                        data[dt_field] = datetime.fromisoformat(str(data[dt_field]))

            if data.get("metadata") is None:
                quirk_type_value = data.get("quirk_type")
                final_quirk_type_val: c.Ldif.ServerTypes
                if isinstance(quirk_type_value, str):
                    try:
                        final_quirk_type_val = c.Ldif.ServerTypes(quirk_type_value)
                    except ValueError:
                        final_quirk_type_val = c.Ldif.ServerTypes.RFC
                else:
                    final_quirk_type_val = c.Ldif.ServerTypes.RFC

                metadata_obj = FlextLdifModelsDomains.QuirkMetadata(
                    quirk_type=final_quirk_type_val,
                )

                data["metadata"] = metadata_obj

            return data

        @computed_field
        def dn_str(self) -> str:
            """Protocol compliance: p.Ldif.Entry.EntryProtocol requires dn: str."""
            if self.dn is None:
                return ""
            return self.dn.value

        @computed_field
        def attributes_dict(self) -> dict[str, list[str]]:
            """Protocol compliance: p.Ldif.Entry.EntryProtocol requires attributes: dict[str, list[str]]."""
            if self.attributes is None:
                return {}
            return self.attributes.attributes

        def model_post_init(self, _context: object, /) -> None:
            """Post-init hook to ensure metadata is always initialized."""
            if self.metadata is None:
                self.metadata = FlextLdifModelsDomains.QuirkMetadata.create_for()

        @model_validator(mode="after")
        def validate_entry_consistency(self) -> Self:
            """Validate cross-field consistency in Entry model."""
            return self

        @staticmethod
        def _validate_dn(dn_value: str) -> list[str]:
            """Validate DN format per RFC 4514 § 2.3, 2.4."""
            violations: list[str] = []
            if not dn_value or not dn_value.strip():
                violations.append(
                    "RFC 2849 § 2: DN is required (empty or whitespace DN)",
                )
                return violations

            components = [comp.strip() for comp in dn_value.split(",") if comp.strip()]
            if not components:
                violations.append("RFC 4514 § 2.4: DN is empty (no RDN components)")
                return violations

            dn_component_pattern = re.compile(
                c.Ldif.LdifPatterns.DN_COMPONENT,
                re.IGNORECASE,
            )
            for idx, comp in enumerate(components):
                if not dn_component_pattern.match(comp):
                    violations.append(
                        f"RFC 4514 § 2.3: Component {idx} '{comp}' invalid format",
                    )
            return violations

        def _validate_attributes_required(self) -> list[str]:
            """Validate that entry has at least one attribute per RFC 2849 § 2."""
            violations: list[str] = []
            if self.attributes is None:
                violations.append(
                    "RFC 2849 § 2: Entry must have at least one attribute (missing)",
                )
                return violations
            if not self.attributes:
                violations.append(
                    "RFC 2849 § 2: Entry must have at least one attribute (empty)",
                )
            return violations

        def _validate_attribute_descriptions(self) -> list[str]:
            """Validate attribute descriptions per RFC 4512 § 2.5."""
            violations: list[str] = []
            if self.attributes is None or not self.attributes:
                return violations

            for attr_desc in self.attributes.attributes:
                if ";" in attr_desc:
                    base_attr, options_str = attr_desc.split(";", 1)
                    options = [
                        opt.strip() for opt in options_str.split(";") if opt.strip()
                    ]
                else:
                    base_attr = attr_desc
                    options = []

                if not base_attr or not base_attr[0].isalpha():
                    violations.append(
                        f"RFC 4512 § 2.5: '{base_attr}' must start with letter",
                    )
                elif not all(c.isalnum() or c == "-" for c in base_attr):
                    violations.append(
                        f"RFC 4512 § 2.5: '{base_attr}' has invalid characters",
                    )

                for option in options:
                    if not option or not option[0].isalpha():
                        violations.append(
                            f"RFC 4512 § 2.5: option '{option}' must start with letter",
                        )
                    elif not all(c.isalnum() or c in {"-", "_"} for c in option):
                        violations.append(
                            f"RFC 4512 § 2.5: option '{option}' has invalid characters",
                        )
            return violations

        def _validate_objectclass(self, dn_value: str) -> list[str]:
            """Validate objectClass presence per RFC 4512 § 2.4.1."""
            violations: list[str] = []

            is_schema_entry = dn_value.lower().startswith(
                "cn=schema",
            ) or dn_value.lower().startswith("cn=subschema")
            if self.attributes is None or is_schema_entry or not self.attributes:
                return violations

            has_objectclass = any(
                attr_name.lower() == "objectclass"
                for attr_name in self.attributes.attributes
            )
            if not has_objectclass:
                violations.append(
                    f"RFC 4512 § 2.4.1: Entry SHOULD have objectClass (DN: {dn_value})",
                )
            return violations

        def _validate_naming_attribute(self, dn_value: str) -> list[str]:
            """Validate naming attribute presence per RFC 4512 § 2.3."""
            violations: list[str] = []
            if not dn_value or self.attributes is None or not self.attributes:
                return violations

            first_rdn = (
                dn_value.split(",", maxsplit=1)[0].strip()
                if "," in dn_value
                else dn_value.strip()
            )
            if "=" not in first_rdn:
                return violations

            naming_attr = first_rdn.split("=")[0].strip().lower()
            has_naming_attr = any(
                attr_name.lower() == naming_attr
                for attr_name in self.attributes.attributes
            )
            if not has_naming_attr:
                violations.append(
                    f"RFC 4512 § 2.3: Entry SHOULD have Naming attribute '{naming_attr}'",
                )
            return violations

        def _validate_binary_options(self) -> list[str]:
            """Validate binary attribute options per RFC 2849 § 5.2."""
            violations: list[str] = []
            if self.attributes is None or not self.attributes:
                return violations

            for attr_name, attr_values in self.attributes.items():
                if ";binary" in attr_name.lower():
                    continue
                for value in attr_values:
                    has_binary = any(
                        (
                            ord(char) < c.Ldif.LdifProcessing.ASCII_SPACE_CHAR
                            and char not in "\t\n\r"
                        )
                        or ord(char) > c.Ldif.LdifProcessing.ASCII_TILDE_CHAR
                        for char in value
                    )
                    if has_binary:
                        violations.append(
                            f"RFC 2849 § 5.2: '{attr_name}' may need ';binary' option",
                        )
                        break
            return violations

        def _validate_attribute_syntax(self) -> list[str]:
            """Validate attribute name/option syntax per RFC 4512 § 2.5.1-2.5.2."""
            violations: list[str] = []
            if self.attributes is None or not self.attributes:
                return violations

            attr_name_pattern = re.compile(r"^[a-zA-Z][a-zA-Z0-9-]*$")
            for attr_desc in self.attributes.attributes:
                parts = attr_desc.split(";")
                base_name = parts[0]

                if not attr_name_pattern.match(base_name):
                    violations.append(f"RFC 4512 § 2.5.1: '{base_name}' invalid syntax")

                if len(parts) > 1:
                    invalid_options = [
                        f"RFC 4512 § 2.5.2: option '{option}' invalid syntax"
                        for option in parts[1:]
                        if option and not attr_name_pattern.match(option)
                    ]
                    violations.extend(invalid_options)
            return violations

        def _validate_changetype(self) -> list[str]:
            """Validate changetype field per RFC 2849 § 5.7."""
            violations: list[str] = []

            if not self.changetype:
                return violations

            valid_changetypes = {"add", "delete", "modify", "moddn", "modrdn"}
            if str(self.changetype).lower() not in valid_changetypes:
                violations.append(
                    f"RFC 2849 § 5.7: changetype '{self.changetype}' invalid",
                )
            return violations

        @model_validator(mode="after")
        def validate_entry_rfc_compliance(self) -> Self:
            """Validate Entry RFC compliance - capture violations, DON'T reject."""
            violations: list[str] = []
            dn_value = "<None>"

            if self.dn is None:
                violations.append("RFC 2849 § 2: DN is required")
            else:
                dn_value = str(self.dn.value)
                violations.extend(self._validate_dn(dn_value))
                violations.extend(self._validate_attributes_required())
                violations.extend(self._validate_attribute_descriptions())
                violations.extend(self._validate_objectclass(dn_value))
                violations.extend(self._validate_naming_attribute(dn_value))
                violations.extend(self._validate_binary_options())
                violations.extend(self._validate_attribute_syntax())
                violations.extend(self._validate_changetype())

            if violations and self.metadata is not None:
                attribute_count = len(self.attributes) if self.attributes else 0

                old_context = {}
                if self.metadata.validation_results is not None:
                    old_context = self.metadata.validation_results.context

                self.metadata.validation_results = (
                    FlextLdifModelsDomains.ValidationMetadata(
                        rfc_violations=violations,
                        context={
                            **old_context,
                            "validator": "validate_entry_rfc_compliance",
                            "dn": dn_value,
                            "attribute_count": str(attribute_count),
                            "total_violations": str(len(violations)),
                        },
                    )
                )

            return self

        def _check_objectclass_rule(
            self,
            rules: ServerValidationRules,
            dn_value: str,
        ) -> list[str]:
            """Check objectClass requirement from server rules."""
            violations: list[str] = []
            if not rules.requires_objectclass:
                return violations

            has_objectclass = (
                any(
                    attr_name.lower() == "objectclass"
                    for attr_name in self.attributes.attributes
                )
                if self.attributes
                else False
            )

            is_schema_entry = dn_value and (
                dn_value.lower().startswith("cn=schema")
                or dn_value.lower().startswith("cn=subschema")
            )

            if not has_objectclass and not is_schema_entry:
                violations.append("Server requires objectClass attribute")
            return violations

        def _check_naming_attr_rule(
            self,
            rules: ServerValidationRules,
            dn_value: str,
        ) -> list[str]:
            """Check naming attribute requirement from server rules."""
            violations: list[str] = []

            if not rules.requires_naming_attr or not dn_value or not self.attributes:
                return violations

            first_rdn = dn_value.split(",", maxsplit=1)[0].strip()
            if "=" not in first_rdn:
                return violations

            naming_attr = first_rdn.split("=")[0].strip().lower()
            has_naming_attr = any(
                attr_name.lower() == naming_attr
                for attr_name in self.attributes.attributes
            )
            if not has_naming_attr:
                violations.append(f"Server requires naming attribute '{naming_attr}'")
            return violations

        def _check_binary_option_rule(
            self,
            rules: ServerValidationRules,
        ) -> list[str]:
            """Check binary attribute option requirement from server rules."""
            violations: list[str] = []

            if not rules.requires_binary_option or not self.attributes:
                return violations

            for attr_name, attr_values in self.attributes.items():
                if ";binary" in attr_name.lower():
                    continue
                for value in attr_values:
                    if any(
                        ord(char) < c.Ldif.LdifProcessing.ASCII_SPACE_CHAR
                        or ord(char) > c.Ldif.LdifProcessing.ASCII_TILDE_CHAR
                        for char in value
                    ):
                        violations.append(
                            f"Server requires ';binary' option for '{attr_name}'",
                        )
                        break
            return violations

        @model_validator(mode="after")
        def validate_server_specific_rules(self) -> Self:
            """Validate Entry using server-injected validation rules."""
            if not self.metadata:
                return self
            if "validation_rules" not in self.metadata.extensions:
                return self

            extensions_extra = self.metadata.extensions.__pydantic_extra__
            validation_rules = (
                extensions_extra.get("validation_rules")
                if isinstance(extensions_extra, dict)
                else self.metadata.extensions.get("validation_rules")
            )
            if not validation_rules:
                return self

            if isinstance(validation_rules, dict):
                try:
                    rules = ServerValidationRules.model_validate(
                        validation_rules,
                    )
                except Exception:
                    return self
            elif isinstance(
                validation_rules,
                ServerValidationRules,
            ):
                rules = validation_rules
            else:
                return self
            dn_value = str(self.dn.value) if self.dn else ""

            server_violations: list[str] = []

            server_violations.extend(self._check_objectclass_rule(rules, dn_value))
            server_violations.extend(self._check_naming_attr_rule(rules, dn_value))
            server_violations.extend(self._check_binary_option_rule(rules))

            if self.metadata:
                self.metadata.extensions["validation_server_type"] = (
                    self.metadata.quirk_type
                )

            if server_violations and self.metadata:
                if self.metadata.validation_results is None:
                    self.metadata.validation_results = (
                        FlextLdifModelsDomains.ValidationMetadata()
                    )

                updated_validation_results = (
                    self.metadata.validation_results.model_copy(
                        update={
                            "server_specific_violations": server_violations,
                            "validation_server_type": self.metadata.quirk_type,
                        },
                    )
                )
                self.metadata.validation_results = updated_validation_results

                violations_typed: t.MetadataAttributeValue = list(server_violations)
                self.metadata.extensions["server_specific_violations"] = (
                    violations_typed
                )

            return self

        @computed_field
        def unconverted_attributes(
            self,
        ) -> dict[str, str | list[str] | bytes]:
            """Get unconverted attributes from metadata extensions (read-only view, DRY pattern)."""
            if self.metadata is None:
                return {}

            extra = self.metadata.extensions.__pydantic_extra__
            if extra is None:
                return {}
            result = extra.get("unconverted_attributes")
            if isinstance(result, dict):
                return result
            return {}

        @classmethod
        def create(
            cls,
            dn: str | FlextLdifModelsDomains.DN,
            attributes: (
                dict[str, str | list[str]] | FlextLdifModelsDomains.Attributes
            ),
            metadata: FlextLdifModelsDomains.QuirkMetadata | None = None,
            acls: list[FlextLdifModelsDomains.Acl] | None = None,
            objectclasses: list[FlextLdifModelsDomains.SchemaObjectClass] | None = None,
            attributes_schema: list[FlextLdifModelsDomains.SchemaAttribute]
            | None = None,
            entry_metadata: FlextLdifModelsMetadata.EntryMetadata | None = None,
            validation_metadata: FlextLdifModelsDomains.ValidationMetadata
            | None = None,
            server_type: c.Ldif.LiteralTypes.ServerTypeLiteral | None = None,
            source_entry: str | None = None,
            unconverted_attributes: FlextLdifModelsMetadata.DynamicMetadata
            | None = None,
            statistics: FlextLdifModelsDomains.EntryStatistics | None = None,
        ) -> FlextResult[Self]:
            """Create a new Entry instance with composition fields (legacy method, prefer builder())."""
            return cls._create_entry(
                dn=dn,
                attributes=attributes,
                metadata=metadata,
                acls=acls,
                objectclasses=objectclasses,
                attributes_schema=attributes_schema,
                entry_metadata=entry_metadata,
                validation_metadata=validation_metadata,
                server_type=server_type,
                source_entry=source_entry,
                unconverted_attributes=unconverted_attributes,
                statistics=statistics,
            )

        @classmethod
        def _normalize_attributes(
            cls,
            attributes: (
                dict[str, str | list[str]] | FlextLdifModelsDomains.Attributes
            ),
        ) -> FlextLdifModelsDomains.Attributes:
            """Normalize attributes to Attributes object."""
            if isinstance(attributes, dict):
                attrs_dict: dict[str, list[str]] = {}
                for attr_name, attr_values in attributes.items():
                    if isinstance(attr_values, str):
                        values_list: list[str] = [str(attr_values)]
                    elif isinstance(attr_values, list):
                        values_list = [str(v) for v in attr_values]
                    else:
                        values_list = [str(attr_values)]
                    attrs_dict[attr_name] = values_list
                return FlextLdifModelsDomains.Attributes(attributes=attrs_dict)
            if isinstance(attributes, FlextLdifModelsDomains.Attributes):
                return attributes

            msg = f"Attributes must be dict or Attributes, got {type(attributes).__name__}"
            raise ValueError(msg)

        @classmethod
        def _build_extension_kwargs(
            cls,
            server_type: c.Ldif.LiteralTypes.ServerTypeLiteral | None,
            source_entry: str | None,
            unconverted_attributes: FlextLdifModelsMetadata.DynamicMetadata | None,
        ) -> dict[str, t.MetadataAttributeValue]:
            """Build extension kwargs for DynamicMetadata."""
            ext_kwargs: dict[str, t.MetadataAttributeValue] = {}
            if server_type:
                ext_kwargs["server_type"] = server_type
            if source_entry:
                ext_kwargs["source_entry"] = source_entry
            if unconverted_attributes:
                ext_kwargs["unconverted_attributes"] = str(
                    dict(unconverted_attributes.items())
                )
            return ext_kwargs

        @classmethod
        def _update_existing_metadata(
            cls,
            metadata: FlextLdifModelsDomains.QuirkMetadata,
            server_type: c.Ldif.LiteralTypes.ServerTypeLiteral | None,
            source_entry: str | None,
            unconverted_attributes: FlextLdifModelsMetadata.DynamicMetadata | None,
        ) -> None:
            """Update existing metadata extensions in place."""
            if server_type:
                metadata.extensions["server_type"] = server_type
            if source_entry:
                metadata.extensions["source_entry"] = source_entry
            if unconverted_attributes:
                extra = unconverted_attributes.__pydantic_extra__
                if extra:
                    for key, value in extra.items():
                        metadata.extensions[f"unconverted_{key}"] = str(value)

        @classmethod
        def _build_metadata(
            cls,
            metadata: FlextLdifModelsDomains.QuirkMetadata | None,
            server_type: c.Ldif.LiteralTypes.ServerTypeLiteral | None,
            source_entry: str | None,
            unconverted_attributes: FlextLdifModelsMetadata.DynamicMetadata | None,
        ) -> FlextLdifModelsDomains.QuirkMetadata | None:
            """Build or update metadata with server-specific extensions."""
            has_new_metadata = server_type or source_entry or unconverted_attributes

            if metadata is None and has_new_metadata:
                ext_kwargs = cls._build_extension_kwargs(
                    server_type,
                    source_entry,
                    unconverted_attributes,
                )

                extensions = FlextLdifModelsMetadata.DynamicMetadata.from_dict(
                    ext_kwargs
                )
                return FlextLdifModelsDomains.QuirkMetadata(
                    quirk_type=c.Ldif.ServerTypes.GENERIC,
                    extensions=extensions,
                )

            if metadata is not None and has_new_metadata:
                cls._update_existing_metadata(
                    metadata,
                    server_type,
                    source_entry,
                    unconverted_attributes,
                )

            return metadata

        @classmethod
        def _create_entry(
            cls,
            dn: str | FlextLdifModelsDomains.DN,
            attributes: (
                dict[str, str | list[str]] | FlextLdifModelsDomains.Attributes
            ),
            metadata: FlextLdifModelsDomains.QuirkMetadata | None = None,
            acls: list[FlextLdifModelsDomains.Acl] | None = None,
            objectclasses: list[FlextLdifModelsDomains.SchemaObjectClass] | None = None,
            attributes_schema: list[FlextLdifModelsDomains.SchemaAttribute]
            | None = None,
            entry_metadata: FlextLdifModelsMetadata.EntryMetadata | None = None,
            validation_metadata: FlextLdifModelsDomains.ValidationMetadata
            | None = None,
            server_type: c.Ldif.LiteralTypes.ServerTypeLiteral | None = None,
            source_entry: str | None = None,
            unconverted_attributes: FlextLdifModelsMetadata.DynamicMetadata
            | None = None,
            statistics: FlextLdifModelsDomains.EntryStatistics | None = None,
        ) -> FlextResult[Self]:
            """Internal method for Entry creation with composition fields."""
            try:
                dn_obj = FlextLdifModelsDomains.DN.from_value(dn)

                attrs_obj = cls._normalize_attributes(attributes)

                metadata = cls._build_metadata(
                    metadata,
                    server_type,
                    source_entry,
                    unconverted_attributes,
                )

                entry_data: dict[
                    str,
                    (
                        FlextLdifModelsDomains.DN
                        | FlextLdifModelsDomains.Attributes
                        | FlextLdifModelsDomains.QuirkMetadata
                        | list[FlextLdifModelsDomains.Acl]
                        | list[FlextLdifModelsDomains.SchemaObjectClass]
                        | list[FlextLdifModelsDomains.SchemaAttribute]
                        | FlextLdifModelsMetadata.EntryMetadata
                        | FlextLdifModelsDomains.ValidationMetadata
                        | FlextLdifModelsDomains.EntryStatistics
                        | c.Ldif.LiteralTypes.ChangeTypeLiteral
                    ),
                ] = {
                    c.Ldif.DictKeys.DN: dn_obj,
                    c.Ldif.DictKeys.ATTRIBUTES: attrs_obj,
                }

                if metadata is not None:
                    entry_data["metadata"] = metadata
                if acls is not None:
                    entry_data["acls"] = acls
                if objectclasses is not None:
                    entry_data["objectclasses"] = objectclasses
                if attributes_schema is not None:
                    entry_data["attributes_schema"] = attributes_schema
                if entry_metadata is not None:
                    entry_data["entry_metadata"] = entry_metadata
                if validation_metadata is not None:
                    entry_data["validation_metadata"] = validation_metadata
                if statistics is not None:
                    entry_data["statistics"] = statistics

                entry_instance = cls.model_validate(entry_data)
                return FlextResult.ok(entry_instance)
            except (ValueError, TypeError, AttributeError) as e:
                return FlextResult.fail(
                    f"Failed to create Entry: {e}",
                )

        @classmethod
        def from_ldap3(
            cls,
            ldap3_entry: dict[str, list[str] | str] | Mapping[str, Sequence[str]],
        ) -> FlextResult[Self]:
            """Create Entry from ldap3 Entry object."""
            try:
                dn_str = str(getattr(ldap3_entry, "entry_dn", ""))

                entry_attrs_raw: dict[
                    str,
                    str | list[str] | bytes | list[bytes] | int | float | bool | None,
                ] = (
                    getattr(ldap3_entry, "entry_attributes_as_dict", {})
                    if hasattr(ldap3_entry, "entry_attributes_as_dict")
                    else {}
                )

                attrs_dict: dict[str, str | list[str]] = {}

                if entry_attrs_raw:
                    for attr_name, attr_value_list in entry_attrs_raw.items():
                        if isinstance(attr_value_list, list):
                            attrs_dict[str(attr_name)] = [
                                str(v) for v in attr_value_list
                            ]
                        elif isinstance(attr_value_list, str):
                            attrs_dict[str(attr_name)] = [attr_value_list]
                        else:
                            attrs_dict[str(attr_name)] = [str(attr_value_list)]

                return cls.create(
                    dn=dn_str,
                    attributes=attrs_dict,
                )

            except Exception as e:
                return FlextResult.fail(
                    f"Failed to create Entry from ldap3: {e}",
                )

        def get_attribute_values(self, attribute_name: str) -> list[str]:
            """Get all values for a specific attribute."""
            if self.attributes is None:
                return []

            attrs_dict = (
                self.attributes.attributes
                if hasattr(self.attributes, "attributes")
                else self.attributes
            )
            if not attrs_dict:
                return []

            attr_name_lower = attribute_name.lower()

            if isinstance(attrs_dict, dict) or hasattr(attrs_dict, "items"):
                for stored_name, attr_values in attrs_dict.items():
                    if stored_name.lower() == attr_name_lower:
                        return attr_values
            return []

        def has_attribute(self, attribute_name: str) -> bool:
            """Check if entry has a specific attribute."""
            return len(self.get_attribute_values(attribute_name)) > 0

        def has_object_class(self, object_class: str) -> bool:
            """Check if entry has specified object class."""
            return object_class in self.get_attribute_values(
                c.Ldif.DictKeys.OBJECTCLASS,
            )

        def get_all_attribute_names(self) -> list[str]:
            """Get list of all attribute names in the entry."""
            if self.attributes is None:
                return []
            return list(self.attributes.keys())

        def get_all_attributes(self) -> dict[str, list[str]]:
            """Get all attributes as dictionary."""
            if self.attributes is None:
                return {}
            return dict(self.attributes.attributes)

        def count_attributes(self) -> int:
            """Count the number of attributes in the entry."""
            if self.attributes is None:
                return 0
            return len(self.attributes)

        def get_dn_components(self) -> list[str]:
            """Get DN components (RDN parts) from the entry's DN."""
            if self.dn is None:
                return []
            return [comp.strip() for comp in self.dn.value.split(",") if comp.strip()]

        def matches_filter(
            self,
            filter_func: Callable[[FlextLdifModelsDomains.Entry], bool] | None = None,
        ) -> bool:
            """Check if entry matches a filter function."""
            if filter_func is None:
                return True
            try:
                return bool(filter_func(self))
            except Exception:
                return False

        def clone(self) -> Self:
            """Create an immutable copy of the entry."""
            return self.model_copy(deep=True)

        @computed_field
        def is_schema_entry(self) -> bool:
            """Check if entry is a schema definition entry."""
            if self.metadata is None:
                return False
            return bool(self.metadata.objectclasses)

        @computed_field
        def is_acl_entry(self) -> bool:
            """Check if entry has Access Control Lists."""
            if self.metadata is None:
                return False
            return bool(self.metadata.acls)

        @computed_field
        def has_validation_errors(self) -> bool:
            """Check if entry has validation errors."""
            if self.metadata is None:
                return False
            if self.metadata.validation_results is None:
                return False
            return bool(self.metadata.validation_results.errors)

        def get_objectclass_names(self) -> list[str]:
            """Get list of objectClass attribute values from entry."""
            return self.get_attribute_values(c.Ldif.DictKeys.OBJECTCLASS)

        def get_entries(self) -> list[Self]:
            """Get this entry as a list for unified protocol."""
            return [self]

    class AttributeTransformation(FrozenLdifModel):
        """Detailed tracking of attribute transformation operations."""

        original_name: str = Field(
            ...,
        )
        target_name: str | None = Field(
            default=None,
        )
        original_values: list[str] = Field(
            default_factory=list,
        )
        target_values: list[str] | None = Field(
            default=None,
        )

        transformation_type: c.Ldif.LiteralTypes.TransformationTypeLiteral = Field(
            ...,
        )
        reason: str = Field(
            default="",
        )

    class DNStatisticsFlagsModel(MutableIgnoreLdifModel):
        """Optional flags for DNStatistics.create_with_transformation()."""

        had_tab_chars: bool | None = Field(default=None)
        had_trailing_spaces: bool | None = Field(default=None)
        had_leading_spaces: bool | None = Field(default=None)
        had_extra_spaces: bool | None = Field(default=None)
        was_base64_encoded: bool | None = Field(default=None)
        had_utf8_chars: bool | None = Field(default=None)
        had_escape_sequences: bool | None = Field(default=None)
        validation_status: str | None = Field(default=None)
        validation_warnings: list[str] | None = Field(default=None)
        validation_errors: list[str] | None = Field(default=None)

        def to_dict(self) -> dict[str, bool | str | list[str]]:
            """Convert to dictionary, excluding None values."""
            result: dict[str, bool | str | list[str]] = {}
            for field_name in type(self).model_fields:
                value = getattr(self, field_name)
                if value is not None:
                    result[field_name] = value
            return result

    class DNStatistics(FrozenIgnoreLdifModel):
        """Statistics tracking for DN transformations and validation."""

        original_dn: str = Field(
            ...,
        )
        cleaned_dn: str = Field(
            ...,
        )
        normalized_dn: str = Field(
            ...,
        )

        transformations: list[str] = Field(
            default_factory=list,
        )

        had_tab_chars: bool = Field(
            default=False,
        )
        had_trailing_spaces: bool = Field(
            default=False,
        )
        had_leading_spaces: bool = Field(
            default=False,
        )
        had_extra_spaces: bool = Field(
            default=False,
        )
        was_base64_encoded: bool = Field(
            default=False,
        )
        had_utf8_chars: bool = Field(
            default=False,
        )
        had_escape_sequences: bool = Field(
            default=False,
        )

        validation_status: str = Field(
            default="valid",
        )
        validation_warnings: list[str] = Field(
            default_factory=list,
        )
        validation_errors: list[str] = Field(
            default_factory=list,
        )

        @field_validator("transformations", mode="after")
        @classmethod
        def deduplicate_transformations(cls, v: list[str]) -> list[str]:
            """Remove duplicate transformations while preserving order."""
            seen: set[str] = set()
            result: list[str] = []
            for item in v:
                if item not in seen:
                    seen.add(item)
                    result.append(item)
            return result

        @computed_field
        def was_transformed(self) -> bool:
            """Check if any transformations were applied."""
            return (
                self.original_dn != self.normalized_dn or len(self.transformations) > 0
            )

        @computed_field
        def transformation_count(self) -> int:
            """Count of unique transformations applied."""
            return len(self.transformations)

        @computed_field
        def has_warnings(self) -> bool:
            """Check if any validation warnings exist."""
            return len(self.validation_warnings) > 0

        @computed_field
        def has_errors(self) -> bool:
            """Check if any validation errors exist."""
            return len(self.validation_errors) > 0

        @classmethod
        def create_minimal(
            cls,
            dn: str,
        ) -> Self:
            """Create minimal statistics for unchanged DN."""
            return cls(
                original_dn=dn,
                cleaned_dn=dn,
                normalized_dn=dn,
            )

        @classmethod
        def create_with_transformation(
            cls,
            original_dn: str,
            cleaned_dn: str,
            normalized_dn: str,
            transformations: list[str] | None = None,
            flags: FlextLdifModelsDomains.DNStatisticsFlagsModel | None = None,
        ) -> Self:
            """Create statistics with transformation details."""
            warnings_val: list[str] = []
            errors_val: list[str] = []
            if flags:
                if flags.validation_warnings:
                    warnings_val = flags.validation_warnings
                if flags.validation_errors:
                    errors_val = flags.validation_errors
            return cls(
                original_dn=original_dn,
                cleaned_dn=cleaned_dn,
                normalized_dn=normalized_dn,
                transformations=transformations if transformations is not None else [],
                had_tab_chars=bool(flags.had_tab_chars) if flags else False,
                had_trailing_spaces=bool(flags.had_trailing_spaces) if flags else False,
                had_leading_spaces=bool(flags.had_leading_spaces) if flags else False,
                had_extra_spaces=bool(flags.had_extra_spaces) if flags else False,
                was_base64_encoded=bool(flags.was_base64_encoded) if flags else False,
                had_utf8_chars=bool(flags.had_utf8_chars) if flags else False,
                had_escape_sequences=bool(flags.had_escape_sequences)
                if flags
                else False,
                validation_status=flags.validation_status
                if flags and flags.validation_status
                else "valid",
                validation_warnings=warnings_val,
                validation_errors=errors_val,
            )

    class EntryStatistics(FrozenIgnoreLdifModel):
        """Statistics tracking for entry-level transformations and validation."""

        was_parsed: bool = Field(
            default=True,
        )
        was_validated: bool = Field(
            default=False,
        )
        was_filtered: bool = Field(
            default=False,
        )
        was_written: bool = Field(
            default=False,
        )
        was_rejected: bool = Field(
            default=False,
        )

        rejection_category: str | None = Field(
            default=None,
        )
        rejection_reason: str | None = Field(
            default=None,
        )

        attributes_added: list[str] = Field(
            default_factory=list,
        )
        attributes_removed: list[str] = Field(
            default_factory=list,
        )
        attributes_modified: list[str] = Field(
            default_factory=list,
        )
        attributes_filtered: list[str] = Field(
            default_factory=list,
        )

        objectclasses_original: list[str] = Field(
            default_factory=list,
        )
        objectclasses_final: list[str] = Field(
            default_factory=list,
        )

        quirks_applied: list[c.Ldif.LiteralTypes.ServerTypeLiteral] = Field(
            default_factory=list,
        )
        quirk_transformations: int = Field(
            default=0,
        )

        dn_statistics: FlextLdifModelsDomains.DNStatistics | None = Field(
            default=None,
        )

        filters_applied: list[str] = Field(
            default_factory=list,
        )
        filter_results: dict[str, bool] = Field(
            default_factory=dict,
        )

        errors: list[str] = Field(
            default_factory=list,
        )
        warnings: list[str] = Field(
            default_factory=list,
        )

        category_assigned: str | None = Field(
            default=None,
        )
        category_confidence: float = Field(
            default=1.0,
            ge=0.0,
            le=1.0,
        )

        @computed_field
        def total_attribute_changes(self) -> int:
            """Total count of attribute modifications."""
            return (
                len(self.attributes_added)
                + len(self.attributes_removed)
                + len(self.attributes_modified)
            )

        @computed_field
        def had_errors(self) -> bool:
            """Check if any errors occurred."""
            return len(self.errors) > 0

        @computed_field
        def had_warnings(self) -> bool:
            """Check if any warnings occurred."""
            return len(self.warnings) > 0

        @computed_field
        def objectclasses_changed(self) -> bool:
            """Check if objectClass values changed."""
            return set(self.objectclasses_original) != set(self.objectclasses_final)

        @computed_field
        def dn_was_transformed(self) -> bool:
            """Check if DN underwent transformation."""
            if self.dn_statistics is None:
                return False
            return bool(self.dn_statistics.was_transformed)

        @field_validator("filters_applied", mode="after")
        @classmethod
        def deduplicate_filters(cls, v: list[str]) -> list[str]:
            """Remove duplicate filters while preserving order."""
            seen: set[str] = set()
            result: list[str] = []
            for item in v:
                if item not in seen:
                    seen.add(item)
                    result.append(item)
            return result

        @field_validator("quirks_applied", mode="after")
        @classmethod
        def deduplicate_quirks(cls, v: list[str]) -> list[str]:
            """Remove duplicate quirks while preserving order."""
            seen: set[str] = set()
            result: list[str] = []
            for item in v:
                if item not in seen:
                    seen.add(item)
                    result.append(item)
            return result

        @classmethod
        def create_minimal(
            cls,
        ) -> Self:
            """Create minimal statistics for newly parsed entry."""
            return cls(was_parsed=True)

        @classmethod
        def create_with_dn_stats(
            cls,
            dn_statistics: FlextLdifModelsDomains.DNStatistics,
        ) -> Self:
            """Create statistics with DN transformation details."""
            return cls(
                was_parsed=True,
                dn_statistics=dn_statistics,
            )

        def mark_validated(self) -> Self:
            """Mark entry as validated."""
            return self.model_copy(update={"was_validated": True})

        def mark_filtered(
            self,
            filter_type: str,
            *,
            passed: bool,
        ) -> Self:
            """Mark entry as filtered with result."""
            filters_applied = [*self.filters_applied, filter_type]
            filter_results = {**self.filter_results, filter_type: passed}
            return self.model_copy(
                update={
                    "was_filtered": True,
                    "filters_applied": filters_applied,
                    "filter_results": filter_results,
                },
            )

        def mark_rejected(
            self,
            category: str,
            reason: str,
        ) -> Self:
            """Mark entry as rejected."""
            return self.model_copy(
                update={
                    "was_rejected": True,
                    "rejection_category": category,
                    "rejection_reason": reason,
                },
            )

        def add_error(self, error: str) -> Self:
            """Add error message."""
            errors = [*self.errors, error]
            return self.model_copy(update={"errors": errors})

        def add_warning(self, warning: str) -> Self:
            """Add warning message."""
            warnings = [*self.warnings, warning]
            return self.model_copy(update={"warnings": warnings})

        def track_attribute_change(
            self,
            attr_name: str,
            change_type: str,
        ) -> Self:
            """Track attribute modification."""
            if change_type == "added":
                attributes_added = [*self.attributes_added, attr_name]
                return self.model_copy(update={"attributes_added": attributes_added})
            if change_type == "removed":
                attributes_removed = [*self.attributes_removed, attr_name]
                return self.model_copy(
                    update={"attributes_removed": attributes_removed},
                )
            if change_type == "modified":
                attributes_modified = [*self.attributes_modified, attr_name]
                return self.model_copy(
                    update={"attributes_modified": attributes_modified},
                )
            if change_type == "filtered":
                attributes_filtered = [*self.attributes_filtered, attr_name]
                return self.model_copy(
                    update={"attributes_filtered": attributes_filtered},
                )
            return self

        def apply_quirk(
            self,
            quirk_type: c.Ldif.LiteralTypes.ServerTypeLiteral,
        ) -> Self:
            """Record quirk application."""
            quirks_applied = [*self.quirks_applied, quirk_type]
            return self.model_copy(
                update={
                    "quirks_applied": quirks_applied,
                    "quirk_transformations": self.quirk_transformations + 1,
                },
            )

    class ValidationMetadata(FrozenLdifModel):
        """Validation results and error tracking metadata."""

        rfc_violations: list[str] = Field(
            default_factory=list,
        )
        errors: list[str] = Field(
            default_factory=list,
        )
        warnings: list[str] = Field(
            default_factory=list,
        )
        context: dict[str, str] = Field(
            default_factory=dict,
        )
        server_specific_violations: list[str] = Field(
            default_factory=list,
        )
        validation_server_type: c.Ldif.LiteralTypes.ServerTypeLiteral | None = Field(
            default=None,
        )

    class WriteOptions(FrozenLdifModel):
        """LDIF writing configuration options."""

        format: str | None = Field(
            default=None,
        )
        base_dn: str | None = Field(
            default=None,
        )
        hidden_attrs: list[str] = Field(
            default_factory=list,
        )
        sort_entries: bool = Field(
            default=False,
        )
        include_comments: bool = Field(
            default=False,
        )
        base64_encode_binary: bool = Field(
            default=False,
        )

    class FormatDetails(FrozenLdifModel):
        """Original formatting details for round-trip preservation."""

        dn_line: str | None = Field(
            default=None,
        )
        syntax: str | None = Field(
            default=None,
        )
        encoding: c.Ldif.LiteralTypes.EncodingLiteral | None = Field(
            default=None,
        )
        spacing: str | None = Field(
            default=None,
        )
        trailing_info: str | None = Field(
            default=None,
        )

    class SchemaFormatDetails(FrozenLdifModel):
        """Schema formatting details for perfect round-trip conversion."""

        original_string_complete: str | None = Field(
            default=None,
        )
        quotes: str | None = Field(
            default=None,
        )
        spacing: str | None = Field(
            default=None,
        )
        field_order: list[str] = Field(
            default_factory=list,
        )
        x_origin: str | None = Field(
            default=None,
        )
        x_ordered: list[str] = Field(
            default_factory=list,
        )
        extensions: FlextLdifModelsMetadata.DynamicMetadata = Field(
            default_factory=FlextLdifModelsMetadata.DynamicMetadata,
        )

    class QuirkMetadata(FlextLdifModelsBase):
        """Universal metadata container for quirk-specific data preservation."""

        model_config = ConfigDict(extra="allow", frozen=False)

        quirk_type: c.Ldif.ServerTypes | c.Ldif.LiteralTypes.ServerTypeLiteral = Field(
            ...,
        )
        extensions: FlextLdifModelsMetadata.DynamicMetadata = Field(
            default_factory=FlextLdifModelsMetadata.DynamicMetadata,
        )

        rfc_violations: list[str] = Field(
            default_factory=list,
        )
        rfc_warnings: list[str] = Field(
            default_factory=list,
        )

        conversion_notes: FlextLdifModelsMetadata.DynamicMetadata = Field(
            default_factory=FlextLdifModelsMetadata.DynamicMetadata,
        )
        attribute_transformations: dict[
            str,
            FlextLdifModelsDomains.AttributeTransformation,
        ] = Field(
            default_factory=dict,
        )

        server_specific_data: FlextLdifModelsMetadata.EntryMetadata = Field(
            default_factory=FlextLdifModelsMetadata.EntryMetadata,
        )
        original_server_type: c.Ldif.LiteralTypes.ServerTypeLiteral | None = Field(
            default=None,
        )
        target_server_type: c.Ldif.LiteralTypes.ServerTypeLiteral | None = Field(
            default=None,
        )

        acls: list[FlextLdifModelsDomains.Acl] = Field(
            default_factory=list,
        )
        objectclasses: list[FlextLdifModelsDomains.SchemaObjectClass] = Field(
            default_factory=list,
        )
        validation_results: FlextLdifModelsDomains.ValidationMetadata | None = Field(
            default=None,
        )
        processing_stats: FlextLdifModelsDomains.EntryStatistics | None = Field(
            default=None,
        )
        write_options: FlextLdifModelsDomains.WriteOptions | None = Field(
            default=None,
        )
        removed_attributes: FlextLdifModelsMetadata.DynamicMetadata = Field(
            default_factory=FlextLdifModelsMetadata.DynamicMetadata,
        )

        original_format_details: FlextLdifModelsDomains.FormatDetails | None = Field(
            default=None,
        )

        schema_format_details: FlextLdifModelsDomains.SchemaFormatDetails | None = (
            Field(
                default=None,
            )
        )
        soft_delete_markers: list[str] = Field(
            default_factory=list,
        )
        original_attribute_case: FlextLdifModelsMetadata.DynamicMetadata = Field(
            default_factory=FlextLdifModelsMetadata.DynamicMetadata,
        )
        schema_quirks_applied: list[c.Ldif.LiteralTypes.ServerTypeLiteral] = Field(
            default_factory=list,
        )
        boolean_conversions: FlextLdifModelsMetadata.DynamicMetadata = Field(
            default_factory=FlextLdifModelsMetadata.DynamicMetadata,
        )

        minimal_differences: FlextLdifModelsMetadata.DynamicMetadata = Field(
            default_factory=FlextLdifModelsMetadata.DynamicMetadata,
        )

        original_strings: FlextLdifModelsMetadata.DynamicMetadata = Field(
            default_factory=FlextLdifModelsMetadata.DynamicMetadata,
        )

        conversion_history: list[
            dict[str, str | int | float | bool | list[str] | None]
        ] = Field(
            default_factory=list,
        )

        @classmethod
        def create_for(
            cls,
            quirk_type: str | c.Ldif.LiteralTypes.ServerTypeLiteral | None = None,
            extensions: FlextLdifModelsMetadata.DynamicMetadata | None = None,
        ) -> Self:
            """Factory method to create QuirkMetadata with extensions."""
            default_quirk_type: c.Ldif.ServerTypes = (
                normalize_server_type(quirk_type)
                if quirk_type is not None
                else c.Ldif.ServerTypes.RFC
            )

            extensions_model: FlextLdifModelsMetadata.DynamicMetadata
            if extensions is None:
                extensions_model = FlextLdifModelsMetadata.DynamicMetadata()
            else:
                extensions_model = extensions
            return cls(
                quirk_type=default_quirk_type,
                extensions=extensions_model,
            )

        def track_attribute_transformation(
            self,
            original_name: str,
            new_name: str | None,
            transformation_type: (c.Ldif.LiteralTypes.TransformationTypeLiteral),
            original_values: Sequence[str] | None = None,
            new_values: list[str] | None = None,
            reason: str | None = None,
        ) -> Self:
            """Track an attribute transformation in metadata."""
            transformation = FlextLdifModelsDomains.AttributeTransformation(
                original_name=original_name,
                target_name=new_name,
                transformation_type=transformation_type,
                original_values=list(original_values) if original_values else [],
                target_values=new_values or [],
            )
            self.attribute_transformations[original_name] = transformation

            note_key = f"attr_{original_name}_{transformation_type}"
            self.conversion_notes[note_key] = (
                reason or f"{transformation_type}: {original_name} → {new_name}"
            )

            return self

        def track_attribute_removal(
            self,
            attribute_name: str,
            values: Sequence[str],
            reason: str | None = None,
        ) -> Self:
            """Track an attribute removal in metadata."""
            values_typed: t.MetadataAttributeValue = list(values)
            self.removed_attributes[attribute_name] = values_typed
            return self.track_attribute_transformation(
                original_name=attribute_name,
                new_name=None,
                transformation_type="attribute_removed",
                original_values=values,
                reason=reason,
            )

        def track_dn_transformation(
            self,
            original_dn: str,
            transformed_dn: str,
            transformation_type: (
                c.Ldif.LiteralTypes.TransformationTypeLiteral
            ) = "dn_normalized",
            *,
            was_base64: bool = False,
            escapes_applied: Sequence[str] | None = None,
        ) -> Self:
            """Track a DN transformation in metadata."""
            rfc_format = c.Ldif.Format
            self.original_strings[rfc_format.META_DN_ORIGINAL] = original_dn
            self.extensions[rfc_format.META_DN_WAS_BASE64] = was_base64
            if escapes_applied:
                escapes_typed: t.MetadataAttributeValue = list(escapes_applied)
                self.extensions[rfc_format.META_DN_ESCAPES_APPLIED] = escapes_typed

            self.conversion_notes[f"dn_{transformation_type}"] = (
                f"DN {transformation_type}: '{original_dn}' → '{transformed_dn}'"
            )

            return self

        def track_rfc_violation(
            self,
            violation: str,
            severity: str = "error",
        ) -> Self:
            """Track an RFC violation or warning."""
            if severity == "warning":
                self.rfc_warnings.append(violation)
            else:
                self.rfc_violations.append(violation)
            return self

        def add_conversion_note(
            self,
            operation: str,
            description: str,
        ) -> Self:
            """Add a conversion note to the audit trail."""
            self.conversion_notes[operation] = description
            return self

        def set_server_context(
            self,
            source_server: c.Ldif.LiteralTypes.ServerTypeLiteral,
            target_server: c.Ldif.LiteralTypes.ServerTypeLiteral | None = None,
        ) -> Self:
            """Set source and target server context."""
            self.original_server_type = source_server
            if target_server:
                self.target_server_type = target_server

            rfc_format = c.Ldif.Format
            self.extensions[rfc_format.META_TRANSFORMATION_SOURCE] = source_server
            if target_server:
                self.extensions[rfc_format.META_TRANSFORMATION_TARGET] = target_server

            return self

        def record_original_format(
            self,
            original_ldif: str,
            attribute_case: FlextLdifModelsMetadata.DynamicMetadata | None = None,
        ) -> Self:
            """Record original LDIF format for round-trip conversion."""
            self.original_strings["entry_original_ldif"] = original_ldif
            if attribute_case:
                for key, value in attribute_case.items():
                    self.original_attribute_case[key] = value
            return self


__all__ = ["FlextLdifModelsDomains"]
