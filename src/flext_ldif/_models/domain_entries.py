"""Domain models for LDIF entities.

This module contains core domain models for LDIF processing including
Distinguished Names, Entries, and Schema elements.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import re
import struct
from collections.abc import (
    Callable,
    KeysView,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
    ValuesView,
)
from contextlib import suppress
from datetime import datetime
from typing import Annotated, ClassVar, Self, TypeIs, override

from pydantic import (
    ConfigDict,
    Field,
    ValidationError,
    computed_field,
    field_validator,
    model_validator,
)

from flext_core import FlextLogger, m, r
from flext_ldif import (
    FlextLdifModelsBases,
    FlextLdifModelsMetadata,
    FlextLdifModelsSettings,
    FlextLdifShared,
    c,
    t,
)


def _empty_conversion_history_factory() -> MutableSequence[t.MutableStrMapping]:
    return []


# Compiled patterns for RFC validation — C-engine regex vs Python char loops.
_ATTR_NAME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9-]*$")
_ATTR_OPTION_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]*$")
_BINARY_CHAR_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\xff]")


class FlextLdifModelsDomainsEntries:
    """LDIF domain models container class.

    This class acts as a namespace container for core LDIF domain models.
    All nested classes are accessed via m.* in the main models.py.
    """

    _logger = FlextLogger(__name__)

    @staticmethod
    def _conversion_history_factory() -> MutableSequence[t.MutableStrMapping]:
        return []

    class DNStatisticsFlags(m.FrozenModel):
        """Flags capturing DN transformation quirks and validation state.

        All fields default to False/empty since flags are optionally set
        during DN processing (equivalent to former total=False TypedDict).
        """

        model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True)
        had_tab_chars: Annotated[
            bool,
            Field(description="DN contained TAB characters"),
        ] = False
        had_trailing_spaces: Annotated[
            bool,
            Field(description="DN had trailing spaces"),
        ] = False
        had_leading_spaces: Annotated[
            bool,
            Field(description="DN had leading spaces"),
        ] = False
        had_extra_spaces: Annotated[
            bool,
            Field(description="DN had multiple consecutive spaces"),
        ] = False
        was_base64_encoded: Annotated[
            bool,
            Field(description="DN was base64 encoded in LDIF (dn::)"),
        ] = False
        had_utf8_chars: Annotated[
            bool,
            Field(
                description="DN contained UTF-8 multi-byte characters",
            ),
        ] = False
        had_escape_sequences: Annotated[
            bool,
            Field(description="DN contained LDAP escape sequences"),
        ] = False
        validation_status: Annotated[
            str,
            Field(
                description="Validation status (use ValidationStatus constants)",
            ),
        ] = "valid"
        validation_warnings: Annotated[
            MutableSequence[str],
            Field(description="Non-fatal validation warnings"),
        ] = Field(default_factory=list)
        validation_errors: Annotated[
            MutableSequence[str],
            Field(description="Fatal validation errors"),
        ] = Field(default_factory=list)

    class DN(m.Value):
        """Distinguished Name value t.NormalizedValue."""

        model_config: ClassVar[ConfigDict] = ConfigDict(
            strict=True,
            frozen=True,
            extra="forbid",
            validate_default=True,
            use_enum_values=True,
            str_strip_whitespace=True,
        )
        value: Annotated[
            str,
            Field(
                ...,
                description="DN string value (lenient processing - no max_length)",
            ),
        ]
        metadata: Annotated[
            FlextLdifModelsMetadata.EntryMetadata,
            Field(
                description="Quirk-specific metadata for preserving original format",
            ),
        ] = Field(default_factory=FlextLdifModelsMetadata.EntryMetadata)
        _DN_COMPONENT_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
            r"^[a-zA-Z][a-zA-Z0-9-]*=(?:[^\\\\,]|\\\\.)*$",
            re.IGNORECASE,
        )

        @override
        def __str__(self) -> str:
            """Return DN value as string for str() conversion."""
            return self.value

        @classmethod
        def from_value(cls, dn: str | Self | None) -> Self:
            """Create DN from string or existing instance.

            Factory method that normalizes DN input to DN t.NormalizedValue.
            Uses Self for proper facade compatibility (models.py exposure).

            Args:
                dn: DN as string or DN t.NormalizedValue

            Returns:
                DN instance (new or existing)

            Raises:
                ValueError: If dn is None

            Note:
                Lenient processing: Empty DN is accepted.
                Validation at Entry level via validate_entry_rfc_compliance().

            """
            if dn is None:
                msg = "dn cannot be None"
                raise ValueError(msg)
            return cls.model_validate({
                "value": str(dn),
                "metadata": FlextLdifModelsMetadata.EntryMetadata.model_validate({}),
            })

    class SchemaAttribute(FlextLdifModelsBases.SchemaElement):
        """LDAP schema attribute definition model (RFC 4512 compliant).

        Represents an LDAP attribute type definition from schema with full
        RFC 4512 support.

        Inherits from FlextLdifModelsBases.SchemaElement:
        - model_config (strict=True, validate_default=True, validate_assignment=True)
        - has_metadata computed field
        - server_type computed field
        - has_server_extensions computed field
        """

        name: Annotated[str, Field(..., description="Attribute name")]
        oid: Annotated[str, Field(..., description="Attribute OID")]
        desc: Annotated[
            str | None,
            Field(description="Attribute description (RFC 4512 DESC)"),
        ] = None
        sup: Annotated[
            str | None,
            Field(description="Superior attribute type (RFC 4512 SUP)"),
        ] = None
        equality: Annotated[
            str | None,
            Field(
                description="Equality matching rule (RFC 4512 EQUALITY)",
            ),
        ] = None
        ordering: Annotated[
            str | None,
            Field(
                description="Ordering matching rule (RFC 4512 ORDERING)",
            ),
        ] = None
        substr: Annotated[
            str | None,
            Field(
                description="Substring matching rule (RFC 4512 SUBSTR)",
            ),
        ] = None
        syntax: Annotated[
            str | None,
            Field(description="Attribute syntax OID (RFC 4512 SYNTAX)"),
        ] = None
        length: Annotated[
            int | None,
            Field(description="Maximum length constraint"),
        ] = None
        usage: Annotated[
            str | None,
            Field(description="Attribute usage (RFC 4512 USAGE)"),
        ] = None
        single_value: Annotated[
            bool,
            Field(
                description="Whether attribute is single-valued (RFC 4512 SINGLE-VALUE)",
            ),
        ] = False
        collective: Annotated[
            bool,
            Field(
                description="Whether attribute is collective (RFC 4512 COLLECTIVE)",
            ),
        ] = False
        no_user_modification: Annotated[
            bool,
            Field(
                description="Whether users can modify this attribute (RFC 4512 NO-USER-MODIFICATION)",
            ),
        ] = False
        immutable: Annotated[
            bool,
            Field(
                description="Whether attribute is immutable (OUD extension)",
            ),
        ] = False
        user_modification: Annotated[
            bool,
            Field(
                description="Whether users can modify this attribute (OUD extension)",
            ),
        ] = True
        obsolete: Annotated[
            bool,
            Field(
                description="Whether attribute is obsolete (OUD extension)",
            ),
        ] = False
        x_origin: Annotated[
            str | None,
            Field(
                description="Origin of attribute definition (server-specific X-ORIGIN extension)",
            ),
        ] = None
        x_file_ref: Annotated[
            str | None,
            Field(
                description="File reference for attribute definition (server-specific X-FILE-REF extension)",
            ),
        ] = None
        x_name: Annotated[
            str | None,
            Field(
                description="Extended name for attribute (server-specific X-NAME extension)",
            ),
        ] = None
        x_alias: Annotated[
            str | None,
            Field(
                description="Extended alias for attribute (server-specific X-ALIAS extension)",
            ),
        ] = None
        x_oid: Annotated[
            str | None,
            Field(
                description="Extended OID for attribute (server-specific X-OID extension)",
            ),
        ] = None
        metadata: FlextLdifModelsDomainsEntries.QuirkMetadata | None = Field(
            default=None, description="Quirk-specific metadata for schema attribute"
        )

    class Syntax(FlextLdifModelsBases.SchemaElement):
        """LDAP attribute syntax definition model (RFC 4517 compliant).

        Represents an LDAP attribute syntax OID and its validation rules per RFC 4517.

        Inherits from FlextLdifModelsBases.SchemaElement:
        - model_config (strict=True, validate_default=True, validate_assignment=True)
        - has_metadata computed field
        - server_type computed field
        - has_server_extensions computed field
        """

        oid: Annotated[
            str,
            Field(
                ...,
                description="Syntax OID (RFC 4517, format: 1.3.6.1.4.1.1466.115.121.1.X)",
            ),
        ]
        name: Annotated[
            str | None,
            Field(
                None,
                description="Human-readable syntax name (e.g., 'Boolean', 'Integer')",
            ),
        ]
        desc: Annotated[
            str | None,
            Field(None, description="Syntax description and purpose"),
        ]
        type_category: Annotated[
            str,
            Field(
                description="Syntax type category: string, integer, binary, dn, time, boolean",
            ),
        ] = "string"
        is_binary: Annotated[
            bool,
            Field(
                description="Whether this syntax uses binary encoding",
            ),
        ] = False
        max_length: Annotated[
            int | None,
            Field(description="Maximum length in bytes (if applicable)"),
        ] = None
        case_insensitive: Annotated[
            bool,
            Field(
                description="Whether comparisons are case-insensitive",
            ),
        ] = False
        allows_multivalued: Annotated[
            bool,
            Field(
                description="Whether attributes using this syntax can be multivalued",
            ),
        ] = True
        encoding: Annotated[
            c.Ldif.EncodingLiteral,
            Field(
                description="Expected character encoding (utf-8, ascii, iso-8859-1, etc.)",
            ),
        ] = c.Ldif.Encoding.UTF8
        validation_pattern: Annotated[
            str | None,
            Field(description="Optional regex pattern for value validation"),
        ] = None
        metadata: FlextLdifModelsDomainsEntries.QuirkMetadata | None = Field(
            default=None, description="Server-specific quirk metadata"
        )

        @classmethod
        def resolve_syntax_oid(
            cls,
            oid: str,
            server_type: c.Ldif.ServerTypeLiteral = c.Ldif.ServerTypes.RFC,
        ) -> Self | None:
            """Resolve a syntax OID to a Syntax model using RFC 4517 validation.

            This method is used by both models and the syntax service to avoid
            circular dependencies.

            Args:
                oid: Syntax OID to resolve
                server_type: LDAP server type for quirk metadata

            Returns:
                Resolved Syntax model with RFC 4517 compliance details, or None if:
                - oid is None or empty
                - syntax OID validation fails
                - syntax resolution fails

            """
            if not oid or not oid.strip():
                return None
            try:
                oid_pattern = re.compile(r"^\\d+(\\.\\d+)*$")
                if not oid_pattern.match(oid):
                    return None
                oid_to_name = dict(c.Ldif.OID_TO_NAME)
                name = oid_to_name.get(oid)
                type_category = (
                    c.Ldif.NAME_TO_TYPE_CATEGORY.get(name, "string")
                    if name
                    else "string"
                )
                metadata = (
                    FlextLdifModelsDomainsEntries.QuirkMetadata.model_validate({
                        "quirk_type": server_type,
                    })
                    if server_type != c.Ldif.ServerTypes.RFC.value
                    else None
                )
                return cls(
                    oid=oid,
                    name=name,
                    desc=None,
                    type_category=type_category,
                    max_length=None,
                    is_binary=False,
                    case_insensitive=False,
                    allows_multivalued=True,
                    encoding=c.Ldif.Encoding.UTF8,
                    validation_pattern=None,
                    validation_metadata=None,
                    metadata=metadata,
                )
            except (
                ValueError,
                KeyError,
                AttributeError,
                UnicodeDecodeError,
                struct.error,
            ):
                return None

        @field_validator("oid")
        @classmethod
        def validate_oid(cls, v: str) -> str:
            """Validate that OID is not empty."""
            if not v or not v.strip():
                msg = "OID cannot be empty"
                raise ValueError(msg)
            return v

    class SchemaObjectClass(FlextLdifModelsBases.SchemaElement):
        """LDAP schema t.NormalizedValue class definition model (RFC 4512 compliant).

        Represents an LDAP t.NormalizedValue class definition from schema with full
        RFC 4512 support.

        Inherits from FlextLdifModelsBases.SchemaElement:
        - model_config (strict=True, validate_default=True, validate_assignment=True)
        - has_metadata computed field
        - server_type computed field
        - has_server_extensions computed field
        """

        name: Annotated[str, Field(..., description="Object class name")]
        oid: Annotated[str, Field(..., description="Object class OID")]
        desc: Annotated[
            str | None,
            Field(description="Object class description (RFC 4512 DESC)"),
        ] = None
        sup: Annotated[
            str | MutableSequence[str] | None,
            Field(
                description="Superior t.NormalizedValue class(es) (RFC 4512 SUP)",
            ),
        ] = None
        kind: Annotated[
            str,
            Field(
                description="Object class kind (RFC 4512: STRUCTURAL, AUXILIARY, ABSTRACT)",
            ),
        ] = "STRUCTURAL"
        must: Annotated[
            MutableSequence[str] | None,
            Field(description="Required attributes (RFC 4512 MUST)"),
        ] = None
        may: Annotated[
            MutableSequence[str] | None,
            Field(description="Optional attributes (RFC 4512 MAY)"),
        ] = None
        metadata: FlextLdifModelsDomainsEntries.QuirkMetadata | None = Field(
            default=None, description="Quirk-specific metadata for schema object class"
        )

    class Attributes(m.ArbitraryTypesModel):
        """LDIF attributes container - simplified dict-like interface."""

        model_config: ClassVar[ConfigDict] = ConfigDict(
            validate_assignment=True,
            extra="forbid",
            use_enum_values=True,
            str_strip_whitespace=True,
        )
        attributes: Annotated[
            t.MutableStrSequenceMapping,
            Field(description="Attribute name to values list"),
        ]
        attribute_metadata: Annotated[
            MutableMapping[str, t.MutableAttributeMapping],
            Field(
                description="Metadata for each attribute, like category or hidden status.",
            ),
        ] = Field(default_factory=dict)
        metadata: Annotated[
            FlextLdifModelsMetadata.EntryMetadata | None,
            Field(
                description="Metadata for preserving ordering and formats",
            ),
        ] = None

        def __getitem__(self, key: str) -> MutableSequence[str]:
            """Get attribute values by name (case-sensitive LDAP).

            Args:
                key: Attribute name

            Returns:
                List of attribute values

            Raises:
                KeyError if attribute not found

            """
            return self.attributes[key]

        def __setitem__(self, key: str, value: MutableSequence[str]) -> None:
            """Set attribute values by name.

            Args:
                key: Attribute name
                value: List of values

            """
            self.attributes[key] = value

        def __len__(self) -> int:
            """Return the number of attributes."""
            return len(self.attributes)

        def __contains__(self, key: str) -> bool:
            """Check if attribute exists."""
            return key in self.attributes

        def add_attribute(self, key: str, values: MutableSequence[str]) -> Self:
            """Add or update an attribute with values.

            Args:
                key: Attribute name
                values: List of values

            Returns:
                Self for method chaining

            """
            self.attributes[key] = values
            return self

        def get(
            self,
            key: str,
            default: MutableSequence[str] | None = None,
        ) -> MutableSequence[str]:
            """Get attribute values with optional default.

            Args:
                key: Attribute name
                default: Default list if not found
                (defaults to empty list if not provided)

            Returns:
                List of values or default (empty list if not found and no default)

            """
            if default is not None:
                return self.attributes.get(key, default)
            if key in self.attributes:
                return self.attributes[key]
            return []

        def get_values(
            self,
            key: str,
            default: MutableSequence[str] | None = None,
        ) -> MutableSequence[str]:
            """Get attribute values as a list (same as get()).

            Args:
                key: Attribute name
                default: Default list if not found

            Returns:
                List of attribute values, or default if not found

            """
            return self.get(key, default)

        def has_attribute(self, key: str) -> bool:
            """Check if attribute exists.

            Args:
                key: Attribute name

            Returns:
                True if attribute exists

            """
            return key in self.attributes

        def items(self) -> MutableSequence[tuple[str, MutableSequence[str]]]:
            """Get attribute name-values pairs.

            Returns:
                List of (name, values) tuples

            """
            return list(self.attributes.items())

        def iter_attributes(self) -> MutableSequence[str]:
            """Get list of all attribute names.

            Returns:
                List of attribute names

            """
            return list(self.attributes.keys())

        def keys(self) -> KeysView[str]:
            """Get attribute names."""
            return self.attributes.keys()

        def remove_attribute(self, key: str) -> Self:
            """Remove an attribute if it exists.

            Args:
                key: Attribute name

            Returns:
                Self for method chaining

            """
            _ = self.attributes.pop(key, None)
            return self

        def values(self) -> ValuesView[MutableSequence[str]]:
            """Get attribute values lists."""
            return self.attributes.values()

    class DnRegistry(m.StrictModel):
        """Registry for tracking canonical DN case during conversions.

        This class maintains a mapping of DNs in normalized form (lowercase, no spaces)
        to their canonical case representation. Used during server conversions to
        ensure DN case consistency.

        Examples:
            registry = FlextLdifModelsDomains.DnRegistry()
            canonical = registry.register_dn("CN=Admin,DC=Example,DC=Com")
            result = registry.get_canonical_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")

        """

        def __init__(self) -> None:
            """Initialize empty DN case registry."""
            super().__init__()
            self._registry: FlextLdifModelsMetadata.DynamicMetadata = (
                FlextLdifModelsMetadata.DynamicMetadata()
            )
            self._case_variants: MutableMapping[str, set[str]] = {}

        @staticmethod
        def _normalize_dn(dn: str) -> str:
            """Convert DN to lowercase for case-insensitive dict lookup.

            NOTE: DnRegistry receives DNs already normalized to RFC 4514 format.
            This method is ONLY for dict key generation (case-insensitive lookup).
            It does NOT validate or normalize the DN - that must be done BEFORE
            calling register_dn().

            Business Rule: This is a pure function that doesn't use instance state.
            Implication: Can be a static method for better clarity and performance.

            Returns:
                Lowercase DN string for use as dictionary key only.

            """
            return dn.lower().replace(" ", "")

        def clear(self) -> None:
            """Clear all DN registrations."""
            self._registry.clear()
            self._case_variants.clear()

        def get_canonical_dn(self, dn: str) -> str | None:
            """Get canonical case for a DN (case-insensitive lookup).

            Args:
                dn: Distinguished Name to lookup

            Returns:
                Canonical case DN string, or None if not registered

            """
            normalized = self._normalize_dn(dn)
            value = self._registry.get(normalized)
            if isinstance(value, str):
                return value
            return None

        def register_dn(self, dn: str, *, force: bool = False) -> str:
            """Register DN and return its canonical case.

            Args:
                dn: Distinguished Name to register
                force: If True, override existing canonical case

            Returns:
                Canonical case DN string

            Example:
                canonical = registry.register_dn("CN=Admin,DC=Com")

            """
            normalized = self._normalize_dn(dn)
            if normalized not in self._case_variants:
                self._case_variants[normalized] = set[str]()
            self._case_variants[normalized].add(dn)
            if normalized not in self._registry or force:
                self._registry[normalized] = dn
            value = self._registry[normalized]
            return str(value)

        def validate_oud_consistency(self) -> r[bool]:
            """Validate DN case consistency for server conversion.

            Returns:
                r[bool]: True if consistent, False with warnings if not

            """
            inconsistencies: MutableSequence[
                MutableMapping[str, str | int | MutableSequence[str]]
            ] = []
            for normalized_dn, variants in self._case_variants.items():
                if len(variants) > 1:
                    canonical_value = self._registry.get(normalized_dn)
                    canonical = (
                        canonical_value if isinstance(canonical_value, str) else ""
                    )
                    inconsistencies.append({
                        "normalized_dn": normalized_dn,
                        "canonical_case": canonical,
                        "variants": list(variants),
                        "variant_count": len(variants),
                    })
            if inconsistencies:
                return r[bool].ok(False)
            return r[bool].ok(True)

    class AclPermissions(m.ArbitraryTypesModel):
        """ACL permissions for LDAP operations.

        Supports:
        - Standard RFC permissions (read, write, add, delete, search, compare)
        - Server-specific permissions (self_write, proxy, browse, auth)
        - Negative permissions (no_write, no_add, no_delete, no_browse, no_self_write)
        - Compound permissions (all)
        """

        read: Annotated[bool, Field(description="Read permission")] = False
        write: Annotated[bool, Field(description="Write permission")] = False
        add: Annotated[bool, Field(description="Add permission")] = False
        delete: Annotated[bool, Field(description="Delete permission")] = False
        search: Annotated[bool, Field(description="Search permission")] = False
        compare: Annotated[bool, Field(description="Compare permission")] = False
        self_write: Annotated[
            bool,
            Field(description="Self-write permission (OID, OUD)"),
        ] = False
        proxy: Annotated[
            bool,
            Field(description="Proxy permission (OID, OUD, 389DS)"),
        ] = False
        browse: Annotated[
            bool,
            Field(
                description="Browse permission (OID) - maps to read+search",
            ),
        ] = False
        auth: Annotated[
            bool,
            Field(
                description="Auth permission (OID) - authentication access",
            ),
        ] = False
        all: Annotated[
            bool,
            Field(description="All permissions (compound permission)"),
        ] = False
        no_write: Annotated[
            bool,
            Field(description="Deny write permission (OID)"),
        ] = False
        no_add: Annotated[
            bool,
            Field(description="Deny add permission (OID)"),
        ] = False
        no_delete: Annotated[
            bool,
            Field(description="Deny delete permission (OID)"),
        ] = False
        no_browse: Annotated[
            bool,
            Field(description="Deny browse permission (OID)"),
        ] = False
        no_self_write: Annotated[
            bool,
            Field(description="Deny self-write permission (OID)"),
        ] = False

        @staticmethod
        def get_rfc_compliant_permissions(
            perms_dict: t.MutableBoolMapping,
        ) -> t.MutableBoolMapping:
            """Filter permissions dict to RFC-compliant fields only.

            Architecture: Server-specific permissions (like OID's "none") are excluded
            from this model and stored in metadata instead. This method ensures
            AclPermissions only contains RFC-compliant or widely-supported permissions.

            Args:
                perms_dict: Dictionary with permission name → bool (from parser)

            Returns:
                Filtered dict containing only RFC-compliant permission keys

            """
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

    class AclTarget(m.ArbitraryTypesModel):
        """ACL target specification."""

        target_dn: Annotated[str, Field(..., description="Target DN pattern")]
        attributes: Annotated[
            MutableSequence[str],
            Field(description="Target attributes"),
        ]

    class AclSubject(m.ArbitraryTypesModel):
        """ACL subject specification."""

        subject_type: Annotated[
            c.Ldif.AclSubjectTypeLiteral,
            Field(..., description="Subject type (user, group, etc.)"),
        ]
        subject_value: Annotated[str, Field(..., description="Subject value/pattern")]

    class Acl(FlextLdifModelsBases.AclElement):
        """Universal ACL model for all LDAP server types.

        Inherits from FlextLdifModelsBases.AclElement:
        - model_config (strict=True, validate_default=True, validate_assignment=True)
        - server_type field with default "rfc"
        - metadata field (QuirkMetadata | None)
        - validation_violations field (list[str])
        - is_valid computed field
        - has_server_quirks computed field
        """

        name: str = Field(default="", description="ACL name")
        target: FlextLdifModelsDomainsEntries.AclTarget | None = Field(
            default=None, description="ACL target specification"
        )
        subject: FlextLdifModelsDomainsEntries.AclSubject | None = Field(
            default=None, description="ACL subject specification"
        )
        permissions: FlextLdifModelsDomainsEntries.AclPermissions | None = Field(
            default=None, description="ACL permission flags"
        )
        raw_line: str = Field(default="", description="Original raw ACL line from LDIF")
        raw_acl: str = Field(default="", description="Original ACL string from LDIF")
        metadata: FlextLdifModelsDomainsEntries.QuirkMetadata | None = Field(
            default=None,
            description="Quirk-specific metadata for ACL processing",
        )

        @classmethod
        def get_acl_format(cls) -> str:
            """Get ACL format for this server type.

            Business Rule: This method doesn't use instance state, only class constants.
            Implication: Can be a class method for better clarity and allows override in subclasses.

            Returns:
                Default ACL format string from constants.

            """
            return c.Ldif.DEFAULT_ACL_FORMAT

        def get_acl_type(self) -> str:
            """Get ACL type identifier for this server.

            #YB|            Uses FROM_LONG mapping to normalize long-form identifiers
            (e.g., "oracle_oid" → "oid") to short-form canonical identifiers.
            """
            short_server_type = c.Ldif.FROM_LONG.get(
                self.server_type,
                self.server_type,
            )
            return f"{short_server_type}_acl"

        @model_validator(mode="after")
        def validate_acl_format(self) -> Self:
            """Validate ACL format - capture violations in metadata, DON'T reject.

            IMPORTANT: Pydantic 2 requires model validators with mode="after" to return
            `self` (not a copy) when validating via __init__. We modify self in-place
            using attribute assignment helpers.

            See: https://docs.pydantic.dev/latest/concepts/validators/#model-validators
            """
            violations: MutableSequence[str] = []
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
            if acl_is_defined and not (self.raw_acl and self.raw_acl.strip()):
                violations.append(
                    "ACL is defined (has target/subject/permissions) but raw_acl is empty",
                )
            if violations:
                self.validation_violations = violations
            return self

    class AclWriteMetadata(m.FrozenModel):
        """Metadata for ACL write formatting operations.

        This frozen model encapsulates ACL metadata extracted from QuirkMetadata.extensions
        for use in ACL formatting during LDIF writing operations.

        Used by Entry quirks to format ACI attributes with original ACL format names,
        following SRP by separating ACL formatting from Writer serialization.

        Attributes:
            original_format: Original ACL string format (always preserve for conversion).
            source_server: Server that parsed this ACL (oid, oud, openldap, etc.).
            name_sanitized: True if ACL name was sanitized (had control chars).
            original_name_raw: Original ACL name before sanitization (for audit).

        Example:
            >>> metadata = AclWriteMetadata.from_extensions(entry.metadata.extensions)
            >>> if metadata.original_format:
            ...     sanitized = FlextLdifUtilities.ACL.sanitize_acl_name(
            ...         metadata.original_format
            ...     )

        """

        original_format: Annotated[
            str | None,
            Field(
                description="Original ACL string format from source server",
            ),
        ] = None
        source_server: Annotated[
            str | None,
            Field(description="Server type that parsed this ACL"),
        ] = None
        name_sanitized: Annotated[
            bool,
            Field(
                description="True if ACL name was sanitized during processing",
            ),
        ] = False
        original_name_raw: Annotated[
            str | None,
            Field(description="Original ACL name before sanitization"),
        ] = None

        @classmethod
        def from_extensions(
            cls,
            extensions: t.MutableContainerMapping | None,
        ) -> Self:
            """Extract ACL write metadata from QuirkMetadata extensions.

            Factory method to create AclWriteMetadata from the extensions dict
            stored in QuirkMetadata.extensions, using MetadataKeys constants.

            Args:
                extensions: QuirkMetadata.extensions dict containing ACL metadata.
                    Expected keys: ACL_ORIGINAL_FORMAT, ACL_SOURCE_SERVER,
                    ACL_NAME_SANITIZED, ACL_ORIGINAL_NAME_RAW.

            Returns:
                AclWriteMetadata instance with extracted values.

            Example:
                >>> extensions = {"original_format": "orclaci: access to entry..."}
                >>> metadata = AclWriteMetadata.from_extensions(extensions)
                >>> metadata.original_format
                'orclaci: access to entry...'

            """
            if not extensions:
                return cls.model_validate({
                    "original_format": None,
                    "source_server": None,
                    "name_sanitized": False,
                    "original_name_raw": None,
                })
            keys = c.Ldif
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
            return self.original_format is not None and bool(self.original_format)

    class Entry(m.Entity):
        """LDIF entry domain model.

        Implements p.Models.Entry through structural typing.
        The protocol requires:
        - dn: str
        - attributes: FlextLdifModelsMetadata.DynamicMetadata

        This model provides these through:
        - dn field (DN) which has .value property returning str
        - attributes field (Attributes) which has .attributes property returning FlextLdifModelsDomains.UnconvertedAttributes
        """

        _flext_enforcement_exempt: ClassVar[bool] = (
            True  # extra="allow" for LDIF dynamic attrs
        )
        model_config: ClassVar[ConfigDict] = ConfigDict(
            strict=True,
            validate_default=True,
            validate_assignment=True,
            extra="allow",
        )
        dn: FlextLdifModelsDomainsEntries.DN | None = Field(
            ...,
            description="Distinguished Name of the entry (REQUIRED per RFC 2849 § 2). Allows None for RFC violation capture. Coerced from str via field_validator - PROTOCOL COMPATIBLE with p.Ldif.Entry.Entry",
        )
        attributes: FlextLdifModelsDomainsEntries.Attributes | None = Field(
            ...,
            description="Entry attributes container (REQUIRED per RFC 2849 § 2). Allows None for RFC violation capture. Coerced from dict[str, list[str]] via field_validator - PROTOCOL COMPATIBLE with p.Ldif.Entry.Entry",
        )

        @field_validator("attributes", mode="before")
        @classmethod
        def coerce_attributes_from_dict(
            cls,
            value: FlextLdifModelsDomainsEntries.Attributes
            | t.MutableContainerMapping
            | None,
        ) -> FlextLdifModelsDomainsEntries.Attributes | None:
            """Convert dict to Attributes instance.

            Allows None to pass through for violation capture in model_validator.
            RFC 2849 § 2 violations (attributes required) are captured in validate_entry_rfc_compliance.
            """
            if value is None:
                return None
            if isinstance(value, FlextLdifModelsDomainsEntries.Attributes):
                return value
            wrapped_value: t.MutableContainerMapping = value
            if "attributes" not in value:
                wrapped_value = {"attributes": value}
            return FlextLdifModelsDomainsEntries.Attributes.model_validate(
                wrapped_value,
            )

        @field_validator("dn", mode="before")
        @classmethod
        def coerce_dn_from_string(
            cls,
            value: FlextLdifModelsDomainsEntries.DN
            | t.MutableContainerMapping
            | str
            | None,
        ) -> FlextLdifModelsDomainsEntries.DN | None:
            """Convert string DN to DN instance.

            Allows None to pass through for violation capture in model_validator.
            RFC 2849 § 2 violations are captured in validate_entry_rfc_compliance.
            """
            if value is None:
                return None
            if isinstance(value, FlextLdifModelsDomainsEntries.DN):
                return value
            if isinstance(value, Mapping):
                return FlextLdifModelsDomainsEntries.DN.model_validate(value)
            return FlextLdifModelsDomainsEntries.DN.model_validate({
                "value": str(value),
                "metadata": FlextLdifModelsMetadata.EntryMetadata.model_validate({}),
            })

        changetype: Annotated[
            c.Ldif.ChangeTypeLiteral | None,
            Field(
                description="Change operation type per RFC 2849 § 5.7 (add/delete/modify/moddn/modrdn)",
            ),
        ] = None
        metadata: FlextLdifModelsDomainsEntries.QuirkMetadata | None = Field(
            default=None,
            description="Quirk-specific metadata for processing data, ACLs, statistics, validation (non-RFC data)",
        )
        validation_metadata: t.ConfigMap | None = Field(
            default=None,
            description="Validation metadata captured during parsing and transformation.",
        )

        @computed_field
        def attributes_dict(self) -> t.MutableStrSequenceMapping:
            """Protocol compliance: p.Ldif.Entry.Entry requires attributes: dict[str, list[str]].

            Returns the attributes as a dict for protocol compatibility.
            """
            if self.attributes is None:
                return {}
            return self.attributes.attributes

        @computed_field
        def dn_str(self) -> str:
            """Protocol compliance: p.Ldif.Entry.Entry requires dn: str.

            Returns the DN as a string for protocol compatibility.
            """
            if self.dn is None:
                return ""
            return self.dn.value

        @computed_field
        def unconverted_attributes(
            self,
        ) -> MutableMapping[str, str | MutableSequence[str] | bytes]:
            """Get unconverted attributes from metadata extensions (read-only view, DRY pattern)."""
            empty_attrs: MutableMapping[str, str | MutableSequence[str] | bytes] = {}
            if self.metadata is None:
                return empty_attrs
            extra = self.metadata.extensions.__pydantic_extra__
            if extra is None:
                return empty_attrs
            result = extra.get("unconverted_attributes")
            if result is not None and self.is_string_key_mapping(result):
                converted_unconverted_attributes: MutableMapping[
                    str,
                    str | MutableSequence[str] | bytes,
                ] = {}
                for key_candidate, raw_value in result.items():
                    key_str = key_candidate
                    if self._is_object_list(raw_value):
                        converted_unconverted_attributes[key_str] = [
                            str(item) for item in raw_value
                        ]
                    elif isinstance(raw_value, str | bytes):
                        converted_unconverted_attributes[key_str] = raw_value
                    else:
                        converted_unconverted_attributes[key_str] = str(raw_value)
                return converted_unconverted_attributes
            return empty_attrs

        @model_validator(mode="before")
        @classmethod
        def ensure_metadata_initialized(
            cls,
            data: t.MutableContainerMapping,
        ) -> MutableMapping[
            str,
            t.NormalizedValue | datetime | FlextLdifModelsDomainsEntries.QuirkMetadata,
        ]:
            """Ensure metadata field is always initialized to a QuirkMetadata instance.

            Also handles datetime coercion from ISO strings for JSON round-trips.
            This is necessary because strict=True doesn't auto-coerce strings to datetime.

            Pydantic v2 Context Pattern: Using model_validator with mode='before'
            to initialize fields before field validators run. This validator executes
            at instantiation time, when the module is fully loaded and FlextLdifModelsDomains
            is in scope.

            Args:
                data: Input data for model instantiation

            Returns:
                Modified data with metadata field initialized and datetimes coerced

            """
            data_dict: MutableMapping[
                str,
                t.NormalizedValue
                | datetime
                | FlextLdifModelsDomainsEntries.QuirkMetadata,
            ] = dict(data)
            for dt_field in ("created_at", "updated_at"):
                field_value = data_dict.get(dt_field)
                if isinstance(field_value, str):
                    with suppress(ValueError):
                        data_dict[dt_field] = datetime.fromisoformat(field_value)
            if data_dict.get("metadata") is None:
                quirk_type_value = data_dict.get("quirk_type")
                final_quirk_type_val: c.Ldif.ServerTypes
                if isinstance(quirk_type_value, str):
                    try:
                        final_quirk_type_val = c.Ldif.ServerTypes(quirk_type_value)
                    except ValueError:
                        final_quirk_type_val = c.Ldif.ServerTypes.RFC
                else:
                    final_quirk_type_val = c.Ldif.ServerTypes.RFC
                metadata_obj = (
                    FlextLdifModelsDomainsEntries.QuirkMetadata.model_validate({
                        "quirk_type": final_quirk_type_val,
                    })
                )
                data_dict["metadata"] = metadata_obj
            return data_dict

        @staticmethod
        def _parse_validation_rules(
            validation_rules: t.NormalizedValue,
        ) -> FlextLdifModelsSettings.ServerValidationRules | None:
            """Normalize dynamic validation_rules payload to ServerValidationRules."""
            if isinstance(
                validation_rules,
                FlextLdifModelsSettings.ServerValidationRules,
            ):
                return validation_rules
            if isinstance(validation_rules, str):
                try:
                    return FlextLdifModelsSettings.ServerValidationRules.model_validate_json(
                        validation_rules,
                    )
                except ValidationError as exc:
                    FlextLdifModelsDomainsEntries._logger.warning(
                        f"Failed to validate server rules from JSON string: {exc}",
                    )
                    return None
            if FlextLdifModelsDomainsEntries.Entry.is_string_key_mapping(
                validation_rules,
            ):
                try:
                    validation_rules_payload: t.MutableContainerMapping = dict(
                        validation_rules.items(),
                    )
                    return FlextLdifModelsSettings.ServerValidationRules.model_validate(
                        validation_rules_payload,
                    )
                except ValidationError as exc:
                    FlextLdifModelsDomainsEntries._logger.warning(
                        f"Failed to validate server rules from mapping: {exc}",
                    )
            return None

        @staticmethod
        def is_string_key_mapping(
            value: t.NormalizedValue,
        ) -> TypeIs[t.MutableContainerMapping]:
            return isinstance(value, Mapping)

        @staticmethod
        def _is_object_list(
            value: t.NormalizedValue,
        ) -> TypeIs[t.MutableContainerList]:
            return isinstance(value, list)

        @staticmethod
        def is_object_sequence(
            value: t.NormalizedValue,
        ) -> TypeIs[t.MutableContainerList]:
            return isinstance(value, Sequence) and not isinstance(value, str | bytes)

        @staticmethod
        def _validate_dn(dn_value: str) -> MutableSequence[str]:
            """Validate DN format per RFC 4514 § 2.3, 2.4.

            Business Rule: This is a pure function that doesn't use instance state.
            Implication: Can be a static method for better clarity and performance.

            Note: dn_value is guaranteed to be non-None since dn field is required.

            Args:
                dn_value: DN string to validate

            Returns:
                List of validation violation messages (empty if valid)

            """
            violations: MutableSequence[str] = []
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
                c.Ldif.DN_COMPONENT,
                re.IGNORECASE,
            )
            for idx, comp in enumerate(components):
                if not dn_component_pattern.match(comp):
                    violations.append(
                        f"RFC 4514 § 2.3: Component {idx} '{comp}' invalid format",
                    )
            return violations

        @override
        def model_post_init(
            self,
            _context: t.ScalarMapping | None,
            /,
        ) -> None:
            """Post-init hook to ensure metadata is always initialized.

            Properly initialized before any code tries to access it.
            Uses self.__dict__ assignment to bypass validate_assignment=True
            and prevent infinite re-validation recursion (Pydantic v2 pattern).
            """
            if self.metadata is None:
                self.metadata = FlextLdifModelsDomainsEntries.QuirkMetadata.create_for()

        @model_validator(mode="after")
        def validate_entry_consistency(self) -> Self:
            """Validate cross-field consistency in Entry model.

            Notes:
            - ObjectClass validation is optional - downstream code handles
              entries without objectClass via rejection or warnings.
            - Schema entries (dn: cn=schema) are allowed without objectClass
              as they contain schema definitions, not directory objects.

            Returns:
            Self (for method chaining)

            """
            return self

        @model_validator(mode="after")
        def validate_entry_rfc_compliance(self) -> Self:
            """Validate Entry RFC compliance - capture violations, DON'T reject.

            RFC 2849 § 2: DN and at least one attribute required
            RFC 4514 § 2.3, 2.4: DN format validation
            RFC 4512 § 2.5: Attribute name format validation

            Strategy: PRESERVE problematic entries for round-trip conversions,
            capture violations in validation_metadata for downstream handling.
            """
            violations: MutableSequence[str] = []
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
                old_context: t.MutableStrMapping = {}
                if self.metadata.validation_results is not None:
                    old_context = {
                        key: str(value)
                        for key, value in self.metadata.validation_results.context.items()
                    }
                self.metadata.validation_results = (
                    FlextLdifModelsDomainsEntries.ValidationMetadata.model_validate({
                        "rfc_violations": violations,
                        "errors": [],
                        "warnings": [],
                        "context": {
                            **old_context,
                            "validator": "validate_entry_rfc_compliance",
                            "dn": dn_value,
                            "attribute_count": str(attribute_count),
                            "total_violations": str(len(violations)),
                        },
                        "server_specific_violations": [],
                        "validation_server_type": None,
                    })
                )
            return self

        @model_validator(mode="after")
        def validate_server_specific_rules(self) -> Self:
            """Validate Entry using server-injected validation rules."""
            if not self.metadata:
                return self
            if "validation_rules" not in self.metadata.extensions:
                return self
            validation_rules = self.metadata.extensions.get("validation_rules")
            if not validation_rules:
                return self
            rules = self._parse_validation_rules(validation_rules)
            if rules is None:
                return self
            dn_value = str(self.dn.value) if self.dn else ""
            server_violations: MutableSequence[str] = []
            server_violations.extend(self._check_objectclass_rule(rules, dn_value))
            server_violations.extend(self._check_naming_attr_rule(rules, dn_value))
            server_violations.extend(self._check_binary_option_rule(rules))
            if self.metadata:
                self.metadata.extensions["validation_server_type"] = (
                    self.metadata.quirk_type
                )
            if server_violations and self.metadata:
                if self.metadata.validation_results is None:
                    self.metadata.validation_results = FlextLdifModelsDomainsEntries.ValidationMetadata.model_validate({
                        "rfc_violations": [],
                        "errors": [],
                        "warnings": [],
                        "context": {},
                        "server_specific_violations": [],
                        "validation_server_type": None,
                    })
                updated_validation_results = (
                    self.metadata.validation_results.model_copy(
                        update={
                            "server_specific_violations": server_violations,
                            "validation_server_type": self.metadata.quirk_type,
                        },
                    )
                )
                self.metadata.validation_results = updated_validation_results
                ext_violations: MutableSequence[t.Ldif.MetadataValue] = list(
                    server_violations,
                )
                self.metadata.extensions.server_specific_violations = ext_violations
            return self

        def _check_binary_option_rule(
            self,
            rules: FlextLdifModelsSettings.ServerValidationRules,
        ) -> MutableSequence[str]:
            """Check binary attribute option requirement from server rules."""
            violations: MutableSequence[str] = []
            if not rules.requires_binary_option or not self.attributes:
                return violations
            for attr_name, attr_values in self.attributes.items():
                if ";binary" in attr_name.lower():
                    continue
                for value in attr_values:
                    if any(
                        ord(char) < c.Ldif.ASCII_PRINTABLE_MIN
                        or ord(char) > c.Ldif.ASCII_PRINTABLE_MAX
                        for char in value
                    ):
                        violations.append(
                            f"Server requires ';binary' option for '{attr_name}'",
                        )
                        break
            return violations

        def _check_naming_attr_rule(
            self,
            rules: FlextLdifModelsSettings.ServerValidationRules,
            dn_value: str,
        ) -> MutableSequence[str]:
            """Check naming attribute requirement from server rules."""
            violations: MutableSequence[str] = []
            if not rules.requires_naming_attr or not dn_value or (not self.attributes):
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

        def _check_objectclass_rule(
            self,
            rules: FlextLdifModelsSettings.ServerValidationRules,
            dn_value: str,
        ) -> MutableSequence[str]:
            """Check objectClass requirement from server rules."""
            violations: MutableSequence[str] = []
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
            if not has_objectclass and (not is_schema_entry):
                violations.append("Server requires objectClass attribute")
            return violations

        def _validate_attribute_descriptions(self) -> MutableSequence[str]:
            """Validate attribute descriptions per RFC 4512 § 2.5.

            Note: self.attributes may be None when using model_construct (bypasses validation).
            """
            violations: MutableSequence[str] = []
            if self.attributes is None or not self.attributes:
                return violations
            for attr_desc in self.attributes.attributes:
                parts = attr_desc.split(";")
                base_attr = parts[0]
                if not _ATTR_NAME_PATTERN.match(base_attr):
                    violations.append(
                        f"RFC 4512 § 2.5: '{base_attr}' must start with letter"
                        if not base_attr or not base_attr[0].isalpha()
                        else f"RFC 4512 § 2.5: '{base_attr}' has invalid characters",
                    )
                for option in parts[1:]:
                    option = option.strip()
                    if not option:
                        continue
                    if not _ATTR_OPTION_PATTERN.match(option):
                        violations.append(
                            f"RFC 4512 § 2.5: option '{option}' must start with letter"
                            if not option or not option[0].isalpha()
                            else f"RFC 4512 § 2.5: option '{option}' has invalid characters",
                        )
            return violations

        def _validate_attribute_syntax(self) -> MutableSequence[str]:
            """Validate attribute name/option syntax per RFC 4512 § 2.5.1-2.5.2.

            Note: self.attributes may be None when using model_construct (bypasses validation).
            """
            violations: MutableSequence[str] = []
            if self.attributes is None or not self.attributes:
                return violations
            for attr_desc in self.attributes.attributes:
                parts = attr_desc.split(";")
                base_name = parts[0]
                if not _ATTR_NAME_PATTERN.match(base_name):
                    violations.append(f"RFC 4512 § 2.5.1: '{base_name}' invalid syntax")
                if len(parts) > 1:
                    invalid_options = [
                        f"RFC 4512 § 2.5.2: option '{option}' invalid syntax"
                        for option in parts[1:]
                        if option and (not _ATTR_NAME_PATTERN.match(option))
                    ]
                    violations.extend(invalid_options)
            return violations

        def _validate_attributes_required(self) -> MutableSequence[str]:
            """Validate that entry has at least one attribute per RFC 2849 § 2.

            Note: self.attributes may be None when using model_construct (bypasses validation).
            """
            violations: MutableSequence[str] = []
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

        def _validate_binary_options(self) -> MutableSequence[str]:
            """Validate binary attribute options per RFC 2849 § 5.2.

            Uses compiled regex for O(1)-per-match detection instead of
            Python char-by-char ord() loops.

            Note: self.attributes may be None when using model_construct (bypasses validation).
            """
            violations: MutableSequence[str] = []
            if self.attributes is None or not self.attributes:
                return violations
            for attr_name, attr_values in self.attributes.items():
                if ";binary" in attr_name.lower():
                    continue
                for value in attr_values:
                    if _BINARY_CHAR_PATTERN.search(value):
                        violations.append(
                            f"RFC 2849 § 5.2: '{attr_name}' may need ';binary' option",
                        )
                        break
            return violations

        def _validate_changetype(self) -> MutableSequence[str]:
            """Validate changetype field per RFC 2849 § 5.7."""
            violations: MutableSequence[str] = []
            if not self.changetype:
                return violations
            valid_changetypes = {"add", "delete", "modify", "moddn", "modrdn"}
            if str(self.changetype).lower() not in valid_changetypes:
                violations.append(
                    f"RFC 2849 § 5.7: changetype '{self.changetype}' invalid",
                )
            return violations

        def _validate_naming_attribute(self, dn_value: str) -> MutableSequence[str]:
            """Validate naming attribute presence per RFC 4512 § 2.3.

            Note: self.attributes may be None when using model_construct (bypasses validation).
            """
            violations: MutableSequence[str] = []
            if not dn_value or self.attributes is None or (not self.attributes):
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

        def _validate_objectclass(self, dn_value: str) -> MutableSequence[str]:
            """Validate objectClass presence per RFC 4512 § 2.4.1.

            Note: self.attributes may be None when using model_construct (bypasses validation).
            """
            violations: MutableSequence[str] = []
            is_schema_entry = dn_value.lower().startswith(
                "cn=schema",
            ) or dn_value.lower().startswith("cn=subschema")
            if self.attributes is None or is_schema_entry or (not self.attributes):
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

        @computed_field
        def has_validation_errors(self) -> bool:
            """Check if entry has validation errors.

            Returns:
            True if entry has validation errors in validation_metadata, False otherwise

            """
            if self.metadata is None:
                return False
            if self.metadata.validation_results is None:
                return False
            return bool(self.metadata.validation_results.errors)

        @computed_field
        def is_acl_entry(self) -> bool:
            """Check if entry has Access Control Lists.

            Returns:
            True if entry has ACLs, False otherwise

            """
            if self.metadata is None:
                return False
            return bool(self.metadata.acls)

        @computed_field
        def is_schema_entry(self) -> bool:
            """Check if entry is a schema definition entry.

            Schema entries contain objectClass definitions and are typically
            found in the schema naming context.

            Returns:
            True if entry has objectClasses, False otherwise

            """
            if self.metadata is None:
                return False
            return bool(self.metadata.objectclasses)

        @classmethod
        def _build_extension_kwargs(
            cls,
            server_type: c.Ldif.ServerTypeLiteral | None,
            source_entry: str | None,
            unconverted_attributes: FlextLdifModelsMetadata.DynamicMetadata | None,
        ) -> t.MutableContainerMapping:
            """Build extension kwargs for DynamicMetadata."""
            ext_kwargs: t.MutableContainerMapping = {}
            if server_type:
                ext_kwargs["server_type"] = server_type
            if source_entry:
                ext_kwargs["source_entry"] = source_entry
            if unconverted_attributes:
                unconverted_dump = unconverted_attributes.model_dump()
                unconverted_typed: t.NormalizedValue = unconverted_dump
                ext_kwargs["unconverted_attributes"] = unconverted_typed
            return ext_kwargs

        @classmethod
        def _build_metadata(
            cls,
            metadata: FlextLdifModelsDomainsEntries.QuirkMetadata | None,
            server_type: c.Ldif.ServerTypeLiteral | None,
            source_entry: str | None,
            unconverted_attributes: FlextLdifModelsMetadata.DynamicMetadata | None,
        ) -> FlextLdifModelsDomainsEntries.QuirkMetadata | None:
            """Build or update metadata with server-specific extensions."""
            has_new_metadata = server_type or source_entry or unconverted_attributes
            if metadata is None and has_new_metadata:
                ext_kwargs = cls._build_extension_kwargs(
                    server_type,
                    source_entry,
                    unconverted_attributes,
                )
                extensions = FlextLdifModelsMetadata.DynamicMetadata.from_dict(
                    ext_kwargs,
                )
                return FlextLdifModelsDomainsEntries.QuirkMetadata.model_validate({
                    "quirk_type": c.Ldif.ServerTypes.GENERIC,
                    "extensions": extensions,
                })
            if metadata is not None and has_new_metadata:
                cls._update_existing_metadata(
                    metadata,
                    server_type,
                    source_entry,
                    unconverted_attributes,
                )
            return metadata

        class _CreateEntryParams(m.Value):
            model_config: ClassVar[ConfigDict] = ConfigDict(
                extra="forbid",
                validate_assignment=True,
            )
            dn: str | FlextLdifModelsDomainsEntries.DN = Field(
                ...,
                description="Distinguished Name as string or DN object",
            )
            attributes: (
                t.MutableAttributeMapping | FlextLdifModelsDomainsEntries.Attributes
            ) = Field(
                ...,
                description="Entry attributes as dict or Attributes object",
            )
            metadata: FlextLdifModelsDomainsEntries.QuirkMetadata | None = Field(
                default=None,
                description="Quirk-specific metadata for the entry",
            )
            acls: MutableSequence[FlextLdifModelsDomainsEntries.Acl] | None = Field(
                default=None,
                description="Access Control Lists for the entry",
            )
            objectclasses: (
                MutableSequence[FlextLdifModelsDomainsEntries.SchemaObjectClass] | None
            ) = Field(
                default=None,
                description="Schema object class definitions",
            )
            attributes_schema: (
                MutableSequence[FlextLdifModelsDomainsEntries.SchemaAttribute] | None
            ) = Field(
                default=None,
                description="Schema attribute definitions",
            )
            entry_metadata: FlextLdifModelsMetadata.EntryMetadata | None = Field(
                default=None,
                description="Entry-level metadata for processing details",
            )
            validation_metadata: (
                FlextLdifModelsDomainsEntries.ValidationMetadata | None
            ) = Field(
                default=None,
                description="Validation results from entry processing",
            )
            server_type: c.Ldif.ServerTypeLiteral | None = Field(
                default=None,
                description="LDAP server type identifier",
            )
            source_entry: str | None = Field(
                default=None,
                description="Original LDIF source entry string",
            )
            unconverted_attributes: FlextLdifModelsMetadata.DynamicMetadata | None = (
                Field(
                    default=None,
                    description="Attributes preserved in original format",
                )
            )
            statistics: FlextLdifModelsDomainsEntries.EntryStatistics | None = Field(
                default=None,
                description="Entry processing statistics",
            )

        @classmethod
        def _create_entry(cls, params: _CreateEntryParams) -> r[Self]:
            """Internal method for Entry creation with composition fields.

            Args:
            params: Validated payload model containing entry fields and metadata

            Returns:
            r[Self] with Entry instance or validation error

            """
            try:
                dn_obj = FlextLdifModelsDomainsEntries.DN.from_value(params.dn)
                attrs_obj = cls._normalize_attributes(params.attributes)
                metadata = cls._build_metadata(
                    params.metadata,
                    params.server_type,
                    params.source_entry,
                    params.unconverted_attributes,
                )
                entry_data: MutableMapping[
                    str,
                    FlextLdifModelsDomainsEntries.DN
                    | FlextLdifModelsDomainsEntries.Attributes
                    | FlextLdifModelsDomainsEntries.QuirkMetadata
                    | MutableSequence[FlextLdifModelsDomainsEntries.Acl]
                    | MutableSequence[FlextLdifModelsDomainsEntries.SchemaObjectClass]
                    | MutableSequence[FlextLdifModelsDomainsEntries.SchemaAttribute]
                    | FlextLdifModelsMetadata.EntryMetadata
                    | FlextLdifModelsDomainsEntries.ValidationMetadata
                    | FlextLdifModelsDomainsEntries.EntryStatistics
                    | c.Ldif.ChangeTypeLiteral,
                ] = {c.Ldif.DictKeys.DN: dn_obj, c.Ldif.DictKeys.ATTRIBUTES: attrs_obj}
                if metadata is not None:
                    entry_data["metadata"] = metadata
                if params.acls is not None:
                    entry_data["acls"] = params.acls
                if params.objectclasses is not None:
                    entry_data["objectclasses"] = params.objectclasses
                if params.attributes_schema is not None:
                    entry_data["attributes_schema"] = params.attributes_schema
                if params.entry_metadata is not None:
                    entry_data["entry_metadata"] = params.entry_metadata
                if params.validation_metadata is not None:
                    entry_data["validation_metadata"] = params.validation_metadata
                if params.statistics is not None:
                    entry_data["statistics"] = params.statistics
                entry_instance = cls.model_validate(entry_data)
                ok_result: r[Self] = r(value=entry_instance, is_success=True)
                return ok_result
            except (ValueError, TypeError, AttributeError) as e:
                fail_result: r[Self] = r(
                    error=f"Failed to create Entry: {e}", is_success=False
                )
                return fail_result

        @classmethod
        def _normalize_attributes(
            cls,
            attributes: t.MutableAttributeMapping
            | FlextLdifModelsDomainsEntries.Attributes,
        ) -> FlextLdifModelsDomainsEntries.Attributes:
            """Normalize attributes to Attributes t.NormalizedValue.

            Args:
                attributes: Attributes as dict or Attributes t.NormalizedValue

            Returns:
                Attributes t.NormalizedValue with normalized values

            Note:
                Lenient processing: Empty attributes dict is accepted and will be captured
                in validation_metadata as RFC violation.

            """
            if isinstance(attributes, FlextLdifModelsDomainsEntries.Attributes):
                return attributes
            attrs_dict: t.MutableStrSequenceMapping = {}
            for attr_name, attr_values in attributes.items():
                if isinstance(attr_values, list):
                    values_list: MutableSequence[str] = [str(v) for v in attr_values]
                elif isinstance(attr_values, str):
                    values_list = [attr_values]
                else:
                    values_list = [str(attr_values)]
                attrs_dict[attr_name] = values_list
            return FlextLdifModelsDomainsEntries.Attributes.model_validate({
                "attributes": attrs_dict,
                "attribute_metadata": {},
                "metadata": None,
            })

        @classmethod
        def _update_existing_metadata(
            cls,
            metadata: FlextLdifModelsDomainsEntries.QuirkMetadata,
            server_type: c.Ldif.ServerTypeLiteral | None,
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
        def create(
            cls,
            dn: str | FlextLdifModelsDomainsEntries.DN,
            attributes: t.MutableAttributeMapping
            | FlextLdifModelsDomainsEntries.Attributes,
            metadata: FlextLdifModelsDomainsEntries.QuirkMetadata | None = None,
            acls: MutableSequence[FlextLdifModelsDomainsEntries.Acl] | None = None,
            objectclasses: MutableSequence[
                FlextLdifModelsDomainsEntries.SchemaObjectClass
            ]
            | None = None,
            attributes_schema: MutableSequence[
                FlextLdifModelsDomainsEntries.SchemaAttribute
            ]
            | None = None,
            entry_metadata: FlextLdifModelsMetadata.EntryMetadata | None = None,
            validation_metadata: FlextLdifModelsDomainsEntries.ValidationMetadata
            | None = None,
            server_type: c.Ldif.ServerTypeLiteral | None = None,
            source_entry: str | None = None,
            unconverted_attributes: FlextLdifModelsMetadata.DynamicMetadata
            | None = None,
            statistics: FlextLdifModelsDomainsEntries.EntryStatistics | None = None,
        ) -> r[Self]:
            params = cls._CreateEntryParams(
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
            return cls._create_entry(params=params)

        def get_attribute_values(self, attribute_name: str) -> MutableSequence[str]:
            """Get all values for a specific attribute.

            LDAP attribute names are case-insensitive.

            Args:
            attribute_name: Name of the attribute to retrieve

            Returns:
            List of attribute values, empty list if attribute doesn't exist

            """
            if self.attributes is None:
                return []
            attrs_dict = self.attributes.attributes
            if not attrs_dict:
                return []
            attr_name_lower = attribute_name.lower()
            for stored_name, attr_values in attrs_dict.items():
                if stored_name.lower() == attr_name_lower:
                    return attr_values
            return []

        def get_dn_components(self) -> MutableSequence[str]:
            """Get DN components (RDN parts) from the entry's DN.

            Returns:
            List of DN components (e.g., ["cn=REDACTED_LDAP_BIND_PASSWORD", "dc=example", "dc=com"])

            """
            if self.dn is None:
                return []
            return [comp.strip() for comp in self.dn.value.split(",") if comp.strip()]

        def get_entries(self) -> MutableSequence[Self]:
            """Get this entry as a list for unified protocol.

            Returns:
                List containing this entry

            """
            return [self]

        def get_objectclass_names(self) -> MutableSequence[str]:
            """Get list of objectClass attribute values from entry."""
            return self.get_attribute_values(c.Ldif.DictKeys.OBJECTCLASS)

        def has_attribute(self, attribute_name: str) -> bool:
            """Check if entry has a specific attribute.

            LDAP attribute names are case-insensitive.

            Args:
            attribute_name: Name of the attribute to check

            Returns:
            True if attribute exists with at least one value, False otherwise

            """
            return bool(self.get_attribute_values(attribute_name))

        def has_object_class(self, object_class: str) -> bool:
            """Check if entry has specified t.NormalizedValue class.

            Args:
            object_class: Name of the t.NormalizedValue class to check

            Returns:
            True if entry has the t.NormalizedValue class, False otherwise

            """
            return object_class in self.get_attribute_values(
                c.Ldif.DictKeys.OBJECTCLASS,
            )

        def matches_filter(
            self,
            filter_func: Callable[[FlextLdifModelsDomainsEntries.Entry], bool]
            | None = None,
        ) -> bool:
            """Check if entry matches a filter function.

            Convenience method for delegation to filters module.
            If no filter provided, returns True (entry matches).

            Args:
            filter_func: Optional callable that takes Entry and returns bool

            Returns:
            True if entry matches filter (or no filter provided), False otherwise

            """
            if filter_func is None:
                return True
            try:
                return bool(filter_func(self))
            except (
                ValueError,
                KeyError,
                AttributeError,
                UnicodeDecodeError,
                struct.error,
            ):
                return False

    class AttributeTransformation(m.FrozenModel):
        """Detailed tracking of attribute transformation operations.

        Records complete transformation history for LDIF attribute conversions,
        including original values, target values, transformation type, and reasoning.
        Essential for audit trails and troubleshooting server migrations.

        Attributes:
            original_name: Original attribute name from source server
            target_name: Transformed attribute name for target server (None if removed)
            original_values: List of original attribute values
            target_values: List of transformed values (None if removed)
            transformation_type: Type of transformation applied
            reason: Human-readable explanation of why transformation was needed

        Example:
            transform = AttributeTransformation(
                original_name="orclaci",
                target_name="aci",
                original_values=["(objectClass=*)(version 3.0...)"],
                target_values=["(objectClass=*)(version 3.0...)"],
                transformation_type="renamed",
                reason="OID proprietary format → RFC 2256 standard ACL"
            )

        """

        original_name: Annotated[
            str,
            Field(..., description="Original attribute name from source server"),
        ]
        target_name: Annotated[
            str | None,
            Field(
                description="Transformed attribute name (None if removed)",
            ),
        ] = None
        original_values: Annotated[
            MutableSequence[str],
            Field(
                description="Original attribute values from source",
            ),
        ]
        target_values: Annotated[
            MutableSequence[str] | None,
            Field(description="Transformed values (None if removed)"),
        ] = None
        transformation_type: Annotated[
            c.Ldif.TransformationTypeLiteral,
            Field(..., description="Type of transformation applied to the attribute"),
        ]
        reason: Annotated[
            str,
            Field(description="Human-readable reason for transformation"),
        ] = ""

    class DNStatistics(m.FrozenDynamicModel):
        """Statistics tracking for DN transformations and validation.

        Immutable value t.NormalizedValue capturing complete DN transformation history
        from original to normalized form. Preserves all metadata for
        round-trip server conversions and diagnostic purposes.

        All DN transformation operations should populate this model to
        maintain a complete audit trail.

        Inherits from m.BaseModel (flext-core):
        - model_config (frozen=True, validate_default=True, validate_assignment=True)
        - aggregate() classmethod (automatic statistics aggregation)
        """

        model_config: ClassVar[ConfigDict] = ConfigDict(extra="ignore")
        original_dn: Annotated[
            str,
            Field(..., description="Original DN as received from input"),
        ]
        cleaned_dn: Annotated[
            str,
            Field(..., description="DN after clean_dn() transformation"),
        ]
        normalized_dn: Annotated[
            str,
            Field(..., description="Final normalized DN (RFC 4514 compliant)"),
        ]
        transformations: Annotated[
            Sequence[str],
            Field(
                description="Ordered list of transformations applied (use TransformationType constants)",
            ),
        ]
        had_tab_chars: Annotated[
            bool,
            Field(description="DN contained TAB characters"),
        ] = False
        had_trailing_spaces: Annotated[
            bool,
            Field(description="DN had trailing spaces"),
        ] = False
        had_leading_spaces: Annotated[
            bool,
            Field(description="DN had leading spaces"),
        ] = False
        had_extra_spaces: Annotated[
            bool,
            Field(description="DN had multiple consecutive spaces"),
        ] = False
        was_base64_encoded: Annotated[
            bool,
            Field(description="DN was base64 encoded in LDIF (dn::)"),
        ] = False
        had_utf8_chars: Annotated[
            bool,
            Field(
                description="DN contained UTF-8 multi-byte characters",
            ),
        ] = False
        had_escape_sequences: Annotated[
            bool,
            Field(description="DN contained LDAP escape sequences"),
        ] = False
        validation_status: Annotated[
            str,
            Field(
                description="Validation status (use ValidationStatus constants)",
            ),
        ] = "valid"
        validation_warnings: Annotated[
            Sequence[str],
            Field(description="Non-fatal validation warnings"),
        ]
        validation_errors: Annotated[
            Sequence[str],
            Field(description="Fatal validation errors"),
        ]

        @computed_field
        def has_errors(self) -> bool:
            """Check if any validation errors exist."""
            return bool(self.validation_errors)

        @computed_field
        def has_warnings(self) -> bool:
            """Check if any validation warnings exist."""
            return bool(self.validation_warnings)

        @computed_field
        def transformation_count(self) -> int:
            """Count of unique transformations applied."""
            return len(self.transformations)

        @computed_field
        def was_transformed(self) -> bool:
            """Check if any transformations were applied."""
            return self.original_dn != self.normalized_dn or bool(self.transformations)

        @classmethod
        def create_minimal(cls, dn: str) -> Self:
            """Create minimal statistics for unchanged DN."""
            return cls.model_validate({
                "original_dn": dn,
                "cleaned_dn": dn,
                "normalized_dn": dn,
            })

        @field_validator("transformations", mode="after")
        @classmethod
        def deduplicate_transformations(
            cls,
            v: MutableSequence[str],
        ) -> MutableSequence[str]:
            """Remove duplicate transformations while preserving order."""
            seen: set[str] = set()
            result: MutableSequence[str] = []
            for item in v:
                if item not in seen:
                    seen.add(item)
                    result.append(item)
            return result

    class EntryStatistics(m.FrozenDynamicModel):
        """Statistics tracking for entry-level transformations and validation.

        Tracks complete entry lifecycle from parsing through validation,
        transformation, filtering, and output. Captures all attribute
        modifications, quirk applications, and rejection reasons.

        Designed for aggregation across large LDIF files to provide
        comprehensive migration diagnostics.

        Inherits from m.BaseModel (flext-core):
        - model_config (frozen=True, validate_default=True, validate_assignment=True)
        - aggregate() classmethod (automatic statistics aggregation)
        """

        model_config: ClassVar[ConfigDict] = ConfigDict(extra="ignore")
        was_parsed: Annotated[
            bool,
            Field(description="Entry was successfully parsed from LDIF"),
        ] = True
        was_validated: Annotated[
            bool,
            Field(description="Entry passed validation checks"),
        ] = False
        was_filtered: Annotated[
            bool,
            Field(
                description="Entry was filtered by rules (base DN, schema, etc.)",
            ),
        ] = False
        was_written: Annotated[
            bool,
            Field(description="Entry was written to output LDIF"),
        ] = False
        was_rejected: Annotated[
            bool,
            Field(description="Entry was rejected during processing"),
        ] = False
        rejection_category: Annotated[
            str | None,
            Field(
                description="Rejection category (use RejectionCategory constants)",
            ),
        ] = None
        rejection_reason: Annotated[
            str | None,
            Field(description="Human-readable rejection reason"),
        ] = None
        attributes_added: Annotated[
            MutableSequence[str],
            Field(
                description="Attribute names added during processing",
            ),
        ]
        attributes_removed: Annotated[
            MutableSequence[str],
            Field(
                description="Attribute names removed during processing",
            ),
        ]
        attributes_modified: Annotated[
            MutableSequence[str],
            Field(
                description="Attribute names modified during processing",
            ),
        ]
        attributes_filtered: Annotated[
            MutableSequence[str],
            Field(
                description="Attribute names filtered by whitelist/blacklist",
            ),
        ]
        objectclasses_original: Annotated[
            MutableSequence[str],
            Field(description="Original objectClass values"),
        ]
        objectclasses_final: Annotated[
            MutableSequence[str],
            Field(
                description="Final objectClass values after transformation",
            ),
        ]
        quirks_applied: Annotated[
            MutableSequence[str],
            Field(
                description="List of quirk types applied to this entry",
            ),
        ]
        quirk_transformations: Annotated[
            int,
            Field(description="Count of quirk transformations applied"),
        ] = 0
        dn_statistics: FlextLdifModelsDomainsEntries.DNStatistics | None = Field(
            default=None, description="DN transformation statistics (if applicable)"
        )
        filters_applied: Annotated[
            MutableSequence[str],
            Field(
                description="List of filters applied (use FilterType constants)",
            ),
        ]
        filter_results: Annotated[
            t.MutableBoolMapping,
            Field(
                description="Filter results: {filter_name: passed}",
            ),
        ]
        errors: Annotated[
            MutableSequence[str],
            Field(
                description="Error messages (use ErrorCategory constants for keys)",
            ),
        ]
        warnings: Annotated[
            MutableSequence[str],
            Field(description="Warning messages"),
        ]
        category_assigned: Annotated[
            str | None,
            Field(
                description="Category assigned (schema, hierarchy, users, groups, acl)",
            ),
        ] = None
        category_confidence: Annotated[
            float,
            Field(
                ge=0.0,
                le=1.0,
                description="Confidence score for category assignment",
            ),
        ] = 1.0

        @computed_field
        def dn_was_transformed(self) -> bool:
            """Check if DN underwent transformation."""
            if self.dn_statistics is None:
                return False
            return bool(self.dn_statistics.was_transformed)

        @computed_field
        def had_errors(self) -> bool:
            """Check if any errors occurred."""
            return bool(self.errors)

        @computed_field
        def had_warnings(self) -> bool:
            """Check if any warnings occurred."""
            return bool(self.warnings)

        @computed_field
        def objectclasses_changed(self) -> bool:
            """Check if objectClass values changed."""
            return set(self.objectclasses_original) != set(self.objectclasses_final)

        @computed_field
        def total_attribute_changes(self) -> int:
            """Total count of attribute modifications."""
            return (
                len(self.attributes_added)
                + len(self.attributes_removed)
                + len(self.attributes_modified)
            )

        @classmethod
        def create_minimal(cls) -> Self:
            """Create minimal statistics for newly parsed entry."""
            return cls.model_validate({"was_parsed": True})

        @field_validator("filters_applied", mode="after")
        @classmethod
        def deduplicate_filters(cls, v: MutableSequence[str]) -> MutableSequence[str]:
            """Remove duplicate filters while preserving order."""
            seen: set[str] = set()
            result: MutableSequence[str] = []
            for item in v:
                if item not in seen:
                    seen.add(item)
                    result.append(item)
            return result

        @field_validator("quirks_applied", mode="after")
        @classmethod
        def deduplicate_quirks(cls, v: MutableSequence[str]) -> MutableSequence[str]:
            """Remove duplicate quirks while preserving order."""
            seen: set[str] = set()
            result: MutableSequence[str] = []
            for item in v:
                if item not in seen:
                    seen.add(item)
                    result.append(item)
            return result

        def add_error(self, error: str) -> Self:
            """Add error message.

            Returns new instance with error added (frozen model).
            """
            errors = [*self.errors, error]
            return self.model_copy(update={"errors": errors})

        def add_warning(self, warning: str) -> Self:
            """Add warning message.

            Returns new instance with warning added (frozen model).
            """
            warnings = [*self.warnings, warning]
            return self.model_copy(update={"warnings": warnings})

        def mark_filtered(self, filter_type: str, *, passed: bool) -> Self:
            """Mark entry as filtered with result.

            Args:
                filter_type: Type of filter applied
                passed: Whether entry passed the filter (keyword-only)

            Returns new instance with updated filter state (frozen model).

            """
            filters_applied = [*self.filters_applied, filter_type]
            filter_results = {**self.filter_results, filter_type: passed}
            return self.model_copy(
                update={
                    "was_filtered": True,
                    "filters_applied": filters_applied,
                    "filter_results": filter_results,
                },
            )

        def mark_rejected(self, category: str, reason: str) -> Self:
            """Mark entry as rejected.

            Returns new instance with rejection details (frozen model).
            """
            return self.model_copy(
                update={
                    "was_rejected": True,
                    "rejection_category": category,
                    "rejection_reason": reason,
                },
            )

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
            str, FlextLdifModelsDomainsEntries.AttributeTransformation
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
        validation_results: FlextLdifModelsDomainsEntries.ValidationMetadata | None = (
            Field(
                default=None,
                description="Validation results with RFC violations, errors, warnings, and context",
            )
        )
        processing_stats: FlextLdifModelsDomainsEntries.EntryStatistics | None = Field(
            default=None,
            description="Complete statistics tracking for entry transformations",
        )
        write_options: FlextLdifModelsDomainsEntries.WriteOptions | None = Field(
            default=None,
            description="Writer configuration including format, base DN, hidden attributes, sorting, and comments",
        )
        removed_attributes: Annotated[
            FlextLdifModelsMetadata.DynamicMetadata,
            Field(
                description="Attributes removed during conversion (was entry_metadata.removed_attributes_with_values)",
            ),
        ] = Field(default_factory=FlextLdifModelsMetadata.DynamicMetadata)
        original_format_details: FlextLdifModelsDomainsEntries.FormatDetails | None = (
            Field(
                default=None,
                description="Original formatting details for round-trip preservation (DN line, syntax, encoding, spacing)",
            )
        )
        schema_format_details: (
            FlextLdifModelsDomainsEntries.SchemaFormatDetails | None
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
        ] = Field(default_factory=_empty_conversion_history_factory)

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
            | t.MutableContainerMapping
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


__all__ = ["FlextLdifModelsDomainsEntries"]
