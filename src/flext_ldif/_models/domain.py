"""Domain models for LDIF entities.

This module contains core domain models for LDIF processing including
Distinguished Names, Entries, and Schema elements.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import re
from collections.abc import Callable, KeysView, Mapping, Sequence, ValuesView
from contextlib import suppress
from datetime import datetime
from typing import ClassVar, Self, TypedDict, Unpack, cast

from flext_core import (
    FlextLogger,
    FlextResult,
    FlextUtilities,
    t,
)
from flext_core._models.base import FlextModelsBase
from flext_core._models.entity import FlextModelsEntity
from flext_core.models import m  # Import FlextModels as m
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
    SchemaElement,
)
from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif._models.validation import ServerValidationRules
from flext_ldif._shared import normalize_server_type
from flext_ldif.constants import c
from flext_ldif.protocols import p

# Type aliases for clarity
# Access types directly via composition - no aliases needed

u = FlextUtilities

logger = FlextLogger(__name__)


class FlextLdifModelsDomains:
    """LDIF domain models container class.

    This class acts as a namespace container for core LDIF domain models.
    All nested classes are accessed via m.* in the main models.py.
    """

    # =========================================================================
    # DOMAIN MODELS - Core LDIF entities
    # =========================================================================

    class DN(m.Value):
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
            description="DN string value (lenient processing - no max_length)",
            # max_length removed for lenient processing - validation at Entry level
        )
        metadata: FlextLdifModelsMetadata.EntryMetadata = Field(
            default_factory=FlextLdifModelsMetadata.EntryMetadata,
            description="Quirk-specific metadata for preserving original format",
        )

        _DN_COMPONENT_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
            r"^[a-zA-Z][a-zA-Z0-9-]*=(?:[^\\,]|\\.)*$",
            re.IGNORECASE,
        )

        # NOTE: DN validation moved to Entry.validate_entry_rfc_compliance()
        # DN is a frozen Value Object and cannot be modified
        # after construction

        @property
        def components(self) -> list[str]:
            """Parse DN into individual RDN components.

            Returns:
                List of RDN components (e.g., ['cn=test', 'ou=users', ...])

            Note:
                Using @property instead of @computed_field to avoid
                serialization issues with extra="forbid" on round-trips.

            """
            if not self.value:
                return []

            # Split by comma and clean up whitespace
            raw_components = [comp.strip() for comp in self.value.split(",")]
            # Filter out empty components
            return [comp for comp in raw_components if comp]

        @property
        def was_base64_encoded(self) -> bool:
            """Check if DN was originally base64-encoded per RFC 2849.

            Uses metadata to track if DN had :: indicator in original LDIF.
            Useful for round-trip conversions between servers (OID → OUD).

            Returns:
                True if DN was base64-encoded in source LDIF, False otherwise

            Example:
                # DN with UTF-8 characters in LDIF:
                dn:: Y249am9zw6ksZGM9ZXhhbXBsZSxkYz1jb20=
                # Decoded to: cn=josé,dc=example,dc=com
                # entry.dn

            """
            if not self.metadata:
                return False
            return getattr(self.metadata, "original_format", None) == "base64"

        def create_statistics(
            self,
            original_dn: str | None = None,
            cleaned_dn: str | None = None,
            transformations: list[str] | None = None,
            **transformation_flags: Unpack[FlextLdifModelsDomains.DNStatisticsFlags],
        ) -> FlextLdifModelsDomains.DNStatistics:
            """Create DNStatistics for this DN with transformation history.

            Helper method for creating complete statistics from DN metadata.
            Uses metadata to populate transformation flags automatically.

            Args:
                original_dn: Original DN before transformations (defaults to self.value)
                cleaned_dn: DN after clean_dn() (defaults to self.value)
                transformations: List of transformation types applied
                **transformation_flags: Additional transformation flags

            Returns:
                DNStatistics instance tracking transformation history

            Example:
                dn = DN(value="cn=test,dc=example,dc=com")
                stats = dn.create_statistics(
                    original_dn="cn=test  ,dc=example,dc=com",
                    transformations=[c.Ldif.TransformationType.SPACE_CLEANED],
                    had_extra_spaces=True,
                )

            """
            # Default to current value if not provided
            final_dn = self.value
            orig_dn = original_dn or final_dn
            clean_dn = cleaned_dn or final_dn

            # Extract flags from metadata if available
            flags = transformation_flags.copy()
            if self.metadata:
                if self.was_base64_encoded:
                    _ = flags.setdefault("was_base64_encoded", True)
                if getattr(self.metadata, "had_utf8_chars", False):
                    _ = flags.setdefault("had_utf8_chars", True)
                if getattr(self.metadata, "had_escape_sequences", False):
                    _ = flags.setdefault("had_escape_sequences", True)

            return FlextLdifModelsDomains.DNStatistics.create_with_transformation(
                original_dn=orig_dn,
                cleaned_dn=clean_dn,
                normalized_dn=final_dn,
                transformations=transformations if transformations is not None else [],
                **flags,
            )

        @classmethod
        def from_value(cls, dn: str | Self | None) -> Self:
            """Create DN from string or existing instance.

            Factory method that normalizes DN input to DN object.
            Uses Self for proper facade compatibility (models.py exposure).

            Args:
                dn: DN as string or DN object

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

            if isinstance(dn, str):
                return cls(value=dn)

            return dn

        def __str__(self) -> str:
            """Return DN value as string for str() conversion."""
            return self.value

    class ExclusionInfo(FlextModelsBase.ArbitraryTypesModel):
        """Metadata for excluded entries/schema items.

        Stored in QuirkMetadata.extensions['exclusion_info'] to track why
        an entry was excluded during filtering operations.

        Example:
            exclusion = ExclusionInfo(
                excluded=True,
                exclusion_reason="DN outside base context",
                filter_criteria=FilterCriteria(
                    filter_type="dn_pattern", pattern="*,dc=old,dc=com"
                ),
                timestamp="2025-10-09T12:34:56Z"
            )

        """

        excluded: bool = Field(
            default=False,
            description="Whether the item is excluded",
        )
        exclusion_reason: str | None = Field(
            default=None,
            description="Human-readable reason for exclusion",
        )
        filter_criteria: str | None = Field(  # Filter criteria as string
            default=None,
            description="Filter criteria that caused the exclusion",
        )
        timestamp: str = Field(
            ...,
            description="ISO 8601 timestamp when exclusion was marked",
        )

    class SchemaAttribute(SchemaElement):
        """LDAP schema attribute definition model (RFC 4512 compliant).

        Represents an LDAP attribute type definition from schema with full
        RFC 4512 support.

        Inherits from SchemaElement:
        - model_config (strict=True, validate_default=True, validate_assignment=True)
        - has_metadata computed field
        - server_type computed field
        - has_server_extensions computed field
        """

        name: str = Field(..., description="Attribute name")
        oid: str = Field(..., description="Attribute OID")
        desc: str | None = Field(
            default=None,
            description="Attribute description (RFC 4512 DESC)",
        )
        sup: str | None = Field(
            default=None,
            description="Superior attribute type (RFC 4512 SUP)",
        )
        equality: str | None = Field(
            default=None,
            description="Equality matching rule (RFC 4512 EQUALITY)",
        )
        ordering: str | None = Field(
            default=None,
            description="Ordering matching rule (RFC 4512 ORDERING)",
        )
        substr: str | None = Field(
            default=None,
            description="Substring matching rule (RFC 4512 SUBSTR)",
        )
        syntax: str | None = Field(
            default=None,
            description="Attribute syntax OID (RFC 4512 SYNTAX)",
        )
        length: int | None = Field(
            default=None,
            description="Maximum length constraint",
        )
        usage: str | None = Field(
            default=None,
            description="Attribute usage (RFC 4512 USAGE)",
        )
        single_value: bool = Field(
            default=False,
            description="Whether attribute is single-valued (RFC 4512 SINGLE-VALUE)",
        )
        collective: bool = Field(
            default=False,
            description="Whether attribute is collective (RFC 4512 COLLECTIVE)",
        )
        no_user_modification: bool = Field(
            default=False,
            description=(
                "Whether users can modify this attribute "
                "(RFC 4512 NO-USER-MODIFICATION)"
            ),
        )
        # OUD and server-specific fields
        immutable: bool = Field(
            default=False,
            description="Whether attribute is immutable (OUD extension)",
        )
        user_modification: bool = Field(
            default=True,
            description="Whether users can modify this attribute (OUD extension)",
        )
        obsolete: bool = Field(
            default=False,
            description="Whether attribute is obsolete (OUD extension)",
        )
        x_origin: str | None = Field(
            default=None,
            description=(
                "Origin of attribute definition (server-specific X-ORIGIN extension)"
            ),
        )
        x_file_ref: str | None = Field(
            default=None,
            description=(
                "File reference for attribute definition "
                "(server-specific X-FILE-REF extension)"
            ),
        )
        x_name: str | None = Field(
            default=None,
            description=(
                "Extended name for attribute (server-specific X-NAME extension)"
            ),
        )
        x_alias: str | None = Field(
            default=None,
            description=(
                "Extended alias for attribute (server-specific X-ALIAS extension)"
            ),
        )
        x_oid: str | None = Field(
            default=None,
            description="Extended OID for attribute (server-specific X-OID extension)",
        )
        metadata: FlextLdifModelsDomains.QuirkMetadata | None = Field(
            default=None,
            description="Quirk-specific metadata",
        )

        @computed_field
        def has_matching_rules(self) -> bool:
            """Check if attribute has any matching rules defined."""
            return bool(self.equality or self.ordering or self.substr)

        @computed_field
        def syntax_definition(self) -> FlextLdifModelsDomains.Syntax | None:
            """Resolve syntax OID to complete Syntax model using RFC 4517 validation.

            Returns:
                Resolved Syntax model with RFC 4517 compliance details, or None if:
                - syntax field is None or empty
                - syntax OID validation fails
                - syntax resolution fails

            """
            if not self.syntax:
                return None
            # Return internal domain type - public layer will wrap if needed
            return FlextLdifModelsDomains.Syntax.resolve_syntax_oid(
                self.syntax,
                server_type="rfc",
            )

    class Syntax(SchemaElement):
        """LDAP attribute syntax definition model (RFC 4517 compliant).

        Represents an LDAP attribute syntax OID and its validation rules per RFC 4517.

        Inherits from SchemaElement:
        - model_config (strict=True, validate_default=True, validate_assignment=True)
        - has_metadata computed field
        - server_type computed field
        - has_server_extensions computed field
        """

        oid: str = Field(
            ...,
            description="Syntax OID (RFC 4517, format: 1.3.6.1.4.1.1466.115.121.1.X)",
        )
        name: str | None = Field(
            None,
            description="Human-readable syntax name (e.g., 'Boolean', 'Integer')",
        )
        desc: str | None = Field(
            None,
            description="Syntax description and purpose",
        )
        type_category: str = Field(
            default="string",
            description="Syntax type category: string, integer, binary, dn, time, boolean",
        )
        is_binary: bool = Field(
            default=False,
            description="Whether this syntax uses binary encoding",
        )
        max_length: int | None = Field(
            None,
            description="Maximum length in bytes (if applicable)",
        )
        case_insensitive: bool = Field(
            default=False,
            description="Whether comparisons are case-insensitive",
        )
        allows_multivalued: bool = Field(
            default=True,
            description="Whether attributes using this syntax can be multivalued",
        )
        encoding: c.Ldif.LiteralTypes.EncodingLiteral = Field(
            default="utf-8",
            description="Expected character encoding (utf-8, ascii, iso-8859-1, etc.)",
        )
        validation_pattern: str | None = Field(
            None,
            description="Optional regex pattern for value validation",
        )
        metadata: FlextLdifModelsDomains.QuirkMetadata | None = Field(
            default=None,
            description="Server-specific quirk metadata",
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
            # Compute directly instead of accessing is_rfc4517_standard property
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
            # Handle missing syntax
            if not oid or not oid.strip():
                return None

            try:
                # RFC 4512 § 1.4: OID format = digit 1*( '.' digit )
                # Validate OID format before attempting resolution
                oid_pattern = re.compile(r"^\d+(\.\d+)*$")
                if not oid_pattern.match(oid):
                    # Invalid OID format - return None per RFC 4512
                    return None
                # Build lookup tables
                oid_to_name = dict(c.Ldif.RfcSyntaxOids.OID_TO_NAME)

                # Look up name from OID
                name = oid_to_name.get(oid)
                type_category = (
                    c.Ldif.RfcSyntaxOids.NAME_TO_TYPE_CATEGORY.get(
                        name,
                        "string",
                    )
                    if name
                    else "string"
                )

                # Create metadata for server-specific handling
                # QuirkMetadata initializes extensions with default DynamicMetadata
                metadata = (
                    FlextLdifModelsDomains.QuirkMetadata(
                        quirk_type=server_type,
                    )
                    if server_type != c.Ldif.ServerTypes.RFC.value
                    else None
                )

                # Create and validate Syntax model
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
                # Return None for any resolution errors
                # This prevents the model from being invalid due to service failures
                return None

    class SchemaObjectClass(SchemaElement):
        """LDAP schema object class definition model (RFC 4512 compliant).

        Represents an LDAP object class definition from schema with full
        RFC 4512 support.

        Inherits from SchemaElement:
        - model_config (strict=True, validate_default=True, validate_assignment=True)
        - has_metadata computed field
        - server_type computed field
        - has_server_extensions computed field
        """

        name: str = Field(..., description="Object class name")
        oid: str = Field(..., description="Object class OID")
        desc: str | None = Field(
            default=None,
            description="Object class description (RFC 4512 DESC)",
        )
        sup: str | (list[str] | None) = Field(
            default=None,
            description="Superior object class(es) (RFC 4512 SUP)",
        )
        kind: str = Field(
            default="STRUCTURAL",
            description="Object class kind (RFC 4512: STRUCTURAL, AUXILIARY, ABSTRACT)",
        )
        must: list[str] | None = Field(
            default=None,
            description="Required attributes (RFC 4512 MUST)",
        )
        may: list[str] | None = Field(
            default=None,
            description="Optional attributes (RFC 4512 MAY)",
        )
        metadata: FlextLdifModelsDomains.QuirkMetadata | None = Field(
            default=None,
            description="Quirk-specific metadata",
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
            description="Attribute name to values list",
        )
        attribute_metadata: dict[str, dict[str, str | list[str]]] = Field(
            default_factory=dict,
            description="Metadata for each attribute, like category or hidden status.",
        )
        metadata: FlextLdifModelsMetadata.EntryMetadata | None = Field(
            default=None,
            description="Metadata for preserving ordering and formats",
        )

        # NOTE: Attribute name validation moved to Entry.validate_entry_rfc_compliance()
        # Attributes uses validate_assignment=True for mutable dict-like operations

        def __len__(self) -> int:
            """Return the number of attributes."""
            return len(self.attributes)

        def __getitem__(self, key: str) -> list[str]:
            """Get attribute values by name (case-sensitive LDAP).

            Args:
                key: Attribute name

            Returns:
                List of attribute values

            Raises:
                KeyError if attribute not found

            """
            return self.attributes[key]

        def __setitem__(self, key: str, value: list[str]) -> None:
            """Set attribute values by name.

            Args:
                key: Attribute name
                value: List of values

            """
            self.attributes[key] = value

        def __contains__(self, key: str) -> bool:
            """Check if attribute exists."""
            return key in self.attributes

        # NOTE: __iter__ method REMOVED - was incompatible with BaseModel type signature
        # Use: entry.attributes.keys() for iteration over attribute names
        # Use: entry.model_dump() for Pydantic default iteration behavior

        def get(self, key: str, default: list[str] | None = None) -> list[str]:
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
            # Return empty list by default (lenient processing)
            return []

        def get_values(self, key: str, default: list[str] | None = None) -> list[str]:
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

        def iter_attributes(self) -> list[str]:
            """Get list of all attribute names.

            Returns:
                List of attribute names

            """
            return list(self.attributes.keys())

        def items(self) -> list[tuple[str, list[str]]]:
            """Get attribute name-values pairs.

            Returns:
                List of (name, values) tuples

            """
            return list(self.attributes.items())

        def keys(self) -> KeysView[str]:
            """Get attribute names."""
            return self.attributes.keys()

        def values(self) -> ValuesView[list[str]]:
            """Get attribute values lists."""
            return self.attributes.values()

        def add_attribute(self, key: str, values: str | list[str]) -> Self:
            """Add or update an attribute with values.

            Args:
                key: Attribute name
                values: Single value or list of values

            Returns:
                Self for method chaining

            """
            if isinstance(values, str):
                values = [values]
            elif isinstance(values, (bytes, bytearray)):
                # Convert bytes to string for LDIF compatibility
                if isinstance(values, (bytes, bytearray)):
                    values = [values.decode("utf-8", errors="replace")]
                else:
                    values = [str(values)]
            self.attributes[key] = values
            return self

        def remove_attribute(self, key: str) -> Self:
            """Remove an attribute if it exists.

            Args:
                key: Attribute name

            Returns:
                Self for method chaining

            """
            _ = self.attributes.pop(key, None)
            return self

        def to_ldap3(
            self,
            exclude: list[str] | None = None,
        ) -> dict[str, list[str]]:
            """Convert to ldap3-compatible attributes dict.

            Args:
                exclude: List of attribute names to exclude from output

            Returns:
                Dict compatible with ldap3 library format

            """
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
            """Create an Attributes instance from data.

            Args:
                attrs_data: Mapping of attribute names to values
                (str, list[str], bytes, list[bytes], int, float, bool, or None)

            Returns:
                FlextResult with Attributes instance or error

            """
            try:
                # Normalize values to list[str]
                normalized_dict: dict[str, list[str]] = {}
                for key, val in attrs_data.items():
                    if isinstance(val, list):
                        # Type guard: val is list-like, so it's iterable
                        normalized_dict[key] = [str(v) for v in val]
                    elif isinstance(val, str):
                        normalized_dict[key] = [val]
                    else:
                        normalized_dict[key] = [str(val)]

                # normalized_dict already has correct type dict[str, list[str]]
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
            """Mark attribute as soft-deleted with audit trail.

            HIGH COMPLEXITY: Uses UTC timestamp, tracks deletion metadata,
            preserves original values for compliance/rollback.

            Uses existing attribute_metadata dict to track deletion.
            Attribute stays in self.attributes but is marked.

            Args:
                attribute_name: Name of attribute to mark deleted
                reason: Reason for deletion (e.g., "migration", "obsolete")
                deleted_by: Server/quirk that deleted it (e.g., "oid", "oud")

            Raises:
                ValueError: If attribute not found in attributes

            """
            if attribute_name not in self.attributes:
                msg = f"Attribute '{attribute_name}' not found in attributes"
                raise ValueError(msg)

            def _to_str(value: str) -> str:
                """Convert str to str, handling byte representation if necessary."""
                return value

            # Store metadata as typed dict
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
            """Get only active attributes (exclude deleted/hidden).

            MEDIUM COMPLEXITY: Filters attributes based on metadata status,
            handles missing metadata gracefully.

            Returns:
                Dict of attribute_name -> values for active attributes only

            """

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
            """Get soft-deleted attributes with their metadata.

            MEDIUM COMPLEXITY: Returns deleted attributes with full audit trail
            (timestamp, reason, original values) for reconciliation.

            Returns:
                Dict of attribute_name -> metadata_dict for deleted attributes

            """
            if not self.attribute_metadata:
                return {}

            return {
                name: meta
                for name, meta in self.attribute_metadata.items()
                if meta.get("status") == "deleted"
            }

    class ErrorDetail(m.Value):
        """Error detail information for failed operations."""

        model_config = ConfigDict(
            strict=True,
            frozen=True,
            extra="forbid",
            validate_default=True,
            use_enum_values=True,
            str_strip_whitespace=True,
        )

        item: str = Field(..., description="Item that failed")
        error: str = Field(..., description="Error message")
        error_code: str | None = Field(default=None, description="Error code")
        context: FlextLdifModelsMetadata.DynamicMetadata = Field(
            default_factory=FlextLdifModelsMetadata.DynamicMetadata,
            description="Context",
        )

    class NormalizedEntryData(FlextLdifModelsBase):
        """BaseModel for entry data with normalized DN references.

        Represents entry attributes and fields after DN normalization.
        Used as return type for DN normalization operations.
        Allows arbitrary additional fields via extra="allow".
        """

        model_config = ConfigDict(
            frozen=True,
            extra="forbid",
            use_enum_values=True,
            str_strip_whitespace=True,
        )

        # No required fields - all fields are dynamically set

    class DnRegistry(FlextLdifModelsBase):
        """Registry for tracking canonical DN case during conversions.

        This class maintains a mapping of DNs in normalized form (lowercase, no spaces)
        to their canonical case representation. Used during server conversions to
        ensure DN case consistency.

        Examples:
            registry = FlextLdifModelsDomains.DnRegistry()
            canonical = registry.register_dn("CN=Admin,DC=Example,DC=Com")
            result = registry.get_canonical_dn("cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")

        """

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
            # Simple normalization: lowercase + remove spaces
            return dn.lower().replace(" ", "")

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
                self._case_variants[normalized] = set()
            self._case_variants[normalized].add(dn)

            if normalized not in self._registry or force:
                self._registry[normalized] = dn

            value = self._registry[normalized]
            if isinstance(value, str):
                return value
            return dn

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

        def has_dn(self, dn: str) -> bool:
            """Check if DN is registered (case-insensitive).

            Args:
                dn: Distinguished Name to check

            Returns:
                True if DN is registered, False otherwise

            """
            normalized = self._normalize_dn(dn)
            return normalized in self._registry

        def get_case_variants(self, dn: str) -> set[str]:
            """Get all case variants seen for a DN.

            Args:
                dn: Distinguished Name to get variants for

            Returns:
                Set of all case variants seen (including canonical)

            """
            normalized = self._normalize_dn(dn)
            return self._case_variants.get(normalized, set())

        def validate_oud_consistency(self) -> FlextResult[bool]:
            """Validate DN case consistency for server conversion.

            Returns:
                FlextResult[bool]: True if consistent, False with warnings if not

            """
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
                # Return False with warning (metadata not supported in FlextResult)
                return FlextResult[bool].ok(False)

            return FlextResult[bool].ok(True)

        def normalize_dn_references(
            self,
            data: dict[str, str | list[str] | dict[str, str]],
            dn_fields: list[str] | None = None,
        ) -> FlextResult[dict[str, str | list[str] | dict[str, str]]]:
            """Normalize DN references in data object to canonical case.

            Args:
                data: Dictionary containing DN references
                dn_fields: List of field names containing DNs or DN lists.
                          If None, uses default DN fields from c.

            Returns:
                FlextResult with normalized data dict

            """
            try:
                # Use default DN-valued attributes if dn_fields not specified
                if dn_fields is None:
                    # Include 'dn' itself plus all DN-valued attributes
                    dn_fields = ["dn"] + list(
                        c.Ldif.DnValuedAttributes.ALL_DN_VALUED,
                    )

                normalized_data = dict(data)

                for field_name in dn_fields:
                    if field_name not in normalized_data:
                        continue

                    field_value = normalized_data[field_name]

                    # Delegate to helper based on type
                    if isinstance(field_value, str):
                        normalized_data[field_name] = self._normalize_single_dn(
                            field_value,
                        )
                    elif isinstance(field_value, list):
                        # Type guard: field_value is list-like, so it's a list
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
            """Normalize a single DN string to canonical case.

            Args:
                dn: DN string to normalize

            Returns:
                Normalized DN string

            """
            canonical = self.get_canonical_dn(dn)
            if canonical:
                return canonical
            # Not registered, use internal _normalize_dn (no circular dependencies)
            return self._normalize_dn(dn)

        def _normalize_dn_list(self, dn_list: list[str]) -> list[str]:
            """Normalize a list of DN values.

            Args:
                dn_list: List of DN strings

            Returns:
                List with DN strings normalized

            """
            return [self._normalize_single_dn(item) for item in dn_list]

        def clear(self) -> None:
            """Clear all DN registrations."""
            self._registry.clear()
            self._case_variants.clear()

        def get_stats(self) -> dict[str, int]:
            """Get registry statistics.

            Returns:
                Dictionary with registry statistics

            """
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

    class QuirkCollection(m.Value):
        """Collection of all quirks (Schema, ACL, Entry) for a single server type.

        Stores all three quirk types together for unified access and management.
        """

        model_config = ConfigDict(
            arbitrary_types_allowed=True,
            frozen=True,
            validate_default=True,
        )

        server_type: c.Ldif.LiteralTypes.ServerTypeLiteral = Field(
            description="Server type identifier (e.g., 'oid', 'oud')",
        )
        schemas: list[p.Ldif.SchemaQuirkProtocol] = Field(
            default_factory=list,
            description="List of Schema quirk model instances",
        )
        acls: list[p.Ldif.AclQuirkProtocol] = Field(
            default_factory=list,
            description="List of ACL quirk model instances",
        )
        entrys: list[p.Ldif.EntryQuirkProtocol] = Field(
            default_factory=list,
            description="List of Entry quirk model instances",
        )

    # =========================================================================
    # ACL MODELS - Must be defined before Entry since Entry references Acl
    # =========================================================================

    class AclPermissions(FlextModelsBase.ArbitraryTypesModel):
        """ACL permissions for LDAP operations.

        Supports:
        - Standard RFC permissions (read, write, add, delete, search, compare)
        - Server-specific permissions (self_write, proxy, browse, auth)
        - Negative permissions (no_write, no_add, no_delete, no_browse, no_self_write)
        - Compound permissions (all)
        """

        # Standard RFC permissions
        read: bool = Field(default=False, description="Read permission")
        write: bool = Field(default=False, description="Write permission")
        add: bool = Field(default=False, description="Add permission")
        delete: bool = Field(default=False, description="Delete permission")
        search: bool = Field(default=False, description="Search permission")
        compare: bool = Field(default=False, description="Compare permission")

        # Server-specific extended permissions
        self_write: bool = Field(
            default=False,
            description="Self-write permission (OID, OUD)",
        )
        proxy: bool = Field(
            default=False,
            description="Proxy permission (OID, OUD, 389DS)",
        )
        browse: bool = Field(
            default=False,
            description="Browse permission (OID) - maps to read+search",
        )
        auth: bool = Field(
            default=False,
            description="Auth permission (OID) - authentication access",
        )
        all: bool = Field(
            default=False,
            description="All permissions (compound permission)",
        )

        # Negative permissions (OID-specific)
        # These represent denial of specific permissions
        no_write: bool = Field(default=False, description="Deny write permission (OID)")
        no_add: bool = Field(default=False, description="Deny add permission (OID)")
        no_delete: bool = Field(
            default=False,
            description="Deny delete permission (OID)",
        )
        no_browse: bool = Field(
            default=False,
            description="Deny browse permission (OID)",
        )
        no_self_write: bool = Field(
            default=False,
            description="Deny self-write permission (OID)",
        )

        @staticmethod
        def get_rfc_compliant_permissions(
            perms_dict: dict[str, bool],
        ) -> dict[str, bool]:
            """Filter permissions dict to RFC-compliant fields only.

            Architecture: Server-specific permissions (like OID's "none") are excluded
            from this model and stored in metadata instead. This method ensures
            AclPermissions only contains RFC-compliant or widely-supported permissions.

            Args:
                perms_dict: Dictionary with permission name → bool (from parser)

            Returns:
                Filtered dict containing only RFC-compliant permission keys

            """
            # RFC-compliant and widely-supported permission keys for AclPermissions model
            rfc_compliant_keys = {
                # Standard RFC permissions
                "read",
                "write",
                "add",
                "delete",
                "search",
                "compare",
                # Server-specific extended (widely supported)
                "self_write",
                "proxy",
                "browse",
                "auth",
                # Compound
                "all",
                # Negative permissions
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

        target_dn: str = Field(..., description="Target DN pattern")
        attributes: list[str] = Field(
            default_factory=list,
            description="Target attributes",
        )

    class AclSubject(FlextModelsBase.ArbitraryTypesModel):
        """ACL subject specification."""

        subject_type: c.Ldif.LiteralTypes.AclSubjectTypeLiteral = Field(
            ...,
            description="Subject type (user, group, etc.)",
        )
        subject_value: str = Field(..., description="Subject value/pattern")

    class Acl(AclElement):
        """Universal ACL model for all LDAP server types.

        Inherits from AclElement:
        - model_config (strict=True, validate_default=True, validate_assignment=True)
        - server_type field with default "rfc"
        - metadata field (Optional[QuirkMetadata])
        - validation_violations field (list[str])
        - is_valid computed field
        - has_server_quirks computed field
        """

        name: str = Field(default="", description="ACL name")
        target: FlextLdifModelsDomains.AclTarget | None = Field(
            default=None,
            description="ACL target",
        )
        subject: FlextLdifModelsDomains.AclSubject | None = Field(
            default=None,
            description="ACL subject",
        )
        permissions: FlextLdifModelsDomains.AclPermissions | None = Field(
            default=None,
            description="ACL permissions",
        )
        # server_type inherited from AclElement (default="rfc")
        raw_line: str = Field(default="", description="Original raw ACL line from LDIF")
        raw_acl: str = Field(default="", description="Original ACL string from LDIF")
        # validation_violations inherited from AclElement (default_factory=list)

        # Metadata field override with specific type (type narrowing from object to QuirkMetadata)
        metadata: FlextLdifModelsDomains.QuirkMetadata | None = Field(
            default=None,
            description="Quirk-specific metadata for ACL processing",
        )

        @model_validator(mode="after")
        def validate_acl_format(self) -> Self:
            """Validate ACL format - capture violations in metadata, DON'T reject.

            IMPORTANT: Pydantic 2 requires model validators with mode="after" to return
            `self` (not a copy) when validating via __init__. We modify self in-place
            using object.__setattr__() to respect immutability patterns.

            See: https://docs.pydantic.dev/latest/concepts/validators/#model-validators
            """
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
                self.raw_acl
            ):
                violations.append(
                    "ACL is defined (has target/subject/permissions) but raw_acl is empty",
                )

            # Modify self in-place (Pydantic 2 best practice for mode="after")
            if violations:
                return self.model_copy(
                    update={"validation_violations": violations},
                )

            # Return existing instance when no violations are present
            return self

        @classmethod
        def get_acl_format(cls) -> str:
            """Get ACL format for this server type.

            Business Rule: This method doesn't use instance state, only class constants.
            Implication: Can be a class method for better clarity and allows override in subclasses.

            Returns:
                Default ACL format string from constants.

            """
            return c.Ldif.AclFormats.DEFAULT_ACL_FORMAT

        def get_acl_type(self) -> str:
            """Get ACL type identifier for this server.

            Uses FROM_LONG mapping to normalize legacy long-form identifiers
            (e.g., "oracle_oid" → "oid") to short-form canonical identifiers.
            """
            # Normalize to short form using FROM_LONG dict
            short_server_type = c.Ldif.ServerTypesMappings.FROM_LONG.get(
                self.server_type,
                self.server_type,
            )
            return f"{short_server_type}_acl"

    class AclWriteMetadata(FlextLdifModelsBase):
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

        model_config = ConfigDict(
            frozen=True,
            strict=True,
            validate_default=True,
        )

        original_format: str | None = Field(
            default=None,
            description="Original ACL string format from source server",
        )
        source_server: str | None = Field(
            default=None,
            description="Server type that parsed this ACL",
        )
        name_sanitized: bool = Field(
            default=False,
            description="True if ACL name was sanitized during processing",
        )
        original_name_raw: str | None = Field(
            default=None,
            description="Original ACL name before sanitization",
        )

        @classmethod
        def from_extensions(
            cls,
            extensions: Mapping[str, t.MetadataAttributeValue] | None,
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

    class Entry(m.Entity):
        """LDIF entry domain model.

        Implements p.Models.EntryProtocol through structural typing.
        The protocol requires:
        - dn: str
        - attributes: FlextLdifModelsMetadata.DynamicMetadata

        This model provides these through:
        - dn field (DN) which has .value property returning str
        - attributes field (Attributes) which has .attributes property returning FlextLdifModelsDomains.UnconvertedAttributes
        """

        model_config = ConfigDict(
            strict=True,
            validate_default=True,
            validate_assignment=True,
            extra="allow",  # Allow dynamic fields from conversions and transformations
        )

        # ===================================================================
        # RFC 2849/4512 COMPLIANT FIELDS ONLY
        # ===================================================================
        # Entry model contains ONLY RFC-compliant LDIF entry data.
        # All processing metadata, validation results, and server-specific
        # data belong in the metadata field (QuirkMetadata).

        # Pydantic v2: Keep field validators for now (BeforeValidator needs module-level functions)
        # NOTE: Fields allow None to pass through for RFC violation capture in model_validator.
        # RFC compliance is enforced in validate_entry_rfc_compliance, not here.
        dn: FlextLdifModelsDomains.DN | None = Field(
            ...,
            description="Distinguished Name of the entry (REQUIRED per RFC 2849 § 2). Allows None for RFC violation capture. Coerced from str via field_validator - PROTOCOL COMPATIBLE with p.Ldif.Entry.EntryProtocol",
        )
        attributes: FlextLdifModelsDomains.Attributes | None = Field(
            ...,
            description="Entry attributes container (REQUIRED per RFC 2849 § 2). Allows None for RFC violation capture. Coerced from dict[str, list[str]] via field_validator - PROTOCOL COMPATIBLE with p.Ldif.Entry.EntryProtocol",
        )

        # PROTOCOL COMPLIANCE: Entry FULLY satisfies p.Ldif.Entry.EntryProtocol
        # Field validators coerce inputs to proper types BEFORE Pydantic validation:
        # - dn: Accepts str | DN via field validator
        # - attributes: Accepts dict | Attributes via field validator

        @field_validator("dn", mode="before")
        @classmethod
        def coerce_dn_from_string(
            cls,
            value: str | dict[str, object] | FlextLdifModelsDomains.DN | None,
        ) -> FlextLdifModelsDomains.DN | None:
            """Convert string DN to DN instance.

            Allows None to pass through for violation capture in model_validator.
            RFC 2849 § 2 violations are captured in validate_entry_rfc_compliance.
            """
            if value is None:
                # Allow None to pass through for RFC violation capture
                return None

            if isinstance(value, FlextLdifModelsDomains.DN):
                return value

            if isinstance(value, dict):
                # Handle dict from model_dump()
                return FlextLdifModelsDomains.DN(**value)

            return FlextLdifModelsDomains.DN(value=value)

        @field_validator("attributes", mode="before")
        @classmethod
        def coerce_attributes_from_dict(
            cls,
            value: dict[str, list[str]]
            | dict[str, object]
            | FlextLdifModelsDomains.Attributes
            | None,
        ) -> FlextLdifModelsDomains.Attributes | None:
            """Convert dict to Attributes instance.

            Allows None to pass through for violation capture in model_validator.
            RFC 2849 § 2 violations (attributes required) are captured in validate_entry_rfc_compliance.
            """
            if value is None:
                # Allow None to pass through for RFC violation capture
                return None

            if isinstance(value, FlextLdifModelsDomains.Attributes):
                return value

            if isinstance(value, dict) and "attributes" in value:
                # Handle dict from model_dump()
                return FlextLdifModelsDomains.Attributes(**value)

            # value is already dict[str, list[str]] from Mapping input
            return FlextLdifModelsDomains.Attributes(attributes=value)

        # ===================================================================
        # REMAINING FIELDS
        # ===================================================================
        # - metadata: Initialized via ensure_metadata_initialized, maps to EntryMetadata
        # - All methods (get_objectclass_names, model_copy) match protocol specifications
        changetype: c.Ldif.LiteralTypes.ChangeTypeLiteral | None = Field(
            default=None,
            description="Change operation type per RFC 2849 § 5.7 (add/delete/modify/moddn/modrdn)",
        )
        metadata: FlextLdifModelsDomains.QuirkMetadata | None = Field(
            default=None,
            description="Quirk-specific metadata for processing data, ACLs, statistics, validation (non-RFC data)",
        )

        @model_validator(mode="before")
        @classmethod
        def ensure_metadata_initialized(
            cls,
            data: dict[str, t.MetadataAttributeValue],
        ) -> dict[str, t.MetadataAttributeValue]:
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
            if not isinstance(data, dict):
                return data

            # Coerce ISO datetime strings to datetime objects for strict=True compatibility
            # This enables JSON round-trips (model_dump(mode='json') -> model_validate)
            for dt_field in ("created_at", "updated_at"):
                if dt_field in data and isinstance(data[dt_field], str):
                    with suppress(ValueError):
                        data[dt_field] = datetime.fromisoformat(data[dt_field])
                    # Let Pydantic handle invalid datetime strings

            # If metadata not provided or is None, initialize with default QuirkMetadata
            if data.get("metadata") is None:
                # Use FlextLdifModelsDomains directly from this module scope
                # This works correctly for subclasses in other modules (e.g., client-a-oud-mig)
                # because we reference the class from flext_ldif._models.domain, not cls.__module__

                # Create default QuirkMetadata with quirk_type from data if available
                # If no quirk_type provided, use 'rfc' as safe default
                quirk_type_value = data.get("quirk_type")
                final_quirk_type_val: c.Ldif.LiteralTypes.ServerTypeLiteral
                if isinstance(quirk_type_value, str) and quirk_type_value in {
                    "oid",
                    "oud",
                    "openldap",
                    "openldap1",
                    "openldap2",
                    "ad",
                    "apache",
                    "ds389",
                    "rfc",
                    "relaxed",
                    "generic",
                    "ibm_tivoli",
                    "novell",
                }:
                    # quirk_type_value is validated as ServerTypeLiteral
                    final_quirk_type_val = quirk_type_value
                else:
                    # Use literal value directly for type safety
                    final_quirk_type_val = "rfc"

                metadata_obj = FlextLdifModelsDomains.QuirkMetadata(
                    quirk_type=final_quirk_type_val,
                )
                # metadata_obj is already MetadataAttributeValue type
                data["metadata"] = metadata_obj

            return data

        @computed_field
        def dn_str(self) -> str:
            """Protocol compliance: p.Ldif.Entry.EntryProtocol requires dn: str.

            Returns the DN as a string for protocol compatibility.
            """
            if self.dn is None:
                return ""
            return self.dn.value

        @computed_field
        def attributes_dict(self) -> dict[str, list[str]]:
            """Protocol compliance: p.Ldif.Entry.EntryProtocol requires attributes: dict[str, list[str]].

            Returns the attributes as a dict for protocol compatibility.
            """
            if self.attributes is None:
                return {}
            return self.attributes.attributes

        def model_post_init(self, _context: object, /) -> None:
            """Post-init hook to ensure metadata is always initialized.

            Runs AFTER all model_validators. This guarantees metadata is
            properly initialized before any code tries to access it.
            """
            if self.metadata is None:
                self.metadata = FlextLdifModelsDomains.QuirkMetadata.create_for()

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
            # Allow entries without objectClass to pass through validation.
            # Downstream code (migration, quirks, etc.) will handle:
            # - Rejection of entries without required objectClass
            # - Logging of warnings for malformed entries
            # - Optional transformation or filtering based on application rules
            return self

        @staticmethod
        def _validate_dn(dn_value: str) -> list[str]:
            """Validate DN format per RFC 4514 § 2.3, 2.4.

            Business Rule: This is a pure function that doesn't use instance state.
            Implication: Can be a static method for better clarity and performance.

            Note: dn_value is guaranteed to be non-None since dn field is required.

            Args:
                dn_value: DN string to validate

            Returns:
                List of validation violation messages (empty if valid)

            """
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
            """Validate that entry has at least one attribute per RFC 2849 § 2.

            Note: self.attributes may be None when using model_construct (bypasses validation).
            """
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
            """Validate attribute descriptions per RFC 4512 § 2.5.

            Note: self.attributes may be None when using model_construct (bypasses validation).
            """
            violations: list[str] = []
            if self.attributes is None or not self.attributes:
                return violations

            for attr_desc in self.attributes.attributes:
                # Split base and options
                if ";" in attr_desc:
                    base_attr, options_str = attr_desc.split(";", 1)
                    options = [
                        opt.strip() for opt in options_str.split(";") if opt.strip()
                    ]
                else:
                    base_attr = attr_desc
                    options = []

                # Validate base attribute
                if not base_attr or not base_attr[0].isalpha():
                    violations.append(
                        f"RFC 4512 § 2.5: '{base_attr}' must start with letter",
                    )
                elif not all(c.isalnum() or c == "-" for c in base_attr):
                    violations.append(
                        f"RFC 4512 § 2.5: '{base_attr}' has invalid characters",
                    )

                # Validate options
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
            """Validate objectClass presence per RFC 4512 § 2.4.1.

            Note: self.attributes may be None when using model_construct (bypasses validation).
            """
            violations: list[str] = []
            # Schema entries exempt from objectClass requirement
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
            """Validate naming attribute presence per RFC 4512 § 2.3.

            Note: self.attributes may be None when using model_construct (bypasses validation).
            """
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
            """Validate binary attribute options per RFC 2849 § 5.2.

            Note: self.attributes may be None when using model_construct (bypasses validation).
            """
            violations: list[str] = []
            if self.attributes is None or not self.attributes:
                return violations

            for attr_name, attr_values in self.attributes.items():
                if ";binary" in attr_name.lower():
                    continue
                for value in attr_values:
                    # ASCII_SPACE_CHAR and ASCII_TILDE_CHAR are in LdifProcessing, not Format.Rfc
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
            """Validate attribute name/option syntax per RFC 4512 § 2.5.1-2.5.2.

            Note: self.attributes may be None when using model_construct (bypasses validation).
            """
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
            # RFC Compliance: changetype is now a direct field on Entry
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
            """Validate Entry RFC compliance - capture violations, DON'T reject.

            RFC 2849 § 2: DN and at least one attribute required
            RFC 4514 § 2.3, 2.4: DN format validation
            RFC 4512 § 2.5: Attribute name format validation

            Strategy: PRESERVE problematic entries for round-trip conversions,
            capture violations in validation_metadata for downstream handling.
            """
            # Collect violations from all validators
            violations: list[str] = []
            dn_value = "<None>"

            # Handle case where dn might be None (e.g., model_construct)
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

            # Capture violations in validation_metadata
            if violations and self.metadata is not None:
                attribute_count = len(self.attributes) if self.attributes else 0
                # Create/update validation results with current violations
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

            # Note: self.attributes is guaranteed to be non-None since it's a required field
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
            # Note: self.attributes is guaranteed to be non-None since it's a required field
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
            # Note: self.attributes is guaranteed to be non-None since it's a required field
            if not rules.requires_binary_option or not self.attributes:
                return violations

            for attr_name, attr_values in self.attributes.items():
                if ";binary" in attr_name.lower():
                    continue
                for value in attr_values:
                    # ASCII_SPACE_CHAR and ASCII_TILDE_CHAR are in LdifProcessing, not Format.Rfc
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
            # Check if server injected validation rules
            if not self.metadata:
                return self
            if "validation_rules" not in self.metadata.extensions:
                return self

            # Get server-injected validation rules
            validation_rules = self.metadata.extensions.get("validation_rules")
            if not validation_rules:
                return self

            # Reconstruct ServerValidationRules from dict if needed
            # (DynamicMetadata may serialize Pydantic models to dict)
            # Business Rule: Server validation rules are injected by server quirks
            # and stored in metadata.extensions. They may be serialized as dicts
            # when metadata is converted to/from JSON. We need to reconstruct the
            # Pydantic model with proper type validation.
            if isinstance(validation_rules, dict):
                try:
                    # Use model_validate for proper type conversion and validation
                    # This handles ScalarValue -> specific types conversion automatically
                    rules = ServerValidationRules.model_validate(
                        validation_rules,
                    )
                except Exception:
                    # If validation fails, skip server-specific validation
                    # This is safe - Entry will still be RFC-compliant
                    return self
            elif isinstance(
                validation_rules,
                ServerValidationRules,
            ):
                rules = validation_rules
            else:
                return self
            dn_value = str(self.dn.value) if self.dn else ""

            # Collect violations from all rule checkers
            server_violations: list[str] = []
            # rules is already ServerValidationRules type
            server_violations.extend(self._check_objectclass_rule(rules, dn_value))
            server_violations.extend(self._check_naming_attr_rule(rules, dn_value))
            server_violations.extend(self._check_binary_option_rule(rules))

            # ALWAYS store validation_server_type when rules were checked
            if self.metadata:
                self.metadata.extensions["validation_server_type"] = (
                    self.metadata.quirk_type
                )

            # Store server-specific violations in validation_metadata (if any)
            if server_violations and self.metadata:
                # Initialize validation_results if None
                if self.metadata.validation_results is None:
                    self.metadata.validation_results = (
                        FlextLdifModelsDomains.ValidationMetadata()
                    )
                # Create new validation_results with updated fields (frozen model)
                updated_validation_results = (
                    self.metadata.validation_results.model_copy(
                        update={
                            "server_specific_violations": server_violations,
                            "validation_server_type": self.metadata.quirk_type or None,
                        },
                    )
                )
                self.metadata.validation_results = updated_validation_results
                # server_violations is list[str], compatible with t.MetadataAttributeValue
                self.metadata.extensions["server_specific_violations"] = (
                    server_violations
                )

            return self

        @computed_field
        def unconverted_attributes(
            self,
        ) -> dict[str, str | list[str] | bytes]:
            """Get unconverted attributes from metadata extensions (read-only view, DRY pattern)."""
            if self.metadata is None:
                return {}
            # Access Pydantic extra fields directly
            extra = self.metadata.extensions.__pydantic_extra__
            if extra is None:
                return {}
            result = extra.get("unconverted_attributes")
            if isinstance(result, dict):
                return result
            return {}

        class Builder:
            """Builder pattern for Entry creation (reduces complexity, improves readability)."""

            _outer_cls: type[FlextLdifModelsDomains.Entry]

            def __init__(self, outer_cls: type[FlextLdifModelsDomains.Entry]) -> None:
                """Initialize builder with reference to outer class."""
                super().__init__()
                self._outer_cls = outer_cls
                self._dn: str | FlextLdifModelsDomains.DN | None = None
                self._attributes: (
                    dict[str, str | list[str]]
                    | FlextLdifModelsDomains.Attributes
                    | None
                ) = None
                self._metadata: FlextLdifModelsDomains.QuirkMetadata | None = None
                self._acls: list[FlextLdifModelsDomains.Acl] | None = None
                self._objectclasses: (
                    list[FlextLdifModelsDomains.SchemaObjectClass] | None
                ) = None
                self._attributes_schema: (
                    list[FlextLdifModelsDomains.SchemaAttribute] | None
                ) = None
                self._entry_metadata: FlextLdifModelsMetadata.EntryMetadata | None = (
                    None
                )
                self._validation_metadata: (
                    FlextLdifModelsDomains.ValidationMetadata | None
                ) = None
                self._server_type: c.Ldif.LiteralTypes.ServerTypeLiteral | None = None
                self._source_entry: str | None = None
                self._unconverted_attributes: (
                    FlextLdifModelsMetadata.DynamicMetadata | None
                ) = None

            def dn(
                self,
                dn: str | FlextLdifModelsDomains.DN,
            ) -> Self:
                self._dn = dn
                return self

            def attributes(
                self,
                attributes: dict[str, str | list[str]]
                | FlextLdifModelsDomains.Attributes,
            ) -> Self:
                self._attributes = attributes
                return self

            def metadata(
                self,
                metadata: FlextLdifModelsDomains.QuirkMetadata,
            ) -> Self:
                self._metadata = metadata
                return self

            def acls(
                self,
                acls: list[FlextLdifModelsDomains.Acl],
            ) -> Self:
                self._acls = acls
                return self

            def objectclasses(
                self,
                objectclasses: list[FlextLdifModelsDomains.SchemaObjectClass],
            ) -> Self:
                self._objectclasses = objectclasses
                return self

            def attributes_schema(
                self,
                attributes_schema: list[FlextLdifModelsDomains.SchemaAttribute],
            ) -> Self:
                self._attributes_schema = attributes_schema
                return self

            def entry_metadata(
                self,
                entry_metadata: FlextLdifModelsMetadata.EntryMetadata,
            ) -> Self:
                self._entry_metadata = entry_metadata
                return self

            def server_type(
                self,
                server_type: c.Ldif.LiteralTypes.ServerTypeLiteral,
            ) -> Self:
                self._server_type = server_type
                return self

            def source_entry(
                self,
                source_entry: str,
            ) -> Self:
                self._source_entry = source_entry
                return self

            def unconverted_attributes(
                self,
                unconverted_attributes: FlextLdifModelsMetadata.DynamicMetadata,
            ) -> Self:
                self._unconverted_attributes = unconverted_attributes
                return self

            def build(self) -> FlextResult[FlextLdifModelsDomains.Entry]:
                """Build the Entry using the accumulated parameters."""
                if self._dn is None or self._attributes is None:
                    return FlextResult[FlextLdifModelsDomains.Entry].fail(
                        "DN and attributes are required",
                    )

                return self._outer_cls.create(
                    dn=self._dn,
                    attributes=self._attributes,
                    metadata=self._metadata,
                    acls=self._acls,
                    objectclasses=self._objectclasses,
                    attributes_schema=self._attributes_schema,
                    entry_metadata=self._entry_metadata,
                    validation_metadata=self._validation_metadata,
                    server_type=self._server_type,
                    source_entry=self._source_entry,
                    unconverted_attributes=self._unconverted_attributes,
                )

        @classmethod
        def builder(cls) -> Builder:
            """Create a new Entry builder instance."""
            return cls.Builder(outer_cls=cls)

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
            server_type: c.Ldif.LiteralTypes.ServerTypeLiteral
            | None = None,  # New parameter
            source_entry: str | None = None,  # New parameter
            unconverted_attributes: FlextLdifModelsMetadata.DynamicMetadata
            | None = None,  # New parameter
            statistics: FlextLdifModelsDomains.EntryStatistics
            | None = None,  # New parameter
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
            """Normalize attributes to Attributes object.

            Args:
                attributes: Attributes as dict or Attributes object

            Returns:
                Attributes object with normalized values

            Note:
                Lenient processing: Empty attributes dict is accepted and will be captured
                in validation_metadata as RFC violation.

            """
            if isinstance(attributes, dict):
                # Lenient processing: Accept empty dict (violation captured in validation_metadata)
                # Empty dict is valid Attributes (Pydantic allows it)
                attrs_dict: dict[str, list[str]] = {}
                for attr_name, attr_values in attributes.items():
                    # Normalize to list if string
                    if isinstance(attr_values, str):
                        values_list: list[str] = [str(attr_values)]
                    elif isinstance(attr_values, list):
                        values_list = [str(v) for v in attr_values]
                    else:
                        # Single value - convert to list
                        values_list = [str(attr_values)]
                    attrs_dict[attr_name] = values_list
                return FlextLdifModelsDomains.Attributes(attributes=attrs_dict)
            if isinstance(attributes, FlextLdifModelsDomains.Attributes):
                return attributes
            # This else block should now be reachable and is valid
            msg = f"Attributes must be dict or Attributes, got {type(attributes).__name__}"
            raise ValueError(msg)

        @classmethod
        def _build_extension_kwargs(
            cls,
            server_type: c.Ldif.LiteralTypes.ServerTypeLiteral | None,
            source_entry: str | None,
            unconverted_attributes: FlextLdifModelsMetadata.DynamicMetadata | None,
        ) -> dict[str, str | dict[str, list[str]]]:
            """Build extension kwargs for DynamicMetadata."""
            ext_kwargs: dict[str, str | dict[str, list[str]]] = {}
            if server_type:
                ext_kwargs["server_type"] = server_type
            if source_entry:
                ext_kwargs["source_entry"] = source_entry
            if unconverted_attributes:
                ext_kwargs["unconverted_attributes"] = (
                    unconverted_attributes.model_dump()
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
                # Type narrowing: convert values to t.MetadataAttributeValue compatible types
                ext_kwargs_typed: dict[str, t.MetadataAttributeValue] = dict(ext_kwargs)
                extensions = FlextLdifModelsMetadata.DynamicMetadata(**ext_kwargs_typed)
                return FlextLdifModelsDomains.QuirkMetadata(
                    quirk_type=c.Ldif.ServerTypes.GENERIC.value,
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
            server_type: c.Ldif.LiteralTypes.ServerTypeLiteral
            | None = None,  # New parameter
            source_entry: str | None = None,  # New parameter
            unconverted_attributes: FlextLdifModelsMetadata.DynamicMetadata
            | None = None,  # New parameter
            statistics: FlextLdifModelsDomains.EntryStatistics
            | None = None,  # New parameter
        ) -> FlextResult[Self]:
            """Internal method for Entry creation with composition fields.

            Args:
            dn: Distinguished Name for the entry
            attributes: Entry attributes as FlextLdifModelsDomains.UnconvertedAttributes or Attributes
            metadata: Optional quirk metadata for preserving original format
            acls: Optional list of Access Control Lists for the entry
            objectclasses: Optional list of ObjectClass definitions for schema validation
            attributes_schema: Optional list of SchemaAttribute definitions for schema validation
            entry_metadata: Optional entry-level metadata (changetype, modifyTimestamp, etc.)
            validation_metadata: Optional validation results and metadata
            server_type: Optional server type for the entry (for quirk metadata)
            source_entry: Optional original source entry string (for quirk metadata)
            unconverted_attributes: Optional dictionary of unconverted attributes (for quirk metadata)
            statistics: Optional entry statistics tracking (transformations, validation, etc.)

            Returns:
            FlextResult with Entry instance or validation error

            """
            try:
                # Normalize DN to DN object (uses Self for facade compatibility)
                dn_obj = FlextLdifModelsDomains.DN.from_value(dn)

                # Normalize attributes to Attributes object
                attrs_obj = cls._normalize_attributes(attributes)

                # Build or update metadata
                metadata = cls._build_metadata(
                    metadata,
                    server_type,
                    source_entry,
                    unconverted_attributes,
                )

                # Use model_validate to ensure Pydantic handles
                # default_factory fields. Only include non-None fields to let Pydantic
                # use default_factory for omitted fields.
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

                # Only add optional fields if they are not None
                # This allows Pydantic to use default_factory for omitted fields
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
            """Create Entry from ldap3 Entry object.

            Args:
                ldap3_entry: ldap3 Entry object with entry_dn and entry_attributes_as_dict

            Returns:
                FlextResult with Entry instance or error

            """
            try:
                # Extract DN
                dn_str = str(getattr(ldap3_entry, "entry_dn", ""))

                # Extract attributes - ldap3 provides dict with various types
                entry_attrs_raw: dict[
                    str,
                    str | list[str] | bytes | list[bytes] | int | float | bool | None,
                ] = (
                    getattr(ldap3_entry, "entry_attributes_as_dict", {})
                    if hasattr(ldap3_entry, "entry_attributes_as_dict")
                    else {}
                )

                # Normalize to dict[str, str | list[str]] (ensure all values are lists of strings)
                attrs_dict: dict[str, str | list[str]] = {}
                # entry_attrs_raw is always dict from ldap3_entry.entry_attributes_as_dict
                if entry_attrs_raw:
                    for attr_name, attr_value_list in entry_attrs_raw.items():
                        if isinstance(attr_value_list, list):
                            # Type guard: attr_value_list is list-like, so it's iterable
                            attrs_dict[str(attr_name)] = [
                                str(v) for v in attr_value_list
                            ]
                        elif isinstance(attr_value_list, str):
                            attrs_dict[str(attr_name)] = [attr_value_list]
                        else:
                            attrs_dict[str(attr_name)] = [str(attr_value_list)]

                # Use Entry.create to handle DN and attribute conversion
                return cls.create(
                    dn=dn_str,
                    attributes=attrs_dict,
                )

            except Exception as e:
                return FlextResult.fail(
                    f"Failed to create Entry from ldap3: {e}",
                )

        def get_attribute_values(self, attribute_name: str) -> list[str]:
            """Get all values for a specific attribute.

            LDAP attribute names are case-insensitive.

            Args:
            attribute_name: Name of the attribute to retrieve

            Returns:
            List of attribute values, empty list if attribute doesn't exist

            """
            # Case-insensitive attribute lookup (LDAP standard)
            if self.attributes is None:
                return []

            # Access the actual attributes dict (Attributes.attributes property)
            attrs_dict = (
                self.attributes.attributes
                if hasattr(self.attributes, "attributes")
                else self.attributes
            )
            if not attrs_dict:
                return []

            attr_name_lower = attribute_name.lower()
            # Handle both dict and Attributes objects
            if isinstance(attrs_dict, dict):
                for stored_name, attr_values in attrs_dict.items():
                    if stored_name.lower() == attr_name_lower:
                        return attr_values
            elif hasattr(attrs_dict, "items"):
                # Attributes object with items() method
                for stored_name, attr_values in attrs_dict.items():
                    if stored_name.lower() == attr_name_lower:
                        return attr_values
            return []

        def has_attribute(self, attribute_name: str) -> bool:
            """Check if entry has a specific attribute.

            LDAP attribute names are case-insensitive.

            Args:
            attribute_name: Name of the attribute to check

            Returns:
            True if attribute exists with at least one value, False otherwise

            """
            return len(self.get_attribute_values(attribute_name)) > 0

        def has_object_class(self, object_class: str) -> bool:
            """Check if entry has specified object class.

            Args:
            object_class: Name of the object class to check

            Returns:
            True if entry has the object class, False otherwise

            """
            return object_class in self.get_attribute_values(
                c.Ldif.DictKeys.OBJECTCLASS,
            )

        def get_all_attribute_names(self) -> list[str]:
            """Get list of all attribute names in the entry.

            Returns:
            List of attribute names (case as stored in entry)

            """
            if self.attributes is None:
                return []
            return list(self.attributes.keys())

        def get_all_attributes(self) -> dict[str, list[str]]:
            """Get all attributes as dictionary.

            Returns:
            Dictionary of attribute_name -> list[str] (deep copy)

            """
            if self.attributes is None:
                return {}
            return dict(self.attributes.attributes)

        def count_attributes(self) -> int:
            """Count the number of attributes in the entry.

            Returns:
            Number of attributes (including multivalued attributes count as 1)

            """
            if self.attributes is None:
                return 0
            return len(self.attributes)

        def get_dn_components(self) -> list[str]:
            """Get DN components (RDN parts) from the entry's DN.

            Returns:
            List of DN components (e.g., ["cn=REDACTED_LDAP_BIND_PASSWORD", "dc=example", "dc=com"])

            """
            # Note: self.dn is guaranteed to be non-None since it's a required field
            if self.dn is None:
                return []
            return [comp.strip() for comp in self.dn.value.split(",") if comp.strip()]

        def matches_filter(
            self,
            filter_func: Callable[[FlextLdifModelsDomains.Entry], bool] | None = None,
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
                # filter_func expects Entry object (per signature)
                return bool(filter_func(self))
            except Exception:
                return False

        def clone(self) -> Self:
            """Create an immutable copy of the entry.

            Returns:
            New Entry instance with same values (shallow copy of attributes)

            """
            # Use model_copy to create a copy - all metadata fields are in metadata
            # Entry only has: dn, attributes, changetype, metadata
            return self.model_copy(deep=True)

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

        def get_objectclass_names(self) -> list[str]:
            """Get list of objectClass attribute values from entry."""
            return self.get_attribute_values(c.Ldif.DictKeys.OBJECTCLASS)

        def get_entries(self) -> list[Self]:
            """Get this entry as a list for unified protocol.

            Returns:
                List containing this entry

            """
            # Return list containing self (no conversion needed)
            return [self]

    class AttributeTransformation(FlextLdifModelsBase):
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

        model_config = ConfigDict(frozen=True, strict=True)

        original_name: str = Field(
            ...,
            description="Original attribute name from source server",
        )
        target_name: str | None = Field(
            default=None,
            description="Transformed attribute name (None if removed)",
        )
        original_values: list[str] = Field(
            default_factory=list,
            description="Original attribute values from source",
        )
        target_values: list[str] | None = Field(
            default=None,
            description="Transformed values (None if removed)",
        )
        # AttributeTransformation uses specific transformation types
        # Using centralized Literal type from constants for consistency
        transformation_type: c.Ldif.LiteralTypes.TransformationTypeLiteral = Field(
            ...,
            description="Type of transformation applied to the attribute",
        )
        reason: str = Field(
            default="",
            description="Human-readable reason for transformation",
        )

    class DNStatisticsFlags(TypedDict, total=False):
        """Optional flags for DNStatistics.create_with_transformation().

        Public TypedDict for type-safe DN transformation flags.
        Used by DNStatistics.create_with_transformation() and FlextLdifUtilitiesDN.
        """

        had_tab_chars: bool
        had_trailing_spaces: bool
        had_leading_spaces: bool
        had_extra_spaces: bool
        was_base64_encoded: bool
        had_utf8_chars: bool
        had_escape_sequences: bool
        validation_status: str
        validation_warnings: list[str]
        validation_errors: list[str]

    # Backward compatibility alias (deprecated, use DNStatisticsFlags)
    _DNStatisticsFlags = DNStatisticsFlags

    class DNStatistics(FlextLdifModelsBase):
        """Statistics tracking for DN transformations and validation.

        Immutable value object capturing complete DN transformation history
        from original to normalized form. Preserves all metadata for
        round-trip server conversions and diagnostic purposes.

        All DN transformation operations should populate this model to
        maintain a complete audit trail.

        Inherits from FlextModels.BaseModel (flext-core):
        - model_config (frozen=True, validate_default=True, validate_assignment=True)
        - aggregate() classmethod (automatic statistics aggregation)
        """

        model_config = ConfigDict(frozen=True, extra="ignore")

        # Core DN states
        original_dn: str = Field(
            ...,
            description="Original DN as received from input",
        )
        cleaned_dn: str = Field(
            ...,
            description="DN after clean_dn() transformation",
        )
        normalized_dn: str = Field(
            ...,
            description="Final normalized DN (RFC 4514 compliant)",
        )

        # Transformation tracking
        transformations: list[str] = Field(
            default_factory=list,
            description="Ordered list of transformations applied (use TransformationType constants)",
        )

        # Common transformation flags
        had_tab_chars: bool = Field(
            default=False,
            description="DN contained TAB characters",
        )
        had_trailing_spaces: bool = Field(
            default=False,
            description="DN had trailing spaces",
        )
        had_leading_spaces: bool = Field(
            default=False,
            description="DN had leading spaces",
        )
        had_extra_spaces: bool = Field(
            default=False,
            description="DN had multiple consecutive spaces",
        )
        was_base64_encoded: bool = Field(
            default=False,
            description="DN was base64 encoded in LDIF (dn::)",
        )
        had_utf8_chars: bool = Field(
            default=False,
            description="DN contained UTF-8 multi-byte characters",
        )
        had_escape_sequences: bool = Field(
            default=False,
            description="DN contained LDAP escape sequences",
        )

        # Validation status
        validation_status: str = Field(
            default="valid",
            description="Validation status (use ValidationStatus constants)",
        )
        validation_warnings: list[str] = Field(
            default_factory=list,
            description="Non-fatal validation warnings",
        )
        validation_errors: list[str] = Field(
            default_factory=list,
            description="Fatal validation errors",
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
            **flags: Unpack[FlextLdifModelsDomains.DNStatisticsFlags],
        ) -> Self:
            """Create statistics with transformation details.

            Args:
                original_dn: Original DN string
                cleaned_dn: Cleaned DN string
                normalized_dn: Normalized DN string
                transformations: List of transformation types applied
                **flags: Optional DNStatistics fields (type-safe via DNStatisticsFlags)

            """
            return cls(
                original_dn=original_dn,
                cleaned_dn=cleaned_dn,
                normalized_dn=normalized_dn,
                transformations=transformations if transformations is not None else [],
                **flags,
            )

    class EntryStatistics(FlextLdifModelsBase):
        """Statistics tracking for entry-level transformations and validation.

        Tracks complete entry lifecycle from parsing through validation,
        transformation, filtering, and output. Captures all attribute
        modifications, quirk applications, and rejection reasons.

        Designed for aggregation across large LDIF files to provide
        comprehensive migration diagnostics.

        Inherits from FlextModels.BaseModel (flext-core):
        - model_config (frozen=True, validate_default=True, validate_assignment=True)
        - aggregate() classmethod (automatic statistics aggregation)
        """

        model_config = ConfigDict(frozen=True, extra="ignore")

        # Entry lifecycle tracking
        was_parsed: bool = Field(
            default=True,
            description="Entry was successfully parsed from LDIF",
        )
        was_validated: bool = Field(
            default=False,
            description="Entry passed validation checks",
        )
        was_filtered: bool = Field(
            default=False,
            description="Entry was filtered by rules (base DN, schema, etc.)",
        )
        was_written: bool = Field(
            default=False,
            description="Entry was written to output LDIF",
        )
        was_rejected: bool = Field(
            default=False,
            description="Entry was rejected during processing",
        )

        # Rejection tracking
        rejection_category: str | None = Field(
            default=None,
            description="Rejection category (use RejectionCategory constants)",
        )
        rejection_reason: str | None = Field(
            default=None,
            description="Human-readable rejection reason",
        )

        # Attribute transformation tracking
        attributes_added: list[str] = Field(
            default_factory=list,
            description="Attribute names added during processing",
        )
        attributes_removed: list[str] = Field(
            default_factory=list,
            description="Attribute names removed during processing",
        )
        attributes_modified: list[str] = Field(
            default_factory=list,
            description="Attribute names modified during processing",
        )
        attributes_filtered: list[str] = Field(
            default_factory=list,
            description="Attribute names filtered by whitelist/blacklist",
        )

        # ObjectClass tracking
        objectclasses_original: list[str] = Field(
            default_factory=list,
            description="Original objectClass values",
        )
        objectclasses_final: list[str] = Field(
            default_factory=list,
            description="Final objectClass values after transformation",
        )

        # Quirk metadata tracking
        quirks_applied: list[c.Ldif.LiteralTypes.ServerTypeLiteral] = Field(
            default_factory=list,
            description="List of quirk types applied to this entry",
        )
        quirk_transformations: int = Field(
            default=0,
            description="Count of quirk transformations applied",
        )

        # DN statistics reference
        dn_statistics: FlextLdifModelsDomains.DNStatistics | None = Field(
            default=None,
            description="DN transformation statistics (if applicable)",
        )

        # Filter tracking
        filters_applied: list[str] = Field(
            default_factory=list,
            description="List of filters applied (use FilterType constants)",
        )
        filter_results: dict[str, bool] = Field(
            default_factory=dict,
            description="Filter results: {filter_name: passed}",
        )

        # Error tracking
        errors: list[str] = Field(
            default_factory=list,
            description="Error messages (use ErrorCategory constants for keys)",
        )
        warnings: list[str] = Field(
            default_factory=list,
            description="Warning messages",
        )

        # Categorization tracking
        category_assigned: str | None = Field(
            default=None,
            description="Category assigned (schema, hierarchy, users, groups, acl)",
        )
        category_confidence: float = Field(
            default=1.0,
            ge=0.0,
            le=1.0,
            description="Confidence score for category assignment",
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
            """Mark entry as validated.

            Returns new instance with was_validated=True (frozen model).
            """
            return self.model_copy(update={"was_validated": True})

        def mark_filtered(
            self,
            filter_type: str,
            *,
            passed: bool,
        ) -> Self:
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

        def mark_rejected(
            self,
            category: str,
            reason: str,
        ) -> Self:
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

        def track_attribute_change(
            self,
            attr_name: str,
            change_type: str,
        ) -> Self:
            """Track attribute modification.

            Returns new instance with attribute change tracked (frozen model).
            """
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
            return self  # No change for unknown type

        def apply_quirk(
            self,
            quirk_type: c.Ldif.LiteralTypes.ServerTypeLiteral,
        ) -> Self:
            """Record quirk application.

            Returns new instance with quirk recorded (frozen model).
            """
            quirks_applied = [*self.quirks_applied, quirk_type]
            return self.model_copy(
                update={
                    "quirks_applied": quirks_applied,
                    "quirk_transformations": self.quirk_transformations + 1,
                },
            )

    class ValidationMetadata(FlextLdifModelsBase):
        """Validation results and error tracking metadata.

        Composed model for QuirkMetadata.validation_results field.
        """

        model_config = ConfigDict(
            frozen=True,
            extra="forbid",
            use_enum_values=True,
            str_strip_whitespace=True,
        )

        rfc_violations: list[str] = Field(
            default_factory=list,
            description="RFC violations detected during validation",
        )
        errors: list[str] = Field(
            default_factory=list,
            description="Validation errors that occurred",
        )
        warnings: list[str] = Field(
            default_factory=list,
            description="Non-fatal validation warnings",
        )
        context: dict[str, str] = Field(
            default_factory=dict,
            description="Validation context information",
        )
        server_specific_violations: list[str] = Field(
            default_factory=list,
            description="Server-specific validation violations",
        )
        validation_server_type: c.Ldif.LiteralTypes.ServerTypeLiteral | None = Field(
            default=None,
            description="Server type used for validation",
        )

    class WriteOptions(FlextLdifModelsBase):
        """LDIF writing configuration options.

        Composed model for QuirkMetadata.write_options field.
        """

        model_config = ConfigDict(
            frozen=True,
            extra="forbid",
            use_enum_values=True,
            str_strip_whitespace=True,
        )

        format: str | None = Field(
            default=None,
            description="LDIF format variant (rfc2849, extended, etc.)",
        )
        base_dn: str | None = Field(
            default=None,
            description="Base DN for relative DN conversions",
        )
        hidden_attrs: list[str] = Field(
            default_factory=list,
            description="Attributes to exclude from output",
        )
        sort_entries: bool = Field(
            default=False,
            description="Whether to sort entries in output",
        )
        include_comments: bool = Field(
            default=False,
            description="Whether to include comment lines",
        )
        base64_encode_binary: bool = Field(
            default=False,
            description="Whether to base64 encode binary attributes",
        )

    class FormatDetails(FlextLdifModelsBase):
        """Original formatting details for round-trip preservation.

        Composed model for QuirkMetadata.original_format_details field.
        """

        model_config = ConfigDict(
            frozen=True,
            extra="forbid",
            use_enum_values=True,
            str_strip_whitespace=True,
        )

        dn_line: str | None = Field(
            default=None,
            description="Original DN line formatting",
        )
        syntax: str | None = Field(
            default=None,
            description="Original attribute syntax information",
        )
        encoding: c.Ldif.LiteralTypes.EncodingLiteral | None = Field(
            default=None,
            description="Original encoding (utf-8, etc.)",
        )
        spacing: str | None = Field(
            default=None,
            description="Original spacing/indentation",
        )
        trailing_info: str | None = Field(
            default=None,
            description="Trailing comments or metadata",
        )

    class SchemaFormatDetails(FlextLdifModelsBase):
        """Schema formatting details for perfect round-trip conversion.

        Composed model for QuirkMetadata.schema_format_details field.
        """

        model_config = ConfigDict(
            frozen=True,
            extra="forbid",
            use_enum_values=True,
            str_strip_whitespace=True,
        )

        original_string_complete: str | None = Field(
            default=None,
            description="Complete original schema definition string for perfect round-trip",
        )
        quotes: str | None = Field(
            default=None,
            description="Quoting style used in schema definition",
        )
        spacing: str | None = Field(
            default=None,
            description="Spacing around schema fields",
        )
        field_order: list[str] = Field(
            default_factory=list,
            description="Original order of schema fields",
        )
        x_origin: str | None = Field(
            default=None,
            description="X-ORIGIN value from schema",
        )
        x_ordered: list[str] = Field(
            default_factory=list,
            description="X-ORDERED field values",
        )
        extensions: FlextLdifModelsMetadata.DynamicMetadata = Field(
            default_factory=FlextLdifModelsMetadata.DynamicMetadata,
            description="Non-standard schema extensions",
        )

    class QuirkMetadata(FlextLdifModelsBase):
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

        model_config = ConfigDict(extra="allow", frozen=False)

        quirk_type: c.Ldif.LiteralTypes.ServerTypeLiteral = Field(
            ...,
            description="Type of quirk this metadata represents",
        )
        extensions: FlextLdifModelsMetadata.DynamicMetadata = Field(
            default_factory=FlextLdifModelsMetadata.DynamicMetadata,
            description="Extensible metadata storage for quirk-specific data (server-injected validation rules, unconverted attributes, etc.)",
        )

        # =====================================================================
        # RFC COMPLIANCE TRACKING (Phase 1: Enhanced Validation)
        # =====================================================================

        rfc_violations: list[str] = Field(
            default_factory=list,
            description="RFC violations detected (e.g., 'RFC 2849 §2: DN required')",
        )
        rfc_warnings: list[str] = Field(
            default_factory=list,
            description="Non-fatal RFC warnings (e.g., unusual but valid formatting)",
        )

        # =====================================================================
        # CONVERSION TRACKING (Phase 1: Audit Trail)
        # =====================================================================

        conversion_notes: FlextLdifModelsMetadata.DynamicMetadata = Field(
            default_factory=FlextLdifModelsMetadata.DynamicMetadata,
            description="Map of conversion operation name → human-readable description",
        )
        attribute_transformations: dict[
            str,
            FlextLdifModelsDomains.AttributeTransformation,
        ] = Field(
            default_factory=dict,
            description="Detailed transformation records keyed by original attribute name",
        )

        # =====================================================================
        # SERVER-SPECIFIC DATA (Phase 1: Round-trip Support)
        # =====================================================================

        server_specific_data: FlextLdifModelsMetadata.EntryMetadata = Field(
            default_factory=FlextLdifModelsMetadata.EntryMetadata,
            description="Preservation of server-proprietary data for round-trip conversions",
        )
        original_server_type: c.Ldif.LiteralTypes.ServerTypeLiteral | None = Field(
            default=None,
            description="Source LDAP server type (e.g., 'oid', 'oud', 'ad', 'openldap')",
        )
        target_server_type: c.Ldif.LiteralTypes.ServerTypeLiteral | None = Field(
            default=None,
            description="Target LDAP server type (e.g., 'oid', 'oud', 'ad', 'openldap')",
        )

        # =====================================================================
        # PROCESSING METADATA (Migrated from Entry - RFC Compliance)
        # =====================================================================
        # These fields were moved from Entry to maintain RFC 2849/4512 purity.
        # Entry should ONLY contain RFC-compliant fields (dn, attributes, changetype).
        # All processing metadata belongs in QuirkMetadata.

        acls: list[FlextLdifModelsDomains.Acl] = Field(
            default_factory=list,
            description="Access Control Lists extracted from entry attributes during parsing",
        )
        objectclasses: list[FlextLdifModelsDomains.SchemaObjectClass] = Field(
            default_factory=list,
            description="ObjectClass definitions for schema validation (not RFC LDIF data)",
        )
        validation_results: FlextLdifModelsDomains.ValidationMetadata | None = Field(
            default=None,
            description="Validation results with RFC violations, errors, warnings, and context",
        )
        processing_stats: FlextLdifModelsDomains.EntryStatistics | None = Field(
            default=None,
            description="Complete statistics tracking for entry transformations",
        )
        write_options: FlextLdifModelsDomains.WriteOptions | None = Field(
            default=None,
            description="Writer configuration including format, base DN, hidden attributes, sorting, and comments",
        )
        removed_attributes: FlextLdifModelsMetadata.DynamicMetadata = Field(
            default_factory=FlextLdifModelsMetadata.DynamicMetadata,
            description="Attributes removed during conversion (was entry_metadata.removed_attributes_with_values)",
        )

        # =====================================================================
        # ZERO DATA LOSS TRACKING (Phase 2: Round-trip Support)
        # =====================================================================
        # These fields ensure no data is lost during OID↔OUD↔RFC conversions.
        # All original formats are preserved for perfect round-trip fidelity.

        original_format_details: FlextLdifModelsDomains.FormatDetails | None = Field(
            default=None,
            description="Original formatting details for round-trip preservation (DN line, syntax, encoding, spacing)",
        )
        # =====================================================================
        # SCHEMA FORMATTING DETAILS (Complete Round-trip Fidelity)
        # =====================================================================
        # These fields capture EVERY minimal difference in schema definitions
        # to ensure perfect round-trip conversion between OID/OUD/RFC

        schema_format_details: FlextLdifModelsDomains.SchemaFormatDetails | None = (
            Field(
                default=None,
                description="Schema formatting details for perfect round-trip conversion (quotes, spacing, field order, extensions)",
            )
        )
        soft_delete_markers: list[str] = Field(
            default_factory=list,
            description=(
                "Attributes soft-deleted during conversion (can be restored). "
                "Different from removed_attributes: these are intentionally hidden "
                "for target server but preserved for reverse conversion."
            ),
        )
        original_attribute_case: FlextLdifModelsMetadata.DynamicMetadata = Field(
            default_factory=FlextLdifModelsMetadata.DynamicMetadata,
            description=(
                "Original case of attribute names: {'objectclass': 'objectClass', "
                "'cn': 'CN'}. Used to restore original case during reverse conversion."
            ),
        )
        schema_quirks_applied: list[c.Ldif.LiteralTypes.ServerTypeLiteral] = Field(
            default_factory=list,
            description=(
                "List of schema quirks applied during parsing: "
                "['matching_rule_normalization', 'syntax_oid_conversion', 'schema_dn_quirk']"
            ),
        )
        boolean_conversions: FlextLdifModelsMetadata.DynamicMetadata = Field(
            default_factory=FlextLdifModelsMetadata.DynamicMetadata,
            description=(
                "Boolean conversion tracking: "
                "{'orcldasisenabled': {'original': '1', 'converted': 'TRUE', 'format': 'OID->RFC'}}"
            ),
        )

        # =====================================================================
        # MINIMAL DIFFERENCES TRACKING (Complete Character-Level Preservation)
        # =====================================================================
        # Captures EVERY minimal difference for perfect round-trip conversion:
        # - Character-by-character differences
        # - Spacing (leading, trailing, internal, between fields)
        # - Case differences (attribute names, objectClass names, etc.)
        # - Punctuation (semicolons, commas, colons, parentheses, etc.)
        # - Quotes (single, double, presence/absence)
        # - Encoding differences
        # - Missing/added characters
        # - String format differences (original vs converted)

        minimal_differences: FlextLdifModelsMetadata.DynamicMetadata = Field(
            default_factory=FlextLdifModelsMetadata.DynamicMetadata,
            description=(
                "Complete minimal differences tracking for zero data loss: "
                "{'dn': {'has_differences': True, 'original': 'cn=test, dc=example', "
                "'converted': 'cn=test,dc=example', 'differences': [...], "
                "'spacing_changes': {...}, 'case_changes': [...], "
                "'punctuation_changes': [...], 'original_length': 20, 'converted_length': 19}, "
                "'attribute_cn': {'has_differences': False, ...}, "
                "'schema_attr_uid': {'has_differences': True, 'original': \"attributetypes: ( 0.9.2342... NAME 'uid' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15{256}' )  \", "
                "'converted': 'attributeTypes: ( 0.9.2342... NAME uid SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )', "
                "'differences': [...], 'syntax_quotes_removed': True, 'trailing_spaces_removed': True, ...}}"
            ),
        )

        # Original strings preservation (NEVER lose original data)
        original_strings: FlextLdifModelsMetadata.DynamicMetadata = Field(
            default_factory=FlextLdifModelsMetadata.DynamicMetadata,
            description=(
                "Complete preservation of original strings before ANY conversion: "
                "{'dn_original': 'cn=test, dc=example;', "
                "'attribute_cn_original': 'CN', "
                "'schema_attr_uid_original': \"attributetypes: ( 0.9.2342... NAME 'uid' SYNTAX '1.3.6.1.4.1.1466.115.121.1.15{256}' )  \", "
                "'acl_original': 'orclaci: { ... }', "
                "'entry_original_ldif': 'dn: cn=test\\ncn: test\\n'}"
            ),
        )

        # Conversion history (complete audit trail)
        conversion_history: list[
            dict[str, str | int | float | bool | list[str] | None]
        ] = Field(
            default_factory=list,
            description=(
                "Complete conversion history for audit trail: "
                "[{'step': 'parse_oid_entry', 'timestamp': '2025-01-01T00:00:00Z', "
                "'original': {...}, 'converted': {...}, 'differences': {...}, "
                "'server_type': 'oid', 'operation': 'parse'}, "
                "{'step': 'normalize_to_rfc', 'timestamp': '2025-01-01T00:00:01Z', "
                "'original': {...}, 'converted': {...}, 'differences': {...}, "
                "'server_type': 'rfc', 'operation': 'normalize'}, ...]"
            ),
        )

        @classmethod
        def create_for(
            cls,
            quirk_type: str | c.Ldif.LiteralTypes.ServerTypeLiteral | None = None,
            extensions: (
                FlextLdifModelsMetadata.DynamicMetadata
                | dict[str, t.MetadataAttributeValue]
                | None
            ) = None,
        ) -> Self:
            """Factory method to create QuirkMetadata with extensions.

            Args:
                quirk_type: Quirk type identifier. Defaults to RFC if not provided.
                extensions: Extensions as DynamicMetadata or dict. Defaults to empty if not provided.

            Returns:
                QuirkMetadata instance with defaults from Constants.

            """
            # Use Constants default for quirk_type if not provided
            # normalize_server_type guarantees valid literal value
            default_quirk_type: c.Ldif.LiteralTypes.ServerTypeLiteral = (
                normalize_server_type(quirk_type)
                if quirk_type is not None
                else cast(
                    "c.Ldif.LiteralTypes.ServerTypeLiteral",
                    c.Ldif.ServerTypes.RFC.value,
                )
            )
            # Convert dict to DynamicMetadata if needed
            extensions_model: FlextLdifModelsMetadata.DynamicMetadata
            if extensions is None:
                extensions_model = FlextLdifModelsMetadata.DynamicMetadata()
            elif isinstance(extensions, dict):
                extensions_model = FlextLdifModelsMetadata.DynamicMetadata(**extensions)
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
            """Track an attribute transformation in metadata.

            RFC Compliance: Stores original data for round-trip support.

            Args:
                original_name: Original attribute name before transformation
                new_name: New attribute name (None if removed)
                transformation_type: Type of transformation (renamed/removed/modified/added)
                original_values: Original values before transformation
                new_values: New values after transformation
                reason: Human-readable reason for transformation

            Returns:
                Self for method chaining

            Example:
                >>> metadata.track_attribute_transformation(
                ...     original_name="orclPassword",
                ...     new_name="userPassword",
                ...     transformation_type=c.Ldif.TransformationType.ATTRIBUTE_RENAMED,
                ...     reason="OID→OUD attribute mapping",
                ... )

            """
            transformation = FlextLdifModelsDomains.AttributeTransformation(
                original_name=original_name,
                target_name=new_name,
                transformation_type=transformation_type,
                original_values=list(original_values) if original_values else [],
                target_values=new_values or [],
            )
            self.attribute_transformations[original_name] = transformation

            # Add conversion note for audit trail
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
            """Track an attribute removal in metadata.

            RFC Compliance: Preserves removed attribute data for round-trip conversions.
            Uses c.Ldif.MetadataKeys.SKIPPED_ATTRIBUTES tracking.

            Args:
                attribute_name: Name of removed attribute
                values: Values that were removed
                reason: Human-readable reason for removal

            Returns:
                Self for method chaining

            Example:
                >>> metadata.track_attribute_removal(
                ...     attribute_name="orclLastAppliedChangeNumber",
                ...     values=["12345"],
                ...     reason="OID-specific operational attribute",
                ... )

            """
            # values is list[str], compatible with t.MetadataAttributeValue
            self.removed_attributes[attribute_name] = values
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
            """Track a DN transformation in metadata.

            RFC 4514 Compliance: Tracks DN normalization and transformations.
            Uses c.Ldif.Format.Rfc.META_DN_* keys.

            Args:
                original_dn: Original DN before transformation
                transformed_dn: DN after transformation
                transformation_type: Type of transformation (normalized/basedn_transform/etc.)
                was_base64: Whether original DN was base64 encoded
                escapes_applied: List of escape sequences that were applied

            Returns:
                Self for method chaining

            Example:
                >>> metadata.track_dn_transformation(
                ...     original_dn="cn=test, dc=example",
                ...     transformed_dn="cn=test,dc=example",
                ...     transformation_type=c.Ldif.TransformationType.DN_NORMALIZED.value,
                ... )

            """
            # Use getattr to access nested constants - helps MyPy understand the structure
            rfc_format = c.Ldif.Format
            self.original_strings[rfc_format.META_DN_ORIGINAL] = original_dn
            self.extensions[rfc_format.META_DN_WAS_BASE64] = was_base64
            if escapes_applied:
                # escapes_applied is Sequence[str] | None, compatible with t.MetadataAttributeValue
                self.extensions[rfc_format.META_DN_ESCAPES_APPLIED] = escapes_applied

            # Add to conversion notes
            self.conversion_notes[f"dn_{transformation_type}"] = (
                f"DN {transformation_type}: '{original_dn}' → '{transformed_dn}'"
            )

            return self

        def track_rfc_violation(
            self,
            violation: str,
            severity: str = "error",
        ) -> Self:
            """Track an RFC violation or warning.

            RFC Compliance: Captures deviations from RFC 2849/4512/4514 standards.

            Args:
                violation: Description of RFC violation (e.g., "RFC 2849 §2: DN required")
                severity: Severity level ("error" or "warning")

            Returns:
                Self for method chaining

            Example:
                >>> metadata.track_rfc_violation(
                ...     violation="RFC 4514 §2.3: Invalid escape sequence",
                ...     severity="error",
                ... )

            """
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

        def set_server_context(
            self,
            source_server: c.Ldif.LiteralTypes.ServerTypeLiteral,
            target_server: c.Ldif.LiteralTypes.ServerTypeLiteral | None = None,
        ) -> Self:
            """Set source and target server context.

            Args:
                source_server: Source LDAP server type (oid, oud, openldap, etc.)
                target_server: Target LDAP server type (optional)

            Returns:
                Self for method chaining

            Example:
                >>> metadata.set_server_context(
                ...     source_server="oid", target_server="oud"
                ... )

            """
            # Direct assignment - parameters are already ServerTypeLiteral
            self.original_server_type = source_server
            if target_server:
                self.target_server_type = target_server

            # Also store in extensions for generic access
            # Use getattr to access nested constants - helps MyPy understand the structure
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
            r"""Record original LDIF format for round-trip conversion.

            RFC Compliance: Preserves ALL original formatting details.

            Args:
                original_ldif: Complete original LDIF string
                attribute_case: Map of normalized→original attribute case

            Returns:
                Self for method chaining

            Example:
                >>> metadata.record_original_format(
                ...     original_ldif="dn: CN=test\\nCN: test\\n",
                ...     attribute_case={"cn": "CN"},
                ... )

            """
            self.original_strings["entry_original_ldif"] = original_ldif
            if attribute_case:
                # DynamicMetadata is a BaseModel with extra="allow", update via __setitem__
                for key, value in attribute_case.items():
                    self.original_attribute_case[key] = value
            return self

    # Classes are already defined above


class SchemaDiscovery(FlextLdifModelsBase):
    """Schema discovery operation configuration and state.

    Used to configure and track schema discovery operations across
    LDAP directories and servers.
    """

    server_type: c.Ldif.LiteralTypes.ServerTypeLiteral = Field(
        default="rfc",
        description="LDAP server type for discovery",
    )
    naming_contexts: list[str] = Field(
        default_factory=list,
        description="Naming contexts to discover schema from",
    )
    include_operational: bool = Field(
        default=False,
        description="Include operational attributes in discovery",
    )
    max_entries: int | None = Field(
        default=None,
        description="Maximum entries to sample for schema discovery",
    )


class SchemaLookup(FlextLdifModelsBase):
    """Schema element lookup configuration and results.

    Used for looking up specific schema elements by OID, name,
    or other criteria across different LDAP servers.
    """

    search_term: str = Field(
        description="Term to search for (OID, name, description)",
    )
    search_type: c.Ldif.LiteralTypes.ServerTypeLiteral = Field(
        default="rfc",
        description="Server type context for lookup",
    )
    element_type: str | None = Field(
        default=None,
        description="Type of element to lookup (attribute, objectclass, syntax)",
    )


# Circular dependencies resolved through proper module structure and forward references

# Rebuild Entry model to resolve forward references from parent class (FlextModelsEntity.Entry)
# The parent class has domain_events: list[FlextModelsEntity.DomainEvent] which needs resolution
# NOTE: We pass _types_namespace to provide FlextModelsEntity for resolution
FlextLdifModelsDomains.Entry.model_rebuild(
    _types_namespace={"FlextModelsEntity": FlextModelsEntity}
)


__all__ = ["FlextLdifModelsDomains"]
