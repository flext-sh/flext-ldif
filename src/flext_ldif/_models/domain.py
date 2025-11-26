"""Domain models for LDIF entities.

This module contains core domain models for LDIF processing including
Distinguished Names, Entries, and Schema elements.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

# Enable forward references for all models in this module

from __future__ import annotations

import base64
import contextlib
import logging
import re
from collections.abc import Callable, Mapping
from typing import ClassVar, Self, TypedDict, Unpack

from flext_core import (
    FlextLogger,
    FlextModels,
    FlextResult,
    FlextUtilities,
)

# No import from models.py to avoid circular import
# Use FlextLdifModelsDomains classes directly
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    computed_field,
    field_validator,
    model_validator,
)

from flext_ldif._models.base import (
    AclElement,
    SchemaElement,
)
from flext_ldif.constants import FlextLdifConstants

# Logger for domain models
logger = FlextLogger(__name__)

# Type aliases removed - use FlextLdifModelsDomains.Entry from models.py


def _create_default_quirk_metadata() -> FlextLdifModelsDomains.QuirkMetadata:
    """Create default QuirkMetadata instance for Field default_factory.

    This function is defined at module level to avoid forward reference issues
    when used in Field default_factory before the class is fully defined.
    """
    # Access the class after it's defined (at runtime, not class definition time)
    return FlextLdifModelsDomains.QuirkMetadata.create_for()


class FlextLdifModelsDomains:
    """LDIF domain models container class.

    This class acts as a namespace container for core LDIF domain models.
    All nested classes are accessed via FlextLdifModels.* in the main models.py.
    """

    class DistinguishedName(FlextModels.Value):
        """Distinguished Name value object."""

        model_config = ConfigDict(
            strict=True,
            validate_default=True,
            validate_assignment=True,
            extra="allow",
        )

        value: str = Field(
            ...,
            description="DN string value (lenient processing - no max_length)",
            # max_length removed for lenient processing - validation at Entry level
        )
        metadata: dict[str, object] = Field(
            default_factory=dict,
            description="Quirk-specific metadata for preserving original format",
        )

        _DN_COMPONENT_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
            FlextLdifConstants.LdifPatterns.DN_COMPONENT,
            re.IGNORECASE,
        )

        # NOTE: DN validation moved to Entry.validate_entry_rfc_compliance()
        # DistinguishedName is a frozen Value Object and cannot be modified after construction

        @computed_field
        def components(self) -> list[str]:
            """Parse DN into individual RDN components.

            Returns:
                List of RDN components (e.g., ['cn=test', 'ou=users', 'dc=example', 'dc=com'])

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
                # entry.dn.was_base64_encoded → True

            """
            if not self.metadata:
                return False
            return self.metadata.get("original_format") == "base64"

        def create_statistics(
            self,
            original_dn: str | None = None,
            cleaned_dn: str | None = None,
            transformations: list[str] | None = None,
            **transformation_flags: Unpack[FlextLdifModelsDomains._DNStatisticsFlags],
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
                dn = DistinguishedName(value="cn=test,dc=example,dc=com")
                stats = dn.create_statistics(
                    original_dn="cn=test  ,dc=example,dc=com",
                    transformations=[FlextLdifConstants.TransformationType.SPACE_CLEANED],
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
                if self.metadata.get("had_utf8_chars"):
                    _ = flags.setdefault("had_utf8_chars", True)
                if self.metadata.get("had_escape_sequences"):
                    _ = flags.setdefault("had_escape_sequences", True)

            return FlextLdifModelsDomains.DNStatistics.create_with_transformation(
                original_dn=orig_dn,
                cleaned_dn=clean_dn,
                normalized_dn=final_dn,
                transformations=transformations if transformations is not None else [],
                **flags,
            )

        def __str__(self) -> str:
            """Return DN value as string for str() conversion."""
            return self.value

    class ExclusionInfo(FlextModels.ArbitraryTypesModel):
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

        Represents an LDAP attribute type definition from schema with full RFC 4512 support.

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
            description="Whether users can modify this attribute (RFC 4512 NO-USER-MODIFICATION)",
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
            description="Origin of attribute definition (server-specific X-ORIGIN extension)",
        )
        x_file_ref: str | None = Field(
            default=None,
            description="File reference for attribute definition (server-specific X-FILE-REF extension)",
        )
        x_name: str | None = Field(
            default=None,
            description="Extended name for attribute (server-specific X-NAME extension)",
        )
        x_alias: str | None = Field(
            default=None,
            description="Extended alias for attribute (server-specific X-ALIAS extension)",
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
        encoding: str = Field(
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
            server_type: str = "rfc",
        ) -> Self | None:
            """Resolve a syntax OID to a Syntax model using RFC 4517 validation.

            This method is used by both models and the syntax service to avoid circular dependencies.

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
                oid_to_name = FlextLdifConstants.RfcSyntaxOids.OID_TO_NAME.copy()

                # Look up name from OID
                name = oid_to_name.get(oid)
                type_category = (
                    FlextLdifConstants.RfcSyntaxOids.NAME_TO_TYPE_CATEGORY.get(
                        name,
                        "string",
                    )
                    if name
                    else "string"
                )

                # Create metadata for server-specific handling
                metadata = (
                    FlextLdifModelsDomains.QuirkMetadata(
                        quirk_type=server_type,
                        extensions={"description": f"RFC 4517 syntax OID: {oid}"},
                    )
                    if server_type != "rfc"
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

        Represents an LDAP object class definition from schema with full RFC 4512 support.

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
        sup: str | list[str] | None = Field(
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

    class LdifAttributes(FlextModels.ArbitraryTypesModel):
        """LDIF attributes container - simplified dict-like interface."""

        model_config = ConfigDict(extra="allow")  # Allow dynamic attribute fields

        attributes: dict[str, list[str]] = Field(
            default_factory=dict,
            description="Attribute name to values list",
        )
        attribute_metadata: dict[str, dict[str, object]] = Field(
            default_factory=dict,
            description="Metadata for each attribute, like category or hidden status.",
        )
        metadata: dict[str, object] | None = Field(
            default=None,
            description="Metadata for preserving ordering and formats",
        )

        # NOTE: Attribute name validation moved to Entry.validate_entry_rfc_compliance()
        # LdifAttributes is a frozen Value Object and cannot be modified after construction

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
                default: Default list if not found (defaults to empty list if not provided)

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

        def keys(self) -> list[str]:
            """Get attribute names."""
            return list(self.attributes.keys())

        def values(self) -> list[list[str]]:
            """Get attribute values lists."""
            return list(self.attributes.values())

        def add_attribute(self, key: str, values: str | list[str]) -> None:
            """Add or update an attribute with values.

            Args:
                key: Attribute name
                values: Single value or list of values

            """
            if isinstance(values, str):
                values = [values]
            self.attributes[key] = values

        def remove_attribute(self, key: str) -> None:
            """Remove an attribute if it exists.

            Args:
                key: Attribute name

            """
            _ = self.attributes.pop(key, None)

        def to_ldap3(
            self,
            exclude: list[str] | None = None,
        ) -> dict[str, str | list[str]]:
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
            attrs_data: Mapping[str, object],
        ) -> FlextResult[FlextLdifModelsDomains.LdifAttributes]:
            """Create an LdifAttributes instance from data.

            Args:
                attrs_data: Mapping of attribute names to values (str, list[str], or object)

            Returns:
                FlextResult with LdifAttributes instance or error

            """
            try:
                # Normalize values to list[str]
                normalized_attrs: dict[str, list[str]] = {}
                for key, val in attrs_data.items():
                    if isinstance(val, list):
                        # Type guard: val is list-like, so it's iterable
                        normalized_attrs[key] = [str(v) for v in val]
                    elif isinstance(val, str):
                        normalized_attrs[key] = [val]
                    else:
                        normalized_attrs[key] = [str(val)]

                return FlextResult[FlextLdifModelsDomains.LdifAttributes].ok(
                    cls(attributes=normalized_attrs),
                )
            except (ValueError, TypeError, AttributeError) as e:
                return FlextResult[FlextLdifModelsDomains.LdifAttributes].fail(
                    f"Failed to create LdifAttributes: {e}",
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

            # Use existing attribute_metadata dict
            self.attribute_metadata[attribute_name] = {
                "status": "deleted",
                "deleted_at": FlextUtilities.Generators.generate_iso_timestamp(),
                "deleted_reason": reason,
                "deleted_by": deleted_by,
                "original_values": self.attributes[attribute_name].copy(),
            }

        def get_active_attributes(self) -> dict[str, list[str]]:
            """Get only active attributes (exclude deleted/hidden).

            MEDIUM COMPLEXITY: Filters attributes based on metadata status,
            handles missing metadata gracefully.

            Returns:
                Dict of attribute_name -> values for active attributes only

            """
            if not self.attribute_metadata:
                return dict(self.attributes)

            return {
                name: values
                for name, values in self.attributes.items()
                if self.attribute_metadata.get(name, {}).get("status", "active")
                not in {"deleted", "hidden"}
            }

        def get_deleted_attributes(self) -> dict[str, dict[str, object]]:
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

    class ErrorDetail(FlextModels.Value):
        """Error detail information for failed operations."""

        model_config = ConfigDict(
            strict=True,
            validate_default=True,
            validate_assignment=True,
            extra="allow",
        )

        item: str = Field(..., description="Item that failed")
        error: str = Field(..., description="Error message")
        error_code: str | None = Field(default=None, description="Error code")
        context: dict[str, object] = Field(default_factory=dict, description="Context")

    class DnRegistry(BaseModel):
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
            self._registry: dict[str, str] = {}
            self._case_variants: dict[str, set[str]] = {}

        def _normalize_dn(self, dn: str) -> str:
            """Convert DN to lowercase for case-insensitive dict lookup.

            NOTE: DnRegistry receives DNs already normalized to RFC 4514 format.
            This method is ONLY for dict key generation (case-insensitive lookup).
            It does NOT validate or normalize the DN - that must be done BEFORE
            calling register_dn().

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

            return self._registry[normalized]

        def get_canonical_dn(self, dn: str) -> str | None:
            """Get canonical case for a DN (case-insensitive lookup).

            Args:
                dn: Distinguished Name to lookup

            Returns:
                Canonical case DN string, or None if not registered

            """
            normalized = self._normalize_dn(dn)
            return self._registry.get(normalized)

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
            inconsistencies: list[dict[str, object]] = []

            for normalized_dn, variants in self._case_variants.items():
                if len(variants) > 1:
                    canonical = self._registry[normalized_dn]
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
            data: dict[str, object],
            dn_fields: list[str] | None = None,
        ) -> FlextResult[dict[str, object]]:
            """Normalize DN references in data object to canonical case.

            Args:
                data: Dictionary containing DN references
                dn_fields: List of field names containing DNs or DN lists.
                          If None, uses default DN fields from FlextLdifConstants.

            Returns:
                FlextResult with normalized data dict

            """
            try:
                # Use default DN-valued attributes if dn_fields not specified
                if dn_fields is None:
                    # Include 'dn' itself plus all DN-valued attributes
                    dn_fields = ["dn"] + list(
                        FlextLdifConstants.DnValuedAttributes.ALL_DN_VALUED,
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

                return FlextResult[dict[str, object]].ok(normalized_data)

            except Exception as e:
                return FlextResult[dict[str, object]].fail(
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

        def _normalize_dn_list(self, dn_list: list[object]) -> list[object]:
            """Normalize a list of DN values, preserving non-string items.

            Args:
                dn_list: List that may contain DN strings and other items

            Returns:
                List with DN strings normalized

            """
            normalized_list: list[object] = []
            for item in dn_list:
                if isinstance(item, str):
                    normalized_list.append(self._normalize_single_dn(item))
                else:
                    normalized_list.append(item)
            return normalized_list

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

    class QuirkCollection(FlextModels.Value):
        """Collection of all quirks (Schema, ACL, Entry) for a single server type.

        Stores all three quirk types together for unified access and management.
        """

        model_config = ConfigDict(
            arbitrary_types_allowed=True,
            frozen=True,
            validate_default=True,
        )

        server_type: str = Field(
            description="Server type identifier (e.g., 'oid', 'oud')",
        )
        schemas: list[object] = Field(
            default_factory=list,
            description="List of Schema quirk model instances",
        )
        acls: list[object] = Field(
            default_factory=list,
            description="List of ACL quirk model instances",
        )
        entrys: list[object] = Field(
            default_factory=list,
            description="List of Entry quirk model instances",
        )

    # =========================================================================
    # ACL MODELS - Must be defined before Entry since Entry references Acl
    # =========================================================================

    class AclPermissions(FlextModels.ArbitraryTypesModel):
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

    class AclTarget(FlextModels.ArbitraryTypesModel):
        """ACL target specification."""

        target_dn: str = Field(..., description="Target DN pattern")
        attributes: list[str] = Field(
            default_factory=list,
            description="Target attributes",
        )

    class AclSubject(FlextModels.ArbitraryTypesModel):
        """ACL subject specification."""

        subject_type: str = Field(..., description="Subject type (user, group, etc.)")
        subject_value: str = Field(..., description="Subject value/pattern")

    class Acl(AclElement):
        """Universal ACL model for all LDAP server types.

        Inherits from AclElement:
        - model_config (strict=True, validate_default=True, validate_assignment=True)
        - server_type field with default "rfc"
        - metadata field (QuirkMetadata | None)
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

            valid_server_types = {
                "rfc",
                "openldap",
                "openldap2",
                "openldap1",
                "oid",
                "oud",
                "389ds",
                "ad",
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
            if acl_is_defined and (not self.raw_acl or not self.raw_acl.strip()):
                violations.append(
                    "ACL is defined (has target/subject/permissions) but raw_acl is empty",
                )

            # Modify self in-place (Pydantic 2 best practice for mode="after")
            if violations:
                # Use object.__setattr__ to bypass Pydantic validation and avoid recursion
                object.__setattr__(self, "validation_violations", violations)  # noqa: PLC2801

            # ALWAYS return self (not a copy) - Pydantic 2 requirement
            return self

        def get_acl_format(self) -> str:
            """Get ACL format for this server type."""
            return FlextLdifConstants.AclFormats.DEFAULT_ACL_FORMAT

        def get_acl_type(self) -> str:
            """Get ACL type identifier for this server.

            Uses FROM_LONG mapping to normalize legacy long-form identifiers
            (e.g., "oracle_oid" → "oid") to short-form canonical identifiers.
            """
            # Normalize to short form using FROM_LONG dict
            short_server_type = FlextLdifConstants.ServerTypes.FROM_LONG.get(
                self.server_type,
                self.server_type,
            )
            return f"{short_server_type}_acl"

    class Entry(FlextModels.Entity):
        """LDIF entry domain model."""

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

        dn: FlextLdifModelsDomains.DistinguishedName = Field(
            ...,
            description="Distinguished Name of the entry (REQUIRED per RFC 2849 § 2)",
        )
        attributes: FlextLdifModelsDomains.LdifAttributes = Field(
            ...,
            description="Entry attributes container (REQUIRED per RFC 2849 § 2)",
        )
        changetype: str | None = Field(
            default=None,
            description="Change operation type per RFC 2849 § 5.7 (add/delete/modify/moddn/modrdn)",
        )
        metadata: FlextLdifModelsDomains.QuirkMetadata = Field(
            default_factory=_create_default_quirk_metadata,
            description="Quirk-specific metadata for processing data, ACLs, statistics, validation (non-RFC data)",
        )

        @field_validator("dn", mode="before")
        @classmethod
        def coerce_dn_from_string(
            cls,
            value: object,
        ) -> FlextLdifModelsDomains.DistinguishedName:
            """Convert string DN to DistinguishedName instance with base64 detection.

            Pydantic v2 Advanced Pattern: Emergency base64 decode at model level.

            Allows tests and direct instantiation to pass strings for DN field.
            Also handles emergency base64 decoding if parser failed to decode.

            Per RFC 2849: DN values starting with ": " indicate failed base64 decode.
            This validator provides a safety net for data quality issues.

            Args:
                value: DN value (str or DistinguishedName)

            Returns:
                DistinguishedName instance

            Raises:
                ValueError: If value is None or cannot be converted

            """
            if value is None:
                msg = "DN cannot be None (required per RFC 2849 § 2)"
                raise ValueError(msg)

            if isinstance(value, FlextLdifModelsDomains.DistinguishedName):
                return value

            if isinstance(value, str):
                # Emergency base64 decode detection (fallback if parser failed)
                # RFC 2849: ": base64..." indicates malformed LDIF that needs fixing
                if value.startswith(": "):
                    # Try to decode base64 (emergency recovery)
                    original_value = value
                    with contextlib.suppress(Exception):
                        # Remove ": " prefix and decode
                        base64_str = value[2:].strip()
                        value = base64.b64decode(base64_str).decode("utf-8")

                    # If decode succeeded, log warning about LDIF quality
                    if value != original_value:
                        logging.getLogger(__name__).warning(
                            "Emergency base64 decode in Entry model. DN was not decoded by parser: %s...",
                            original_value[:50],
                        )

                return FlextLdifModelsDomains.DistinguishedName(value=value)

            msg = f"DN must be str or DistinguishedName, got {type(value).__name__}"
            raise ValueError(msg)

        @model_validator(mode="after")
        def validate_entry_consistency(self) -> FlextLdifModelsDomains.Entry:
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

        def _validate_dn(self, dn_value: str) -> list[str]:
            """Validate DN format per RFC 4514 § 2.3, 2.4.

            Note: dn_value is guaranteed to be non-None since dn field is required.
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
                FlextLdifConstants.LdifPatterns.DN_COMPONENT,
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
            if not self.attributes.attributes:
                violations.append(
                    "RFC 2849 § 2: Entry must have at least one attribute (empty)",
                )
            return violations

        def _validate_attribute_descriptions(self) -> list[str]:
            """Validate attribute descriptions per RFC 4512 § 2.5.

            Note: self.attributes may be None when using model_construct (bypasses validation).
            """
            violations: list[str] = []
            if self.attributes is None or not self.attributes.attributes:
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
            if (
                self.attributes is None
                or is_schema_entry
                or not self.attributes.attributes
            ):
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
            if (
                not dn_value
                or self.attributes is None
                or not self.attributes.attributes
            ):
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
            if self.attributes is None or not self.attributes.attributes:
                return violations

            for attr_name, attr_values in self.attributes.attributes.items():
                if ";binary" in attr_name.lower():
                    continue
                for value in attr_values:
                    has_binary = any(
                        (
                            ord(c) < FlextLdifConstants.ASCII_SPACE_CHAR
                            and c not in "\t\n\r"
                        )
                        or ord(c) > FlextLdifConstants.ASCII_TILDE_CHAR
                        for c in value
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
            if self.attributes is None or not self.attributes.attributes:
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
        def validate_entry_rfc_compliance(self) -> FlextLdifModelsDomains.Entry:
            """Validate Entry RFC compliance - capture violations, DON'T reject.

            RFC 2849 § 2: DN and at least one attribute required
            RFC 4514 § 2.3, 2.4: DN format validation
            RFC 4512 § 2.5: Attribute name format validation

            Strategy: PRESERVE problematic entries for round-trip conversions,
            capture violations in validation_metadata for downstream handling.
            """
            # Collect violations from all validators
            violations: list[str] = []

            # Handle case where dn might be None (e.g., model_construct)
            if self.dn is None:
                violations.append("RFC 2849 § 2.1: DN is required")
                # Capture violations in validation_metadata (default_factory ensures dict exists)
                if violations:
                    self.metadata.validation_results["rfc_violations"] = violations
                return self
            dn_value = str(self.dn.value)
            violations.extend(self._validate_dn(dn_value))
            violations.extend(self._validate_attributes_required())
            violations.extend(self._validate_attribute_descriptions())
            violations.extend(self._validate_objectclass(dn_value))
            violations.extend(self._validate_naming_attribute(dn_value))
            violations.extend(self._validate_binary_options())
            violations.extend(self._validate_attribute_syntax())
            violations.extend(self._validate_changetype())

            # Capture violations in validation_metadata (default_factory ensures dict exists)
            if violations:
                self.metadata.validation_results["rfc_violations"] = violations
                attribute_count = (
                    len(self.attributes.attributes) if self.attributes else 0
                )
                self.metadata.validation_results["validation_context"] = {
                    "validator": "validate_entry_rfc_compliance",
                    "dn": dn_value,
                    "attribute_count": attribute_count,
                    "total_violations": len(violations),
                }

                # ALSO store violations in metadata.extensions for server conversions
                # Metadata is always initialized via default_factory, so it's never None
                self.metadata.extensions["rfc_violations"] = violations

            return self

        def _check_objectclass_rule(
            self,
            rules: dict[str, object],
            dn_value: str,
        ) -> list[str]:
            """Check objectClass requirement from server rules."""
            violations: list[str] = []
            if not rules.get("requires_objectclass"):
                return violations

            # Note: self.attributes is guaranteed to be non-None since it's a required field
            has_objectclass = (
                any(
                    attr_name.lower() == "objectclass"
                    for attr_name in self.attributes.attributes
                )
                if self.attributes.attributes
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
            rules: dict[str, object],
            dn_value: str,
        ) -> list[str]:
            """Check naming attribute requirement from server rules."""
            violations: list[str] = []
            # Note: self.attributes is guaranteed to be non-None since it's a required field
            if (
                not rules.get("requires_naming_attr")
                or not dn_value
                or not self.attributes.attributes
            ):
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
            rules: dict[str, object],
        ) -> list[str]:
            """Check binary attribute option requirement from server rules."""
            violations: list[str] = []
            # Note: self.attributes is guaranteed to be non-None since it's a required field
            if (
                not rules.get("requires_binary_option")
                or rules.get("auto_detect_binary")
                or not self.attributes.attributes
            ):
                return violations

            for attr_name, attr_values in self.attributes.attributes.items():
                if ";binary" in attr_name.lower():
                    continue
                for value in attr_values:
                    if any(
                        ord(c) < FlextLdifConstants.ASCII_SPACE_CHAR
                        or ord(c) > FlextLdifConstants.ASCII_TILDE_CHAR
                        for c in value
                    ):
                        violations.append(
                            f"Server requires ';binary' option for '{attr_name}'",
                        )
                        break
            return violations

        @model_validator(mode="after")
        def validate_server_specific_rules(self) -> FlextLdifModelsDomains.Entry:
            """Validate Entry using server-injected validation rules."""
            # Check if server injected validation rules
            if not self.metadata:
                return self
            if "validation_rules" not in self.metadata.extensions:
                return self

            # Get server-injected validation rules
            validation_rules = self.metadata.extensions.get("validation_rules")
            if not isinstance(validation_rules, dict):
                return self

            # Type guard: validation_rules passed is_dict_like check
            rules = validation_rules
            dn_value = str(self.dn.value) if self.dn else ""

            # Collect violations from all rule checkers
            server_violations: list[str] = []
            server_violations.extend(self._check_objectclass_rule(rules, dn_value))
            server_violations.extend(self._check_naming_attr_rule(rules, dn_value))
            server_violations.extend(self._check_binary_option_rule(rules))

            # ALWAYS store validation_server_type when rules were checked
            if self.metadata:
                self.metadata.extensions["validation_server_type"] = (
                    self.metadata.quirk_type
                )

            # Store server-specific violations in validation_metadata (if any)
            if server_violations:
                # default_factory ensures dict exists
                self.metadata.validation_results["server_specific_violations"] = (
                    server_violations
                )
                if self.metadata:
                    self.metadata.validation_results["validation_server_type"] = (
                        self.metadata.quirk_type
                    )
                    self.metadata.extensions["server_specific_violations"] = (
                        server_violations
                    )

            return self

        @computed_field
        def unconverted_attributes(self) -> dict[str, object]:
            """Get unconverted attributes from metadata extensions (read-only view, DRY pattern)."""
            result = (
                self.metadata.extensions.get("unconverted_attributes", {})
                if self.metadata
                else {}
            )
            # Type guard: ensure we return dict[str, object]
            if isinstance(result, dict):
                return result
            return {}

        class Builder:
            """Builder pattern for Entry creation (reduces complexity, improves readability)."""

            def __init__(self) -> None:
                """Initialize builder."""
                super().__init__()
                self._dn: str | FlextLdifModelsDomains.DistinguishedName | None = None
                self._attributes: (
                    dict[str, str | list[str]]
                    | FlextLdifModelsDomains.LdifAttributes
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
                self._entry_metadata: dict[str, object] | None = None
                self._validation_metadata: dict[str, object] | None = None
                self._server_type: str | None = None
                self._source_entry: str | None = None
                self._unconverted_attributes: dict[str, object] | None = None

            def dn(
                self,
                dn: str | FlextLdifModelsDomains.DistinguishedName,
            ) -> FlextLdifModelsDomains.Entry.Builder:
                self._dn = dn
                return self

            def attributes(
                self,
                attributes: dict[str, str | list[str]]
                | FlextLdifModelsDomains.LdifAttributes,
            ) -> FlextLdifModelsDomains.Entry.Builder:
                self._attributes = attributes
                return self

            def metadata(
                self,
                metadata: FlextLdifModelsDomains.QuirkMetadata,
            ) -> FlextLdifModelsDomains.Entry.Builder:
                self._metadata = metadata
                return self

            def acls(
                self,
                acls: list[FlextLdifModelsDomains.Acl],
            ) -> FlextLdifModelsDomains.Entry.Builder:
                self._acls = acls
                return self

            def objectclasses(
                self,
                objectclasses: list[FlextLdifModelsDomains.SchemaObjectClass],
            ) -> FlextLdifModelsDomains.Entry.Builder:
                self._objectclasses = objectclasses
                return self

            def attributes_schema(
                self,
                attributes_schema: list[FlextLdifModelsDomains.SchemaAttribute],
            ) -> FlextLdifModelsDomains.Entry.Builder:
                self._attributes_schema = attributes_schema
                return self

            def entry_metadata(
                self,
                entry_metadata: dict[str, object],
            ) -> FlextLdifModelsDomains.Entry.Builder:
                self._entry_metadata = entry_metadata
                return self

            def validation_metadata(
                self,
                validation_metadata: dict[str, object],
            ) -> FlextLdifModelsDomains.Entry.Builder:
                self._validation_metadata = validation_metadata
                return self

            def server_type(
                self,
                server_type: str,
            ) -> FlextLdifModelsDomains.Entry.Builder:
                self._server_type = server_type
                return self

            def source_entry(
                self,
                source_entry: str,
            ) -> FlextLdifModelsDomains.Entry.Builder:
                self._source_entry = source_entry
                return self

            def unconverted_attributes(
                self,
                unconverted_attributes: dict[str, object],
            ) -> FlextLdifModelsDomains.Entry.Builder:
                self._unconverted_attributes = unconverted_attributes
                return self

            def build(self) -> FlextResult[FlextLdifModelsDomains.Entry]:
                """Build the Entry using the accumulated parameters."""
                if self._dn is None or self._attributes is None:
                    return FlextResult[FlextLdifModelsDomains.Entry].fail(
                        "DN and attributes are required",
                    )

                return FlextLdifModelsDomains.Entry.create(
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
        def builder(cls) -> FlextLdifModelsDomains.Entry.Builder:
            """Create a new Entry builder instance."""
            return cls.Builder()

        @classmethod
        def create(
            cls,
            dn: str | FlextLdifModelsDomains.DistinguishedName,
            attributes: (
                dict[str, str | list[str]] | FlextLdifModelsDomains.LdifAttributes
            ),
            metadata: FlextLdifModelsDomains.QuirkMetadata | None = None,
            acls: list[FlextLdifModelsDomains.Acl] | None = None,
            objectclasses: list[FlextLdifModelsDomains.SchemaObjectClass] | None = None,
            attributes_schema: list[FlextLdifModelsDomains.SchemaAttribute]
            | None = None,
            entry_metadata: dict[str, object] | None = None,
            validation_metadata: dict[str, object] | None = None,
            server_type: str | None = None,  # New parameter
            source_entry: str | None = None,  # New parameter
            unconverted_attributes: dict[str, object] | None = None,  # New parameter
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
        def _normalize_dn(
            cls,
            dn: str | FlextLdifModelsDomains.DistinguishedName,
        ) -> FlextLdifModelsDomains.DistinguishedName:
            """Normalize DN to DistinguishedName object.

            Args:
                dn: DN as string or DistinguishedName object

            Returns:
                DistinguishedName object (validated by Pydantic)

            Note:
                Lenient processing: Empty DN is accepted and will be captured
                in validation_metadata as RFC violation.

            """
            if dn is None:
                msg = "DN cannot be None (required per RFC 2849 § 2)"
                raise ValueError(msg)

            if isinstance(dn, str):
                # Lenient processing: Accept empty DN (violation captured in validation_metadata)
                # Empty string is valid DistinguishedName value (Pydantic allows it)
                return FlextLdifModelsDomains.DistinguishedName(value=dn)

            return dn

        @classmethod
        def _normalize_attributes(
            cls,
            attributes: (
                dict[str, str | list[str]] | FlextLdifModelsDomains.LdifAttributes
            ),
        ) -> FlextLdifModelsDomains.LdifAttributes:
            """Normalize attributes to LdifAttributes object.

            Args:
                attributes: Attributes as dict or LdifAttributes object

            Returns:
                LdifAttributes object with normalized values

            Note:
                Lenient processing: Empty attributes dict is accepted and will be captured
                in validation_metadata as RFC violation.

            """
            if attributes is None:
                msg = "Attributes cannot be None (required per RFC 2849 § 2)"
                raise ValueError(msg)

            if isinstance(attributes, dict):
                # Lenient processing: Accept empty dict (violation captured in validation_metadata)
                # Empty dict is valid LdifAttributes (Pydantic allows it)
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
                return FlextLdifModelsDomains.LdifAttributes(
                    attributes=attrs_dict,
                )

            # Already LdifAttributes instance
            if isinstance(attributes, FlextLdifModelsDomains.LdifAttributes):
                return attributes
            # Should not reach here, but ensure return type
            msg = f"Attributes must be dict or LdifAttributes, got {type(attributes).__name__}"
            raise TypeError(msg)

        @classmethod
        def _build_metadata(
            cls,
            metadata: FlextLdifModelsDomains.QuirkMetadata | None,
            server_type: str | None,
            source_entry: str | None,
            unconverted_attributes: dict[str, object] | None,
        ) -> FlextLdifModelsDomains.QuirkMetadata | None:
            """Build or update metadata with server-specific extensions.

            Args:
                metadata: Existing metadata or None
                server_type: Optional server type
                source_entry: Optional original source entry
                unconverted_attributes: Optional unconverted attributes

            Returns:
                Created/updated metadata or None

            """
            # Check if any new metadata needs to be added
            has_new_metadata = server_type or source_entry or unconverted_attributes

            if metadata is None and has_new_metadata:
                # Create new metadata
                extensions_dict: dict[str, object] = {}
                if server_type:
                    extensions_dict["server_type"] = server_type
                if source_entry:
                    extensions_dict["source_entry"] = source_entry
                if unconverted_attributes:
                    extensions_dict["unconverted_attributes"] = unconverted_attributes
                return FlextLdifModelsDomains.QuirkMetadata(
                    quirk_type="entry_builder",
                    extensions=extensions_dict,
                )
            if metadata is not None and has_new_metadata:
                # Update existing metadata
                if server_type:
                    metadata.extensions["server_type"] = server_type
                if source_entry:
                    metadata.extensions["source_entry"] = source_entry
                if unconverted_attributes:
                    metadata.extensions["unconverted_attributes"] = (
                        unconverted_attributes
                    )

            return metadata

        @classmethod
        def _create_entry(
            cls,
            dn: str | FlextLdifModelsDomains.DistinguishedName,
            attributes: (
                dict[str, str | list[str]] | FlextLdifModelsDomains.LdifAttributes
            ),
            metadata: FlextLdifModelsDomains.QuirkMetadata | None = None,
            acls: list[FlextLdifModelsDomains.Acl] | None = None,
            objectclasses: list[FlextLdifModelsDomains.SchemaObjectClass] | None = None,
            attributes_schema: list[FlextLdifModelsDomains.SchemaAttribute]
            | None = None,
            entry_metadata: dict[str, object] | None = None,
            validation_metadata: dict[str, object] | None = None,
            server_type: str | None = None,  # New parameter
            source_entry: str | None = None,  # New parameter
            unconverted_attributes: dict[str, object] | None = None,  # New parameter
            statistics: FlextLdifModelsDomains.EntryStatistics
            | None = None,  # New parameter
        ) -> FlextResult[Self]:
            """Internal method for Entry creation with composition fields.

            Args:
            dn: Distinguished Name for the entry
            attributes: Entry attributes as dict[str, list[str]] or LdifAttributes
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
                # Normalize DN to DistinguishedName object
                dn_obj = cls._normalize_dn(dn)

                # Normalize attributes to LdifAttributes object
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
                entry_data: dict[str, object] = {
                    FlextLdifConstants.DictKeys.DN: dn_obj,
                    FlextLdifConstants.DictKeys.ATTRIBUTES: attrs_obj,
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
            ldap3_entry: object,
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
                entry_attrs_raw: dict[str, object] = (
                    getattr(ldap3_entry, "entry_attributes_as_dict", {})
                    if hasattr(ldap3_entry, "entry_attributes_as_dict")
                    else {}
                )

                # Normalize to dict[str, list[str]] (ensure all values are lists of strings)
                attrs_dict: dict[str, list[str]] = {}
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
                # attrs_dict is already dict[str, list[str]], convert to dict[str, str | list[str]]
                # Entry.create accepts dict[str, str | list[str]], so we can use attrs_dict directly
                # since list[str] is compatible with str | list[str]
                attrs_typed: dict[str, str | list[str]] = dict(attrs_dict.items())
                return cls.create(
                    dn=dn_str,
                    attributes=attrs_typed,
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
            # Note: self.attributes is guaranteed to be non-None since it's a required field
            attr_name_lower = attribute_name.lower()
            for stored_name, attr_values in self.attributes.attributes.items():
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
                FlextLdifConstants.DictKeys.OBJECTCLASS,
            )

        def get_all_attribute_names(self) -> list[str]:
            """Get list of all attribute names in the entry.

            Returns:
            List of attribute names (case as stored in entry)

            """
            # Note: self.attributes is guaranteed to be non-None since it's a required field
            return list(self.attributes.attributes.keys())

        def get_all_attributes(self) -> dict[str, list[str]]:
            """Get all attributes as dictionary.

            Returns:
            Dictionary of attribute_name -> list[str] (deep copy)

            """
            # Note: self.attributes is guaranteed to be non-None since it's a required field
            return dict(self.attributes.attributes)

        def count_attributes(self) -> int:
            """Count the number of attributes in the entry.

            Returns:
            Number of attributes (including multivalued attributes count as 1)

            """
            # Note: self.attributes is guaranteed to be non-None since it's a required field
            return len(self.attributes.attributes)

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

        def clone(self) -> FlextLdifModelsDomains.Entry:
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
            return bool(self.metadata.objectclasses)

        @computed_field
        def is_acl_entry(self) -> bool:
            """Check if entry has Access Control Lists.

            Returns:
            True if entry has ACLs, False otherwise

            """
            return bool(self.metadata.acls)

        @computed_field
        def has_validation_errors(self) -> bool:
            """Check if entry has validation errors.

            Returns:
            True if entry has validation errors in validation_metadata, False otherwise

            """
            if (
                not self.metadata.validation_results
                or len(self.metadata.validation_results) == 0
            ):
                return False
            return bool(self.metadata.validation_results.get("errors"))

        def get_objectclass_names(self) -> list[str]:
            """Get list of objectClass attribute values from entry."""
            return self.get_attribute_values(FlextLdifConstants.DictKeys.OBJECTCLASS)

        def get_entries(self) -> list[FlextLdifModelsDomains.Entry]:
            """Get this entry as a list for unified protocol.

            Returns:
                List containing this entry

            """
            # Convert domain entry to public facade entry
            return [
                FlextLdifModelsDomains.Entry(
                    dn=FlextLdifModelsDomains.DistinguishedName(
                        value=self.dn.value
                        if hasattr(self.dn, "value")
                        else str(self.dn)
                    ),
                    attributes=FlextLdifModelsDomains.LdifAttributes(
                        attributes=dict(self.attributes.attributes)
                        if hasattr(self.attributes, "attributes")
                        else dict(self.attributes)
                    ),
                )
            ]

    class AttributeTransformation(BaseModel):
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
        transformation_type: str = Field(
            ...,
            description="Type of transformation: renamed, removed, modified, added",
        )
        reason: str = Field(
            default="",
            description="Human-readable reason for transformation",
        )

        @field_validator("transformation_type")
        @classmethod
        def validate_transformation_type(cls, v: str) -> str:
            """Validate transformation type is one of the allowed values."""
            allowed_types = {"renamed", "removed", "modified", "added"}
            if v not in allowed_types:
                msg = (
                    f"Invalid transformation_type '{v}'. "
                    f"Must be one of: {', '.join(sorted(allowed_types))}"
                )
                raise ValueError(msg)
            return v

    class QuirkMetadata(BaseModel):
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

        quirk_type: str = Field(
            ...,
            description="Type of quirk this metadata represents",
        )
        extensions: dict[str, object] = Field(
            default_factory=dict,
            description="Extensible metadata storage for quirk-specific data",
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

        conversion_notes: dict[str, str] = Field(
            default_factory=dict,
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

        server_specific_data: dict[str, object] = Field(
            default_factory=dict,
            description="Preservation of server-proprietary data for round-trip conversions",
        )
        original_server_type: str | None = Field(
            default=None,
            description="Source LDAP server type (e.g., 'oid', 'oud', 'ad', 'openldap')",
        )
        target_server_type: str | None = Field(
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
        validation_results: dict[str, object] = Field(
            default_factory=dict,
            description="Validation results and metadata from entry processing (was validation_metadata)",
        )
        processing_stats: FlextLdifModelsDomains.EntryStatistics | None = Field(
            default=None,
            description="Complete statistics tracking for entry transformations (was statistics)",
        )
        write_options: dict[str, object] = Field(
            default_factory=dict,
            description="Writer configuration options (was entry_metadata._write_options)",
        )
        removed_attributes: dict[str, list[str]] = Field(
            default_factory=dict,
            description="Attributes removed during conversion (was entry_metadata.removed_attributes_with_values)",
        )

        # =====================================================================
        # ZERO DATA LOSS TRACKING (Phase 2: Round-trip Support)
        # =====================================================================
        # These fields ensure no data is lost during OID↔OUD↔RFC conversions.
        # All original formats are preserved for perfect round-trip fidelity.

        original_format_details: dict[str, object] = Field(
            default_factory=dict,
            description=(
                "Preservation of original formatting for round-trip: "
                "{'dn_spacing': 'cn=test, dc=example', "
                "'boolean_format': '0/1', "
                "'aci_indentation': [...], "
                "'objectclass_case': {'person': 'Person'}, "
                "'syntax_quotes': True, "
                "'syntax_spacing': '  ', "
                "'attribute_case': 'attributetypes', "
                "'objectclass_case': 'objectclasses', "
                "'name_format': 'single', "
                "'x_origin_presence': False}"
            ),
        )
        # =====================================================================
        # SCHEMA FORMATTING DETAILS (Complete Round-trip Fidelity)
        # =====================================================================
        # These fields capture EVERY minimal difference in schema definitions
        # to ensure perfect round-trip conversion between OID/OUD/RFC

        schema_format_details: dict[str, object] = Field(
            default_factory=dict,
            description=(
                "Complete schema formatting preservation for zero data loss: "
                "{'syntax_quotes': True, "  # OID uses SYNTAX '1.2.3', OUD/RFC use SYNTAX 1.2.3
                "'syntax_spacing': '  ', "  # Spaces after SYNTAX (OID has 2 spaces, OUD has 0)
                "'syntax_spacing_before': '', "  # Spaces before SYNTAX keyword
                "'attribute_case': 'attributetypes', "  # attributetypes vs attributeTypes
                "'objectclass_case': 'objectclasses', "  # objectclasses vs objectClasses
                "'name_format': 'single', "  # 'single' vs 'multiple' (NAME 'uid' vs NAME ( 'uid' 'userid' ))
                "'name_values': ['uid'], "  # Original name values if multiple
                "'x_origin_presence': False, "  # Whether X-ORIGIN was present
                "'x_origin_value': None, "  # Original X-ORIGIN value if present
                "'obsolete_presence': False, "  # Whether OBSOLETE was present
                "'obsolete_position': None, "  # Position of OBSOLETE in definition
                "'equality_presence': True, "  # Whether EQUALITY was present
                "'substr_presence': True, "  # Whether SUBSTR was present
                "'ordering_presence': False, "  # Whether ORDERING was present
                "'field_order': ['OID', 'NAME', 'EQUALITY', 'SUBSTR', 'SYNTAX'], "  # Original field order
                "'spacing_between_fields': {'NAME_EQUALITY': ' ', 'EQUALITY_SUBSTR': ' '}, "  # Spaces between fields
                "'trailing_spaces': '  ', "  # Trailing spaces after closing paren
                "'original_string_complete': '( 0.9.2342... )  '}"  # Complete original string with ALL formatting
            ),
        )
        soft_delete_markers: list[str] = Field(
            default_factory=list,
            description=(
                "Attributes soft-deleted during conversion (can be restored). "
                "Different from removed_attributes: these are intentionally hidden "
                "for target server but preserved for reverse conversion."
            ),
        )
        original_attribute_case: dict[str, str] = Field(
            default_factory=dict,
            description=(
                "Original case of attribute names: {'objectclass': 'objectClass', "
                "'cn': 'CN'}. Used to restore original case during reverse conversion."
            ),
        )
        schema_quirks_applied: list[str] = Field(
            default_factory=list,
            description=(
                "List of schema quirks applied during parsing: "
                "['matching_rule_normalization', 'syntax_oid_conversion', 'schema_dn_quirk']"
            ),
        )
        boolean_conversions: dict[str, dict[str, str]] = Field(
            default_factory=dict,
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

        minimal_differences: dict[str, dict[str, object]] = Field(
            default_factory=dict,
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
        original_strings: dict[str, str] = Field(
            default_factory=dict,
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
        conversion_history: list[dict[str, object]] = Field(
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
            quirk_type: str | None = None,
            extensions: dict[str, object] | None = None,
        ) -> Self:
            """Factory method to create QuirkMetadata with extensions.

            Args:
                quirk_type: Quirk type identifier. Defaults to RFC if not provided.
                extensions: Extensions dictionary. Defaults to empty dict if not provided.

            Returns:
                QuirkMetadata instance with defaults from Constants.

            """
            # Use Constants default for quirk_type if not provided
            default_quirk_type = (
                quirk_type
                if quirk_type is not None
                else FlextLdifConstants.ServerTypes.RFC
            )
            # Use empty dict as default value, not fallback
            extensions_dict: dict[str, object] = (
                extensions if extensions is not None else {}
            )
            return cls(
                quirk_type=default_quirk_type,
                extensions=extensions_dict,
            )

        def track_attribute_transformation(
            self,
            original_name: str,
            new_name: str | None,
            transformation_type: str,
            original_values: list[str] | None = None,
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
                ...     transformation_type="renamed",
                ...     reason="OID→OUD attribute mapping"
                ... )

            """
            transformation = FlextLdifModelsDomains.AttributeTransformation(
                original_name=original_name,
                new_name=new_name,
                transformation_type=transformation_type,
                original_values=original_values or [],
                new_values=new_values or [],
            )
            self.attribute_transformations[original_name] = transformation

            # Add conversion note for audit trail
            note_key = f"attr_{original_name}_{transformation_type}"
            self.conversion_notes[note_key] = reason or f"{transformation_type}: {original_name} → {new_name}"

            return self

        def track_attribute_removal(
            self,
            attribute_name: str,
            values: list[str],
            reason: str | None = None,
        ) -> Self:
            """Track an attribute removal in metadata.

            RFC Compliance: Preserves removed attribute data for round-trip conversions.
            Uses FlextLdifConstants.MetadataKeys.SKIPPED_ATTRIBUTES tracking.

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
                ...     reason="OID-specific operational attribute"
                ... )

            """
            self.removed_attributes[attribute_name] = values
            return self.track_attribute_transformation(
                original_name=attribute_name,
                new_name=None,
                transformation_type="removed",
                original_values=values,
                reason=reason,
            )

        def track_dn_transformation(
            self,
            original_dn: str,
            transformed_dn: str,
            transformation_type: str = "normalized",
            was_base64: bool = False,
            escapes_applied: list[str] | None = None,
        ) -> Self:
            """Track a DN transformation in metadata.

            RFC 4514 Compliance: Tracks DN normalization and transformations.
            Uses FlextLdifConstants.Rfc.META_DN_* keys.

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
                ...     transformation_type="normalized",
                ... )

            """
            from flext_ldif import FlextLdifConstants

            self.original_strings[FlextLdifConstants.Rfc.META_DN_ORIGINAL] = original_dn
            self.extensions[FlextLdifConstants.Rfc.META_DN_WAS_BASE64] = was_base64
            if escapes_applied:
                self.extensions[FlextLdifConstants.Rfc.META_DN_ESCAPES_APPLIED] = escapes_applied

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
                ...     severity="error"
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
                ...     description="Converted OID ACL format to RFC 4515 filter"
                ... )

            """
            self.conversion_notes[operation] = description
            return self

        def set_server_context(
            self,
            source_server: str,
            target_server: str | None = None,
        ) -> Self:
            """Set source and target server context.

            Args:
                source_server: Source LDAP server type (oid, oud, openldap, etc.)
                target_server: Target LDAP server type (optional)

            Returns:
                Self for method chaining

            Example:
                >>> metadata.set_server_context(
                ...     source_server="oid",
                ...     target_server="oud"
                ... )

            """
            from flext_ldif import FlextLdifConstants

            self.original_server_type = source_server
            self.target_server_type = target_server

            # Also store in extensions for generic access
            self.extensions[FlextLdifConstants.Rfc.META_TRANSFORMATION_SOURCE] = source_server
            if target_server:
                self.extensions[FlextLdifConstants.Rfc.META_TRANSFORMATION_TARGET] = target_server

            return self

        def record_original_format(
            self,
            original_ldif: str,
            attribute_case: dict[str, str] | None = None,
        ) -> Self:
            """Record original LDIF format for round-trip conversion.

            RFC Compliance: Preserves ALL original formatting details.

            Args:
                original_ldif: Complete original LDIF string
                attribute_case: Map of normalized→original attribute case

            Returns:
                Self for method chaining

            Example:
                >>> metadata.record_original_format(
                ...     original_ldif="dn: CN=test\\nCN: test\\n",
                ...     attribute_case={"cn": "CN"}
                ... )

            """
            self.original_strings["entry_original_ldif"] = original_ldif
            if attribute_case:
                self.original_attribute_case.update(attribute_case)
            return self

    class _DNStatisticsFlags(TypedDict, total=False):
        """Optional flags for DNStatistics.create_with_transformation()."""

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

    class DNStatistics(BaseModel):
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
            default=FlextLdifConstants.ValidationStatus.VALID,
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
        ) -> FlextLdifModelsDomains.DNStatistics:
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
            **flags: Unpack[FlextLdifModelsDomains._DNStatisticsFlags],
        ) -> FlextLdifModelsDomains.DNStatistics:
            """Create statistics with transformation details.

            Args:
                original_dn: Original DN string
                cleaned_dn: Cleaned DN string
                normalized_dn: Normalized DN string
                transformations: List of transformation types applied
                **flags: Optional DNStatistics fields (type-safe via _DNStatisticsFlags)

            """
            return cls(
                original_dn=original_dn,
                cleaned_dn=cleaned_dn,
                normalized_dn=normalized_dn,
                transformations=transformations if transformations is not None else [],
                **flags,
            )

    class EntryStatistics(BaseModel):
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
        quirks_applied: list[str] = Field(
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
        ) -> FlextLdifModelsDomains.EntryStatistics:
            """Create minimal statistics for newly parsed entry."""
            return cls(was_parsed=True)

        @classmethod
        def create_with_dn_stats(
            cls,
            dn_statistics: FlextLdifModelsDomains.DNStatistics,
        ) -> FlextLdifModelsDomains.EntryStatistics:
            """Create statistics with DN transformation details."""
            return cls(
                was_parsed=True,
                dn_statistics=dn_statistics,
            )

        def mark_validated(self) -> FlextLdifModelsDomains.EntryStatistics:
            """Mark entry as validated.

            Returns new instance with was_validated=True (frozen model).
            """
            return self.model_copy(update={"was_validated": True})

        def mark_filtered(
            self,
            filter_type: str,
            *,
            passed: bool,
        ) -> FlextLdifModelsDomains.EntryStatistics:
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
        ) -> FlextLdifModelsDomains.EntryStatistics:
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

        def add_error(self, error: str) -> FlextLdifModelsDomains.EntryStatistics:
            """Add error message.

            Returns new instance with error added (frozen model).
            """
            errors = [*self.errors, error]
            return self.model_copy(update={"errors": errors})

        def add_warning(self, warning: str) -> FlextLdifModelsDomains.EntryStatistics:
            """Add warning message.

            Returns new instance with warning added (frozen model).
            """
            warnings = [*self.warnings, warning]
            return self.model_copy(update={"warnings": warnings})

        def track_attribute_change(
            self,
            attr_name: str,
            change_type: str,
        ) -> FlextLdifModelsDomains.EntryStatistics:
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
            quirk_type: str,
        ) -> FlextLdifModelsDomains.EntryStatistics:
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
