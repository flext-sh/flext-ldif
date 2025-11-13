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
from collections.abc import Callable, Iterator, Mapping
from datetime import UTC, datetime
from typing import ClassVar, cast

from flext_core import (
    FlextLogger,
    FlextModels,
    FlextResult,
)
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    computed_field,
    field_validator,
    model_validator,
)

from flext_ldif.constants import FlextLdifConstants

# Logger for domain models
logger = FlextLogger(__name__)

# Type aliases removed - use FlextLdifModelsDomains.Entry from models.py


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
            description="DN string value",
            max_length=FlextLdifConstants.LdifValidation.MAX_DN_LENGTH,
        )
        metadata: dict[str, object] | None = Field(
            default=None,
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

        @computed_field
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

    class SchemaAttribute(FlextModels.ArbitraryTypesModel):
        """LDAP schema attribute definition model (RFC 4512 compliant).

        Represents an LDAP attribute type definition from schema with full RFC 4512 support.
        """

        name: str = Field(..., description="Attribute name")
        oid: str = Field(..., description="Attribute OID")
        desc: str | None = Field(
            None,
            description="Attribute description (RFC 4512 DESC)",
        )
        sup: str | None = Field(
            None,
            description="Superior attribute type (RFC 4512 SUP)",
        )
        equality: str | None = Field(
            None,
            description="Equality matching rule (RFC 4512 EQUALITY)",
        )
        ordering: str | None = Field(
            None,
            description="Ordering matching rule (RFC 4512 ORDERING)",
        )
        substr: str | None = Field(
            None,
            description="Substring matching rule (RFC 4512 SUBSTR)",
        )
        syntax: str | None = Field(
            None,
            description="Attribute syntax OID (RFC 4512 SYNTAX)",
        )
        length: int | None = Field(None, description="Maximum length constraint")
        usage: str | None = Field(None, description="Attribute usage (RFC 4512 USAGE)")
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
            None,
            description="Origin of attribute definition (server-specific X-ORIGIN extension)",
        )
        x_file_ref: str | None = Field(
            None,
            description="File reference for attribute definition (server-specific X-FILE-REF extension)",
        )
        x_name: str | None = Field(
            None,
            description="Extended name for attribute (server-specific X-NAME extension)",
        )
        x_alias: str | None = Field(
            None,
            description="Extended alias for attribute (server-specific X-ALIAS extension)",
        )
        x_oid: str | None = Field(
            None,
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
            return FlextLdifModelsDomains.Syntax.resolve_syntax_oid(
                self.syntax,
                server_type="rfc",
            )

    class Syntax(FlextModels.ArbitraryTypesModel):
        """LDAP attribute syntax definition model (RFC 4517 compliant).

        Represents an LDAP attribute syntax OID and its validation rules per RFC 4517.
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

        @staticmethod
        def resolve_syntax_oid(
            oid: str,
            server_type: str = "rfc",
        ) -> FlextLdifModelsDomains.Syntax | None:
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
                return FlextLdifModelsDomains.Syntax(
                    oid=oid,
                    name=name,
                    desc=None,
                    type_category=type_category,
                    max_length=None,
                    validation_pattern=None,
                    metadata=metadata,
                )

            except (ImportError, Exception):
                # Return None for any resolution errors
                # This prevents the model from being invalid due to service failures
                return None

    class SchemaObjectClass(FlextModels.ArbitraryTypesModel):
        """LDAP schema object class definition model (RFC 4512 compliant).

        Represents an LDAP object class definition from schema with full RFC 4512 support.
        """

        name: str = Field(..., description="Object class name")
        oid: str = Field(..., description="Object class OID")
        desc: str | None = Field(
            None,
            description="Object class description (RFC 4512 DESC)",
        )
        sup: str | list[str] | None = Field(
            None,
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

        def __iter__(self) -> Iterator[str]:
            """Iterate over attribute names (intentionally overrides BaseModel).

            BaseModel.__iter__ yields (name, value) tuples, but we only yield names
            for dict-like behavior. This is intentional for LDIF attribute access.

            Allows: for name in entry.attributes: ...

            Returns:
                Generator of attribute names

            """
            yield from self.attributes.keys()

        def get(self, key: str, default: list[str] | None = None) -> list[str]:
            """Get attribute values with optional default.

            Args:
                key: Attribute name
                default: Default list if not found

            Returns:
                List of values or default

            """
            return self.attributes.get(key, default or [])

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
            self.attributes.pop(key, None)

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
            exclude_set = set(exclude or [])
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
                "deleted_at": datetime.now(UTC).isoformat(),
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
            result = registry.get_canonical_dn("cn=admin,dc=example,dc=com")

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
                    inconsistencies.append({
                        "normalized_dn": normalized_dn,
                        "canonical_case": canonical,
                        "variants": list(variants),
                        "variant_count": len(variants),
                    })

            if inconsistencies:
                result = FlextResult[bool].ok(False)
                result.metadata = {
                    "inconsistencies": inconsistencies,
                    "warning": f"Found {len(inconsistencies)} DNs with case inconsistencies",
                }
                return result

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
                        normalized_data[field_name] = self._normalize_dn_list(
                            field_value,
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
        """ACL permissions for LDAP operations."""

        read: bool = Field(default=False, description="Read permission")
        write: bool = Field(default=False, description="Write permission")
        add: bool = Field(default=False, description="Add permission")
        delete: bool = Field(default=False, description="Delete permission")
        search: bool = Field(default=False, description="Search permission")
        compare: bool = Field(default=False, description="Compare permission")
        self_write: bool = Field(default=False, description="Self-write permission")
        proxy: bool = Field(default=False, description="Proxy permission")

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

    class Acl(FlextModels.ArbitraryTypesModel):
        """Universal ACL model for all LDAP server types."""

        model_config = ConfigDict(
            strict=True,
            validate_default=True,
            validate_assignment=True,
        )

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
        server_type: str = Field(
            default="rfc",
            description="LDAP server type (openldap, openldap2, openldap1, oid, oud, 389ds)",
        )
        raw_line: str = Field(default="", description="Original raw ACL line from LDIF")
        raw_acl: str = Field(default="", description="Original ACL string from LDIF")
        validation_violations: list[str] = Field(
            default_factory=list,
            description="Validation violations captured during ACL processing",
        )
        metadata: FlextLdifModelsDomains.QuirkMetadata | None = Field(
            default=None,
            description="Quirk-specific metadata for ACL processing",
        )

        @model_validator(mode="after")
        def validate_acl_format(self) -> FlextLdifModelsDomains.Acl:
            """Validate ACL format - capture violations in metadata, DON'T reject."""
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
                    f"Invalid server_type '{self.server_type}' - "
                    f"expected one of: {', '.join(sorted(valid_server_types))}"
                )

            acl_is_defined = (
                self.target is not None
                or self.subject is not None
                or self.permissions is not None
            )
            if acl_is_defined and (not self.raw_acl or not self.raw_acl.strip()):
                violations.append(
                    "ACL is defined (has target/subject/permissions) but raw_acl is empty"
                )

            if violations:
                return self.model_copy(update={"validation_violations": violations})

            return self

        def get_acl_format(self) -> str:
            """Get ACL format for this server type."""
            return FlextLdifConstants.AclFormats.DEFAULT_ACL_FORMAT

        def get_acl_type(self) -> str:
            """Get ACL type identifier for this server."""
            short_form_map = {
                "oracle_oid": "oid",
                "oracle_oud": "oud",
            }
            short_server_type = short_form_map.get(self.server_type, self.server_type)
            return f"{short_server_type}_acl"

    class Entry(FlextModels.Entity):
        """LDIF entry domain model."""

        model_config = ConfigDict(
            strict=True,
            validate_default=True,
            validate_assignment=True,
            extra="allow",  # Allow dynamic fields from conversions and transformations
        )

        dn: FlextLdifModelsDomains.DistinguishedName | None = Field(
            default=None,
            description="Distinguished Name of the entry (Optional to capture None violations)",
        )
        attributes: FlextLdifModelsDomains.LdifAttributes | None = Field(
            default=None,
            description="Entry attributes container (Optional to capture None violations)",
        )
        metadata: FlextLdifModelsDomains.QuirkMetadata | None = Field(
            default=None,
            description="Quirk-specific metadata for preserving original entry format and server-specific data",
        )
        acls: list[FlextLdifModelsDomains.Acl] | None = Field(
            default=None,
            description="Access Control Lists extracted from entry attributes",
        )
        objectclasses: list[FlextLdifModelsDomains.SchemaObjectClass] | None = Field(
            default=None,
            description="ObjectClass definitions for schema validation",
        )
        attributes_schema: list[FlextLdifModelsDomains.SchemaAttribute] | None = Field(
            default=None,
            description="AttributeType definitions for schema validation",
        )
        entry_metadata: dict[str, object] | None = Field(
            default=None,
            description="Entry-level metadata (changetype, modifyTimestamp, etc.)",
        )
        validation_metadata: dict[str, object] = Field(
            default_factory=dict,
            description="Validation results and metadata from entry processing",
        )

        @field_validator("dn", mode="before")
        @classmethod
        def coerce_dn_from_string(
            cls, value: object
        ) -> FlextLdifModelsDomains.DistinguishedName | None:
            """Convert string DN to DistinguishedName instance with base64 detection.

            Pydantic v2 Advanced Pattern: Emergency base64 decode at model level.

            Allows tests and direct instantiation to pass strings for DN field.
            Also handles emergency base64 decoding if parser failed to decode.

            Per RFC 2849: DN values starting with ": " indicate failed base64 decode.
            This validator provides a safety net for data quality issues.

            Args:
                value: DN value (str, DistinguishedName, or None)

            Returns:
                DistinguishedName instance or None

            """
            if value is None or isinstance(
                value, FlextLdifModelsDomains.DistinguishedName
            ):
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
                            f"Emergency base64 decode in Entry model. "
                            f"DN was not decoded by parser: {original_value[:50]}..."
                        )

                return FlextLdifModelsDomains.DistinguishedName(value=value)
            return None

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

        @model_validator(mode="after")
        def validate_entry_rfc_compliance(self) -> FlextLdifModelsDomains.Entry:
            """Validate Entry RFC compliance - capture violations, DON'T reject.

            RFC 2849 § 2: DN and at least one attribute required
            RFC 4514 § 2.3, 2.4: DN format validation
            RFC 4512 § 2.5: Attribute name format validation

            Strategy: PRESERVE problematic entries for round-trip conversions,
            capture violations in validation_metadata for downstream handling.

            Since Entry is NOT frozen (it's an Entity), we can directly modify
            self.validation_metadata in this mode="after" validator.
            """
            violations: list[str] = []

            # RFC 2849 § 2 + RFC 4514 § 2.3, 2.4: DN validation
            dn_value = str(self.dn.value) if self.dn else None

            if dn_value is None:
                violations.append("RFC 2849 § 2: DN is required (received None)")
            elif not dn_value or not dn_value.strip():
                violations.append(
                    "RFC 2849 § 2: DN is required (empty or whitespace DN)"
                )
            else:
                # Validate DN format (RFC 4514 § 2.3, 2.4)
                components = [
                    comp.strip() for comp in dn_value.split(",") if comp.strip()
                ]

                if not components:
                    violations.append("RFC 4514 § 2.4: DN is empty (no RDN components)")
                else:
                    # Validate each component format
                    dn_component_pattern = re.compile(
                        FlextLdifConstants.LdifPatterns.DN_COMPONENT,
                        re.IGNORECASE,
                    )
                    for idx, comp in enumerate(components):
                        if not dn_component_pattern.match(comp):
                            violations.append(
                                f"RFC 4514 § 2.3: Component {idx} '{comp}' invalid format - "
                                f"expected 'attribute=value' pattern"
                            )

            # RFC 2849 § 2: Attributes validation
            if self.attributes is None:
                violations.append(
                    "RFC 2849 § 2: Entry must have at least one attribute (received None)"
                )
            elif not self.attributes.attributes or len(self.attributes.attributes) == 0:
                violations.append(
                    "RFC 2849 § 2: Entry must have at least one attribute (empty attributes)"
                )
            else:
                # RFC 4512 § 2.5: Attribute name format validation
                attr_name_pattern = re.compile(r"^[a-zA-Z][a-zA-Z0-9-]*$")

                violations.extend(
                    f"RFC 4512 § 2.5 violation: Invalid attribute name '{attr_name}' - "
                    f"must start with letter and contain only letters, digits, hyphens"
                    for attr_name in self.attributes.attributes
                    if not attr_name_pattern.match(attr_name)
                )

            # Capture violations in validation_metadata (Entry is NOT frozen, so we can modify it)
            if violations:
                if self.validation_metadata is None:
                    self.validation_metadata = {}

                self.validation_metadata["rfc_violations"] = violations
                self.validation_metadata["validation_context"] = {
                    "validator": "validate_entry_rfc_compliance",
                    "dn": dn_value,
                    "attribute_count": len(self.attributes.attributes)
                    if self.attributes
                    else 0,
                    "total_violations": len(violations),
                }

            return self

        @computed_field
        def unconverted_attributes(self) -> dict[str, object]:
            """Get unconverted attributes from metadata extensions (read-only view, DRY pattern)."""
            result = (
                self.metadata.extensions.get("unconverted_attributes", {})
                if self.metadata
                else {}
            )
            return result if isinstance(result, dict) else {}

        class Builder:
            """Builder pattern for Entry creation (reduces complexity, improves readability)."""

            def __init__(self) -> None:
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
                self, dn: str | FlextLdifModelsDomains.DistinguishedName
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
                self, metadata: FlextLdifModelsDomains.QuirkMetadata
            ) -> FlextLdifModelsDomains.Entry.Builder:
                self._metadata = metadata
                return self

            def acls(
                self, acls: list[FlextLdifModelsDomains.Acl]
            ) -> FlextLdifModelsDomains.Entry.Builder:
                self._acls = acls
                return self

            def objectclasses(
                self, objectclasses: list[FlextLdifModelsDomains.SchemaObjectClass]
            ) -> FlextLdifModelsDomains.Entry.Builder:
                self._objectclasses = objectclasses
                return self

            def attributes_schema(
                self, attributes_schema: list[FlextLdifModelsDomains.SchemaAttribute]
            ) -> FlextLdifModelsDomains.Entry.Builder:
                self._attributes_schema = attributes_schema
                return self

            def entry_metadata(
                self, entry_metadata: dict[str, object]
            ) -> FlextLdifModelsDomains.Entry.Builder:
                self._entry_metadata = entry_metadata
                return self

            def validation_metadata(
                self, validation_metadata: dict[str, object]
            ) -> FlextLdifModelsDomains.Entry.Builder:
                self._validation_metadata = validation_metadata
                return self

            def server_type(
                self, server_type: str
            ) -> FlextLdifModelsDomains.Entry.Builder:
                self._server_type = server_type
                return self

            def source_entry(
                self, source_entry: str
            ) -> FlextLdifModelsDomains.Entry.Builder:
                self._source_entry = source_entry
                return self

            def unconverted_attributes(
                self, unconverted_attributes: dict[str, object]
            ) -> FlextLdifModelsDomains.Entry.Builder:
                self._unconverted_attributes = unconverted_attributes
                return self

            def build(self) -> FlextResult[FlextLdifModelsDomains.Entry]:
                """Build the Entry using the accumulated parameters."""
                if self._dn is None or self._attributes is None:
                    return FlextResult[FlextLdifModelsDomains.Entry].fail(
                        "DN and attributes are required"
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
        ) -> FlextResult[FlextLdifModelsDomains.Entry]:
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
            )

        @classmethod
        def _create_entry(  # noqa: C901
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
        ) -> FlextResult[FlextLdifModelsDomains.Entry]:
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

            Returns:
            FlextResult with Entry instance or validation error

            """
            try:
                # Convert string DN to DistinguishedName if needed
                dn_obj: FlextLdifModelsDomains.DistinguishedName
                if isinstance(dn, str):
                    # Directly instantiate DistinguishedName - Pydantic will validate
                    dn_obj = FlextLdifModelsDomains.DistinguishedName(value=dn)
                else:
                    dn_obj = dn

                # Convert dict[str, object] to LdifAttributes if needed
                attrs_obj: FlextLdifModelsDomains.LdifAttributes
                if isinstance(attributes, dict):
                    # Normalize attribute values to list[str]
                    attrs_dict: dict[str, list[str]] = {}
                    for attr_name, attr_values in attributes.items():
                        # Normalize to list if string
                        values_list: list[str] = (
                            [str(attr_values)]
                            if isinstance(attr_values, str)
                            else [str(v) for v in attr_values]
                        )
                        attrs_dict[attr_name] = values_list
                    attrs_obj = FlextLdifModelsDomains.LdifAttributes(
                        attributes=attrs_dict
                    )
                else:
                    attrs_obj = attributes

                # Handle metadata creation and update
                if metadata is None:
                    if server_type or source_entry or unconverted_attributes:
                        extensions_dict: dict[str, object] = {}
                        if server_type:
                            extensions_dict["server_type"] = server_type
                        if source_entry:
                            extensions_dict["source_entry"] = source_entry
                        if unconverted_attributes:
                            extensions_dict["unconverted_attributes"] = (
                                unconverted_attributes
                            )
                        metadata = FlextLdifModelsDomains.QuirkMetadata(
                            quirk_type="entry_builder",
                            extensions=extensions_dict,
                        )
                elif server_type or source_entry or unconverted_attributes:
                    # Update existing metadata if new values are provided
                    if server_type:
                        metadata.extensions["server_type"] = server_type
                    if source_entry:
                        metadata.extensions["source_entry"] = source_entry
                    if unconverted_attributes:
                        metadata.extensions["unconverted_attributes"] = (
                            unconverted_attributes
                        )

                # Use model_validate to ensure Pydantic handles
                # default_factory fields. Entity fields have defaults.
                entry_data = {
                    FlextLdifConstants.DictKeys.DN: dn_obj,
                    FlextLdifConstants.DictKeys.ATTRIBUTES: attrs_obj,
                    "metadata": metadata,
                    "acls": acls,
                    "objectclasses": objectclasses,
                    "attributes_schema": attributes_schema,
                    "entry_metadata": entry_metadata,
                    "validation_metadata": validation_metadata,
                }
                return FlextResult[FlextLdifModelsDomains.Entry].ok(
                    cls.model_validate(entry_data),
                )
            except (ValueError, TypeError, AttributeError) as e:
                return FlextResult[FlextLdifModelsDomains.Entry].fail(
                    f"Failed to create Entry: {e}",
                )

        @classmethod
        def from_ldap3(
            cls, ldap3_entry: object
        ) -> FlextResult[FlextLdifModelsDomains.Entry]:
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
                if isinstance(entry_attrs_raw, dict):
                    for attr_name, attr_value_list in entry_attrs_raw.items():
                        if isinstance(attr_value_list, list):
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
                    attributes=cast("dict[str, str | list[str]]", attrs_dict),
                )

            except Exception as e:
                return FlextResult[FlextLdifModelsDomains.Entry].fail(
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
            if self.attributes is None:
                return []
            return list(self.attributes.attributes.keys())

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
            return len(self.attributes.attributes)

        def get_dn_components(self) -> list[str]:
            """Get DN components (RDN parts) from the entry's DN.

            Returns:
            List of DN components (e.g., ["cn=admin", "dc=example", "dc=com"])

            """
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

        def to_dict(self) -> dict[str, object]:
            """Convert Entry to dictionary representation.

            Used for serialization and data interchange.

            Returns:
            Dictionary with all entry fields

            """
            return {
                "dn": self.dn.value if self.dn else None,
                "attributes": self.get_all_attributes(),
                "metadata": self.metadata,
                "acls": self.acls,
                "objectclasses": self.objectclasses,
                "entry_metadata": self.entry_metadata,
                "validation_metadata": self.validation_metadata,
            }

        def clone(self) -> FlextLdifModelsDomains.Entry:
            """Create an immutable copy of the entry.

            Returns:
            New Entry instance with same values (shallow copy of attributes)

            """
            return FlextLdifModelsDomains.Entry(
                dn=self.dn,
                attributes=(
                    FlextLdifModelsDomains.LdifAttributes(
                        attributes=dict(self.attributes.attributes),
                    )
                    if self.attributes
                    else None
                ),
                metadata=self.metadata,
                acls=list(self.acls) if self.acls else None,
                objectclasses=list(self.objectclasses) if self.objectclasses else None,
                entry_metadata=dict(self.entry_metadata)
                if self.entry_metadata
                else None,
                validation_metadata=dict(self.validation_metadata)
                if self.validation_metadata
                else None,
            )

        @computed_field
        def is_schema_entry(self) -> bool:
            """Check if entry is a schema definition entry.

            Schema entries contain objectClass definitions and are typically
            found in the schema naming context.

            Returns:
            True if entry has objectClasses, False otherwise

            """
            return bool(self.objectclasses)

        @computed_field
        def is_acl_entry(self) -> bool:
            """Check if entry has Access Control Lists.

            Returns:
            True if entry has ACLs, False otherwise

            """
            return bool(self.acls)

        @computed_field
        def has_validation_errors(self) -> bool:
            """Check if entry has validation errors.

            Returns:
            True if entry has validation errors in validation_metadata, False otherwise

            """
            if not self.validation_metadata:
                return False
            return bool(self.validation_metadata.get("errors"))

        def get_objectclass_names(self) -> list[str]:
            """Get list of objectClass attribute values from entry."""
            return self.get_attribute_values(FlextLdifConstants.DictKeys.OBJECTCLASS)

    class QuirkMetadata(BaseModel):
        """Universal metadata container for quirk-specific data preservation.

        Used to store server-specific quirks, transformations, and metadata
        that needs to be preserved during LDIF processing operations.
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

        @classmethod
        def create_for(
            cls,
            quirk_type: str,
            extensions: dict[str, object] | None = None,
        ) -> FlextLdifModelsDomains.QuirkMetadata:
            """Factory method to create QuirkMetadata with extensions."""
            return cls(
                quirk_type=quirk_type,
                extensions=extensions or {},
            )
