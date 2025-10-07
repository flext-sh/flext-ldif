"""FLEXT LDIF Models - Unified Namespace for LDIF Domain Models.

This module provides a unified namespace class that aggregates all LDIF domain models
from specialized sub-modules. It extends flext-core FlextModels with LDIF-specific
domain entities organized into focused modules.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from flext_core import FlextModels, FlextResult
from pydantic import ConfigDict, Field, computed_field

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.typings import FlextLdifTypes


class FlextLdifModels(FlextModels):
    """LDIF domain models extending flext-core FlextModels.

    Unified namespace class that aggregates all LDIF domain models from specialized sub-modules.
    Provides a single access point for all LDIF models while maintaining modular organization.

    This class extends flext-core FlextModels and organizes LDIF-specific models into
    focused sub-modules for better maintainability and reduced complexity.
    """

    model_config = ConfigDict(
        validate_assignment=True,
        use_enum_values=True,
        arbitrary_types_allowed=True,
        extra="allow",  # Allow extra fields for backward compatibility
        frozen=False,
        validate_return=True,
        ser_json_timedelta="iso8601",
        ser_json_bytes="base64",
        hide_input_in_errors=True,
        json_schema_extra={
            "examples": [
                {
                    "ldif_processing_enabled": True,
                    "validation_enabled": True,
                    "schema_validation_enabled": True,
                    "acl_processing_enabled": True,
                }
            ],
            "description": "LDIF processing models for comprehensive directory data operations",
        },
    )

    # =========================================================================
    # CORE DOMAIN MODELS - Fundamental LDIF Entities
    # =========================================================================

    class DistinguishedName(FlextModels.Value):
        """Distinguished Name value object."""

        value: str = Field(..., description="DN string value")

        @property
        def normalized_value(self) -> str:
            """Get normalized DN value."""
            return self.value.lower().strip()

        @property
        def components(self) -> list[str]:
            """Get DN components."""
            return [comp.strip() for comp in self.value.split(",") if comp.strip()]

    class Entry(FlextModels.Entity):
        """LDIF entry domain model."""

        dn: FlextLdifModels.DistinguishedName = Field(
            ..., description="Distinguished Name of the entry"
        )
        attributes: FlextLdifModels.LdifAttributes = Field(
            ..., description="Entry attributes container"
        )

        @classmethod
        def create(
            cls, data: dict[str, object] | None = None, **kwargs: object
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Create Entry instance with validation, returns FlextResult."""
            try:
                if data is None:
                    data = {}
                data.update(kwargs)

                # Handle DN conversion if needed
                if "dn" in data and isinstance(data["dn"], str):
                    data["dn"] = FlextLdifModels.DistinguishedName(value=data["dn"])

                # Handle attributes conversion if needed
                if "attributes" in data and isinstance(data["attributes"], dict):
                    # Raw attributes mapping from keys to list of values
                    raw_attrs = cast("dict[str, list[str]]", data["attributes"])
                    ldif_attrs = FlextLdifModels.LdifAttributes(
                        attributes={
                            name: FlextLdifModels.AttributeValues(values=values)
                            for name, values in raw_attrs.items()
                        }
                    )
                    data["attributes"] = ldif_attrs
                else:
                    # Handle raw LDIF format where attributes are at top level
                    raw_attrs_else: dict[str, list[str]] = {}
                    keys_to_remove: list[str] = []
                    for key, value in data.items():
                        if key != "dn":
                            if isinstance(value, list):
                                existing_values = cast("list[str]", value)
                                raw_attrs_else[key] = existing_values
                            else:
                                raw_attrs_else[key] = [str(value)]
                            keys_to_remove.append(key)
                    for key in keys_to_remove:
                        del data[key]
                    if raw_attrs_else:
                        ldif_attrs = FlextLdifModels.LdifAttributes(
                            attributes={
                                name: FlextLdifModels.AttributeValues(values=values)
                                for name, values in raw_attrs_else.items()
                            }
                        )
                        data["attributes"] = ldif_attrs

                # Use model_validate for proper Pydantic validation with type coercion
                instance = cls.model_validate(data)
                return FlextResult[FlextLdifModels.Entry].ok(instance)
            except Exception as e:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Failed to create Entry: {e}"
                )

        def get_attribute(self, name: str) -> list[str] | None:
            """Get attribute value(s) by name.

            Args:
                name: Attribute name to retrieve

            Returns:
                List of attribute values, or None if attribute doesn't exist

            """
            return self.attributes.get(name)

        def has_attribute(self, name: str) -> bool:
            """Check if entry has attribute with given name.

            Args:
                name: Attribute name to check

            Returns:
                True if attribute exists, False otherwise

            """
            return name in self.attributes.attributes

        def get_attribute_values(self, name: str) -> list[str]:
            """Get attribute values by name, returning empty list if not found.

            Args:
                name: Attribute name to retrieve

            Returns:
                List of attribute values, empty list if attribute doesn't exist

            """
            return self.attributes.get(name) or []

    class AttributeValues(FlextModels.Value):
        """LDIF attribute values container."""

        values: list[str] = Field(default_factory=list, description="Attribute values")

        @property
        def single_value(self) -> str | None:
            """Get single value if list has exactly one element."""
            return self.values[0] if len(self.values) == 1 else None

    class AttributeName(FlextModels.Value):
        """LDIF attribute name value object."""

        name: str = Field(..., description="Attribute name")

    class LdifUrl(FlextModels.Value):
        """LDIF URL value object."""

        url: str = Field(..., description="LDIF URL")

    class Encoding(FlextModels.Value):
        """LDIF encoding value object."""

        encoding: str = Field(..., description="Character encoding")

    class LdifAttribute(FlextModels.Value):
        """LDIF attribute model."""

        name: str = Field(..., description="Attribute name")
        values: list[str] = Field(default_factory=list, description="Attribute values")

        @classmethod
        def create(cls, *args: object, **kwargs: object) -> FlextResult[object]:
            """Create LdifAttribute instance with validation."""
            try:
                data: dict[str, Any] = {}
                if args:
                    if isinstance(args[0], dict):
                        data = args[0]
                    else:
                        return FlextResult[object].fail("First argument must be a dict")
                data.update(kwargs)
                instance = cls(**data)
                return FlextResult[object].ok(instance)
            except Exception as e:
                return FlextResult[object].fail(f"Failed to create LdifAttribute: {e}")

    class LdifAttributes(FlextModels.Value):
        """LDIF attributes container."""

        attributes: dict[str, FlextLdifModels.AttributeValues] = Field(
            default_factory=dict, description="Attribute name to values mapping"
        )

        @property
        def data(self) -> dict[str, list[str]]:
            """Get attributes data as dict of lists."""
            return {name: attr.values for name, attr in self.attributes.items()}

        def get(self, name: str, default: list[str] | None = None) -> list[str] | None:
            """Get attribute values by name."""
            attr_values = self.attributes.get(name)
            return attr_values.values if attr_values else default

        def get_attribute(self, name: str) -> FlextLdifModels.AttributeValues | None:
            """Get attribute by name."""
            return self.attributes.get(name)

        def add_attribute(self, name: str, value: str | list[str]) -> None:
            """Add attribute value(s)."""
            if isinstance(value, str):
                value = [value]
            if name in self.attributes:
                self.attributes[name].values.extend(value)
            else:
                self.attributes[name] = FlextLdifModels.AttributeValues(values=value)

        def remove_attribute(self, name: str) -> None:
            """Remove attribute by name."""
            self.attributes.pop(name, None)

    class ChangeRecord(FlextModels.Value):
        """LDIF change record for modifications."""

        dn: str = Field(..., description="Distinguished Name")
        changetype: str = Field(..., description="Type of change")
        changes: list[dict[str, Any]] = Field(
            default_factory=list, description="List of changes"
        )

    class LdifValidationResult(FlextModels.Value):
        """Result of LDIF validation operations."""

        is_valid: bool = Field(default=False, description="Whether validation passed")
        errors: list[str] = Field(
            default_factory=list, description="List of validation errors"
        )
        warnings: list[str] = Field(
            default_factory=list, description="List of validation warnings"
        )

    class AnalyticsResult(FlextModels.Value):
        """Result of LDIF analytics operations."""

        total_entries: int = Field(
            default=0, description="Total number of entries analyzed"
        )
        object_class_distribution: dict[str, int] = Field(
            default_factory=dict, description="Distribution of object classes"
        )
        patterns_detected: list[str] = Field(
            default_factory=list, description="Detected patterns in the data"
        )

    class SearchConfig(FlextModels.Value):
        """Configuration for LDAP search operations."""

        base_dn: str = Field(..., description="Base DN for the search")
        search_filter: str = Field(
            default="(objectClass=*)", description="LDAP search filter"
        )
        attributes: list[str] = Field(
            default_factory=list, description="Attributes to retrieve"
        )
        scope: str = Field(default="sub", description="Search scope (base, one, sub)")
        time_limit: int = Field(
            default=30, description="Time limit for search in seconds"
        )
        size_limit: int = Field(
            default=0, description="Size limit for search results (0 = no limit)"
        )

    # =========================================================================
    # CQRS MODELS - Commands and Queries
    # =========================================================================

    class ParseQuery(FlextModels.Query):
        """Query for parsing LDIF content."""

        source: str = Field(..., description="LDIF source content, file path, or lines")
        format: str = Field(
            default="auto", description="LDIF format to use for parsing"
        )
        encoding: str = Field(
            default="utf-8", description="Character encoding for LDIF content"
        )
        strict: bool = Field(
            default=True, description="Whether to use strict validation during parsing"
        )

    class ValidateQuery(FlextModels.Query):
        """Query for validating LDIF entries."""

        entries: list[Any] = Field(..., description="Entries to validate")
        schema_config: FlextLdifTypes.Dict | None = Field(
            default=None, description="Schema configuration for validation"
        )
        strict: bool = Field(
            default=True, description="Whether to use strict validation"
        )

    class AnalyzeQuery(FlextModels.Query):
        """Query for analyzing LDIF entries."""

        entries: list[Any] = Field(..., description="Entries to analyze")
        metrics: FlextLdifTypes.Dict | None = Field(
            default=None, description="Metrics configuration"
        )
        include_patterns: bool = Field(
            default=True, description="Whether to include pattern detection"
        )

    class WriteCommand(FlextModels.Command):
        """Command for writing entries to LDIF format."""

        entries: list[Any] = Field(..., description="Entries to write")
        format: str = Field(default="rfc", description="Output LDIF format")
        output: str | None = Field(
            default=None, description="Output path (None for string return)"
        )
        line_width: int = Field(
            default=76, ge=40, le=120, description="Maximum line width"
        )

    class MigrateCommand(FlextModels.Command):
        """Command for migrating LDIF entries between server types."""

        entries: list[Any] = Field(..., description="Entries to migrate")
        source_format: str = Field(..., description="Source LDIF format")
        target_format: str = Field(..., description="Target LDIF format")
        options: FlextLdifTypes.Dict | None = Field(
            default=None, description="Migration options"
        )

    class RegisterQuirkCommand(FlextModels.Command):
        """Command for registering server-specific quirks."""

        quirk_type: str = Field(..., description="Type of quirk to register")
        quirk_impl: object = Field(..., description="Quirk implementation instance")
        override: bool = Field(
            default=False, description="Whether to override existing quirk"
        )

    # =========================================================================
    # BASE CLASSES - Shared Foundations (for backward compatibility)
    # =========================================================================

    # Base classes for extension (imported from original models structure)
    # These are maintained for backward compatibility and internal use

    class BaseOperationResult(FlextModels.Value):
        """Base class for operation results with common fields."""

        operation_id: str = Field(default="", description="Unique operation identifier")
        timestamp: str = Field(default="", description="Operation timestamp")
        duration_ms: float = Field(
            default=0.0, ge=0, description="Operation duration in milliseconds"
        )
        errors: list[str] = Field(
            default_factory=list, description="List of error messages"
        )
        warnings: list[str] = Field(
            default_factory=list, description="List of warning messages"
        )

        @computed_field
        def has_errors(self) -> bool:
            """Check if operation has errors."""
            return len(self.errors) > 0

        @computed_field
        def has_warnings(self) -> bool:
            """Check if operation has warnings."""
            return len(self.warnings) > 0

    class BaseSchemaAttribute(FlextModels.Value):
        """Base class for schema attributes."""

        name: str = Field(..., description="Attribute name")
        oid: str = Field(default="", description="Attribute OID")
        description: str = Field(default="", description="Attribute description")
        syntax: str = Field(default="", description="Attribute syntax")
        single_value: bool = Field(
            default=False, description="Whether attribute is single-valued"
        )

        @property
        def required_attributes(self) -> list[str]:
            """Required attributes (for compatibility)."""
            return []

        @property
        def optional_attributes(self) -> list[str]:
            """Optional attributes (for compatibility)."""
            return [self.name]

    class SchemaAttribute(FlextModels.Value):
        """Schema attribute model."""

        name: str = Field(..., description="Attribute name")
        oid: str = Field(default="", description="Attribute OID")
        description: str = Field(default="", description="Attribute description")
        syntax: str = Field(default="", description="Attribute syntax")

    class BaseSchemaObjectClass(FlextModels.Value):
        """Base class for schema object classes."""

        name: str = Field(..., description="Object class name")
        oid: str = Field(default="", description="Object class OID")
        description: str = Field(default="", description="Object class description")
        superior: str | list[str] | None = Field(
            default=None, description="Superior object classes"
        )

        @property
        def required_attributes(self) -> list[str]:
            """Required attributes (MUST)."""
            return []

        @property
        def optional_attributes(self) -> list[str]:
            """Optional attributes (MAY)."""
            return []

    class SchemaObjectClass(FlextModels.Value):
        """Schema object class model for LDIF schema definitions."""

        name: str = Field(..., description="Object class name")
        oid: str = Field(default="", description="Object class OID")
        description: str = Field(default="", description="Object class description")
        required_attributes: list[str] = Field(
            default_factory=list, description="Required attributes (MUST)"
        )
        optional_attributes: list[str] = Field(
            default_factory=list, description="Optional attributes (MAY)"
        )
        structural: bool = Field(
            default=True, description="Whether this is a structural object class"
        )
        superior: str | list[str] | None = Field(
            default=None, description="Superior object classes"
        )

        @computed_field
        def must(self) -> list[str]:
            """MUST attributes (alias for required_attributes)."""
            return self.required_attributes

        @computed_field
        def may(self) -> list[str]:
            """MAY attributes (alias for optional_attributes)."""
            return self.optional_attributes

        @computed_field
        def attribute_summary(self) -> FlextLdifTypes.Dict:
            """Summary of attribute requirements."""
            return {
                "required_count": len(self.required_attributes),
                "optional_count": len(self.optional_attributes),
                "total_count": len(self.required_attributes)
                + len(self.optional_attributes),
                "is_structural": self.structural,
            }

    class BaseAclPermissions(FlextModels.Value):
        """Base class for ACL permissions."""

        # Permission constants
        TOTAL_PERMISSIONS: int = 7

        read: bool = Field(default=False, description="Read permission")
        write: bool = Field(default=False, description="Write permission")
        add: bool = Field(default=False, description="Add permission")
        delete: bool = Field(default=False, description="Delete permission")
        search: bool = Field(default=False, description="Search permission")
        compare: bool = Field(default=False, description="Compare permission")
        proxy: bool = Field(default=False, description="Proxy permission")

        @computed_field
        def permissions_summary(self) -> FlextLdifTypes.Dict:
            """Summary of granted permissions."""
            granted = [k for k, v in self.__dict__.items() if isinstance(v, bool) and v]
            return {
                "granted_count": len(granted),
                "total_permissions": self.TOTAL_PERMISSIONS,
                "granted_permissions": granted,
                "all_granted": len(granted) == self.TOTAL_PERMISSIONS,
            }

    class BaseAclSubject(FlextModels.Value):
        """Base class for ACL subjects."""

        subject_type: str = Field(..., description="Type of subject (dn, group, etc.)")
        subject_value: str = Field(..., description="Subject value")
        subject_dn: str = Field(default="", description="Subject DN if applicable")

        @computed_field
        def subject_key(self) -> str:
            """Unique key for the subject."""
            return f"{self.subject_type}:{self.subject_value}"

    class AclTarget(FlextModels.Value):
        """ACL target specification."""

        target_dn: str = Field(..., description="Target DN")
        attributes: list[str] = Field(
            default_factory=list, description="Target attributes"
        )

    class AclSubject(FlextModels.Value):
        """ACL subject specification."""

        subject_type: str = Field(
            default="user", description="Type of subject (user, group, etc.)"
        )
        subject_value: str = Field(..., description="Subject identifier")

    class AclPermissions(FlextModels.Value):
        """ACL permissions specification."""

        read: bool = Field(default=False, description="Read permission")
        write: bool = Field(default=False, description="Write permission")
        search: bool = Field(default=False, description="Search permission")
        compare: bool = Field(default=False, description="Compare permission")
        add: bool = Field(default=False, description="Add permission")
        delete: bool = Field(default=False, description="Delete permission")
        modify: bool = Field(default=False, description="Modify permission")

        @property
        def permissions(self) -> list[str]:
            """Get list of granted permissions."""
            granted = []
            if self.read:
                granted.append("read")
            if self.write:
                granted.append("write")
            if self.search:
                granted.append("search")
            if self.compare:
                granted.append("compare")
            if self.add:
                granted.append("add")
            if self.delete:
                granted.append("delete")
            if self.modify:
                granted.append("modify")
            return granted

    class UnifiedAcl(FlextModels.Value):
        """Unified ACL representation across different LDAP servers."""

        name: str = Field(..., description="ACL name")
        target: FlextLdifModels.AclTarget = Field(..., description="ACL target")
        subject: FlextLdifModels.AclSubject = Field(..., description="ACL subject")
        permissions: FlextLdifModels.AclPermissions = Field(
            ..., description="ACL permissions"
        )
        scope: str = Field(default="subtree", description="ACL scope")
        server_type: str = Field(..., description="Server type this ACL is for")
        raw_acl: str = Field(..., description="Raw ACL string")

    # =========================================================================
    # SCHEMA MODELS - Schema discovery and validation
    # =========================================================================

    class SchemaDiscoveryResult(FlextModels.Value):
        """Result of schema discovery operations."""

        attributes: dict[str, dict[str, str]] = Field(
            default_factory=dict, description="Discovered attributes"
        )
        objectclasses: dict[str, dict[str, str]] = Field(
            default_factory=dict, description="Discovered object classes"
        )
        total_attributes: int = Field(default=0, description="Total attributes found")
        total_objectclasses: int = Field(
            default=0, description="Total object classes found"
        )
        server_type: str = Field(default="", description="Server type")
        entry_count: int = Field(default=0, description="Number of entries processed")

        @property
        def object_classes(self) -> dict[str, dict[str, str]]:
            """Alias for objectclasses."""
            return self.objectclasses

    class OidSchemaAttribute(FlextModels.Value):
        """OID schema attribute model."""

        name: str = Field(..., description="Attribute name")
        oid: str = Field(..., description="Attribute OID")
        syntax: str = Field(default="", description="Attribute syntax")
        description: str = Field(default="", description="Attribute description")

        @classmethod
        def from_ldif_line(
            cls, line: str
        ) -> FlextResult[FlextLdifModels.OidSchemaAttribute]:
            """Create from LDIF line."""
            try:
                # Simple parsing - in real implementation this would be more complex
                parts = line.split(":", 1)
                if len(parts) != FlextLdifConstants.LdifValidation.MIN_LDIF_LINE_PARTS:
                    return FlextResult[FlextLdifModels.OidSchemaAttribute].fail(
                        "Invalid LDIF line format"
                    )

                name = parts[0].strip()
                value = parts[1].strip()

                instance = cls(name=name, oid=value)
                return FlextResult[FlextLdifModels.OidSchemaAttribute].ok(instance)
            except Exception as e:
                return FlextResult[FlextLdifModels.OidSchemaAttribute].fail(
                    f"Failed to parse: {e}"
                )

    class OidSchemaObjectClass(FlextModels.Value):
        """OID schema object class model."""

        name: str = Field(..., description="Object class name")
        oid: str = Field(..., description="Object class OID")
        superior: str = Field(default="", description="Superior object class")
        description: str = Field(default="", description="Object class description")

        @classmethod
        def from_ldif_line(
            cls, line: str
        ) -> FlextResult[FlextLdifModels.OidSchemaObjectClass]:
            """Create from LDIF line."""
            try:
                # Simple parsing - in real implementation this would be more complex
                parts = line.split(":", 1)
                if len(parts) != FlextLdifConstants.LdifValidation.MIN_LDIF_LINE_PARTS:
                    return FlextResult[FlextLdifModels.OidSchemaObjectClass].fail(
                        "Invalid LDIF line format"
                    )

                name = parts[0].strip()
                value = parts[1].strip()

                instance = cls(name=name, oid=value)
                return FlextResult[FlextLdifModels.OidSchemaObjectClass].ok(instance)
            except Exception as e:
                return FlextResult[FlextLdifModels.OidSchemaObjectClass].fail(
                    f"Failed to parse: {e}"
                )

    class OidEntryLevelAci(FlextModels.Value):
        """OID entry-level ACI model."""

        dn: str = Field(..., description="Entry DN")
        aci: str = Field(..., description="ACI value")

        @classmethod
        def from_ldif_line(
            cls, line: str
        ) -> FlextResult[FlextLdifModels.OidEntryLevelAci]:
            """Create from LDIF line."""
            try:
                # Simple parsing - in real implementation this would be more complex
                parts = line.split(":", 1)
                if len(parts) != FlextLdifConstants.LdifValidation.MIN_LDIF_LINE_PARTS:
                    return FlextResult[FlextLdifModels.OidEntryLevelAci].fail(
                        "Invalid LDIF line format"
                    )

                dn = parts[0].strip()
                aci = parts[1].strip()

                instance = cls(dn=dn, aci=aci)
                return FlextResult[FlextLdifModels.OidEntryLevelAci].ok(instance)
            except Exception as e:
                return FlextResult[FlextLdifModels.OidEntryLevelAci].fail(
                    f"Failed to parse: {e}"
                )

    class OidAci(FlextModels.Value):
        """OID ACI model."""

        aci: str = Field(..., description="ACI value")
        target: str = Field(default="", description="ACI target")
        subject: str = Field(default="", description="ACI subject")

        @classmethod
        def from_ldif_line(cls, line: str) -> FlextResult[FlextLdifModels.OidAci]:
            """Create from LDIF line."""
            try:
                # Simple parsing - in real implementation this would be more complex
                parts = line.split(":", 1)
                if len(parts) != FlextLdifConstants.LdifValidation.MIN_LDIF_LINE_PARTS:
                    return FlextResult[FlextLdifModels.OidAci].fail(
                        "Invalid LDIF line format"
                    )

                aci = parts[1].strip()

                instance = cls(aci=aci)
                return FlextResult[FlextLdifModels.OidAci].ok(instance)
            except Exception as e:
                return FlextResult[FlextLdifModels.OidAci].fail(f"Failed to parse: {e}")

    # =========================================================================
    # EVENT MODELS - Domain Events
    # =========================================================================

    class EntryParsedEvent(FlextModels.DomainEvent):
        """Event emitted when an entry is successfully parsed."""

        entry: FlextLdifModels.Entry = Field(..., description="Parsed entry")
        source: str = Field(..., description="Source of the entry")

    class EntriesValidatedEvent(FlextModels.DomainEvent):
        """Event emitted when entries are validated."""

        entries: list[FlextLdifModels.Entry] = Field(
            ..., description="Validated entries"
        )
        validation_result: FlextLdifModels.LdifValidationResult = Field(
            ..., description="Validation result"
        )

    class AnalyticsGeneratedEvent(FlextModels.DomainEvent):
        """Event emitted when analytics are generated."""

        analytics: FlextLdifModels.AnalyticsResult = Field(
            ..., description="Generated analytics"
        )

    class EntriesWrittenEvent(FlextModels.DomainEvent):
        """Event emitted when entries are written."""

        entries: list[FlextLdifModels.Entry] = Field(..., description="Written entries")
        output_path: Path | None = Field(default=None, description="Output path")

    class MigrationCompletedEvent(FlextModels.DomainEvent):
        """Event emitted when migration is completed."""

        source_server: str = Field(..., description="Source server type")
        target_server: str = Field(..., description="Target server type")
        statistics: FlextLdifTypes.Dict = Field(..., description="Migration statistics")

    class QuirkRegisteredEvent(FlextModels.DomainEvent):
        """Event emitted when a quirk is registered."""

        quirk_type: str = Field(..., description="Type of quirk")
        server_type: str = Field(..., description="Server type")

    # =========================================================================
    # COMPUTED FIELDS - Metadata and Statistics
    # =========================================================================

    @computed_field
    def active_ldif_models_count(self) -> int:
        """Computed field returning the number of active LDIF model types."""
        model_types = [
            "DistinguishedName",
            "LdifAttribute",
            "LdifAttributes",
            "Entry",
            "ChangeRecord",
            "SchemaObjectClass",
            "SchemaDiscoveryResult",
            "AclTarget",
            "AclSubject",
            "AclPermissions",
            "UnifiedAcl",
            "ParseResult",
            "TransformResult",
            "AnalyticsResult",
            "WriteResult",
            "FilterResult",
            "ParseQuery",
            "ValidateQuery",
            "AnalyzeQuery",
            "WriteCommand",
            "MigrateCommand",
            "EntryParsedEvent",
            "EntriesValidatedEvent",
            "AnalyticsGeneratedEvent",
            "TechnologySpecification",
            "OidSpecification",
            "OudSpecification",
        ]
        return len(model_types)

    class LdifDocument(FlextModels.Entity):
        """LDIF document model containing entries and domain events."""

        entries: list[FlextLdifModels.Entry] = Field(
            default_factory=list, description="LDIF entries in the document"
        )
        domain_events: list[FlextModels.DomainEvent] = Field(
            default_factory=list,
            description="Domain events associated with the document",
        )

        @classmethod
        def from_ldif_string(
            cls, ldif_string: str
        ) -> FlextResult[FlextLdifModels.LdifDocument]:
            """Create LdifDocument from LDIF string."""
            try:
                # Simple implementation - parse basic LDIF
                lines = ldif_string.strip().split("\n")
                entries = []
                current_entry: dict[str, object] = {}
                in_entry = False

                for line in lines:
                    stripped_line = line.rstrip()
                    if not stripped_line or stripped_line.startswith("#"):
                        continue
                    if stripped_line.lower().startswith("dn:"):
                        if in_entry and current_entry:
                            # Create previous entry
                            entry_result = FlextLdifModels.Entry.create(current_entry)
                            if entry_result.is_success:
                                entries.append(entry_result.unwrap())
                        current_entry = {"dn": stripped_line[3:].strip()}
                        in_entry = True
                    elif ":" in stripped_line and in_entry:
                        key, value = stripped_line.split(":", 1)
                        key = key.strip()
                        value = value.strip()
                        if key in current_entry:
                            existing = current_entry[key]
                            if not isinstance(existing, list):
                                current_entry[key] = [str(existing), value]
                            else:
                                existing_list = cast("list[str]", existing)
                                existing_list.append(value)
                        else:
                            current_entry[key] = [value] if key != "dn" else value

                if current_entry:
                    entry_result = FlextLdifModels.Entry.create(current_entry)
                    if entry_result.is_success:
                        entries.append(entry_result.unwrap())

                return FlextResult[FlextLdifModels.LdifDocument].ok(
                    cls(entries=entries, domain_events=[])
                )
            except Exception as e:
                return FlextResult[FlextLdifModels.LdifDocument].fail(
                    f"Failed to parse LDIF: {e}"
                )

        def to_ldif_string(self) -> str:
            """Convert LdifDocument to LDIF string."""
            lines: list[str] = []
            for entry in self.entries:
                lines.append(f"dn: {entry.dn.value}")
                for attr_name, attr_values in entry.attributes.attributes.items():
                    lines.extend(
                        f"{attr_name}: {value}" for value in attr_values.values
                    )
                lines.append("")
            return "\n".join(lines)

    class LdifProcessingResult(FlextModels.Value):
        """Result of LDIF processing operations."""

        success: bool = Field(..., description="Whether processing succeeded")
        entries_processed: int = Field(..., description="Number of entries processed")
        errors: list[str] = Field(default_factory=list, description="Processing errors")
        warnings: list[str] = Field(
            default_factory=list, description="Processing warnings"
        )

    class ServiceStatus(FlextModels.Value):
        """Status information for LDIF services."""

        service_name: str = Field(..., description="Name of the service")
        status: str = Field(..., description="Current status")
        version: str = Field(..., description="Service version")
        uptime: float = Field(..., description="Service uptime in seconds")

    @computed_field
    def ldif_model_summary(self) -> FlextLdifTypes.Dict:
        """Computed field providing summary of LDIF model capabilities."""
        return {
            "entry_models": 4,
            "schema_models": 3,
            "acl_models": 4,
            "utility_models": 4,
            "result_models": 5,
            "event_models": 6,
            "command_models": 6,
            "total_models": self.active_ldif_models_count,
            "pattern_support": True,
            "validation_support": True,
            "serialization_support": True,
            "modular_organization": True,
        }
