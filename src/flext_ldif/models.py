"""FLEXT LDIF Models - Advanced Pydantic 2 Models with Monadic Composition.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import cast

from pydantic import ConfigDict, Field, field_validator

from flext_core import FlextModels, FlextResult
from flext_ldif.constants import FlextLdifConstants


def _create_ldif_attributes() -> FlextLdifModels.LdifAttributes:
    """Helper function to create LdifAttributes instance."""
    return FlextLdifModels.LdifAttributes()


class FlextLdifModels(FlextModels):
    """LDIF domain models extending flext-core FlextModels.

    Contains ONLY Pydantic v2 model definitions with business logic.
    Uses flext-core SOURCE OF TRUTH for model patterns and validation.
    Implements advanced monadic composition patterns with FlextResult.
    """

    # =============================================================================
    # ADVANCED BASE MODEL CLASSES - Monadic Composition Patterns
    # =============================================================================

    class DistinguishedName(FlextModels.Value):
        """Distinguished Name (DN) for LDIF entries.

        Represents a unique identifier for LDAP entries following RFC 4514.
        """

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
        )

        value: str = Field(
            ...,
            min_length=1,
            max_length=2048,
            description="The DN string value",
        )

        @field_validator("value")
        @classmethod
        def validate_dn_format(cls, v: str) -> str:
            """Validate DN format."""
            if not v.strip():
                error_msg = "DN cannot be empty"
                raise ValueError(error_msg)
            return v.strip()

        @property
        def components(self) -> list[str]:
            """Get DN components."""
            return [comp.strip() for comp in self.value.split(",") if comp.strip()]

        @property
        def depth(self) -> int:
            """Get DN depth (number of components)."""
            return len(self.components)

    class LdifAttribute(FlextModels.Value):
        """LDIF attribute with name and values."""

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
        )

        name: str = Field(
            ...,
            min_length=1,
            description="Attribute name",
        )

        values: list[str] = Field(
            default_factory=list,
            description="Attribute values",
        )

        @field_validator("name")
        @classmethod
        def validate_name(cls, v: str) -> str:
            """Validate attribute name."""
            if not v.strip():
                error_msg = "Attribute name cannot be empty"
                raise ValueError(error_msg)
            return v.strip().lower()

        @property
        def single_value(self) -> str | None:
            """Get single value (first value if multiple exist)."""
            return self.values[0] if self.values else None

    class LdifAttributes(FlextModels.Value):
        """Collection of LDIF attributes."""

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
        )

        attributes: dict[str, FlextLdifModels.AttributeValues] = Field(
            default_factory=dict,
            description="Dictionary of attribute names to AttributeValues",
        )

        def get_attribute(self, name: str) -> FlextLdifModels.AttributeValues | None:
            """Get attribute values by name."""
            name_lower = name.lower()
            for key, attr_values in self.attributes.items():
                if key.lower() == name_lower:
                    return attr_values
            return None

        def set_attribute(self, name: str, values: list[str]) -> None:
            """Set attribute values."""
            self.attributes[name.lower()] = FlextLdifModels.AttributeValues(
                values=values
            )

        def has_attribute(self, name: str) -> bool:
            """Check if attribute exists."""
            name_lower = name.lower()
            return any(key.lower() == name_lower for key in self.attributes)

        @property
        def data(self) -> dict[str, FlextLdifModels.AttributeValues]:
            """Get attributes data dictionary."""
            return self.attributes

        def __getitem__(self, name: str) -> FlextLdifModels.AttributeValues | None:
            """Dictionary-like access to attributes."""
            return self.get_attribute(name)

        def __setitem__(self, name: str, values: list[str]) -> None:
            """Dictionary-like setting of attributes."""
            # Since the model is frozen, we need to use object.__setattr__
            if hasattr(self, "attributes"):
                self.attributes[name.lower()] = FlextLdifModels.AttributeValues(
                    values=values
                )
            else:
                object.__setattr__(
                    self,
                    "attributes",
                    {name.lower(): FlextLdifModels.AttributeValues(values=values)},
                )

        def __contains__(self, name: str) -> bool:
            """Dictionary-like 'in' check."""
            return self.has_attribute(name)

        def add_attribute(self, name: str, values: str | list[str]) -> None:
            """Add attribute with values."""
            if isinstance(values, str):
                values = [values]
            self.set_attribute(name, values)

        def remove_attribute(self, name: str) -> None:
            """Remove attribute by name."""
            name_lower = name.lower()
            keys_to_remove = [
                key for key in self.attributes if key.lower() == name_lower
            ]
            for key in keys_to_remove:
                del self.attributes[key]

    class Entry(FlextModels.Entity):
        """LDIF entry representing a complete LDAP object."""

        model_config = ConfigDict(
            validate_assignment=True,
            extra="forbid",
        )

        dn: FlextLdifModels.DistinguishedName = Field(
            ...,
            description="Distinguished Name of the entry",
        )

        attributes: FlextLdifModels.LdifAttributes = Field(
            default_factory=_create_ldif_attributes,
            description="Entry attributes",
        )

        def get_attribute(self, name: str) -> FlextLdifModels.AttributeValues | None:
            """Get attribute values by name."""
            return self.attributes.get_attribute(name)

        def has_attribute(self, name: str) -> bool:
            """Check if attribute exists."""
            return self.attributes.has_attribute(name)

        def get_attribute_values(self, name: str) -> list[str]:
            """Get attribute values as a list of strings."""
            attr_values = self.get_attribute(name)
            return attr_values.values if attr_values else []

        def get_single_value(self, name: str) -> str | None:
            """Get single attribute value (first value if multiple exist)."""
            attr_values = self.get_attribute(name)
            return attr_values.single_value if attr_values else None

        def is_person_entry(self) -> bool:
            """Check if entry is a person entry."""
            attr_values = self.get_attribute("objectClass")
            if not attr_values:
                return False
            person_classes = {"person", "inetorgperson"}
            return any(oc.lower() in person_classes for oc in attr_values.values)

        def is_group_entry(self) -> bool:
            """Check if entry is a group entry."""
            attr_values = self.get_attribute("objectClass")
            if not attr_values:
                return False
            group_classes = {"group", "groupofnames", "groupofuniquenames"}
            return any(oc.lower() in group_classes for oc in attr_values.values)

        def is_organizational_unit(self) -> bool:
            """Check if entry is an organizational unit."""
            attr_values = self.get_attribute("objectClass")
            if not attr_values:
                return False
            return "organizationalunit" in [oc.lower() for oc in attr_values.values]

        def has_object_class(self, object_class: str) -> bool:
            """Check if entry has specific object class."""
            attr_values = self.get_attribute("objectClass")
            if not attr_values:
                return False
            return object_class.lower() in [oc.lower() for oc in attr_values.values]

        def validate_business_rules(self) -> FlextResult[bool]:
            """Validate entry against business rules."""
            try:
                # Basic validation - ensure DN exists and has attributes
                if not self.dn.value.strip():
                    return FlextResult[bool].fail("DN cannot be empty")

                # Check for required objectClass
                if not self.has_attribute("objectClass"):
                    return FlextResult[bool].fail(
                        "Entry must have objectClass attribute"
                    )

                return FlextResult[bool].ok(True)
            except Exception as e:
                return FlextResult[bool].fail(str(e))

        @classmethod
        def create(
            cls, data: dict[str, object] | None = None, **kwargs: object
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Create a new Entry instance."""
            try:
                # Handle both dict and individual parameter patterns
                if data is not None:
                    dn = str(data.get("dn", ""))
                    attributes = data.get("attributes")
                    if isinstance(attributes, dict):
                        # Convert to proper format
                        attrs_dict = {}
                        for key, value in attributes.items():
                            if isinstance(value, list):
                                attrs_dict[key] = FlextLdifModels.AttributeValues(
                                    values=[str(v) for v in value]
                                )
                            elif isinstance(value, FlextLdifModels.AttributeValues):
                                # Already an AttributeValues object, use it directly
                                attrs_dict[key] = value
                            else:
                                attrs_dict[key] = FlextLdifModels.AttributeValues(
                                    values=[str(value)]
                                )
                        attributes = attrs_dict
                    else:
                        attributes = {}
                else:
                    dn = str(kwargs.get("dn", ""))
                    attributes = kwargs.get("attributes", {})
                    # Convert attributes to proper format when passed as kwargs
                    if isinstance(attributes, dict):
                        attrs_dict = {}
                        for key, value in attributes.items():
                            if isinstance(value, list):
                                attrs_dict[key] = FlextLdifModels.AttributeValues(
                                    values=[str(v) for v in value]
                                )
                            elif isinstance(value, FlextLdifModels.AttributeValues):
                                # Already an AttributeValues object, use it directly
                                attrs_dict[key] = value
                            else:
                                attrs_dict[key] = FlextLdifModels.AttributeValues(
                                    values=[str(value)]
                                )
                        attributes = attrs_dict

                dn_obj = FlextLdifModels.DistinguishedName(value=dn)
                attrs_dict = cast(
                    "dict[str, FlextLdifModels.AttributeValues]", attributes or {}
                )
                attrs_obj = FlextLdifModels.LdifAttributes(attributes=attrs_dict)
                return FlextResult[FlextLdifModels.Entry].ok(
                    cls(dn=dn_obj, attributes=attrs_obj, domain_events=[])
                )
            except Exception as e:
                return FlextResult[FlextLdifModels.Entry].fail(str(e))

        def to_ldif_string(self, indent: int = 0) -> str:
            """Convert entry to LDIF string."""
            lines = [f"dn: {self.dn.value}"]
            indent_str = " " * indent if indent > 0 else ""

            attribute_lines = [
                f"{indent_str}{attr_name}: {value}"
                for attr_name, attr_values in self.attributes.attributes.items()
                for value in attr_values.values
            ]
            lines.extend(attribute_lines)

            return "\n".join(lines)

        @classmethod
        def from_ldif_string(
            cls, ldif_string: str
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Create Entry from LDIF string."""
            try:
                lines = ldif_string.strip().split("\n")
                dn = ""
                attributes: dict[str, FlextLdifModels.AttributeValues] = {}

                for line in lines:
                    stripped_line = line.strip()
                    if not stripped_line or stripped_line.startswith("#"):
                        continue
                    if stripped_line.startswith("dn:"):
                        dn = stripped_line[3:].strip()
                    elif ":" in stripped_line:
                        attr_line = stripped_line.split(":", 1)
                        if (
                            len(attr_line)
                            == FlextLdifConstants.Processing.MIN_ATTRIBUTE_PARTS
                        ):
                            attr_name = attr_line[0].strip()
                            attr_value = attr_line[1].strip()
                            if attr_name not in attributes:
                                attributes[attr_name] = FlextLdifModels.AttributeValues(
                                    values=[]
                                )
                            attributes[attr_name].values.append(attr_value)

                if not dn:
                    return FlextResult[FlextLdifModels.Entry].fail(
                        "No DN found in LDIF string"
                    )

                return cls.create(data={"dn": dn, "attributes": attributes})
            except Exception as e:
                return FlextResult[FlextLdifModels.Entry].fail(str(e))

    class ChangeRecord(FlextModels.Entity):
        """LDIF change record for modify operations."""

        model_config = ConfigDict(
            validate_assignment=True,
            extra="forbid",
        )

        dn: FlextLdifModels.DistinguishedName = Field(
            ...,
            description="Distinguished Name of the entry",
        )

        changetype: str = Field(
            ...,
            description="Type of change (add, modify, delete)",
        )

        attributes: FlextLdifModels.LdifAttributes = Field(
            default_factory=_create_ldif_attributes,
            description="Change attributes",
        )

        @classmethod
        def create(
            cls,
            dn: str,
            changetype: str,
            attributes: dict[str, list[str]] | None = None,
        ) -> FlextResult[FlextLdifModels.ChangeRecord]:
            """Create a new ChangeRecord instance."""
            try:
                dn_obj = FlextLdifModels.DistinguishedName(value=dn)

                # Convert attributes to proper format
                attrs_dict: dict[str, FlextLdifModels.AttributeValues] = {}
                if attributes:
                    for key, value in attributes.items():
                        if isinstance(value, list):
                            attrs_dict[key] = FlextLdifModels.AttributeValues(
                                values=[str(v) for v in value]
                            )
                        else:
                            attrs_dict[key] = FlextLdifModels.AttributeValues(
                                values=[str(value)]
                            )

                attrs_obj = FlextLdifModels.LdifAttributes(attributes=attrs_dict)
                return FlextResult[FlextLdifModels.ChangeRecord].ok(
                    cls(
                        dn=dn_obj,
                        changetype=changetype,
                        attributes=attrs_obj,
                    )
                )
            except Exception as e:
                return FlextResult[FlextLdifModels.ChangeRecord].fail(str(e))

    class SchemaObjectClass(FlextModels.Value):
        """LDAP object class definition."""

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
        )

        name: str = Field(
            ...,
            description="Object class name",
        )

        oid: str = Field(
            ...,
            description="Object identifier",
        )

        description: str = Field(
            default="",
            description="Object class description",
        )

        must: list[str] = Field(
            default_factory=list,
            description="Required attributes",
        )

        may: list[str] = Field(
            default_factory=list,
            description="Optional attributes",
        )

        superior: list[str] = Field(
            default_factory=list,
            description="Superior object classes",
        )

        structural: bool = Field(
            default=False,
            description="Whether this is a structural object class",
        )

        required_attributes: list[str] = Field(
            default_factory=list,
            description="Required attributes",
        )

        optional_attributes: list[str] = Field(
            default_factory=list,
            description="Optional attributes",
        )

        @classmethod
        def create(cls, *args: object, **kwargs: object) -> FlextResult[object]:
            """Create a new SchemaObjectClass instance."""
            try:
                _ = args  # Suppress unused argument warning
                name = str(kwargs.get("name", ""))
                description = str(kwargs.get("description", ""))
                required_attrs = kwargs.get("required_attributes", [])
                required_attributes = (
                    list(required_attrs)
                    if isinstance(required_attrs, (list, tuple))
                    else []
                )
                instance = cls(
                    name=name,
                    oid=str(kwargs.get("oid", "")),
                    description=description,
                    required_attributes=required_attributes,
                )
                return FlextResult[object].ok(instance)
            except Exception as e:
                return FlextResult[object].fail(str(e))

    class SchemaDiscoveryResult(FlextModels.Value):
        """Result of schema discovery operation."""

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
        )

        object_classes: dict[str, FlextLdifModels.SchemaObjectClass] = Field(
            default_factory=dict,
            description="Discovered object classes",
        )

        attributes: dict[str, FlextLdifModels.SchemaAttribute] = Field(
            default_factory=dict,
            description="Discovered attributes",
        )

        server_type: str = Field(
            default="generic",
            description="Server type",
        )

        entry_count: int = Field(
            default=0,
            description="Number of entries processed",
        )

        @classmethod
        def create(cls, *args: object, **kwargs: object) -> FlextResult[object]:
            """Create a new SchemaDiscoveryResult instance."""
            try:
                # Extract parameters from kwargs (ignore args for compatibility)
                _ = args  # Suppress unused argument warning
                obj_classes = kwargs.get("object_classes", {})
                object_classes = (
                    dict(obj_classes) if isinstance(obj_classes, dict) else {}
                )
                attrs = kwargs.get("attributes", {})
                attributes = dict(attrs) if isinstance(attrs, dict) else {}
                server_type = str(kwargs.get("server_type", "generic"))
                entry_count_val = kwargs.get("entry_count", 0)
                entry_count = (
                    int(entry_count_val)
                    if isinstance(entry_count_val, (int, str))
                    else 0
                )

                instance = cls(
                    object_classes=object_classes or {},
                    attributes=attributes or {},
                    server_type=server_type,
                    entry_count=entry_count,
                )
                return FlextResult[object].ok(instance)
            except Exception as e:
                return FlextResult[object].fail(str(e))

    # =============================================================================
    # ACL MODELS - LDAP Access Control List Models
    # =============================================================================

    class AclTarget(FlextModels.Value):
        """ACL target definition."""

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
        )

        target_dn: str = Field(
            default="",
            description="Target DN for ACL",
        )

        @classmethod
        def create(cls, *args: object, **kwargs: object) -> FlextResult[object]:
            """Create a new AclTarget instance."""
            try:
                _ = args  # Suppress unused argument warning
                target_dn = str(kwargs.get("target_dn", ""))
                instance = cls(target_dn=target_dn)
                return FlextResult[object].ok(instance)
            except Exception as e:
                return FlextResult[object].fail(str(e))

    class AclSubject(FlextModels.Value):
        """ACL subject definition."""

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
        )

        subject_dn: str = Field(
            default="",
            description="Subject DN for ACL",
        )

        @classmethod
        def create(cls, *args: object, **kwargs: object) -> FlextResult[object]:
            """Create a new AclSubject instance."""
            try:
                _ = args  # Suppress unused argument warning
                subject_dn = str(kwargs.get("subject_dn", ""))
                instance = cls(subject_dn=subject_dn)
                return FlextResult[object].ok(instance)
            except Exception as e:
                return FlextResult[object].fail(str(e))

    class AclPermissions(FlextModels.Value):
        """ACL permissions definition."""

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
        )

        read: bool = Field(
            default=False,
            description="Read permission",
        )

        write: bool = Field(
            default=False,
            description="Write permission",
        )

        add: bool = Field(
            default=False,
            description="Add permission",
        )

        delete: bool = Field(
            default=False,
            description="Delete permission",
        )

        search: bool = Field(
            default=False,
            description="Search permission",
        )

        compare: bool = Field(
            default=False,
            description="Compare permission",
        )

        proxy: bool = Field(
            default=False,
            description="Proxy permission",
        )

        @classmethod
        def create(cls, *args: object, **kwargs: object) -> FlextResult[object]:
            """Create a new AclPermissions instance."""
            try:
                _ = args  # Suppress unused argument warning
                read = bool(kwargs.get("read"))
                write = bool(kwargs.get("write"))
                add = bool(kwargs.get("add"))
                delete = bool(kwargs.get("delete"))
                search = bool(kwargs.get("search"))
                compare = bool(kwargs.get("compare"))
                proxy = bool(kwargs.get("proxy"))

                instance = cls(
                    read=read,
                    write=write,
                    add=add,
                    delete=delete,
                    search=search,
                    compare=compare,
                    proxy=proxy,
                )
                return FlextResult[object].ok(instance)
            except Exception as e:
                return FlextResult[object].fail(str(e))

    class UnifiedAcl(FlextModels.Entity):
        """Unified ACL model combining target, subject, and permissions."""

        model_config = ConfigDict(
            validate_assignment=True,
            extra="forbid",
        )

        target: FlextLdifModels.AclTarget = Field(
            ...,
            description="ACL target",
        )

        subject: FlextLdifModels.AclSubject = Field(
            ...,
            description="ACL subject",
        )

        permissions: FlextLdifModels.AclPermissions = Field(
            ...,
            description="ACL permissions",
        )

        name: str = Field(
            default="",
            description="ACL name",
        )

        server_type: str = Field(
            default="",
            description="Server type",
        )

        raw_acl: str = Field(
            default="",
            description="Raw ACL string",
        )

        @classmethod
        def create(
            cls,
            *,
            target: FlextLdifModels.AclTarget,
            subject: FlextLdifModels.AclSubject,
            permissions: FlextLdifModels.AclPermissions,
            name: str = "",
            server_type: str = "",
            raw_acl: str = "",
        ) -> FlextResult[FlextLdifModels.UnifiedAcl]:
            """Create a new UnifiedAcl instance."""
            try:
                return FlextResult[FlextLdifModels.UnifiedAcl].ok(
                    cls(
                        target=target,
                        subject=subject,
                        permissions=permissions,
                        name=name,
                        server_type=server_type,
                        raw_acl=raw_acl,
                    )
                )
            except Exception as e:
                return FlextResult[FlextLdifModels.UnifiedAcl].fail(str(e))

    # =============================================================================
    # SCHEMA MODELS - Additional Schema-related Models
    # =============================================================================

    class SchemaAttribute(FlextModels.Value):
        """LDAP schema attribute definition."""

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
        )

        name: str = Field(
            ...,
            description="Attribute name",
        )

        oid: str = Field(
            ...,
            description="Attribute OID",
        )

        syntax: str = Field(
            default="",
            description="Attribute syntax",
        )

        description: str = Field(
            default="",
            description="Attribute description",
        )

        single_value: bool = Field(
            default=False,
            description="Whether attribute is single-valued",
        )

        @classmethod
        def create(cls, *args: object, **kwargs: object) -> FlextResult[object]:
            """Create a new SchemaAttribute instance."""
            try:
                _ = args  # Suppress unused argument warning
                instance = cls(
                    name=str(kwargs.get("name", "")),
                    oid=str(kwargs.get("oid", "")),
                    syntax=str(kwargs.get("syntax", "")),
                    description=str(kwargs.get("description", "")),
                    single_value=bool(kwargs.get("single_value")),
                )
                return FlextResult[object].ok(instance)
            except Exception as e:
                return FlextResult[object].fail(str(e))

    # =============================================================================
    # ADDITIONAL MODELS REQUIRED BY TESTS
    # =============================================================================

    class SearchConfig(FlextModels.Value):
        """Search configuration for LDIF operations."""

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
        )

        base_dn: str = Field(
            ...,
            min_length=1,
            description="Base DN for search",
        )

        search_filter: str = Field(
            default="(objectClass=*)",
            description="LDAP search filter",
        )

        attributes: list[str] = Field(
            default_factory=list,
            description="Attributes to return",
        )

        @field_validator("base_dn")
        @classmethod
        def validate_base_dn(cls, v: str) -> str:
            """Validate base DN."""
            if not v.strip():
                msg = "Base DN cannot be empty"
                raise ValueError(msg)
            return v.strip()

    class LdifDocument(FlextModels.Entity):
        """LDIF document containing multiple entries."""

        model_config = ConfigDict(
            validate_assignment=True,
            extra="forbid",
        )

        entries: list[FlextLdifModels.Entry] = Field(
            default_factory=list,
            description="LDIF entries",
        )

        @classmethod
        def from_ldif_string(
            cls, ldif_string: str
        ) -> FlextResult[FlextLdifModels.LdifDocument]:
            """Create LdifDocument from LDIF string."""
            try:
                if not ldif_string.strip():
                    return FlextResult[FlextLdifModels.LdifDocument].ok(
                        cls(entries=[], domain_events=[])
                    )

                # Split by double newlines to separate entries
                entry_blocks = ldif_string.strip().split("\n\n")
                entries = []

                for block in entry_blocks:
                    if block.strip():
                        result = FlextLdifModels.Entry.from_ldif_string(block)
                        if result.is_success:
                            entries.append(result.value)
                        else:
                            return FlextResult[FlextLdifModels.LdifDocument].fail(
                                f"Failed to parse entry: {result.error}"
                            )

                return FlextResult[FlextLdifModels.LdifDocument].ok(
                    cls(entries=entries, domain_events=[])
                )
            except Exception as e:
                return FlextResult[FlextLdifModels.LdifDocument].fail(str(e))

        def to_ldif_string(self) -> str:
            """Convert document to LDIF string."""
            return "\n\n".join(entry.to_ldif_string() for entry in self.entries)

    # =============================================================================
    # ALIASES FOR BACKWARD COMPATIBILITY
    # =============================================================================

    # Alias for Entry class (tests expect LdifEntry)
    LdifEntry = Entry
    # Alias for ChangeRecord class (tests expect LdifChangeRecord)
    LdifChangeRecord = ChangeRecord

    class AttributeValues(FlextModels.Value):
        """Simple attribute values container for tests."""

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
        )

        values: list[str] = Field(
            default_factory=list,
            description="Attribute values",
        )

        def __len__(self) -> int:
            """Return the number of values."""
            return len(self.values)

        def __getitem__(self, index: int) -> str:
            """Get value by index."""
            return self.values[index]

        def __contains__(self, item: str) -> bool:
            """Check if value exists in the list."""
            return item in self.values

        @property
        def single_value(self) -> str | None:
            """Get single value (first value if multiple exist)."""
            return self.values[0] if self.values else None

    # Aliases for test compatibility
    DN = DistinguishedName
    Attributes = LdifAttributes


__all__ = ["FlextLdifModels"]
