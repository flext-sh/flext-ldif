"""FLEXT LDIF Models - Advanced Pydantic 2 Models with Monadic Composition.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

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

    class LdifAttributes(FlextModels.Value):
        """Collection of LDIF attributes."""

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
        )

        attributes: dict[str, list[str]] = Field(
            default_factory=dict,
            description="Dictionary of attribute names to values",
        )

        def get_attribute(self, name: str) -> list[str]:
            """Get attribute values by name."""
            name_lower = name.lower()
            for key, values in self.attributes.items():
                if key.lower() == name_lower:
                    return values
            return []

        def set_attribute(self, name: str, values: list[str]) -> None:
            """Set attribute values."""
            self.attributes[name.lower()] = values

        def has_attribute(self, name: str) -> bool:
            """Check if attribute exists."""
            name_lower = name.lower()
            return any(key.lower() == name_lower for key in self.attributes)

        @property
        def data(self) -> dict[str, list[str]]:
            """Get attributes data dictionary."""
            return self.attributes

        def __getitem__(self, name: str) -> list[str]:
            """Dictionary-like access to attributes."""
            return self.get_attribute(name)

        def __setitem__(self, name: str, values: list[str]) -> None:
            """Dictionary-like setting of attributes."""
            # Since the model is frozen, we need to use object.__setattr__
            if hasattr(self, "attributes"):
                self.attributes[name.lower()] = values
            else:
                object.__setattr__(self, "attributes", {name.lower(): values})

        def __contains__(self, name: str) -> bool:
            """Dictionary-like 'in' check."""
            return self.has_attribute(name)

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

        def get_attribute(self, name: str) -> list[str]:
            """Get attribute values by name."""
            return self.attributes.get_attribute(name)

        def has_attribute(self, name: str) -> bool:
            """Check if attribute exists."""
            return self.attributes.has_attribute(name)

        def get_single_value(self, name: str) -> str | None:
            """Get single attribute value (first value if multiple exist)."""
            values = self.get_attribute(name)
            return values[0] if values else None

        def is_person_entry(self) -> bool:
            """Check if entry is a person entry."""
            object_classes = self.get_attribute("objectClass")
            person_classes = {"person", "inetorgperson"}
            return any(oc.lower() in person_classes for oc in object_classes)

        def is_group_entry(self) -> bool:
            """Check if entry is a group entry."""
            object_classes = self.get_attribute("objectClass")
            group_classes = {"group", "groupofnames", "groupofuniquenames"}
            return any(oc.lower() in group_classes for oc in object_classes)

        def is_organizational_unit(self) -> bool:
            """Check if entry is an organizational unit."""
            object_classes = self.get_attribute("objectClass")
            return "organizationalunit" in [oc.lower() for oc in object_classes]

        def has_object_class(self, object_class: str) -> bool:
            """Check if entry has specific object class."""
            object_classes = self.get_attribute("objectClass")
            return object_class.lower() in [oc.lower() for oc in object_classes]

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
                                attrs_dict[key] = [str(v) for v in value]
                            else:
                                attrs_dict[key] = [str(value)]
                        attributes = attrs_dict
                    else:
                        attributes = {}
                else:
                    dn = str(kwargs.get("dn", ""))
                    attributes = kwargs.get("attributes", {})

                dn_obj = FlextLdifModels.DistinguishedName(value=dn)
                attrs_obj = FlextLdifModels.LdifAttributes(attributes=attributes or {})
                return FlextResult[FlextLdifModels.Entry].ok(
                    cls(dn=dn_obj, attributes=attrs_obj, domain_events=[])
                )
            except Exception as e:
                return FlextResult[FlextLdifModels.Entry].fail(str(e))

        @classmethod
        def from_ldif_string(
            cls, ldif_string: str
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Create Entry from LDIF string."""
            try:
                lines = ldif_string.strip().split("\n")
                dn = ""
                attributes: dict[str, list[str]] = {}

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
                                attributes[attr_name] = []
                            attributes[attr_name].append(attr_value)

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
                attrs_obj = FlextLdifModels.LdifAttributes(attributes=attributes or {})
                return FlextResult[FlextLdifModels.ChangeRecord].ok(
                    cls(
                        dn=dn_obj,
                        changetype=changetype,
                        attributes=attrs_obj,
                        domain_events=[],
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

        attributes: dict[str, dict[str, str]] = Field(
            default_factory=dict,
            description="Discovered attributes",
        )

        @classmethod
        def create(cls, *args: object, **kwargs: object) -> FlextResult[object]:
            """Create a new SchemaDiscoveryResult instance."""
            try:
                # Extract parameters from kwargs (ignore args for compatibility)
                _ = args  # Suppress unused argument warning
                object_classes = kwargs.get("object_classes", {})
                attributes = kwargs.get("attributes", {})

                instance = cls(
                    object_classes=object_classes or {}, attributes=attributes or {}
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
                target_dn = kwargs.get("target_dn", "")
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
                subject_dn = kwargs.get("subject_dn", "")
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
                read = kwargs.get("read", False)
                write = kwargs.get("write", False)
                add = kwargs.get("add", False)
                delete = kwargs.get("delete", False)
                search = kwargs.get("search", False)
                compare = kwargs.get("compare", False)
                proxy = kwargs.get("proxy", False)

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
                        domain_events=[],
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
                    name=kwargs.get("name", ""),
                    oid=kwargs.get("oid", ""),
                    syntax=kwargs.get("syntax", ""),
                    description=kwargs.get("description", ""),
                    single_value=kwargs.get("single_value", False),
                )
                return FlextResult[object].ok(instance)
            except Exception as e:
                return FlextResult[object].fail(str(e))

    # =============================================================================
    # ALIASES FOR BACKWARD COMPATIBILITY
    # =============================================================================

    # Alias for Entry class (tests expect LdifEntry)
    LdifEntry = Entry
    # Alias for ChangeRecord class (tests expect LdifChangeRecord)
    LdifChangeRecord = ChangeRecord


__all__ = ["FlextLdifModels"]
