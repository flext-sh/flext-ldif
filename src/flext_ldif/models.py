"""FLEXT LDIF Models.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import cast, override

from pydantic import BaseModel, Field, field_validator

from flext_core import FlextModels, FlextResult
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.mixins import FlextLdifMixins


def _create_default_ldif_attributes() -> FlextLdifModels.LdifAttributes:
    """Create default LdifAttributes instance."""
    return FlextLdifModels.LdifAttributes()


class FlextLdifModels(FlextModels):
    """LDIF domain models extending flext-core FlextModels.

    Contains ONLY Pydantic v2 model definitions with business logic.
    Uses flext-core SOURCE OF TRUTH for model patterns and validation.
    """

    class DistinguishedName(BaseModel, FlextLdifMixins.ValidationMixin):
        """Pydantic model for LDAP Distinguished Name."""

        value: str = Field(..., min_length=1, description="DN string value")

        @field_validator("value")
        @staticmethod
        @override
        def validate_dn_format(value: str) -> str:
            """Validate DN format and characters."""
            return FlextLdifMixins.ValidationMixin.validate_dn_format(value)

        @property
        def depth(self) -> int:
            """Get DN component depth."""
            return len([
                component for component in self.value.split(",") if component.strip()
            ])

        @property
        def components(self) -> list[str]:
            """Get DN components as list."""
            return [
                component.strip()
                for component in self.value.split(",")
                if component.strip()
            ]

        @classmethod
        def create(
            cls, dn_value: str
        ) -> FlextResult[FlextLdifModels.DistinguishedName]:
            """Create DN with validation returning FlextResult."""
            try:
                instance = cls(value=dn_value)
                return FlextResult[FlextLdifModels.DistinguishedName].ok(instance)
            except ValueError as e:
                return FlextResult[FlextLdifModels.DistinguishedName].fail(str(e))
            except Exception as e:
                return FlextResult[FlextLdifModels.DistinguishedName].fail(
                    f"DN creation error: {e}"
                )

    class LdifAttributes(BaseModel, FlextLdifMixins.ValidationMixin):
        """Pydantic model for LDIF entry attributes."""

        data: dict[str, list[str]] = Field(
            default_factory=dict, description="Attribute name to values mapping"
        )

        @field_validator("data")
        @classmethod
        def validate_attributes(cls, v: object) -> dict[str, list[str]]:
            """Validate attribute data structure."""
            if not isinstance(v, dict):
                raise TypeError(FlextLdifConstants.ErrorMessages.ATTRIBUTES_TYPE_ERROR)

            validated_dict = cast("dict[str, object]", v)
            for attr_name, attr_values in validated_dict.items():
                FlextLdifMixins.ValidationMixin.validate_attribute_name(str(attr_name))
                FlextLdifMixins.ValidationMixin.validate_attribute_values(
                    cast("list[str]", attr_values)
                )

            return cast("dict[str, list[str]]", v)

        def get_attribute(self, name: str) -> list[str] | None:
            """Get attribute values by name."""
            return self.data.get(name)

        def has_attribute(self, name: str) -> bool:
            """Check if attribute exists."""
            return name in self.data

        def add_attribute(self, name: str, values: list[str]) -> None:
            """Add attribute with values."""
            self.data[name] = values

        def remove_attribute(self, name: str) -> bool:
            """Remove attribute. Returns True if removed, False if not found."""
            return self.data.pop(name, None) is not None

        def __contains__(self, name: str) -> bool:
            """Support 'in' operator for attribute names."""
            return name in self.data

        def __len__(self) -> int:
            """Support len() function for number of attributes."""
            return len(self.data)

        @classmethod
        def create(
            cls, data: dict[str, list[str]]
        ) -> FlextResult[FlextLdifModels.LdifAttributes]:
            """Create attributes with validation returning FlextResult."""
            try:
                instance = cls(data=data)
                return FlextResult[FlextLdifModels.LdifAttributes].ok(instance)
            except ValueError as e:
                return FlextResult[FlextLdifModels.LdifAttributes].fail(str(e))
            except Exception as e:
                return FlextResult[FlextLdifModels.LdifAttributes].fail(
                    f"attributes creation error: {e}"
                )

    class Entry(BaseModel):
        """Pydantic model for LDIF entry."""

        dn: FlextLdifModels.DistinguishedName = Field(
            ..., description="Distinguished Name"
        )
        attributes: FlextLdifModels.LdifAttributes = Field(
            ..., description="Entry attributes"
        )

        def get_attribute(self, name: str) -> list[str] | None:
            """Get attribute values by name."""
            return self.attributes.get_attribute(name)

        def get_single_value(self, name: str) -> str | None:
            """Get single attribute value by name."""
            values = self.get_attribute(name)
            return values[0] if values else None

        def has_attribute(self, name: str) -> bool:
            """Check if attribute exists."""
            return self.attributes.has_attribute(name)

        def has_object_class(self, object_class: str) -> bool:
            """Check if entry has specified object class."""
            object_classes = self.get_attribute("objectClass") or []
            return object_class.lower() in [oc.lower() for oc in object_classes]

        def is_person_entry(self) -> bool:
            """Check if entry is a person entry."""
            object_classes = self.get_attribute("objectClass") or []
            person_classes = {oc.lower() for oc in object_classes}
            ldap_person_classes = {
                oc.lower()
                for oc in FlextLdifConstants.ObjectClasses.LDAP_PERSON_CLASSES
            }
            return bool(person_classes.intersection(ldap_person_classes))

        def is_group_entry(self) -> bool:
            """Check if entry is a group entry."""
            object_classes = self.get_attribute("objectClass") or []
            group_classes = {oc.lower() for oc in object_classes}
            ldap_group_classes = {
                oc.lower() for oc in FlextLdifConstants.ObjectClasses.LDAP_GROUP_CLASSES
            }
            return bool(group_classes.intersection(ldap_group_classes))

        def is_organizational_unit(self) -> bool:
            """Check if entry is an organizational unit."""
            return self.has_object_class("organizationalUnit")

        def validate_business_rules(self) -> FlextResult[bool]:
            """Validate entry against business rules."""
            # Basic validation - entry must have DN and at least one attribute
            if not self.dn.value:  # pragma: no cover
                return FlextResult[bool].fail("Entry must have a valid DN")

            if not self.attributes.data:  # pragma: no cover
                return FlextResult[bool].fail("Entry must have at least one attribute")

            # Check minimum DN components
            if (
                self.dn.depth < FlextLdifConstants.LdifValidation.MIN_DN_COMPONENTS
            ):  # pragma: no cover
                return FlextResult[bool].fail("DN must have at least one component")

            return FlextResult[bool].ok(True)

        @classmethod
        def create(
            cls,
            data: dict[str, object] | str,
            attributes: dict[str, list[str]] | None = None,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Create entry with validation returning FlextResult.

            Args:
                data: Either dict with 'dn' and 'attributes', or a DN string
                attributes: Optional attributes dict if data is a DN string

            """
            # Handle dict input (new unified API)
            if isinstance(data, dict):
                dn = data.get("dn")
                if not isinstance(dn, str):
                    return FlextResult[FlextLdifModels.Entry].fail(
                        "DN must be a string"
                    )

                attrs = data.get("attributes", {})
                if not isinstance(attrs, dict):
                    return FlextResult[FlextLdifModels.Entry].fail(
                        "Attributes must be a dictionary"
                    )

                # Normalize attributes to proper format
                normalized_attrs: dict[str, list[str]] = {}
                attributes_dict = cast("dict[str, object]", attrs)
                for key, value in attributes_dict.items():
                    key_str: str = str(key)
                    if isinstance(value, str):
                        normalized_attrs[key_str] = [value]
                    elif isinstance(value, list):
                        normalized_attrs[key_str] = [
                            str(v) for v in cast("list[object]", value) if v is not None
                        ]
                    else:
                        normalized_attrs[key_str] = [str(value)]

                dn_str = dn
                attrs_data = normalized_attrs
            # Handle string DN with separate attributes (backward compatibility)
            elif isinstance(data, str) and attributes is not None:
                dn_str = data
                attrs_data = attributes
            else:
                return FlextResult[FlextLdifModels.Entry].fail(
                    "Invalid input: provide dict with 'dn'/'attributes' or DN string with attributes dict"
                )

            # Create DN
            dn_result = FlextLdifModels.DistinguishedName.create(dn_str)
            if dn_result.is_failure:
                return FlextResult["FlextLdifModels.Entry"].fail(
                    dn_result.error or "Invalid DN"
                )

            # Create attributes
            attrs_result = FlextLdifModels.LdifAttributes.create(attrs_data)
            if attrs_result.is_failure:
                return FlextResult["FlextLdifModels.Entry"].fail(
                    attrs_result.error or "Invalid attributes"
                )

            try:
                entry = cls(dn=dn_result.value, attributes=attrs_result.value)
                return FlextResult["FlextLdifModels.Entry"].ok(entry)
            except Exception as e:  # pragma: no cover
                return FlextResult["FlextLdifModels.Entry"].fail(str(e))

    class LdifUrl(BaseModel, FlextLdifMixins.ValidationMixin):
        """Pydantic model for LDIF URL references."""

        url: str = Field(..., description="URL string")
        description: str = Field(default="", description="Optional description")

        @field_validator("url")
        @classmethod
        def validate_ldif_url_format(cls, v: str) -> str:
            """Basic URL format validation."""
            return FlextLdifMixins.ValidationMixin.validate_url_format(v)

        @classmethod
        def create(
            cls, url: str, description: str = ""
        ) -> FlextResult[FlextLdifModels.LdifUrl]:
            """Create URL with validation returning FlextResult."""
            try:
                instance = cls(url=url, description=description)
                return FlextResult[FlextLdifModels.LdifUrl].ok(instance)
            except ValueError as e:
                return FlextResult[FlextLdifModels.LdifUrl].fail(str(e))
            except Exception as e:
                return FlextResult[FlextLdifModels.LdifUrl].fail(
                    f"URL creation error: {e}"
                )

    class ChangeRecord(BaseModel):
        """Pydantic model for LDIF change records (RFC 2849)."""

        dn: FlextLdifModels.DistinguishedName = Field(
            ..., description="Distinguished Name"
        )
        changetype: str = Field(
            ..., description="Change type (add, modify, delete, modrdn)"
        )
        attributes: FlextLdifModels.LdifAttributes = Field(
            default_factory=_create_default_ldif_attributes,
            description="Entry attributes",
        )
        modifications: list[dict[str, object]] = Field(
            default_factory=list,
            description="Modification operations for modify changetype",
        )

        @field_validator("changetype")
        @classmethod
        def validate_changetype(cls, v: str) -> str:
            """Validate change type."""
            valid_types = ["add", "modify", "delete", "modrdn"]
            if v.lower() not in valid_types:
                msg = f"Invalid changetype: {v}. Must be one of {valid_types}"
                raise ValueError(msg)
            return v.lower()

        def get_attribute(self, name: str) -> list[str] | None:
            """Get attribute values by name."""
            return self.attributes.get_attribute(name)

        def has_attribute(self, name: str) -> bool:
            """Check if attribute exists."""
            return self.attributes.has_attribute(name)

        def add_modification(
            self, operation: str, attr_name: str, attr_values: list[str]
        ) -> None:
            """Add modification operation."""
            modification = {
                "operation": operation,
                "attribute": attr_name,
                "values": attr_values,
            }
            self.modifications.append(modification)

        @classmethod
        def create(
            cls,
            data: dict[str, object],
        ) -> FlextResult[FlextLdifModels.ChangeRecord]:
            """Create change record with validation returning FlextResult."""
            try:
                # Extract DN
                dn_value = data.get("dn")
                if not isinstance(dn_value, str):
                    return FlextResult[FlextLdifModels.ChangeRecord].fail(
                        "DN must be a string"
                    )

                # Extract changetype
                changetype_value = data.get("changetype")
                if not isinstance(changetype_value, str):
                    return FlextResult[FlextLdifModels.ChangeRecord].fail(
                        "changetype must be a string"
                    )

                # Extract attributes
                attrs = data.get("attributes", {})
                if not isinstance(attrs, dict):
                    attrs = {}

                # Normalize attributes to proper format
                normalized_attrs: dict[str, list[str]] = {}
                attributes_dict = cast("dict[str, object]", attrs)
                for key, value in attributes_dict.items():
                    key_str: str = str(key)
                    if isinstance(value, str):
                        normalized_attrs[key_str] = [value]
                    elif isinstance(value, list):
                        normalized_attrs[key_str] = [
                            str(v) for v in cast("list[object]", value) if v is not None
                        ]
                    else:
                        normalized_attrs[key_str] = [str(value)]

                # Create DN
                dn_result = FlextLdifModels.DistinguishedName.create(dn_value)
                if dn_result.is_failure:
                    return FlextResult[FlextLdifModels.ChangeRecord].fail(
                        dn_result.error or "Invalid DN"
                    )

                # Create attributes
                attrs_result = FlextLdifModels.LdifAttributes.create(normalized_attrs)
                if attrs_result.is_failure:
                    return FlextResult[FlextLdifModels.ChangeRecord].fail(
                        attrs_result.error or "Invalid attributes"
                    )

                # Extract modifications
                modifications = data.get("modifications", [])
                if not isinstance(modifications, list):
                    modifications = []

                # Create change record
                change_record = cls(
                    dn=dn_result.value,
                    changetype=changetype_value,
                    attributes=attrs_result.value,
                    modifications=modifications,
                )
                return FlextResult[FlextLdifModels.ChangeRecord].ok(change_record)

            except Exception as e:
                return FlextResult[FlextLdifModels.ChangeRecord].fail(str(e))

    class LdifVersion(BaseModel):
        """Pydantic model for LDIF version control."""

        version: str = Field(default="1", description="LDIF version")
        encoding: str = Field(default="utf-8", description="Character encoding")

        @field_validator("version")
        @classmethod
        def validate_version(cls, v: str) -> str:
            """Validate LDIF version."""
            if v != "1":
                msg = f"Unsupported LDIF version: {v}"
                raise ValueError(msg)
            return v

        @field_validator("encoding")
        @classmethod
        def validate_encoding(cls, v: str) -> str:
            """Validate character encoding."""
            return FlextLdifMixins.ValidationMixin.validate_encoding(v)

        @classmethod
        def create(
            cls, version: str = "1", encoding: str = "utf-8"
        ) -> FlextResult[FlextLdifModels.LdifVersion]:
            """Create version record with validation returning FlextResult."""
            try:
                instance = cls(version=version, encoding=encoding)
                return FlextResult[FlextLdifModels.LdifVersion].ok(instance)
            except ValueError as e:
                return FlextResult[FlextLdifModels.LdifVersion].fail(str(e))
            except Exception as e:
                return FlextResult[FlextLdifModels.LdifVersion].fail(
                    f"Version creation error: {e}"
                )

    class SchemaAttribute(BaseModel):
        """Schema attribute model."""

        name: str = Field(..., description="Attribute name")
        syntax: str = Field(default="", description="Attribute syntax OID")
        description: str = Field(default="", description="Attribute description")
        single_value: bool = Field(
            default=False, description="Whether attribute is single-valued"
        )
        user_modifiable: bool = Field(
            default=True, description="Whether users can modify this attribute"
        )

        @classmethod
        def create(
            cls,
            name: str,
            syntax: str = "",
            description: str = "",
            *,
            single_value: bool = False,
            user_modifiable: bool = True,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Create a schema attribute."""
            try:
                instance = cls(
                    name=name,
                    syntax=syntax,
                    description=description,
                    single_value=single_value,
                    user_modifiable=user_modifiable,
                )
                return FlextResult[FlextLdifModels.SchemaAttribute].ok(instance)
            except Exception as e:
                return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                    f"Schema attribute creation error: {e}"
                )

    class SchemaObjectClass(BaseModel):
        """Schema object class model."""

        name: str = Field(..., description="ObjectClass name")
        oid: str = Field(default="", description="ObjectClass OID")
        description: str = Field(default="", description="ObjectClass description")
        superior: list[str] = Field(
            default_factory=list, description="Superior objectClasses"
        )
        structural: bool = Field(
            default=True, description="Whether this is a structural objectClass"
        )
        required_attributes: list[str] = Field(
            default_factory=list, description="Required attributes"
        )
        optional_attributes: list[str] = Field(
            default_factory=list, description="Optional attributes"
        )

        @classmethod
        def create(
            cls,
            name: str,
            oid: str = "",
            description: str = "",
            superior: list[str] | None = None,
            *,
            structural: bool = True,
            required_attributes: list[str] | None = None,
            optional_attributes: list[str] | None = None,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Create a schema object class."""
            try:
                instance = cls(
                    name=name,
                    oid=oid,
                    description=description,
                    superior=superior or [],
                    structural=structural,
                    required_attributes=required_attributes or [],
                    optional_attributes=optional_attributes or [],
                )
                return FlextResult[FlextLdifModels.SchemaObjectClass].ok(instance)
            except Exception as e:
                return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                    f"Schema objectClass creation error: {e}"
                )

    class SchemaDiscoveryResult(BaseModel):
        """Schema discovery result model."""

        attributes: dict[str, FlextLdifModels.SchemaAttribute] = Field(
            default_factory=dict, description="Discovered attributes"
        )
        object_classes: dict[str, FlextLdifModels.SchemaObjectClass] = Field(
            default_factory=dict, description="Discovered objectClasses"
        )
        server_type: str = Field(default="generic", description="Detected server type")
        entry_count: int = Field(default=0, description="Number of entries analyzed")
        discovered_dns: list[str] = Field(
            default_factory=list, description="Unique DNs discovered"
        )

        @classmethod
        def create(
            cls,
            attributes: dict[str, FlextLdifModels.SchemaAttribute] | None = None,
            object_classes: dict[str, FlextLdifModels.SchemaObjectClass] | None = None,
            server_type: str = "generic",
            entry_count: int = 0,
            discovered_dns: list[str] | None = None,
        ) -> FlextResult[FlextLdifModels.SchemaDiscoveryResult]:
            """Create a schema discovery result."""
            try:
                instance = cls(
                    attributes=attributes or {},
                    object_classes=object_classes or {},
                    server_type=server_type,
                    entry_count=entry_count,
                    discovered_dns=discovered_dns or [],
                )
                return FlextResult[FlextLdifModels.SchemaDiscoveryResult].ok(instance)
            except Exception as e:
                return FlextResult[FlextLdifModels.SchemaDiscoveryResult].fail(
                    f"Schema discovery result creation error: {e}"
                )

    # =========================================================================
    # ACL MODELS - Access Control List models
    # =========================================================================

    class AclTarget(BaseModel):
        """ACL target specification."""

        target_dn: str | None = None
        target_filter: str | None = None
        target_attributes: list[str] | None = None

        @classmethod
        def create(
            cls,
            target_dn: str | None = None,
            target_filter: str | None = None,
            target_attributes: list[str] | None = None,
        ) -> FlextResult[FlextLdifModels.AclTarget]:
            """Create ACL target with validation."""
            try:
                instance = cls(
                    target_dn=target_dn,
                    target_filter=target_filter,
                    target_attributes=target_attributes,
                )
                return FlextResult[FlextLdifModels.AclTarget].ok(instance)
            except Exception as e:
                return FlextResult[FlextLdifModels.AclTarget].fail(str(e))

    class AclSubject(BaseModel):
        """ACL subject specification."""

        subject_dn: str | None = None
        subject_filter: str | None = None
        subject_type: str | None = None

        @classmethod
        def create(
            cls,
            subject_dn: str | None = None,
            subject_filter: str | None = None,
            subject_type: str | None = None,
        ) -> FlextResult[FlextLdifModels.AclSubject]:
            """Create ACL subject with validation."""
            try:
                instance = cls(
                    subject_dn=subject_dn,
                    subject_filter=subject_filter,
                    subject_type=subject_type,
                )
                return FlextResult[FlextLdifModels.AclSubject].ok(instance)
            except Exception as e:
                return FlextResult[FlextLdifModels.AclSubject].fail(str(e))

    class AclPermissions(BaseModel):
        """ACL permissions specification."""

        read: bool = False
        write: bool = False
        add: bool = False
        delete: bool = False
        search: bool = False
        compare: bool = False
        proxy: bool = False

        @classmethod
        def create(
            cls,
            *,
            read: bool = False,
            write: bool = False,
            add: bool = False,
            delete: bool = False,
            search: bool = False,
            compare: bool = False,
            proxy: bool = False,
        ) -> FlextResult[FlextLdifModels.AclPermissions]:
            """Create ACL permissions with validation."""
            try:
                instance = cls(
                    read=read,
                    write=write,
                    add=add,
                    delete=delete,
                    search=search,
                    compare=compare,
                    proxy=proxy,
                )
                return FlextResult[FlextLdifModels.AclPermissions].ok(instance)
            except Exception as e:
                return FlextResult[FlextLdifModels.AclPermissions].fail(str(e))

    class UnifiedAcl(BaseModel):
        """Unified ACL entry across server types."""

        name: str
        target: FlextLdifModels.AclTarget
        subject: FlextLdifModels.AclSubject
        permissions: FlextLdifModels.AclPermissions
        server_type: str
        raw_acl: str

        @classmethod
        def create(
            cls,
            name: str,
            target: FlextLdifModels.AclTarget,
            subject: FlextLdifModels.AclSubject,
            permissions: FlextLdifModels.AclPermissions,
            server_type: str,
            raw_acl: str,
        ) -> FlextResult[FlextLdifModels.UnifiedAcl]:
            """Create unified ACL with validation."""
            try:
                instance = cls(
                    name=name,
                    target=target,
                    subject=subject,
                    permissions=permissions,
                    server_type=server_type,
                    raw_acl=raw_acl,
                )
                return FlextResult[FlextLdifModels.UnifiedAcl].ok(instance)
            except Exception as e:
                return FlextResult[FlextLdifModels.UnifiedAcl].fail(str(e))

    class AclEntry(BaseModel):
        """ACL entry in LDIF format."""

        dn: str
        acl_attribute: str
        acl_values: list[str]
        server_type: str

        @classmethod
        def create(
            cls,
            dn: str,
            acl_attribute: str,
            acl_values: list[str],
            server_type: str,
        ) -> FlextResult[FlextLdifModels.AclEntry]:
            """Create ACL entry with validation."""
            try:
                instance = cls(
                    dn=dn,
                    acl_attribute=acl_attribute,
                    acl_values=acl_values,
                    server_type=server_type,
                )
                return FlextResult[FlextLdifModels.AclEntry].ok(instance)
            except Exception as e:
                return FlextResult[FlextLdifModels.AclEntry].fail(str(e))


__all__ = ["FlextLdifModels"]
