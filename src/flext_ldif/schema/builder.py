"""FLEXT LDIF Schema Builder.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from flext_core import FlextLogger, FlextResult, FlextService
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels


class FlextLdifSchemaBuilder(FlextService[FlextLdifModels.SchemaDiscoveryResult]):
    """Schema builder for standard LDAP schemas."""

    def __init__(self) -> None:
        """Initialize schema builder."""
        super().__init__()
        self._logger = FlextLogger(__name__)

    def execute(self) -> FlextResult[FlextLdifModels.SchemaDiscoveryResult]:
        """Execute schema builder service."""
        return self.build_standard_person_schema()

    def build_standard_person_schema(
        self,
    ) -> FlextResult[FlextLdifModels.SchemaDiscoveryResult]:
        """Build standard person schema.

        Returns:
            FlextResult containing person schema

        """
        attributes: dict[str, FlextLdifModels.SchemaAttribute] = {}
        object_classes: dict[str, FlextLdifModels.SchemaObjectClass] = {}

        standard_attrs = [
            ("cn", "Common Name"),
            ("sn", "Surname"),
            ("uid", "User ID"),
            ("mail", "Email Address"),
            ("telephoneNumber", "Telephone Number"),
            ("objectClass", "Object Class"),
        ]

        for attr_name, description in standard_attrs:
            attr_result = FlextLdifModels.SchemaAttribute.create(
                name=attr_name,
                description=description,
                single_value=attr_name in {"cn", "sn", "uid"},
            )
            if attr_result.is_success:
                attributes[attr_name] = attr_result.value

        for oc_name in FlextLdifConstants.ObjectClasses.LDAP_PERSON_CLASSES:
            oc_result = FlextLdifModels.SchemaObjectClass.create(
                name=oc_name,
                description=f"Standard LDAP {oc_name}",
                required_attributes=["cn", "sn"] if oc_name == "person" else ["cn"],
            )
            if oc_result.is_success:
                object_classes[oc_name] = oc_result.value

        return FlextLdifModels.SchemaDiscoveryResult.create(
            attributes=attributes,
            object_classes=object_classes,
            server_type="generic",
            entry_count=0,
        )

    def build_standard_group_schema(
        self,
    ) -> FlextResult[FlextLdifModels.SchemaDiscoveryResult]:
        """Build standard group schema.

        Returns:
            FlextResult containing group schema

        """
        attributes: dict[str, FlextLdifModels.SchemaAttribute] = {}
        object_classes: dict[str, FlextLdifModels.SchemaObjectClass] = {}

        standard_attrs = [
            ("cn", "Common Name"),
            ("member", "Group Member"),
            ("uniqueMember", "Unique Group Member"),
            ("objectClass", "Object Class"),
        ]

        for attr_name, description in standard_attrs:
            attr_result = FlextLdifModels.SchemaAttribute.create(
                name=attr_name,
                description=description,
                single_value=attr_name == "cn",
            )
            if attr_result.is_success:
                attributes[attr_name] = attr_result.value

        for oc_name in FlextLdifConstants.ObjectClasses.LDAP_GROUP_CLASSES:
            required_attrs = (
                ["member"] if oc_name == "groupofnames" else ["uniqueMember"]
            )
            oc_result = FlextLdifModels.SchemaObjectClass.create(
                name=oc_name,
                description=f"Standard LDAP {oc_name}",
                required_attributes=["cn", *required_attrs],
            )
            if oc_result.is_success:
                object_classes[oc_name] = oc_result.value

        return FlextLdifModels.SchemaDiscoveryResult.create(
            attributes=attributes,
            object_classes=object_classes,
            server_type="generic",
            entry_count=0,
        )


__all__ = ["FlextLdifSchemaBuilder"]
