"""FLEXT LDIF ACL - Access Control List Models.

ACL models for LDAP access control definitions.
Extends flext-core FlextModels with LDIF-specific ACL entities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextModels, FlextResult, FlextTypes
from pydantic import (
    ConfigDict,
    Field,
    SerializationInfo,
    computed_field,
    field_serializer,
)

from flext_ldif.models import FlextLdifModels


class FlextLdifAcl:
    """ACL-related models extending FlextModels.

    Contains models for LDAP access control:
    - AclTarget: ACL target definitions
    - AclSubject: ACL subject definitions
    - AclPermissions: ACL permission definitions
    - UnifiedAcl: Complete ACL model
    """

    class AclTarget(FlextModels.Value):
        """ACL target definition."""

        model_config = ConfigDict(
            frozen=True,
            validate_assignment=True,
            extra="forbid",
            hide_input_in_errors=True,
        )

        target_dn: str = Field(
            default="",
            description="Target DN for ACL",
        )

        @computed_field
        def target_key(self) -> str:
            """Computed field for unique target key."""
            return f"target:{self.target_dn.lower()}"

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

    class AclSubject(FlextLdifModels.BaseAclSubject):
        """Standard ACL subject definition.

        Extends BaseAclSubject with standard LDIF behavior.
        """

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
                instance = cls(
                    subject_type="dn",
                    subject_value=subject_dn,
                    subject_dn=subject_dn,
                )
                return FlextResult[object].ok(instance)
            except Exception as e:
                return FlextResult[object].fail(str(e))

    class AclPermissions(FlextLdifModels.BaseAclPermissions):
        """Standard ACL permissions definition.

        Extends BaseAclPermissions with standard LDIF behavior.
        """

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

        @field_serializer("read", when_used="json")
        def serialize_permissions_with_summary(
            self, value: bool, _info: SerializationInfo
        ) -> FlextTypes.Dict:
            """Serialize permissions with summary context.

            Note: Boolean parameter required by Pydantic field_serializer protocol.
            """
            return {"read": value, "permissions_context": self.permissions_summary}

    class UnifiedAcl(FlextModels.Entity):
        """Unified ACL model combining target, subject, and permissions."""

        model_config = ConfigDict(
            validate_assignment=True, extra="forbid", hide_input_in_errors=True
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

        @computed_field
        def acl_key(self) -> str:
            """Computed field for unique ACL key."""
            return (
                f"acl:{self.name}:{self.target.target_key}:{self.subject.subject_key}"
            )

        @computed_field
        def acl_summary(self) -> FlextTypes.Dict:
            """Computed field for ACL summary."""
            return {
                "name": self.name,
                "target_dn": self.target.target_dn,
                "subject_dn": self.subject.subject_dn,
                "permissions_granted": self.permissions.permissions_summary[
                    "granted_count"
                ],
                "server_type": self.server_type,
            }

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

        @field_serializer("target", when_used="json")
        def serialize_target_with_acl_context(
            self, value: FlextLdifModels.AclTarget, _info: object
        ) -> FlextTypes.Dict:
            """Serialize target with ACL context."""
            return {
                "target": value.target_dn,
                "acl_context": {
                    "name": self.name,
                    "subject": self.subject.subject_dn,
                    "server_type": self.server_type,
                },
            }
