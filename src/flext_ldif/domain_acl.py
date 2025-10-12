"""ACL domain models."""

from __future__ import annotations

from flext_core import FlextCore
from pydantic import Field


class AclPermissions(FlextCore.Models.Value):
    """ACL permissions for LDAP operations."""

    model_config = {"frozen": True}

    read: bool = Field(default=False, description="Read permission")
    write: bool = Field(default=False, description="Write permission")
    add: bool = Field(default=False, description="Add permission")
    delete: bool = Field(default=False, description="Delete permission")
    search: bool = Field(default=False, description="Search permission")
    compare: bool = Field(default=False, description="Compare permission")
    self_write: bool = Field(default=False, description="Self-write permission")
    proxy: bool = Field(default=False, description="Proxy permission")

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
        self_write: bool = False,
        proxy: bool = False,
    ) -> FlextCore.Result[AclPermissions]:
        """Create AclPermissions instance."""
        try:
            return FlextCore.Result[AclPermissions].ok(
                cls(
                    read=read,
                    write=write,
                    add=add,
                    delete=delete,
                    search=search,
                    compare=compare,
                    self_write=self_write,
                    proxy=proxy,
                )
            )
        except Exception as e:
            return FlextCore.Result[AclPermissions].fail(
                f"Failed to create AclPermissions: {e}"
            )


class AclTarget(FlextCore.Models.Value):
    """ACL target specification."""

    model_config = {"frozen": True}

    target_dn: str = Field(..., description="Target DN pattern")
    attributes: list[str] = Field(default_factory=list, description="Target attributes")

    @classmethod
    def create(
        cls, target_dn: str, attributes: list[str] | None = None
    ) -> FlextCore.Result[AclTarget]:
        """Create AclTarget instance."""
        try:
            return FlextCore.Result[AclTarget].ok(
                cls(target_dn=target_dn, attributes=attributes or [])
            )
        except Exception as e:
            return FlextCore.Result[AclTarget].fail(f"Failed to create AclTarget: {e}")


class AclSubject(FlextCore.Models.Value):
    """ACL subject specification."""

    model_config = {"frozen": True}

    subject_type: str = Field(..., description="Subject type (user, group, etc.)")
    subject_value: str = Field(..., description="Subject value/pattern")

    @classmethod
    def create(
        cls, subject_type: str, subject_value: str
    ) -> FlextCore.Result[AclSubject]:
        """Create AclSubject instance."""
        try:
            return FlextCore.Result[AclSubject].ok(
                cls(subject_type=subject_type, subject_value=subject_value)
            )
        except Exception as e:
            return FlextCore.Result[AclSubject].fail(
                f"Failed to create AclSubject: {e}"
            )


class UnifiedAcl(FlextCore.Models.Value):
    """Unified ACL representation."""

    model_config = {"frozen": True}

    target: AclTarget = Field(..., description="ACL target")
    subject: AclSubject = Field(..., description="ACL subject")
    permissions: AclPermissions = Field(..., description="ACL permissions")

    @classmethod
    def create(
        cls, target: AclTarget, subject: AclSubject, permissions: AclPermissions
    ) -> FlextCore.Result[UnifiedAcl]:
        """Create UnifiedAcl instance."""
        try:
            return FlextCore.Result[UnifiedAcl].ok(
                cls(target=target, subject=subject, permissions=permissions)
            )
        except Exception as e:
            return FlextCore.Result[UnifiedAcl].fail(
                f"Failed to create UnifiedAcl: {e}"
            )
