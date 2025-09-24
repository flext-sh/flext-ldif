"""FLEXT LDIF ACLs Coordinator.

Unified ACL management coordinator using flext-core paradigm with nested operation classes.
"""

from typing import Any, ClassVar

from flext_core import FlextLogger, FlextResult, FlextService
from flext_ldif.acl import FlextLdifAclParser, FlextLdifAclService
from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks import constants


class FlextLdifAcls(FlextService):
    """Unified ACL management coordinator following flext-core single class paradigm."""

    model_config: ClassVar[dict[str, Any]] = {"arbitrary_types_allowed": True, "validate_assignment": False, "extra": "allow"}

    class Parser:
        """Nested class for ACL parsing operations."""

        def __init__(self, parent: "FlextLdifAcls") -> None:
            """Initialize ACL parser with parent coordinator reference."""
            self._parent = parent
            self._parser = FlextLdifAclParser()
            self._logger = FlextLogger(__name__)

        def parse_openldap(
            self, acl_string: str
        ) -> FlextResult[FlextLdifModels.UnifiedAcl]:
            """Parse OpenLDAP olcAccess ACL format."""
            return self._parser.parse_openldap_acl(acl_string)

        def parse_389ds(
            self, acl_string: str
        ) -> FlextResult[FlextLdifModels.UnifiedAcl]:
            """Parse 389DS ACI ACL format."""
            return self._parser.parse_389ds_acl(acl_string)

        def parse_oracle(
            self, acl_string: str, server_type: str = constants.SERVER_TYPE_ORACLE_OID
        ) -> FlextResult[FlextLdifModels.UnifiedAcl]:
            """Parse Oracle OID/OUD ACL format."""
            return self._parser.parse_oracle_acl(acl_string, server_type)

        def parse_ad(
            self, acl_string: str
        ) -> FlextResult[FlextLdifModels.UnifiedAcl]:
            """Parse Active Directory ACL format."""
            return self._parser.parse_acl(acl_string, constants.SERVER_TYPE_ACTIVE_DIRECTORY)

        def parse(
            self, acl_string: str, server_type: str
        ) -> FlextResult[FlextLdifModels.UnifiedAcl]:
            """Parse ACL string based on server type."""
            return self._parser.parse_acl(acl_string, server_type)

    class Service:
        """Nested class for ACL service operations."""

        def __init__(self, parent: "FlextLdifAcls") -> None:
            """Initialize ACL service with parent coordinator reference."""
            self._parent = parent
            self._service = FlextLdifAclService()
            self._logger = FlextLogger(__name__)

        def extract_from_entry(
            self, entry: FlextLdifModels.Entry, server_type: str | None = None
        ) -> FlextResult[list[FlextLdifModels.UnifiedAcl]]:
            """Extract ACLs from LDIF entry."""
            return self._service.extract_acls_from_entry(entry, server_type)

        def extract_from_entries(
            self, entries: list[FlextLdifModels.Entry], server_type: str | None = None
        ) -> FlextResult[list[FlextLdifModels.UnifiedAcl]]:
            """Extract ACLs from multiple entries."""
            all_acls: list[FlextLdifModels.UnifiedAcl] = []

            for entry in entries:
                acl_result = self._service.extract_acls_from_entry(entry, server_type)
                if acl_result.is_success:
                    all_acls.extend(acl_result.value)

            return FlextResult[list[FlextLdifModels.UnifiedAcl]].ok(all_acls)

    class Builder:
        """Nested class for ACL building operations."""

        def __init__(self, parent: "FlextLdifAcls") -> None:
            """Initialize ACL builder with parent coordinator reference."""
            self._parent = parent
            self._logger = FlextLogger(__name__)

        def build_read_permission(
            self, target_dn: str, subject_dn: str
        ) -> FlextResult[FlextLdifModels.UnifiedAcl]:
            """Build ACL with read permission."""
            target_result = FlextLdifModels.AclTarget.create(
                target_dn=target_dn
            )
            if target_result.is_failure:
                return FlextResult[FlextLdifModels.UnifiedAcl].fail(target_result.error or "Target creation failed")

            subject_result = FlextLdifModels.AclSubject.create(
                subject_dn=subject_dn
            )
            if subject_result.is_failure:
                return FlextResult[FlextLdifModels.UnifiedAcl].fail(subject_result.error or "Subject creation failed")

            perms_result = FlextLdifModels.AclPermissions.create(
                read=True, search=True, compare=True
            )
            if perms_result.is_failure:
                return FlextResult[FlextLdifModels.UnifiedAcl].fail(perms_result.error or "Permissions creation failed")

            return FlextLdifModels.UnifiedAcl.create(
                name="read_permission",
                target=target_result.value,
                subject=subject_result.value,
                permissions=perms_result.value,
                server_type="generic",
                raw_acl=f'to {target_dn} by {subject_dn} read'
            )

        def build_write_permission(
            self, target_dn: str, subject_dn: str
        ) -> FlextResult[FlextLdifModels.UnifiedAcl]:
            """Build ACL with write permission."""
            target_result = FlextLdifModels.AclTarget.create(
                target_dn=target_dn
            )
            if target_result.is_failure:
                return FlextResult[FlextLdifModels.UnifiedAcl].fail(target_result.error or "Target creation failed")

            subject_result = FlextLdifModels.AclSubject.create(
                subject_dn=subject_dn
            )
            if subject_result.is_failure:
                return FlextResult[FlextLdifModels.UnifiedAcl].fail(subject_result.error or "Subject creation failed")

            perms_result = FlextLdifModels.AclPermissions.create(
                read=True, write=True, add=True, delete=True
            )
            if perms_result.is_failure:
                return FlextResult[FlextLdifModels.UnifiedAcl].fail(perms_result.error or "Permissions creation failed")

            return FlextLdifModels.UnifiedAcl.create(
                name="write_permission",
                target=target_result.value,
                subject=subject_result.value,
                permissions=perms_result.value,
                server_type="generic",
                raw_acl=f'to {target_dn} by {subject_dn} write'
            )

        def build_REDACTED_LDAP_BIND_PASSWORD_permission(
            self, target_dn: str, subject_dn: str
        ) -> FlextResult[FlextLdifModels.UnifiedAcl]:
            """Build ACL with REDACTED_LDAP_BIND_PASSWORD permission."""
            target_result = FlextLdifModels.AclTarget.create(
                target_dn=target_dn
            )
            if target_result.is_failure:
                return FlextResult[FlextLdifModels.UnifiedAcl].fail(target_result.error or "Target creation failed")

            subject_result = FlextLdifModels.AclSubject.create(
                subject_dn=subject_dn
            )
            if subject_result.is_failure:
                return FlextResult[FlextLdifModels.UnifiedAcl].fail(subject_result.error or "Subject creation failed")

            perms_result = FlextLdifModels.AclPermissions.create(
                read=True, write=True, add=True, delete=True,
                search=True, compare=True, proxy=True
            )
            if perms_result.is_failure:
                return FlextResult[FlextLdifModels.UnifiedAcl].fail(perms_result.error or "Permissions creation failed")

            return FlextLdifModels.UnifiedAcl.create(
                name="REDACTED_LDAP_BIND_PASSWORD_permission",
                target=target_result.value,
                subject=subject_result.value,
                permissions=perms_result.value,
                server_type="generic",
                raw_acl=f'to {target_dn} by {subject_dn} write'
            )

    class Converter:
        """Nested class for ACL format conversion operations."""

        def __init__(self, parent: "FlextLdifAcls") -> None:
            """Initialize ACL converter with parent coordinator reference."""
            self._parent = parent
            self._logger = FlextLogger(__name__)

        def _get_access_level(self, perms: FlextLdifModels.AclPermissions) -> str:
            """Determine access level from permissions."""
            if perms.read and perms.write and perms.add and perms.delete:
                return "write"
            if perms.read:
                return "read"
            return "none"

        def _get_operations_list(self, perms: FlextLdifModels.AclPermissions) -> list[str]:
            """Get list of allowed operations from permissions."""
            ops = []
            if perms.read:
                ops.append("read")
            if perms.write:
                ops.append("write")
            if perms.add:
                ops.append("add")
            if perms.delete:
                ops.append("delete")
            if perms.search:
                ops.append("search")
            if perms.compare:
                ops.append("compare")
            if perms.proxy:
                ops.append("proxy")
            return ops

        def to_openldap(
            self, acl: FlextLdifModels.UnifiedAcl
        ) -> FlextResult[str]:
            """Convert unified ACL to OpenLDAP olcAccess format."""
            try:
                access_level = self._get_access_level(acl.permissions)
                target = acl.target.target_dn or "*"
                subject = acl.subject.subject_dn or "*"
                openldap_acl = f'to {target} by {subject} {access_level}'
                return FlextResult[str].ok(openldap_acl)
            except Exception as e:
                return FlextResult[str].fail(f"OpenLDAP conversion failed: {e}")

        def to_389ds(
            self, acl: FlextLdifModels.UnifiedAcl
        ) -> FlextResult[str]:
            """Convert unified ACL to 389DS ACI format."""
            try:
                operations = self._get_operations_list(acl.permissions)
                operations_str = ",".join(operations)
                target = acl.target.target_dn or "*"
                subject = acl.subject.subject_dn or "ldap:///anyone"
                aci = (
                    f'(target="{target}") '
                    f'(targetattr="*") '
                    f'(version 3.0; acl "{acl.name}"; '
                    f'allow ({operations_str}) '
                    f'userdn="{subject}";)'
                )
                return FlextResult[str].ok(aci)
            except Exception as e:
                return FlextResult[str].fail(f"389DS conversion failed: {e}")

        def to_oracle(
            self, acl: FlextLdifModels.UnifiedAcl
        ) -> FlextResult[str]:
            """Convert unified ACL to Oracle orclaci format."""
            try:
                operations = self._get_operations_list(acl.permissions)
                operations_str = "+".join(operations)
                target = acl.target.target_dn or "*"
                subject = acl.subject.subject_dn or "*"
                oracle_acl = f'access to {target} by {subject} ({operations_str})'
                return FlextResult[str].ok(oracle_acl)
            except Exception as e:
                return FlextResult[str].fail(f"Oracle conversion failed: {e}")

        def to_ad(
            self, acl: FlextLdifModels.UnifiedAcl
        ) -> FlextResult[str]:
            """Convert unified ACL to Active Directory SDDL format."""
            try:
                access_level = self._get_access_level(acl.permissions).upper()
                subject = acl.subject.subject_dn or "S-1-1-0"
                ad_acl = f'O:{subject}G:DAD:(A;;{access_level};;;{subject})'
                return FlextResult[str].ok(ad_acl)
            except Exception as e:
                return FlextResult[str].fail(f"AD conversion failed: {e}")

    def __init__(self) -> None:
        """Initialize ACL coordinator with nested operation classes."""
        super().__init__()
        self._logger = FlextLogger(__name__)

        self.parser = self.Parser(self)
        self.service = self.Service(self)
        self.builder = self.Builder(self)
        self.converter = self.Converter(self)

    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute health check - required by FlextService."""
        return FlextResult[dict[str, object]].ok(
            {
                "status": "healthy",
                "service": "FlextLdifAcls",
                "operations": ["parser", "service", "builder", "converter"],
            }
        )


__all__ = ["FlextLdifAcls"]
