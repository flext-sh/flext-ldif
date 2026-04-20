"""ACL Service - Direct ACL Processing with flext-core APIs."""

from __future__ import annotations

from collections.abc import (
    Mapping,
    Sequence,
)
from typing import override

from flext_ldif import (
    FlextLdifServer,
    m,
    r,
    s,
    t,
    u,
)


class FlextLdifAcl(s[m.Ldif.AclResponse]):
    """Direct ACL processing service using flext-core APIs."""

    _server: FlextLdifServer

    def __init__(self, server: FlextLdifServer | None = None) -> None:
        """Initialize ACL service with optional server instance."""
        object.__setattr__(
            self,
            "_server",
            server if server is not None else FlextLdifServer.get_global_instance(),
        )

    @staticmethod
    def _build_acl_response(
        acls: Sequence[t.Ldif.AclLike],
        *,
        processed_entries: int = 1,
        failed_entries: int = 0,
    ) -> m.Ldif.AclResponse:
        return m.Ldif.AclResponse(
            acls=u.Ldif.as_acls(acls),
            statistics=m.Ldif.Statistics(
                processed_entries=processed_entries,
                acls_extracted=len(acls),
                failed_entries=failed_entries,
            ),
        )

    @staticmethod
    def _is_schema_entry(entry: m.Ldif.Entry) -> bool:
        """Check if entry is a schema entry."""
        return u.Ldif.is_schema_entry(entry, strict=False)

    @staticmethod
    def evaluate_acl_context(
        acls: Sequence[t.Ldif.AclLike],
        required_permissions: m.Ldif.AclPermissions | t.MutableBoolMapping,
    ) -> r[m.Ldif.AclEvaluationResult]:
        """Evaluate if ACLs grant required permissions."""
        if isinstance(required_permissions, Mapping):
            required = m.Ldif.AclPermissions(
                read=bool(required_permissions.get("read", False)),
                write=bool(required_permissions.get("write", False)),
                delete=bool(required_permissions.get("delete", False)),
                add=bool(required_permissions.get("add", False)),
                search=bool(required_permissions.get("search", False)),
                compare=bool(required_permissions.get("compare", False)),
            )
        else:
            required = required_permissions
        if not acls:
            return r[m.Ldif.AclEvaluationResult].ok(
                m.Ldif.AclEvaluationResult(
                    granted=False,
                    matched_acl=None,
                    message="No ACLs to evaluate - access denied by default",
                ),
            )
        perm_names = ["read", "write", "delete", "add", "search", "compare"]
        required_perms = [p for p in perm_names if getattr(required, p, False)]
        if not required_perms:
            return r[m.Ldif.AclEvaluationResult].ok(
                m.Ldif.AclEvaluationResult(
                    granted=True,
                    matched_acl=u.Ldif.as_acl(acls[0]) if acls else None,
                    message="No permissions required - access granted trivially",
                ),
            )

        def acl_grants_all(acl: t.Ldif.AclLike) -> bool:
            """Check if ACL grants all required permissions."""
            permissions = acl.permissions
            if permissions is None:
                return False
            return all(getattr(permissions, perm, False) for perm in required_perms)

        def predicate(value: t.Ldif.AclLike) -> bool:
            """Check if ACL grants all permissions."""
            return acl_grants_all(value)

        found_result = u.find(acls, predicate=predicate)
        if found_result.success:
            found_acl = found_result.value
            return r[m.Ldif.AclEvaluationResult].ok(
                m.Ldif.AclEvaluationResult(
                    granted=True,
                    matched_acl=u.Ldif.as_acl(found_acl),
                    message=f"ACL '{found_acl.name}' grants required permissions: {required_perms}",
                ),
            )
        return r[m.Ldif.AclEvaluationResult].ok(
            m.Ldif.AclEvaluationResult(
                granted=False,
                matched_acl=None,
                message=f"No ACL grants required permissions: {required_perms}",
            ),
        )

    @override
    def execute(self) -> r[m.Ldif.AclResponse]:
        """Execute ACL service health check."""
        return r[m.Ldif.AclResponse].ok(
            m.Ldif.AclResponse(acls=[], statistics=m.Ldif.Statistics()),
        )

    def extract_acls_from_entry(
        self,
        entry: m.Ldif.Entry,
        server_type: str,
    ) -> r[m.Ldif.AclResponse]:
        """Extract ACLs from entry using server-specific attribute names."""
        acl_attr_name = u.Ldif.get_acl_attributes()
        if not acl_attr_name:
            return r[m.Ldif.AclResponse].ok(self._build_acl_response([]))
        acl_values = u.Ldif.get_attribute_values(entry, next(iter(acl_attr_name)))
        if not acl_values:
            return r[m.Ldif.AclResponse].ok(self._build_acl_response([]))
        acls: t.Ldif.AclSequence = []
        failed_count = 0

        for acl_value in acl_values:
            parse_result = self.parse_acl_string(acl_value, server_type)
            if parse_result.success:
                acls.append(parse_result.value)
                continue
            failed_count += 1
            logger = u.fetch_logger(__name__)
            logger.warning(
                "Failed to parse ACL value",
                error=str(parse_result.error) if parse_result.error else "",
                server_type=server_type,
            )
        return r[m.Ldif.AclResponse].ok(
            self._build_acl_response(acls, failed_entries=failed_count),
        )

    def parse_acl_string(self, acl_string: str, server_type: str) -> r[m.Ldif.Acl]:
        """Parse ACL string using server-specific quirks."""
        try:
            normalized_server_type = u.Ldif.normalize_server_type(server_type)
        except (ValueError, TypeError) as error:
            return r[m.Ldif.Acl].fail(
                f"Invalid server type: {server_type} - {error}",
            )
        try:
            acl_quirk = self._server.acl(
                "openldap1" if server_type == "openldap" else normalized_server_type,
            )
            if acl_quirk is None and server_type == "openldap":
                acl_quirk = self._server.acl("openldap2")
        except ValueError as error:
            return r[m.Ldif.Acl].fail(str(error))
        if acl_quirk is None:
            return r[m.Ldif.Acl].fail(
                f"No ACL quirk found for server type: {normalized_server_type}",
            )
        return (
            r[m.Ldif.Acl]
            .from_result(
                acl_quirk.parse_quirk(acl_string),
            )
            .map(
                m.Ldif.Acl.model_validate,
            )
            .map_error(
                lambda error: error or "ACL parsing failed",
            )
        )


__all__: list[str] = ["FlextLdifAcl"]
