"""ACL Service - Direct ACL Processing with flext-core APIs."""

from __future__ import annotations

from flext_ldif import (
    c,
    m,
    p,
    r,
    s,
    t,
    u,
)


class FlextLdifAcl(s):
    """Direct ACL processing service using flext-core APIs."""

    @staticmethod
    def _build_acl_response(
        acls: t.SequenceOf[t.Ldif.AclLike],
        *,
        processed_entries: int = 1,
        failed_entries: int = 0,
    ) -> p.Ldif.AclResponse:
        return m.Ldif.AclResponse(
            acls=u.Ldif.as_acls(acls),
            statistics=m.Ldif.Statistics(
                processed_entries=processed_entries,
                acls_extracted=len(acls),
                failed_entries=failed_entries,
            ),
        )

    @staticmethod
    def _is_schema_entry(entry: p.Ldif.Entry) -> bool:
        """Check if entry is a schema entry."""
        is_schema: bool = u.Ldif.is_schema_entry(entry, strict=False)
        return is_schema

    @staticmethod
    def evaluate_acl_context(
        acls: t.SequenceOf[t.Ldif.AclLike],
        required_permissions: m.Ldif.AclPermissions | t.MutableBoolMapping,
    ) -> p.Result[p.Ldif.AclEvaluationResult]:
        """Evaluate if ACLs grant required permissions."""
        required = (
            required_permissions
            if isinstance(required_permissions, m.Ldif.AclPermissions)
            else m.Ldif.AclPermissions.model_validate(
                m.Ldif.AclPermissions.filter_rfc_compliant_permissions(
                    dict(required_permissions),
                ),
            )
        )
        permission_keys = (
            c.Ldif.RfcAclPermission.READ.value,
            c.Ldif.RfcAclPermission.WRITE.value,
            c.Ldif.RfcAclPermission.DELETE.value,
            c.Ldif.RfcAclPermission.ADD.value,
            c.Ldif.RfcAclPermission.SEARCH.value,
            c.Ldif.RfcAclPermission.COMPARE.value,
        )
        required_perms = [
            permission
            for permission in permission_keys
            if getattr(required, permission)
        ]
        evaluation = m.Ldif.AclEvaluationResult(
            granted=False,
            matched_acl=None,
            message="No ACLs to evaluate - access denied by default",
        )
        if not acls:
            pass
        elif not required_perms:
            evaluation = m.Ldif.AclEvaluationResult(
                granted=True,
                matched_acl=u.Ldif.as_acl(acls[0]),
                message="No permissions required - access granted trivially",
            )
        else:
            found_result = u.find(
                acls,
                predicate=lambda acl: (
                    (permissions := acl.permissions) is not None
                    and all(getattr(permissions, perm) for perm in required_perms)
                ),
            )
            if found_result.success:
                found_acl = found_result.value
                evaluation = m.Ldif.AclEvaluationResult(
                    granted=True,
                    matched_acl=u.Ldif.as_acl(found_acl),
                    message=f"ACL '{found_acl.name}' grants required permissions: {required_perms}",
                )
            else:
                evaluation = m.Ldif.AclEvaluationResult(
                    granted=False,
                    matched_acl=None,
                    message=f"No ACL grants required permissions: {required_perms}",
                )
        return r[p.Ldif.AclEvaluationResult].ok(evaluation)

    def service_check(self) -> p.Result[p.Ldif.AclResponse]:
        """Return a minimal ACL response for service wiring checks."""
        return r[p.Ldif.AclResponse].ok(
            m.Ldif.AclResponse(acls=[], statistics=m.Ldif.Statistics()),
        )

    def extract_acls_from_entry(
        self,
        entry: p.Ldif.Entry,
        server_type: str,
    ) -> p.Result[p.Ldif.AclResponse]:
        """Extract ACLs from entry using server-specific attribute names."""
        acl_attr_name = u.Ldif.get_acl_attributes()
        if not acl_attr_name:
            return r[p.Ldif.AclResponse].ok(self._build_acl_response([]))
        acl_values = u.Ldif.get_attribute_values(entry, next(iter(acl_attr_name)))
        if not acl_values:
            return r[p.Ldif.AclResponse].ok(self._build_acl_response([]))
        acls: t.Ldif.AclSequence = []
        failed_count = 0

        for acl_value in acl_values:
            parse_result = self.parse_acl_string(acl_value, server_type)
            if parse_result.success:
                acls.append(parse_result.value)
                continue
            failed_count += 1
            self.logger.warning(
                "Failed to parse ACL value",
                error=parse_result.error or "",
                server_type=server_type,
            )
        return r[p.Ldif.AclResponse].ok(
            self._build_acl_response(acls, failed_entries=failed_count),
        )

    def parse_acl_string(
        self,
        acl_string: str,
        server_type: str,
    ) -> p.Result[p.Ldif.Acl]:
        """Parse ACL string using server-specific servers."""
        try:
            normalized_server_type = u.Ldif.normalize_server_type(server_type)
        except c.EXC_TYPE_VALIDATION as error:
            return r[p.Ldif.Acl].fail(
                f"Invalid server type: {server_type} - {error}",
            )
        try:
            acl_server = self.server.acl(
                "openldap1" if server_type == "openldap" else normalized_server_type,
            )
            if acl_server is None and server_type == "openldap":
                acl_server = self.server.acl("openldap2")
        except ValueError as error:
            return r[p.Ldif.Acl].fail(str(error))
        if acl_server is None:
            return r[p.Ldif.Acl].fail(
                f"No ACL server found for server type: {normalized_server_type}",
            )
        return (
            r[p.Ldif.Acl]
            .from_result(
                acl_server.parse_server(acl_string),
            )
            .map(
                m.Ldif.Acl.model_validate,
            )
            .map_error(
                lambda error: error or "ACL parsing failed",
            )
        )


__all__: list[str] = ["FlextLdifAcl"]
