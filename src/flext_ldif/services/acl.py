"""ACL Service - Direct ACL Processing with flext-core APIs.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import c, m, p, r, s, t, u


class FlextLdifAcl(s):
    """Direct ACL processing service using flext-core APIs."""

    @staticmethod
    def _is_schema_entry(entry: m.Ldif.Entry) -> bool:
        """Check if entry is a schema entry.

        Returns:
            The resulting ``bool``.
        """
        is_schema: bool = u.Ldif.is_schema_entry(entry, strict=False)
        return is_schema

    @staticmethod
    def evaluate_acl_context(
        acls: t.SequenceOf[t.Ldif.AclLike],
        required_permissions: m.Ldif.AclPermissions | t.MutableBoolMapping,
    ) -> p.Result[m.Ldif.AclEvaluationResult]:
        """Evaluate if ACLs grant required permissions.

        Returns:
            The resulting ``p.Result[m.Ldif.AclEvaluationResult]``.
        """
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
        return r[m.Ldif.AclEvaluationResult].ok(evaluation)

    @staticmethod
    def service_check() -> p.Result[m.Ldif.AclResponse]:
        """Return a minimal ACL response for service wiring checks."""
        return r[m.Ldif.AclResponse].ok(
            m.Ldif.AclResponse(acls=[], statistics=m.Ldif.Statistics()),
        )

    def extract_acls_from_entry(
        self,
        entry: m.Ldif.Entry,
        server_type: str,
    ) -> p.Result[m.Ldif.AclResponse]:
        """Extract ACLs from entry using server-specific attribute names.

        Returns:
            The resulting ``p.Result[m.Ldif.AclResponse]``.
        """
        try:
            normalized_server_type = u.Ldif.normalize_server_type(server_type)
        except c.EXC_TYPE_VALIDATION as error:
            return r[m.Ldif.AclResponse].fail(str(error), exception=error)
        acl_server = self._server.acl(normalized_server_type)
        if acl_server is None:
            return r[m.Ldif.AclResponse].fail(
                f"No ACL server found for server type: {normalized_server_type}",
            )
        acls: t.MutableSequenceOf[m.Ldif.Acl] = []
        for attribute_name in acl_server.resolve_acl_attributes():
            for acl_value in u.Ldif.get_attribute_values(entry, attribute_name):
                parse_result = acl_server.parse_server(acl_value)
                if parse_result.failure:
                    return r[m.Ldif.AclResponse].from_failure(parse_result)
                acls.append(parse_result.value)
        return r[m.Ldif.AclResponse].ok(
            m.Ldif.AclResponse(
                acls=acls,
                statistics=m.Ldif.Statistics(
                    processed_entries=1,
                    acls_extracted=len(acls),
                ),
            ),
        )

    def parse_acl_string(
        self,
        acl_string: str,
        server_type: str,
    ) -> p.Result[m.Ldif.Acl]:
        """Parse ACL string using server-specific servers.

        Returns:
            The resulting ``p.Result[m.Ldif.Acl]``.
        """
        try:
            normalized_server_type = u.Ldif.normalize_server_type(server_type)
        except c.EXC_TYPE_VALIDATION as error:
            return r[m.Ldif.Acl].fail(str(error), exception=error)
        try:
            acl_server = self._server.acl(normalized_server_type)
        except ValueError as error:
            return r[m.Ldif.Acl].fail(str(error), exception=error)
        if acl_server is None:
            return r[m.Ldif.Acl].fail(
                f"No ACL server found for server type: {normalized_server_type}",
            )

        return acl_server.parse_server(acl_string)


__all__: list[str] = ["FlextLdifAcl"]
