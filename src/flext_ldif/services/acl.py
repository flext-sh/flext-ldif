"""ACL Service - Direct ACL Processing with flext-core APIs.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif import c, m, p, r, t, u
from flext_ldif.services import FlextLdifServer


class FlextLdifAcl(FlextLdifServer):
    """Direct ACL processing service using flext-core APIs."""

    @staticmethod
    def _is_schema_entry(entry: p.Ldif.Entry) -> bool:
        """Check if entry is a schema entry.

        Returns:
            The resulting ``bool``.

        """
        is_schema: bool = u.Ldif.detects_schema_entry(entry, strict=False)
        return is_schema

    @staticmethod
    def evaluate_acl_context(
        acls: t.SequenceOf[t.Ldif.AclLike],
        required_permissions: p.Ldif.AclPermissions | t.MutableBoolMapping,
    ) -> p.Result[p.Ldif.AclEvaluationResult]:
        """Evaluate if ACLs grant required permissions.

        Returns:
            The resulting ``p.Result[p.Ldif.AclEvaluationResult]``.

        """
        if isinstance(required_permissions, m.Ldif.AclPermissions):
            required = required_permissions
        else:
            mapping: t.MutableBoolMapping = required_permissions
            perms_dict: t.MutableBoolMapping = dict(mapping.items())
            required = m.Ldif.AclPermissions.model_validate(
                m.Ldif.AclPermissions.filter_rfc_compliant_permissions(perms_dict),
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
        evaluation: p.Ldif.AclEvaluationResult = m.Ldif.AclEvaluationResult(
            granted=False,
            matched_acl=None,
            message="No ACLs to evaluate - access denied by default",
            statistics=m.Ldif.Statistics(),
        )
        if not acls:
            pass
        elif not required_perms:
            evaluation = m.Ldif.AclEvaluationResult(
                granted=True,
                matched_acl=u.Ldif.as_acl(acls[0]),
                message="No permissions required - access granted trivially",
                statistics=m.Ldif.Statistics(),
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
                    message=f"ACL '{found_acl.name}' "
                    f"grants required permissions: {required_perms}",
                    statistics=m.Ldif.Statistics(),
                )
            else:
                evaluation = m.Ldif.AclEvaluationResult(
                    granted=False,
                    matched_acl=None,
                    message=f"No ACL grants required permissions: {required_perms}",
                    statistics=m.Ldif.Statistics(),
                )
        return r[p.Ldif.AclEvaluationResult].ok(evaluation)

    @staticmethod
    def service_check() -> p.Result[p.Ldif.AclResponse]:
        """Return a minimal ACL response for service wiring checks."""
        return r[p.Ldif.AclResponse].ok(
            m.Ldif.AclResponse(acls=[], statistics=m.Ldif.Statistics()),
        )

    def extract_acls_from_entry(
        self,
        entry: p.Ldif.Entry,
        server_type: str,
    ) -> p.Result[p.Ldif.AclResponse]:
        """Extract ACLs from entry using server-specific attribute names.

        Returns:
            The resulting ``p.Result[p.Ldif.AclResponse]``.

        """
        try:
            normalized_server_type = u.Ldif.normalize_server_type(server_type)
        except c.EXC_TYPE_VALIDATION as error:
            return r[p.Ldif.AclResponse].fail(str(error), exception=error)
        resolved = self.acl(normalized_server_type)
        if resolved.failure:
            return r[p.Ldif.AclResponse].from_failure(resolved)
        acl_server = resolved.value
        acls: t.MutableSequenceOf[p.Ldif.Acl] = []
        for attribute_name in acl_server.resolve_acl_attributes():
            for acl_value in u.Ldif.resolve_attribute_values(entry, attribute_name):
                parse_result = acl_server.parse_server(acl_value)
                if parse_result.failure:
                    return r[p.Ldif.AclResponse].from_failure(parse_result)
                acls.append(parse_result.value)
        return r[p.Ldif.AclResponse].ok(
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
    ) -> p.Result[p.Ldif.Acl]:
        """Parse ACL string using server-specific servers.

        Returns:
            The resulting ``p.Result[p.Ldif.Acl]``.

        """
        try:
            normalized_server_type = u.Ldif.normalize_server_type(server_type)
        except c.EXC_TYPE_VALIDATION as error:
            return r[p.Ldif.Acl].fail(str(error), exception=error)
        return self.acl(normalized_server_type).flat_map(
            lambda server: server.parse_server(acl_string).map(
                lambda acl: acl  # m.Acl is structurally compatible with p.Acl
            )
        )


__all__: list[str] = ["FlextLdifAcl"]
