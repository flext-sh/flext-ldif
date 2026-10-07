"""Oracle Internet Directory (OID) ACL server — OID ACL write assembly.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableMapping
from typing import ClassVar, override

from flext_ldif import c, m, p, r, t, u
from flext_ldif.servers._oid.server_constants import FlextLdifServersOidConstants
from flext_ldif.servers.rfc import FlextLdifServersRfc


class FlextLdifServersOidAclWriteMixin(FlextLdifServersRfc.Acl):
    """OID ACL OID ACL write assembly."""

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)

    @override
    def resolve_acl_attributes(self) -> t.MutableSequenceOf[str]:
        """Get RFC + OID extensions.

        Returns:
            The resulting ``t.MutableSequenceOf[str]``.
        """
        return [
            *FlextLdifServersOidConstants.RFC_ACL_ATTRIBUTES,
            *FlextLdifServersOidConstants.OID_ACL_ATTRIBUTES,
        ]

    def _authorize_write_permissions(
        self,
        acl_subject: m.Ldif.AclSubject | t.MutableConfigurationMapping,
        acl_permissions: m.Ldif.AclPermissions | t.MutableBoolMapping | None,
        metadata: m.Ldif.ServerMetadata
        | MutableMapping[
            str,
            t.Ldif.Scalar | t.MutableSequenceOf[str] | t.MutableAttributeMapping | None,
        ]
        | None,
    ) -> t.StrPair:
        """Prepare OID subject and permissions clauses for ACL write.

        Returns:
            The resulting ``t.StrPair``.
        """
        subject_dict = self._normalize_to_dict(acl_subject)
        subject_public = m.Ldif.AclSubject.model_validate(subject_dict)
        metadata_public: m.Ldif.ServerMetadata | None = None
        if metadata:
            try:
                metadata_public = m.Ldif.ServerMetadata.model_validate(metadata)
            except c.Ldif.EXC_LDIF_PARSE:
                metadata_dict = self._normalize_to_dict(metadata)
                metadata_public = m.Ldif.ServerMetadata.model_validate(metadata_dict)
        oid_subject_type = self._map_rfc_subject_to_oid(subject_public, metadata_public)
        subject_value = self._prepare_subject_value_with_suffix(
            subject_public.subject_value,
            oid_subject_type,
        )
        subject_clause = self._format_oid_subject(oid_subject_type, subject_value)
        permissions_dict = self._normalize_permissions_to_dict(acl_permissions)
        permissions_clause = self._format_oid_permissions(permissions_dict)
        return (subject_clause, permissions_clause)

    @override
    def _write_acl(
        self,
        acl_data: m.Ldif.Acl,
        _format_option: str | None = None,
    ) -> p.Result[str]:
        """Write ACL to OID orclaci format (Phase 2: Denormalization).

        Returns:
            The resulting ``p.Result[str]``.
        """
        if acl_data.raw_acl and acl_data.raw_acl.startswith(
            FlextLdifServersOidConstants.ORCLACI + ":",
        ):
            return r[str].ok(acl_data.raw_acl)
        acl_parts = [
            FlextLdifServersOidConstants.ORCLACI + ":",
            FlextLdifServersOidConstants.ACL_ACCESS_TO,
        ]
        if acl_data.target:
            target_public = m.Ldif.AclTarget.model_validate(
                acl_data.target.model_dump(),
            )
            acl_parts.append(
                self._format_oid_target(
                    target_public.target_dn,
                    target_public.attributes or [],
                ),
            )
        if acl_data.subject:
            subject_public = m.Ldif.AclSubject.model_validate(acl_data.subject)
            if acl_data.permissions:
                permissions_public = m.Ldif.AclPermissions.model_validate(
                    acl_data.permissions,
                )
            else:
                permissions_public = None
            if acl_data.metadata:
                metadata_public = m.Ldif.ServerMetadata.model_validate(
                    acl_data.metadata,
                )
            else:
                metadata_public = None
            subject_clause, permissions_clause = self._authorize_write_permissions(
                subject_public,
                permissions_public,
                metadata_public,
            )
            acl_parts.extend([
                FlextLdifServersOidConstants.ACL_BY,
                subject_clause,
                permissions_clause,
            ])
        if acl_data.metadata:
            metadata_public = m.Ldif.ServerMetadata.model_validate(acl_data.metadata)
        else:
            metadata_public = None
        acl_parts.extend(self._build_metadata_extensions(metadata_public))
        orclaci_str = " ".join(acl_parts)
        return r[str].ok(orclaci_str)


__all__: list[str] = ["FlextLdifServersOidAclWriteMixin"]
