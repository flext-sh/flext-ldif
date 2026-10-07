"""Oracle Internet Directory (OID) Servers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar

from flext_ldif import m, p, t, u
from flext_ldif.servers._oid.acl_format import FlextLdifServersOidAclFormatMixin
from flext_ldif.servers._oid.acl_parse import FlextLdifServersOidAclParseMixin
from flext_ldif.servers._oid.acl_subjects import FlextLdifServersOidAclSubjectMixin
from flext_ldif.servers._oid.acl_write import FlextLdifServersOidAclWriteMixin
from flext_ldif.servers._oid.server_constants import FlextLdifServersOidConstants
from flext_ldif.servers.rfc import FlextLdifServersRfc


class _OidAclTargetAttributesJson(m.RootModel[t.MutableSequenceOf[str]]):
    pass


class FlextLdifServersOidAcl(
    FlextLdifServersOidAclWriteMixin,
    FlextLdifServersOidAclParseMixin,
    FlextLdifServersOidAclSubjectMixin,
    FlextLdifServersOidAclFormatMixin,
    FlextLdifServersRfc.Acl,
):
    """Oracle Internet Directory (OID) ACL implementation."""

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)
    OidAclMetadataConfig: ClassVar[type[m.Ldif.OidAclMetadataConfig]] = (
        m.Ldif.OidAclMetadataConfig
    )

    @staticmethod
    def _build_oid_acl_metadata(
        settings: m.Ldif.OidAclMetadataConfig,
    ) -> t.Ldif.MutableMetadataMapping:
        """Build metadata extensions for OID ACL with Oracle-specific features.

        Returns:
            The resulting ``t.Ldif.MutableMetadataMapping``.
        """
        target_attrs_str: str = (
            _OidAclTargetAttributesJson(root=settings.target_attrs).model_dump_json()
            if settings.target_attrs
            else ""
        )
        permissions_str: str = (
            u.Ldif.dump_json_payload(dict(settings.perms_dict))
            if settings.perms_dict
            else ""
        )
        metadata_raw = u.Ldif.build_acl_metadata_complete(
            "oid",
            acl_line=settings.acl_line,
            subject_type=settings.oid_subject_type,
            subject_value=settings.oid_subject_value,
            target_dn=settings.target_dn,
            target_attrs=target_attrs_str,
            permissions=permissions_str,
            target_subject_type=settings.rfc_subject_type,
            acl_filter=settings.acl_filter,
            acl_constraint=settings.acl_constraint,
            bindmode=settings.bindmode,
            deny_group_override=settings.deny_group_override is True,
            append_to_all=settings.append_to_all is True,
            bind_ip_filter=settings.bind_ip_filter,
            constrain_to_added_object=settings.constrain_to_added_object,
            target_key=FlextLdifServersOidConstants.OID_ACL_SOURCE_TARGET,
        )
        json_value_adapter = t.json_value_adapter()
        metadata_dict: t.Ldif.MutableMetadataMapping = {
            key: json_value_adapter.validate_python(u.to_jsonable_python(value))
            for key, value in metadata_raw.items()
        }
        if settings.oid_subject_type:
            metadata_dict["acl_source_subject_type"] = settings.oid_subject_type
        return metadata_dict
