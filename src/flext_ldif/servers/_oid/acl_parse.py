"""Oracle Internet Directory (OID) ACL server — OID ACL parsing.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar, override

from flext_ldif import c, m, p, r, t, u
from flext_ldif.servers._oid.acl_subjects import FlextLdifServersOidAclSubjectMixin
from flext_ldif.servers._oid.server_constants import FlextLdifServersOidConstants
from flext_ldif.servers.rfc import FlextLdifServersRfc


class FlextLdifServersOidAclParseMixin(FlextLdifServersOidAclSubjectMixin):
    """OID ACL OID ACL parsing."""

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
            u.Ldif.dump_json_payload(list(settings.target_attrs))
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

    @staticmethod
    def _extract_oid_target(
        content: str,
    ) -> tuple[str | None, t.MutableSequenceOf[str]]:
        """Extract target DN and attributes from OID ACL.

        Returns:
            The resulting ``tuple[str | None, t.MutableSequenceOf[str]]``.
        """
        target_dn: str | None = None
        attributes: t.MutableSequenceOf[str] = []
        patterns = FlextLdifServersOidConstants
        target_match = patterns.ACL_TARGET_DN_EXTRACT_RE.search(content)
        if target_match:
            target_dn = target_match.group(1)
        attr_match = patterns.ACL_TARGET_ATTR_OID_EXTRACT_RE.search(content)
        if attr_match:
            attr_str = attr_match.group(1)
            attributes = [a.strip() for a in attr_str.split(",")]
        return (target_dn, attributes)

    @staticmethod
    def _parse_oid_permissions(content: str) -> t.MutableBoolMapping:
        """Parse OID ACL permissions clause.

        Returns:
            The resulting ``t.MutableBoolMapping``.
        """
        permissions: t.MutableBoolMapping = {}
        const = FlextLdifServersOidConstants
        perm_match = const.ACL_PERMS_EXTRACT_OID_RE.search(content)
        if perm_match:
            perms_str = perm_match.group(1)
            raw_perms = [p.strip() for p in perms_str.split(",")]
            for raw_perm in raw_perms:
                if not raw_perm:
                    continue
                is_negative = raw_perm.lower().startswith("no")
                perm_name = raw_perm
                if perm_name.lower() in const.ACL_PERMISSION_MAPPING:
                    mapped_names = const.ACL_PERMISSION_MAPPING[perm_name.lower()]
                    for mapped_name in mapped_names:
                        permissions[mapped_name] = not is_negative
                else:
                    permissions[perm_name.lower()] = not is_negative
        return permissions

    @override
    def can_handle_acl(self, acl_line: str | m.Ldif.Acl) -> bool:
        """Check if this is an Oracle OID ACL.

        Returns:
            The resulting ``bool``.
        """
        can_handle = False
        if not isinstance(acl_line, str):
            try:
                acl_model = m.Ldif.Acl.model_validate(acl_line)
            except c.Ldif.EXC_LDIF_PARSE:
                acl_model = None
            if acl_model and acl_model.metadata and acl_model.metadata.server_type:
                can_handle = acl_model.metadata.server_type == self._get_server_type()
        else:
            acl_line_lower = acl_line.strip().lower()
            can_handle = bool(acl_line_lower) and acl_line_lower.startswith((
                f"{FlextLdifServersOidConstants.ORCLACI}:",
                f"{FlextLdifServersOidConstants.ORCLENTRYLEVELACI}:",
                "access to ",
            ))
        return can_handle

    @override
    def _parse_acl(self, acl_line: str) -> p.Result[m.Ldif.Acl]:
        """Parse Oracle OID ACL string to RFC-compliant internal model.

        Returns:
            The resulting ``p.Result[m.Ldif.Acl]``.
        """
        parent_result = super()._parse_acl(acl_line)
        if parent_result.failure:
            return parent_result
        if (
            parent_result.success
            and (acl_data := parent_result.value)
            and self.can_handle_acl(acl_line)
            and any(
                getattr(acl_data, field) is not None
                for field in ("permissions", "target", "subject")
            )
        ):
            updated_acl = self._update_acl_with_oid_metadata(acl_data, acl_line)
            return r[m.Ldif.Acl].ok(updated_acl)
        if (
            parent_result.success
            and (acl_data := parent_result.value)
            and (not self.can_handle_acl(acl_line))
        ):
            return r[m.Ldif.Acl].ok(acl_data)
        return self._parse_oid_specific_acl(acl_line)

    def _parse_oid_specific_acl(self, acl_line: str) -> p.Result[m.Ldif.Acl]:
        """Parse OID-specific ACL format when RFC parser fails.

        Returns:
            The resulting ``p.Result[m.Ldif.Acl]``.
        """
        try:
            return self._parse_oid_specific_acl_core(acl_line)
        except c.Ldif.EXC_LDIF_PARSE as e:
            max_len = FlextLdifServersOidConstants.MAX_LOG_LINE_LENGTH
            acl_preview = acl_line[:max_len] if len(acl_line) > max_len else acl_line
            FlextLdifServersOidAclParseMixin._module_logger.debug(
                "OID ACL parse failed",
                error=e,
                error_type=type(e).__name__,
                acl_line=acl_preview,
                acl_line_length=len(acl_line),
            )
            return r[m.Ldif.Acl].fail_op("OID ACL parsing", e)

    def _parse_oid_specific_acl_core(self, acl_line: str) -> p.Result[m.Ldif.Acl]:
        """Parse OID-specific ACL data into the canonical ACL model.

        Returns:
            The resulting ``p.Result[m.Ldif.Acl]``.
        """
        target_dn, target_attrs = self._extract_oid_target(acl_line)
        if not target_dn:
            target_dn = "entry"
        oid_subject_type, oid_subject_value = self._resolve_oid_subject(acl_line)
        rfc_subject_type, rfc_subject_value = self._map_oid_subject_to_rfc(
            oid_subject_type,
            oid_subject_value,
        )
        perms_dict = self._parse_oid_permissions(acl_line)
        options = self._extract_oid_acl_options(acl_line)
        settings = self.OidAclMetadataConfig.model_validate({
            "acl_line": acl_line,
            "oid_subject_type": oid_subject_type,
            "rfc_subject_type": rfc_subject_type,
            "oid_subject_value": oid_subject_value,
            "perms_dict": perms_dict,
            "target_dn": target_dn,
            "target_attrs": target_attrs,
            **options,
        })
        extensions = self._build_oid_acl_metadata(settings)
        server_type: c.Ldif.ServerTypes = c.Ldif.ServerTypes.OID
        rfc_compliant_perms = m.Ldif.AclPermissions.filter_rfc_compliant_permissions(
            perms_dict,
        )
        acl_model = m.Ldif.Acl.model_validate({
            "name": FlextLdifServersRfc.Constants.ACL_ATTRIBUTE_NAME,
            "target": m.Ldif.AclTarget.model_validate({
                "target_dn": target_dn,
                "attributes": target_attrs or [],
            }),
            "subject": m.Ldif.AclSubject.model_validate({
                "subject_type": str(rfc_subject_type),
                "subject_value": rfc_subject_value,
            }),
            "permissions": m.Ldif.AclPermissions(**rfc_compliant_perms),
            "server_type": server_type,
            "metadata": m.Ldif.ServerMetadata.model_validate({
                "server_type": server_type,
                "extensions": extensions,
            }),
            "raw_acl": acl_line,
            "raw_line": acl_line,
            "validation_violations": [],
        })
        return r[m.Ldif.Acl].ok(acl_model)

    def _resolve_oid_subject(
        self,
        acl_line: str,
    ) -> tuple[str, str]:
        """Detect the OID subject of one ACL line and resolve its value.

        Returns:
            The resulting ``tuple[str, str | None]``.
        """
        oid_subject_type = self._detect_oid_subject(acl_line)
        if not oid_subject_type:
            oid_subject_type = FlextLdifServersOidConstants.OidAclSubjectType.SELF
            return (
                oid_subject_type,
                FlextLdifServersOidConstants.OidAclSubjectType.SELF,
            )
        subject_value: str | None = None
        for (
            regex,
            subj_type,
            _,
        ) in FlextLdifServersOidConstants.ACL_SUBJECT_PATTERNS.values():
            if subj_type == oid_subject_type and regex:
                subject_value = u.Ldif.extract_component(
                    acl_line,
                    regex,
                    group=1,
                )
                if subject_value:
                    break
        return oid_subject_type, (
            subject_value or FlextLdifServersOidConstants.OidAclSubjectType.ANONYMOUS
        )

    @staticmethod
    def _extract_oid_acl_options(acl_line: str) -> dict[str, str | bool]:
        """Extract the optional ACL components of one OID ACL line.

        Returns:
            The resulting ``dict[str, str | bool]``.
        """
        extract = u.Ldif.extract_component
        kls = FlextLdifServersOidConstants
        return {
            "acl_filter": extract(acl_line, kls.ACL_FILTER_PATTERN, group=1) or "",
            "acl_constraint": extract(
                acl_line,
                kls.ACL_CONSTRAINT_PATTERN,
                group=1,
            )
            or "",
            "bindmode": extract(acl_line, kls.ACL_BINDMODE_PATTERN, group=1) or "",
            "deny_group_override": extract(
                acl_line,
                kls.ACL_DENY_GROUP_OVERRIDE_PATTERN,
            )
            is not None,
            "append_to_all": extract(
                acl_line,
                kls.ACL_APPEND_TO_ALL_PATTERN,
            )
            is not None,
            "bind_ip_filter": extract(
                acl_line,
                kls.ACL_BIND_IP_FILTER_PATTERN,
                group=1,
            )
            or "",
            "constrain_to_added_object": extract(
                acl_line,
                kls.ACL_CONSTRAIN_TO_ADDED_PATTERN,
                group=1,
            )
            or "",
        }

    @staticmethod
    def _update_acl_with_oid_metadata(
        acl_data: m.Ldif.Acl,
        _acl_line: str,
    ) -> m.Ldif.Acl:
        """Update ACL with OID server type and metadata.

        Returns:
            The resulting ``m.Ldif.Acl``.
        """
        server_type = FlextLdifServersOidConstants.SERVER_TYPE
        updated_metadata = (
            acl_data.metadata.model_copy(update={"server_type": server_type})
            if acl_data.metadata
            else u.Ldif.server_metadata_for(server_type)
        )
        updated_acl: m.Ldif.Acl = acl_data.model_copy(
            update={"server_type": server_type, "metadata": updated_metadata},
        )
        return updated_acl


__all__: list[str] = ["FlextLdifServersOidAclParseMixin"]
