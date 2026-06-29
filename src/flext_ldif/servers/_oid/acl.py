"""Oracle Internet Directory (OID) Servers."""

from __future__ import annotations

from collections.abc import (
    Mapping,
    MutableMapping,
)
from typing import ClassVar, override

from flext_ldif import (
    FlextLdifServersRfc,
    c,
    m,
    p,
    r,
    t,
    u,
)
from flext_ldif.servers._oid.constants import FlextLdifServersOidConstants

logger = u.fetch_logger(__name__)


class _OidAclTargetAttributesJson(m.RootModel[t.MutableSequenceOf[str]]):
    pass


class FlextLdifServersOidAcl(FlextLdifServersRfc.Acl):
    """Oracle Internet Directory (OID) ACL implementation."""

    OidAclMetadataConfig: ClassVar[type[m.Ldif.OidAclMetadataConfig]] = (
        m.Ldif.OidAclMetadataConfig
    )

    RFC_ACL_ATTRIBUTES: ClassVar[t.StrSequence] = (
        FlextLdifServersOidConstants.RFC_ACL_ATTRIBUTES
    )
    OID_ACL_ATTRIBUTES: ClassVar[t.StrSequence] = (
        FlextLdifServersOidConstants.OID_ACL_ATTRIBUTES
    )

    @override
    def resolve_acl_attributes(self) -> t.MutableSequenceOf[str]:
        """Get RFC + OID extensions."""
        return [*self.RFC_ACL_ATTRIBUTES, *self.OID_ACL_ATTRIBUTES]

    @staticmethod
    def _detect_oid_subject(content: str) -> str | None:
        """Detect OID ACL subject type by matching ACL_SUBJECT_PATTERNS."""
        if not content:
            return None
        const = FlextLdifServersOidConstants
        for pattern_key, (_, subject_type, _) in const.ACL_SUBJECT_PATTERNS.items():
            if pattern_key.lower() in content.lower():
                detected_subject: str = subject_type
                return detected_subject
        return None

    @staticmethod
    def _extract_oid_target(
        content: str,
    ) -> tuple[str | None, t.MutableSequenceOf[str]]:
        """Extract target DN and attributes from OID ACL."""
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
    def _format_oid_permissions(
        permissions: m.Ldif.DynamicMetadata,
    ) -> str:
        """Format OID ACL permissions clause."""
        allowed_perms: t.MutableSequenceOf[str] = []
        for perm, allowed in permissions.items():
            if allowed:
                oid_perm_name = FlextLdifServersOidConstants.ACL_PERMISSION_NAMES.get(
                    perm,
                    perm,
                )
                allowed_perms.append(oid_perm_name)
        if allowed_perms:
            return f"({','.join(allowed_perms)})"
        return "(none)"

    @staticmethod
    def _format_oid_subject(subject_type: str, subject_value: str) -> str:
        """Format OID ACL subject clause in orclaci format."""
        clean_value = FlextLdifServersOidAcl.clean_subject_value(subject_value)
        sc = FlextLdifServersOidConstants
        match subject_type.lower():
            case sc.OidAclSubjectType.SELF:
                result = sc.OidAclSubjectType.SELF
            case "anonymous" | sc.OidAclSubjectType.ANONYMOUS:
                result = sc.OidAclSubjectType.ANONYMOUS
            case sc.OidAclSubjectType.GROUP_DN | "group":
                result = f'group="{clean_value}"'
            case sc.OidAclSubjectType.USER_DN | "user":
                result = f'"{clean_value}"'
            case sc.OidAclSubjectType.DN_ATTR:
                result = f"dnattr=({clean_value})"
            case sc.OidAclSubjectType.GUID_ATTR:
                result = f"guidattr=({clean_value})"
            case sc.OidAclSubjectType.GROUP_ATTR:
                result = f"groupattr=({clean_value})"
            case _:
                result = (
                    f'"{clean_value}"'
                    if clean_value
                    else sc.OidAclSubjectType.ANONYMOUS
                )
        return result

    @staticmethod
    def _format_oid_target(target_dn: str, attributes: t.MutableSequenceOf[str]) -> str:
        """Format OID ACL target clause."""
        if not attributes or target_dn == "entry":
            return "entry"
        if len(attributes) == 1 and attributes[0] == "*":
            return "attr=(*)"
        attrs_str = ",".join(attributes)
        return f"attr=({attrs_str})"

    @staticmethod
    def _normalize_permissions_to_dict(
        permissions: m.Ldif.AclPermissions | t.MutableBoolMapping | None,
    ) -> t.MutableBoolMapping:
        """Normalize permissions to dict for formatting."""
        if not permissions:
            return {}
        permissions_model = m.Ldif.AclPermissions.model_validate(permissions)
        raw_perms = permissions_model.model_dump()
        return {
            "read": bool(raw_perms.get("read", False)),
            "write": bool(raw_perms.get("write", False)),
            "add": bool(raw_perms.get("add", False)),
            "delete": bool(raw_perms.get("delete", False)),
            "search": bool(raw_perms.get("search", False)),
            "compare": bool(raw_perms.get("compare", False)),
            "self_write": bool(raw_perms.get("self_write", False)),
            "proxy": bool(raw_perms.get("proxy", False)),
            "browse": bool(raw_perms.get("browse", False)),
            "auth": bool(raw_perms.get("auth", False)),
            "all": bool(raw_perms.get("all", False)),
        }

    @staticmethod
    def _normalize_to_dict(
        value: m.Ldif.AclSubject
        | m.Ldif.ServerMetadata
        | t.MutableConfigurationMapping
        | MutableMapping[
            str,
            t.Ldif.Scalar | t.MutableSequenceOf[str] | t.MutableAttributeMapping | None,
        ]
        | str
        | None,
    ) -> t.MutableConfigurationMapping:
        """Normalize value to dict for model validation."""
        if isinstance(value, Mapping):
            return {
                key: raw_value
                for key, raw_value in value.items()
                if isinstance(raw_value, (str, int, bool))
            }
        if value is None:
            return {}
        if isinstance(value, str):
            return {"subject_type": value}
        dumped = value.model_dump()
        return {
            key: raw_value
            for key, raw_value in dumped.items()
            if isinstance(raw_value, (str, int, bool))
        }

    @staticmethod
    def _parse_oid_permissions(content: str) -> t.MutableBoolMapping:
        """Parse OID ACL permissions clause."""
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

    @staticmethod
    def clean_subject_value(subject_value: str) -> str:
        """Clean OID subject value by removing ldap:/// prefix and parser suffixes."""
        clean_value = subject_value
        if clean_value.startswith("ldap:///"):
            clean_value = clean_value[8:]
            if "?" in clean_value:
                clean_value = clean_value.split("?")[0]
        if "#" in clean_value:
            suffixes_to_strip = {"#GROUPDN", "#LDAPURL", "#USERDN"}
            for suffix in suffixes_to_strip:
                if clean_value.endswith(suffix):
                    clean_value = clean_value[: -len(suffix)]
                    break
        return clean_value

    @override
    def can_handle_acl(self, acl_line: str | m.Ldif.Acl) -> bool:
        """Check if this is an Oracle OID ACL."""
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

    def _build_metadata_extensions(
        self,
        metadata: m.Ldif.ServerMetadata
        | MutableMapping[
            str,
            t.Ldif.Scalar | t.MutableSequenceOf[str] | t.MutableAttributeMapping | None,
        ]
        | None,
    ) -> t.MutableSequenceOf[str]:
        """Build OID ACL extension clauses from metadata."""
        if not metadata:
            return []
        meta_extensions = self._extract_extensions_dict(metadata)
        if not meta_extensions:
            return []
        return self._format_extensions(meta_extensions)

    def _build_oid_acl_metadata(
        self,
        settings: m.Ldif.OidAclMetadataConfig,
    ) -> t.Ldif.MutableMetadataMapping:
        """Build metadata extensions for OID ACL with Oracle-specific features."""
        target_attrs_str: str = (
            _OidAclTargetAttributesJson(root=settings.target_attrs).model_dump_json()
            if settings.target_attrs
            else ""
        )
        permissions_str: str = (
            m.Ldif.DynamicMetadata.from_dict(settings.perms_dict).model_dump_json()
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

    def _extract_extensions_dict(
        self,
        metadata: m.Ldif.ServerMetadata
        | MutableMapping[
            str,
            t.Ldif.Scalar | t.MutableSequenceOf[str] | t.MutableAttributeMapping | None,
        ],
    ) -> t.Ldif.MutableMetadataMapping:
        """Extract extensions dict from metadata, converting types if needed."""
        metadata = m.Ldif.ServerMetadata.model_validate(metadata)
        extensions = getattr(metadata, "extensions", None)
        return extensions.to_dict() if extensions is not None else {}

    def _format_extensions(
        self,
        meta_extensions: t.Ldif.MutableMetadataMapping,
    ) -> t.MutableSequenceOf[str]:
        """Format extension values based on metadata key type."""
        extensions: t.MutableSequenceOf[str] = []
        acl_filter = meta_extensions.get(c.Ldif.ACL_FILTER)
        if isinstance(acl_filter, str) and acl_filter:
            extensions.append(f"filter={acl_filter}")
        acl_constraint = meta_extensions.get(c.Ldif.ACL_CONSTRAINT)
        if isinstance(acl_constraint, str) and acl_constraint:
            extensions.append(f"added_object_constraint=({acl_constraint})")
        bindmode = meta_extensions.get(c.Ldif.ACL_BINDMODE)
        if isinstance(bindmode, str) and bindmode:
            extensions.append(f"bindmode=({bindmode})")
        bind_ip_filter = meta_extensions.get(c.Ldif.ACL_BIND_IP_FILTER)
        if isinstance(bind_ip_filter, str) and bind_ip_filter:
            extensions.append(f"bindipfilter=({bind_ip_filter})")
        constrain_to_added = meta_extensions.get(
            c.Ldif.ACL_CONSTRAIN_TO_ADDED_OBJECT,
        )
        if isinstance(constrain_to_added, str) and constrain_to_added:
            extensions.append(f"constraintonaddedobject=({constrain_to_added})")
        deny_group_override = meta_extensions.get(
            c.Ldif.ACL_DENY_GROUP_OVERRIDE,
        )
        if deny_group_override is True or (
            isinstance(deny_group_override, str) and deny_group_override
        ):
            extensions.append("DenyGroupOverride")
        append_to_all = meta_extensions.get(c.Ldif.ACL_APPEND_TO_ALL)
        if append_to_all is True or (isinstance(append_to_all, str) and append_to_all):
            extensions.append("AppendToAll")
        return extensions

    def _get_source_subject_type(
        self,
        metadata: m.Ldif.ServerMetadata | None,
    ) -> str | None:
        """Get source subject type from metadata."""
        if not metadata or not metadata.extensions:
            return None
        source_subject_type_raw = metadata.extensions.get(
            c.Ldif.ACL_SOURCE_SUBJECT_TYPE,
        )
        try:
            source_subject_type: str = t.str_adapter().validate_python(
                source_subject_type_raw,
            )
            return source_subject_type
        except c.ValidationError:
            return None

    def _map_bind_rules_to_oid(
        self,
        rfc_subject_value: str,
        source_subject_type: str | None,
    ) -> str:
        """Map bind_rules/group to OID subject type."""
        sc = FlextLdifServersOidConstants
        if (
            isinstance(source_subject_type, str)
            and source_subject_type
            in {
                sc.OidAclSubjectType.DN_ATTR,
                sc.OidAclSubjectType.GUID_ATTR,
                sc.OidAclSubjectType.GROUP_ATTR,
            }
        ) or (
            isinstance(source_subject_type, str)
            and source_subject_type
            in {
                sc.OidAclSubjectType.GROUP_DN,
                sc.OidAclSubjectType.USER_DN,
            }
        ):
            result = source_subject_type
        elif (
            source_subject_type == "group"
            or (
                "group=" in rfc_subject_value.lower()
                or "groupdn" in rfc_subject_value.lower()
            )
            or "cn=groups" in rfc_subject_value.lower()
        ):
            result = sc.OidAclSubjectType.GROUP_DN
        else:
            result = sc.OidAclSubjectType.USER_DN
        return result

    def _map_oid_subject_to_rfc(
        self,
        oid_subject_type: str,
        oid_subject_value: str,
    ) -> tuple[c.Ldif.AclSubjectType, str]:
        """Map OID subject types to RFC subject types."""
        sc = FlextLdifServersOidConstants
        if oid_subject_type == sc.OidAclSubjectType.SELF:
            result = (c.Ldif.AclSubjectType.SELF, "ldap:///self")
        elif oid_subject_type == sc.OidAclSubjectType.GROUP_DN:
            result = (c.Ldif.AclSubjectType.GROUP, oid_subject_value)
        elif oid_subject_type == sc.OidAclSubjectType.USER_DN or oid_subject_type in {
            sc.OidAclSubjectType.DN_ATTR,
            sc.OidAclSubjectType.GUID_ATTR,
            sc.OidAclSubjectType.GROUP_ATTR,
        }:
            result = (c.Ldif.AclSubjectType.DN, oid_subject_value)
        elif sc.OidAclSubjectType.ANONYMOUS in {
            oid_subject_type,
            oid_subject_value,
        }:
            result = (c.Ldif.AclSubjectType.ANONYMOUS, sc.OidAclSubjectType.ANONYMOUS)
        else:
            result = (c.Ldif.AclSubjectType.DN, oid_subject_value)
        return result

    def _map_rfc_subject_to_oid(
        self,
        rfc_subject: m.Ldif.AclSubject,
        metadata: m.Ldif.ServerMetadata | None,
    ) -> str:
        """Map RFC subject type to OID subject type for writing."""
        rfc_subject_type = str(rfc_subject.subject_type)
        rfc_subject_value = rfc_subject.subject_value
        source_subject_type = self._get_source_subject_type(metadata)
        sc = FlextLdifServersOidConstants
        if isinstance(source_subject_type, str) and source_subject_type in {
            sc.OidAclSubjectType.DN_ATTR,
            sc.OidAclSubjectType.GUID_ATTR,
            sc.OidAclSubjectType.GROUP_ATTR,
        }:
            result = source_subject_type
        else:
            match rfc_subject_type:
                case "self":
                    result = sc.OidAclSubjectType.SELF
                case "anonymous":
                    result = sc.OidAclSubjectType.ANONYMOUS
                case _ if rfc_subject_value == sc.OidAclSubjectType.ANONYMOUS:
                    result = sc.OidAclSubjectType.ANONYMOUS
                case rfc_type if rfc_type in {
                    sc.OidAclSubjectType.DN_ATTR.value,
                    sc.OidAclSubjectType.GUID_ATTR.value,
                    sc.OidAclSubjectType.GROUP_ATTR.value,
                    sc.OidAclSubjectType.GROUP_DN.value,
                    sc.OidAclSubjectType.USER_DN.value,
                }:
                    result = rfc_type
                case "dn":
                    if isinstance(source_subject_type, str) and source_subject_type in {
                        sc.OidAclSubjectType.DN_ATTR,
                        sc.OidAclSubjectType.GUID_ATTR,
                        sc.OidAclSubjectType.GROUP_ATTR,
                    }:
                        result = source_subject_type
                    else:
                        result = sc.OidAclSubjectType.USER_DN
                case _:
                    result = (
                        source_subject_type
                        if isinstance(source_subject_type, str)
                        else sc.OidAclSubjectType.USER_DN
                    )
        return result

    @override
    def _parse_acl(self, acl_line: str) -> p.Result[m.Ldif.Acl]:
        """Parse Oracle OID ACL string to RFC-compliant internal model."""
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
        """Parse OID-specific ACL format when RFC parser fails."""
        try:
            return self._parse_oid_specific_acl_core(acl_line)
        except c.Ldif.EXC_LDIF_PARSE as e:
            max_len = FlextLdifServersOidConstants.MAX_LOG_LINE_LENGTH
            acl_preview = acl_line[:max_len] if len(acl_line) > max_len else acl_line
            logger.debug(
                "OID ACL parse failed",
                error=e,
                error_type=type(e).__name__,
                acl_line=acl_preview,
                acl_line_length=len(acl_line),
            )
            return r[m.Ldif.Acl].fail_op("OID ACL parsing", e)

    def _parse_oid_specific_acl_core(self, acl_line: str) -> p.Result[m.Ldif.Acl]:
        """Parse OID-specific ACL data into the canonical ACL model."""
        target_dn, target_attrs = self._extract_oid_target(acl_line)
        if not target_dn:
            target_dn = "entry"
        oid_subject_type = self._detect_oid_subject(acl_line)
        oid_subject_value: str | None = None
        if oid_subject_type:
            for (
                regex,
                subj_type,
                _,
            ) in FlextLdifServersOidConstants.ACL_SUBJECT_PATTERNS.values():
                if subj_type == oid_subject_type and regex:
                    oid_subject_value = u.Ldif.extract_component(
                        acl_line,
                        regex,
                        group=1,
                    )
                    if oid_subject_value:
                        break
            oid_subject_value = (
                oid_subject_value
                or FlextLdifServersOidConstants.OidAclSubjectType.ANONYMOUS
            )
        else:
            oid_subject_type = FlextLdifServersOidConstants.OidAclSubjectType.SELF
            oid_subject_value = FlextLdifServersOidConstants.OidAclSubjectType.SELF
        rfc_subject_type, rfc_subject_value = self._map_oid_subject_to_rfc(
            oid_subject_type,
            oid_subject_value,
        )
        perms_dict = self._parse_oid_permissions(acl_line)
        acl_filter = u.Ldif.extract_component(
            acl_line,
            FlextLdifServersOidConstants.ACL_FILTER_PATTERN,
            group=1,
        )
        acl_constraint = u.Ldif.extract_component(
            acl_line,
            FlextLdifServersOidConstants.ACL_CONSTRAINT_PATTERN,
            group=1,
        )
        bindmode = u.Ldif.extract_component(
            acl_line,
            FlextLdifServersOidConstants.ACL_BINDMODE_PATTERN,
            group=1,
        )
        deny_group_override = (
            u.Ldif.extract_component(
                acl_line,
                FlextLdifServersOidConstants.ACL_DENY_GROUP_OVERRIDE_PATTERN,
            )
            is not None
        )
        append_to_all = (
            u.Ldif.extract_component(
                acl_line,
                FlextLdifServersOidConstants.ACL_APPEND_TO_ALL_PATTERN,
            )
            is not None
        )
        bind_ip_filter = u.Ldif.extract_component(
            acl_line,
            FlextLdifServersOidConstants.ACL_BIND_IP_FILTER_PATTERN,
            group=1,
        )
        constrain_to_added_object = u.Ldif.extract_component(
            acl_line,
            FlextLdifServersOidConstants.ACL_CONSTRAIN_TO_ADDED_PATTERN,
            group=1,
        )
        settings = self.OidAclMetadataConfig.model_validate({
            "acl_line": acl_line,
            "oid_subject_type": oid_subject_type,
            "rfc_subject_type": rfc_subject_type,
            "oid_subject_value": oid_subject_value,
            "perms_dict": perms_dict,
            "target_dn": target_dn,
            "target_attrs": target_attrs,
            "acl_filter": acl_filter or "",
            "acl_constraint": acl_constraint or "",
            "bindmode": bindmode or "",
            "deny_group_override": deny_group_override,
            "append_to_all": append_to_all,
            "bind_ip_filter": bind_ip_filter or "",
            "constrain_to_added_object": constrain_to_added_object or "",
        })
        extensions = self._build_oid_acl_metadata(settings)
        server_type: c.Ldif.ServerTypes = c.Ldif.ServerTypes.OID
        rfc_compliant_perms = m.Ldif.AclPermissions.filter_rfc_compliant_permissions(
            perms_dict,
        )
        extensions_metadata = m.Ldif.DynamicMetadata.from_dict(
            extensions,
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
                "extensions": extensions_metadata,
            }),
            "raw_acl": acl_line,
            "raw_line": acl_line,
            "validation_violations": [],
        })
        return r[m.Ldif.Acl].ok(acl_model)

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
        """Prepare OID subject and permissions clauses for ACL write."""
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
        permissions_metadata = m.Ldif.DynamicMetadata.from_dict(permissions_dict)
        permissions_clause = self._format_oid_permissions(permissions_metadata)
        return (subject_clause, permissions_clause)

    def _prepare_subject_value_with_suffix(
        self,
        subject_value: str,
        oid_subject_type: str,
    ) -> str:
        """Prepare subject value with OID-specific suffix if needed."""
        sc = FlextLdifServersOidConstants
        if (
            oid_subject_type
            in {
                sc.OidAclSubjectType.DN_ATTR,
                sc.OidAclSubjectType.GUID_ATTR,
                sc.OidAclSubjectType.GROUP_ATTR,
            }
            and "#" not in subject_value
        ):
            type_suffix: dict[str, str] = {
                sc.OidAclSubjectType.DN_ATTR: sc.OidAclSubjectSuffix.LDAPURL,
                sc.OidAclSubjectType.GUID_ATTR: sc.OidAclSubjectSuffix.USERDN,
                sc.OidAclSubjectType.GROUP_ATTR: sc.OidAclSubjectSuffix.GROUPDN,
            }
            return f"{subject_value}#{type_suffix[oid_subject_type]}"
        return subject_value

    def _update_acl_with_oid_metadata(
        self,
        acl_data: m.Ldif.Acl,
        _acl_line: str,
    ) -> m.Ldif.Acl:
        """Update ACL with OID server type and metadata."""
        server_type = FlextLdifServersOidConstants.SERVER_TYPE
        updated_metadata = (
            acl_data.metadata.model_copy(update={"server_type": server_type})
            if acl_data.metadata
            else m.Ldif.ServerMetadata.create_for(
                server_type,
                extensions=m.Ldif.DynamicMetadata(),
            )
        )
        updated_acl: m.Ldif.Acl = acl_data.model_copy(
            update={
                "server_type": server_type,
                "metadata": updated_metadata,
            },
        )
        return updated_acl

    @override
    def _write_acl(
        self,
        acl_data: m.Ldif.Acl,
        _format_option: str | None = None,
    ) -> p.Result[str]:
        """Write ACL to OID orclaci format (Phase 2: Denormalization)."""
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
