"""Oracle Internet Directory (OID) Quirks."""

from __future__ import annotations

import re
import struct
from collections.abc import Mapping, MutableMapping, MutableSequence
from typing import ClassVar, Literal, override

from pydantic import RootModel

from flext_core import FlextLogger, r
from flext_ldif import (
    FlextLdifModelsDomains,
    FlextLdifModelsMetadata,
    FlextLdifServersOidConstants,
    FlextLdifServersRfc,
    FlextLdifUtilitiesACL,
    FlextLdifUtilitiesMetadata,
    c,
    m,
    t,
)

logger = FlextLogger(__name__)
_OidConstants = FlextLdifServersOidConstants


class _OidAclTargetAttributesJson(RootModel[MutableSequence[str]]):
    pass


class FlextLdifServersOidAcl(FlextLdifServersRfc.Acl):
    """Oracle Internet Directory (OID) ACL implementation."""

    OidAclMetadataConfig: ClassVar[type[m.Ldif.OidAclMetadataConfig]] = (
        m.Ldif.OidAclMetadataConfig
    )

    RFC_ACL_ATTRIBUTES: ClassVar[MutableSequence[str]] = [
        "aci",
        "acl",
        "olcAccess",
        "aclRights",
        "aclEntry",
    ]
    OID_ACL_ATTRIBUTES: ClassVar[MutableSequence[str]] = [
        "orclaci",
        "orclentrylevelaci",
        "orclContainerLevelACL",
    ]

    @override
    def get_acl_attributes(self) -> MutableSequence[str]:
        """Get RFC + OID extensions."""
        return [*self.RFC_ACL_ATTRIBUTES, *self.OID_ACL_ATTRIBUTES]

    @staticmethod
    def _detect_oid_subject(content: str) -> str | None:
        """Detect OID ACL subject type by matching ACL_SUBJECT_PATTERNS."""
        if not content:
            return None
        const = _OidConstants
        for pattern_key, (_, subject_type, _) in const.ACL_SUBJECT_PATTERNS.items():
            if pattern_key.lower() in content.lower():
                return subject_type
        return None

    @staticmethod
    def _extract_oid_target(content: str) -> tuple[str | None, MutableSequence[str]]:
        """Extract target DN and attributes from OID ACL."""
        target_dn: str | None = None
        attributes: MutableSequence[str] = []
        patterns = _OidConstants
        target_match = re.search(patterns.ACL_TARGET_DN_EXTRACT, content, re.IGNORECASE)
        if target_match:
            target_dn = target_match.group(1)
        attr_match = re.search(
            patterns.ACL_TARGET_ATTR_OID_EXTRACT,
            content,
            re.IGNORECASE,
        )
        if attr_match:
            attr_str = attr_match.group(1)
            attributes = [a.strip() for a in attr_str.split(",")]
        return (target_dn, attributes)

    @staticmethod
    def _format_oid_permissions(
        permissions: FlextLdifModelsMetadata.DynamicMetadata | m.Ldif.DynamicMetadata,
    ) -> str:
        """Format OID ACL permissions clause."""
        allowed_perms: MutableSequence[str] = []
        for perm, allowed in permissions.items():
            if allowed:
                oid_perm_name = _OidConstants.ACL_PERMISSION_NAMES.get(perm, perm)
                allowed_perms.append(oid_perm_name)
        if allowed_perms:
            return f"({','.join(allowed_perms)})"
        return "(none)"

    @staticmethod
    def _format_oid_subject(subject_type: str, subject_value: str) -> str:
        """Format OID ACL subject clause in orclaci format."""
        clean_value = FlextLdifServersOidAcl.clean_subject_value(subject_value)
        match subject_type.lower():
            case "self":
                return "self"
            case "anonymous" | "*":
                return "*"
            case "group_dn" | "group":
                return f'group="{clean_value}"'
            case "user_dn" | "user":
                return f'"{clean_value}"'
            case "dn_attr":
                return f"dnattr=({clean_value})"
            case "guid_attr":
                return f"guidattr=({clean_value})"
            case "group_attr":
                return f"groupattr=({clean_value})"
            case _:
                return f'"{clean_value}"' if clean_value else "*"

    @staticmethod
    def _format_oid_target(target_dn: str, attributes: MutableSequence[str]) -> str:
        """Format OID ACL target clause."""
        if not attributes or target_dn == "entry":
            return "entry"
        if len(attributes) == 1 and attributes[0] == "*":
            return "attr=(*)"
        attrs_str = ",".join(attributes)
        return f"attr=({attrs_str})"

    @staticmethod
    def _normalize_permissions_to_dict(
        permissions: m.Ldif.AclPermissions | MutableMapping[str, bool] | None,
    ) -> MutableMapping[str, bool]:
        """Normalize permissions to dict for formatting."""
        if not permissions:
            return {}
        try:
            permissions_model = m.Ldif.AclPermissions.model_validate(permissions)
        except (ValueError, KeyError, AttributeError, UnicodeDecodeError, struct.error):
            return {}
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
        | m.Ldif.QuirkMetadata
        | t.MutableConfigurationMapping
        | MutableMapping[
            str,
            t.Scalar | MutableSequence[str] | t.MutableAttributeMapping | None,
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
    def _parse_oid_permissions(content: str) -> MutableMapping[str, bool]:
        """Parse OID ACL permissions clause."""
        permissions: MutableMapping[str, bool] = {}
        const = _OidConstants
        perm_match = re.search(const.ACL_PERMS_EXTRACT_OID, content, re.IGNORECASE)
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
        if not isinstance(acl_line, str):
            try:
                acl_model = m.Ldif.Acl.model_validate(acl_line)
            except (
                ValueError,
                KeyError,
                AttributeError,
                UnicodeDecodeError,
                struct.error,
            ):
                return False
            if acl_model.metadata and acl_model.metadata.quirk_type:
                return acl_model.metadata.quirk_type == self._get_server_type()
            return False
        if not acl_line:
            return False
        acl_line_str: str = str(acl_line)
        acl_line_lower = acl_line_str.strip().lower()
        if acl_line_lower.startswith((
            f"{FlextLdifServersOidConstants.ORCLACI}:",
            f"{FlextLdifServersOidConstants.ORCLENTRYLEVELACI}:",
        )):
            return True
        return acl_line_lower.startswith("access to ")

    @override
    def convert_rfc_acl_to_aci(
        self,
        rfc_acl_attrs: MutableMapping[str, MutableSequence[str]],
        target_server: str = "oid",
    ) -> r[MutableMapping[str, MutableSequence[str]]]:
        """Convert RFC ACL format to Oracle OID orclaci format."""
        _ = target_server
        return r[MutableMapping[str, MutableSequence[str]]].ok(rfc_acl_attrs)

    def _build_metadata_extensions(
        self,
        metadata: m.Ldif.QuirkMetadata
        | MutableMapping[
            str,
            t.Scalar | MutableSequence[str] | t.MutableAttributeMapping | None,
        ]
        | None,
    ) -> MutableSequence[str]:
        """Build OID ACL extension clauses from metadata."""
        if not metadata:
            return []
        meta_extensions = self._extract_extensions_dict(metadata)
        if not meta_extensions:
            return []
        return self._format_extensions(meta_extensions)

    def _build_oid_acl_metadata(
        self,
        config: m.Ldif.OidAclMetadataConfig,
    ) -> t.MutableConfigurationMapping:
        """Build metadata extensions for OID ACL with Oracle-specific features."""
        target_attrs_str: str = (
            _OidAclTargetAttributesJson(root=config.target_attrs).model_dump_json()
            if config.target_attrs
            else ""
        )
        permissions_str: str = (
            m.Ldif.DynamicMetadata.from_dict(config.perms_dict).model_dump_json()
            if config.perms_dict
            else ""
        )
        metadata_dict: t.MutableConfigurationMapping = dict(
            FlextLdifUtilitiesMetadata.build_acl_metadata_complete(
                "oid",
                acl_line=config.acl_line,
                server_type="oid",
                subject_type=config.oid_subject_type,
                subject_value=config.oid_subject_value,
                target_dn=config.target_dn,
                target_attrs=target_attrs_str,
                permissions=permissions_str,
                target_subject_type=config.rfc_subject_type,
                acl_filter=config.acl_filter,
                acl_constraint=config.acl_constraint,
                bindmode=config.bindmode,
                deny_group_override=config.deny_group_override is True,
                append_to_all=config.append_to_all is True,
                bind_ip_filter=config.bind_ip_filter,
                constrain_to_added_object=config.constrain_to_added_object,
                target_key=FlextLdifServersOidConstants.OID_ACL_SOURCE_TARGET,
            ),
        )
        if config.oid_subject_type:
            metadata_dict["acl_source_subject_type"] = config.oid_subject_type
        return metadata_dict

    def _extract_extensions_dict(
        self,
        metadata: m.Ldif.QuirkMetadata
        | MutableMapping[
            str,
            t.Scalar | MutableSequence[str] | t.MutableAttributeMapping | None,
        ],
    ) -> MutableMapping[str, t.Scalar | MutableSequence[str] | None]:
        """Extract extensions dict from metadata, converting types if needed."""
        try:
            metadata = m.Ldif.QuirkMetadata.model_validate(metadata)
        except (ValueError, KeyError, AttributeError, UnicodeDecodeError, struct.error):
            return {}
        return getattr(metadata, "extensions", None) or {}

    def _format_extensions(
        self,
        meta_extensions: MutableMapping[str, t.Scalar | MutableSequence[str] | None],
    ) -> MutableSequence[str]:
        """Format extension values based on metadata key type."""
        extensions: MutableSequence[str] = []
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
        metadata: m.Ldif.QuirkMetadata | None,
    ) -> str | None:
        """Get source subject type from metadata."""
        if not metadata or not metadata.extensions:
            return None
        source_subject_type_raw = metadata.extensions.get(
            c.Ldif.ACL_SOURCE_SUBJECT_TYPE,
        )
        if isinstance(source_subject_type_raw, str):
            return source_subject_type_raw
        msg = f"Expected str | None, got {type(source_subject_type_raw)}"
        raise TypeError(msg)

    def _map_bind_rules_to_oid(
        self,
        rfc_subject_value: str,
        source_subject_type: str | None,
    ) -> str:
        """Map bind_rules/group to OID subject type."""
        if source_subject_type in {"dn_attr", "guid_attr", "group_attr"}:
            return source_subject_type
        if source_subject_type in {"group_dn", "user_dn"}:
            return source_subject_type
        if source_subject_type == "group":
            return "group_dn"
        if (
            "group=" in rfc_subject_value.lower()
            or "groupdn" in rfc_subject_value.lower()
        ):
            return "group_dn"
        if "cn=groups" in rfc_subject_value.lower():
            return "group_dn"
        return "user_dn"

    def _map_oid_subject_to_rfc(
        self,
        oid_subject_type: str,
        oid_subject_value: str,
    ) -> tuple[c.Ldif.AclSubjectType, str]:
        """Map OID subject types to RFC subject types."""
        if oid_subject_type == "self":
            return (c.Ldif.AclSubjectType.SELF, "ldap:///self")
        if oid_subject_type == "group_dn":
            return (c.Ldif.AclSubjectType.GROUP, oid_subject_value)
        if oid_subject_type == "user_dn":
            return (c.Ldif.AclSubjectType.DN, oid_subject_value)
        if oid_subject_type in {"dn_attr", "guid_attr", "group_attr"}:
            return (c.Ldif.AclSubjectType.DN, oid_subject_value)
        if oid_subject_type == "*" or oid_subject_value == "*":
            return (c.Ldif.AclSubjectType.ANONYMOUS, "*")
        return (c.Ldif.AclSubjectType.DN, oid_subject_value)

    def _map_rfc_subject_to_oid(
        self,
        rfc_subject: m.Ldif.AclSubject,
        metadata: m.Ldif.QuirkMetadata | None,
    ) -> str:
        """Map RFC subject type to OID subject type for writing."""
        rfc_subject_type = rfc_subject.subject_type
        rfc_subject_value = rfc_subject.subject_value
        source_subject_type = self._get_source_subject_type(metadata)
        if source_subject_type in {"dn_attr", "guid_attr", "group_attr"}:
            return source_subject_type
        match rfc_subject_type:
            case "self":
                return "self"
            case "anonymous":
                return "*"
            case rfc_type if rfc_subject_value == "*":
                return "*"
            case rfc_type if rfc_type in {
                "dn_attr",
                "guid_attr",
                "group_attr",
                "group_dn",
                "user_dn",
            }:
                return rfc_type
            case "dn":
                if source_subject_type in {"dn_attr", "guid_attr", "group_attr"}:
                    return source_subject_type
                return "user_dn"
            case _:
                return source_subject_type or "user_dn"

    @override
    def _parse_acl(self, acl_line: str) -> r[m.Ldif.Acl]:
        """Parse Oracle OID ACL string to RFC-compliant internal model."""
        parent_result = super()._parse_acl(acl_line)
        if parent_result.is_failure:
            return parent_result
        if (
            parent_result.is_success
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
            parent_result.is_success
            and (acl_data := parent_result.value)
            and (not self.can_handle_acl(acl_line))
        ):
            return r[m.Ldif.Acl].ok(acl_data)
        return self._parse_oid_specific_acl(acl_line)

    def _parse_oid_specific_acl(self, acl_line: str) -> r[m.Ldif.Acl]:
        """Parse OID-specific ACL format when RFC parser fails."""
        try:
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
                        oid_subject_value = FlextLdifUtilitiesACL.extract_component(
                            acl_line,
                            regex,
                            group=1,
                        )
                        if oid_subject_value:
                            break
                oid_subject_value = oid_subject_value or "*"
            else:
                oid_subject_type = "self"
                oid_subject_value = "self"
            rfc_subject_type, rfc_subject_value = self._map_oid_subject_to_rfc(
                oid_subject_type,
                oid_subject_value,
            )
            perms_dict = self._parse_oid_permissions(acl_line)
            acl_filter = FlextLdifUtilitiesACL.extract_component(
                acl_line,
                FlextLdifServersOidConstants.ACL_FILTER_PATTERN,
                group=1,
            )
            acl_constraint = FlextLdifUtilitiesACL.extract_component(
                acl_line,
                FlextLdifServersOidConstants.ACL_CONSTRAINT_PATTERN,
                group=1,
            )
            bindmode = FlextLdifUtilitiesACL.extract_component(
                acl_line,
                FlextLdifServersOidConstants.ACL_BINDMODE_PATTERN,
                group=1,
            )
            deny_group_override = (
                FlextLdifUtilitiesACL.extract_component(
                    acl_line,
                    FlextLdifServersOidConstants.ACL_DENY_GROUP_OVERRIDE_PATTERN,
                )
                is not None
            )
            append_to_all = (
                FlextLdifUtilitiesACL.extract_component(
                    acl_line,
                    FlextLdifServersOidConstants.ACL_APPEND_TO_ALL_PATTERN,
                )
                is not None
            )
            bind_ip_filter = FlextLdifUtilitiesACL.extract_component(
                acl_line,
                FlextLdifServersOidConstants.ACL_BIND_IP_FILTER_PATTERN,
                group=1,
            )
            constrain_to_added_object = FlextLdifUtilitiesACL.extract_component(
                acl_line,
                FlextLdifServersOidConstants.ACL_CONSTRAIN_TO_ADDED_PATTERN,
                group=1,
            )
            config = self.OidAclMetadataConfig.model_validate({
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
            extensions = self._build_oid_acl_metadata(config)
            server_type: Literal["oid"] = "oid"
            rfc_compliant_perms = m.Ldif.AclPermissions.get_rfc_compliant_permissions(
                perms_dict,
            )
            extensions_metadata = FlextLdifModelsMetadata.DynamicMetadata.from_dict(
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
                "metadata": m.Ldif.QuirkMetadata.model_validate({
                    "quirk_type": server_type,
                    "extensions": extensions_metadata,
                }),
                "raw_acl": acl_line,
                "raw_line": acl_line,
                "validation_violations": [],
            })
            return r[m.Ldif.Acl].ok(acl_model)
        except (
            ValueError,
            KeyError,
            AttributeError,
            UnicodeDecodeError,
            struct.error,
        ) as e:
            max_len = FlextLdifServersOidConstants.MAX_LOG_LINE_LENGTH
            acl_preview = acl_line[:max_len] if len(acl_line) > max_len else acl_line
            logger.debug(
                "OID ACL parse failed",
                error=e,
                error_type=type(e).__name__,
                acl_line=acl_preview,
                acl_line_length=len(acl_line),
            )
            return r[m.Ldif.Acl].fail(f"OID ACL parsing failed: {e}")

    def _authorize_write_permissions(
        self,
        acl_subject: m.Ldif.AclSubject | t.MutableConfigurationMapping,
        acl_permissions: m.Ldif.AclPermissions | MutableMapping[str, bool] | None,
        metadata: m.Ldif.QuirkMetadata
        | MutableMapping[
            str,
            t.Scalar | MutableSequence[str] | t.MutableAttributeMapping | None,
        ]
        | None,
    ) -> tuple[str, str]:
        """Prepare OID subject and permissions clauses for ACL write."""
        subject_dict = self._normalize_to_dict(acl_subject)
        subject_public = m.Ldif.AclSubject.model_validate(subject_dict)
        metadata_public: m.Ldif.QuirkMetadata | None = None
        if metadata:
            try:
                metadata_public = m.Ldif.QuirkMetadata.model_validate(metadata)
            except (
                ValueError,
                KeyError,
                AttributeError,
                UnicodeDecodeError,
                struct.error,
            ):
                metadata_dict = self._normalize_to_dict(metadata)
                metadata_public = m.Ldif.QuirkMetadata.model_validate(metadata_dict)
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
        if (
            oid_subject_type in {"dn_attr", "guid_attr", "group_attr"}
            and "#" not in subject_value
        ):
            type_suffix = {
                "dn_attr": "LDAPURL",
                "guid_attr": "USERDN",
                "group_attr": "GROUPDN",
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
            acl_data.metadata.model_copy(update={"quirk_type": server_type})
            if acl_data.metadata
            else m.Ldif.QuirkMetadata.create_for(
                server_type,
                extensions=FlextLdifModelsMetadata.DynamicMetadata(),
            )
        )
        return acl_data.model_copy(
            update={
                "server_type": server_type,
                "metadata": updated_metadata,
            },
        )

    @override
    def _write_acl(
        self,
        acl_data: FlextLdifModelsDomains.Acl,
        _format_option: str | None = None,
    ) -> r[str]:
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
                metadata_public = m.Ldif.QuirkMetadata.model_validate(acl_data.metadata)
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
            metadata_public = m.Ldif.QuirkMetadata.model_validate(acl_data.metadata)
        else:
            metadata_public = None
        acl_parts.extend(self._build_metadata_extensions(metadata_public))
        orclaci_str = " ".join(acl_parts)
        return r[str].ok(orclaci_str)
