"""Oracle Unified Directory (OUD) Servers."""

from __future__ import annotations

from collections.abc import (
    Mapping,
    MutableMapping,
)
from typing import ClassVar, Self, override

from flext_ldif import c, m, p, r, t, u
from flext_ldif.servers._base.acl import FlextLdifServersBaseSchemaAcl
from flext_ldif.servers._oud.constants import FlextLdifServersOudConstants
from flext_ldif.servers._oud.utilities import FlextLdifServersOudUtilities
from flext_ldif.servers.rfc import FlextLdifServersRfc


class FlextLdifServersOudAcl(FlextLdifServersRfc.Acl):
    """Oracle OUD ACL Implementation (RFC 4876 ACI Format)."""

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)
    RFC_ACL_ATTRIBUTES: ClassVar[t.StrSequence] = (
        FlextLdifServersOudConstants.RFC_ACL_ATTRIBUTES
    )
    OUD_ACL_ATTRIBUTES: ClassVar[t.StrSequence] = (
        FlextLdifServersOudConstants.OUD_ACL_ATTRIBUTES
    )

    def __init__(
        self,
        acl_service: p.Ldif.AclServer | None = None,
        parent_server: Self | None = None,
        **kwargs: t.Ldif.Scalar,
    ) -> None:
        """Initialize OUD ACL server."""
        filtered_kwargs: t.MutableConfigValueMapping = {
            k: v
            for k, v in kwargs.items()
            if k != "_parent_server" and isinstance(v, (str, float, bool))
        }
        acl_service_typed: p.Ldif.AclServer | None = (
            acl_service if acl_service is not None else None
        )
        parent_server_typed: FlextLdifServersBaseSchemaAcl | None = (
            parent_server
            if isinstance(parent_server, FlextLdifServersBaseSchemaAcl)
            else None
        )
        FlextLdifServersBaseSchemaAcl.__init__(
            self,
            acl_service=acl_service_typed,
            _parent_server=parent_server_typed,
            **filtered_kwargs,
        )

    @staticmethod
    def _extension_get_str(
        extensions: t.Ldif.MetadataInputMapping | None,
        key: str,
    ) -> str | None:
        """Read a metadata extension as string."""
        if not extensions:
            return None
        value = extensions.get(key)
        return value if isinstance(value, str) else None

    @staticmethod
    def _is_aci_start(line: str) -> bool:
        """Check if line starts an ACI definition."""
        return line.lower().startswith(
            FlextLdifServersOudConstants.ACL_ACI_PREFIX.lower(),
        )

    @staticmethod
    def _is_ds_cfg_acl(line: str) -> bool:
        """Check if line is a ds-cfg ACL format."""
        return line.lower().startswith(
            FlextLdifServersOudConstants.ACL_DS_CFG_PREFIX.lower(),
        )

    @staticmethod
    def _scalar_or_list_value(value: t.JsonPayload | None) -> bool:
        """Check if value is scalar metadata value or list."""
        return isinstance(value, (str, int, float, bool, list))

    @override
    # NOTE (multi-agent, mro-0ftd.3.7.2): param type = protocol to match base
    # (contravariant override); concrete model still built via model_validate.
    def can_handle(self, acl_line: str | p.Ldif.Acl) -> bool:
        """Check if this is an Oracle OUD ACL (public method)."""
        return self.can_handle_acl(acl_line)

    @override
    def can_handle_acl(self, acl_line: str | p.Ldif.Acl) -> bool:
        """Check if this is an Oracle OUD ACL line (implements abstract method from base.py)."""
        if not isinstance(acl_line, str):
            try:
                acl_model = m.Ldif.Acl.model_validate(acl_line)
            except c.Ldif.EXC_LDIF_PARSE:
                return False
            if acl_model.metadata and acl_model.metadata.server_type:
                metadata_server_type = str(acl_model.metadata.server_type)
                current_server_type: str = self._get_server_type()
                return metadata_server_type == current_server_type
            return bool(
                acl_model.name
                and u.Ldif.normalize_attribute_name(acl_model.name)
                == u.Ldif.normalize_attribute_name(
                    FlextLdifServersOudConstants.ACL_ATTRIBUTE_NAME,
                ),
            )
        normalized = acl_line.strip()
        if not normalized:
            return False
        normalized_lower = normalized.lower()
        oud_prefixes = [
            FlextLdifServersOudConstants.ACL_ACI_PREFIX,
            FlextLdifServersOudConstants.ACL_TARGETATTR_PREFIX,
            FlextLdifServersOudConstants.ACL_TARGETSCOPE_PREFIX,
            FlextLdifServersOudConstants.ACL_DEFAULT_VERSION,
        ]
        starts_like_oud = (
            any(normalized.startswith(prefix) for prefix in oud_prefixes)
            or "ds-cfg-" in normalized_lower
        )
        is_non_legacy_acl = not any(
            pattern in normalized_lower for pattern in ["access to", "(", ")", "=", ":"]
        )
        return starts_like_oud or is_non_legacy_acl

    @override
    def resolve_acl_attributes(self) -> t.MutableSequenceOf[str]:
        """Get RFC + OUD extensions."""
        return [*self.RFC_ACL_ATTRIBUTES, *self.OUD_ACL_ATTRIBUTES]

    def _build_aci_permissions(self, acl_data: m.Ldif.Acl) -> p.Result[str]:
        """Build ACI permissions clause from ACL model."""
        perms = acl_data.permissions
        target_perms_dict: t.MappingKV[str, t.JsonPayload] | None = None
        if not perms and acl_data.metadata:
            extensions = acl_data.metadata.extensions
            target_perms_dict_raw = (
                extensions.get("acl_target_permissions") if extensions else None
            )
            if not target_perms_dict_raw:
                target_perms_dict_raw = (
                    extensions.get("target_permissions") if extensions else None
                )
            permissions_value: t.JsonPayload | None = target_perms_dict_raw
            if isinstance(permissions_value, Mapping):
                target_perms_dict = t.json_mapping_adapter().validate_python(
                    permissions_value,
                )
        if target_perms_dict:
            perms_data: t.Ldif.MutableMetadataInputMapping = {}
            for key, val in target_perms_dict.items():
                k = key
                if isinstance(val, Mapping):
                    continue
                if isinstance(val, (str, bool, int, float)):
                    perms_data[k] = val
                elif isinstance(val, list):
                    str_list: t.JsonValueList = [
                        item for item in val if isinstance(item, str)
                    ]
                    perms_data[k] = u.normalize_to_metadata(str_list)
            if perms_data:
                perms = m.Ldif.AclPermissions(
                    read=bool(perms_data.get("read")),
                    write=bool(perms_data.get("write")),
                    add=bool(perms_data.get("add")),
                    delete=bool(perms_data.get("delete")),
                    search=bool(perms_data.get("search")),
                    compare=bool(perms_data.get("compare")),
                    self_write=bool(
                        perms_data.get("self_write") or perms_data.get("selfwrite"),
                    ),
                    proxy=bool(perms_data.get("proxy")),
                )
            else:
                perms = None
        if not perms:
            return r[str].fail("ACL model has no permissions t.JsonValue")
        ops: t.MutableSequenceOf[str] = [
            field_name
            for field_name in (
                "read",
                "write",
                "add",
                "delete",
                "search",
                "compare",
                "self_write",
                "proxy",
            )
            if getattr(perms, field_name, False)
        ]
        permission_normalization = {"self_write": "selfwrite"}
        normalized_ops = [permission_normalization.get(op, op) for op in ops]
        filtered_ops = u.Ldif.filter_supported_permissions(
            normalized_ops,
            FlextLdifServersOudConstants.SUPPORTED_PERMISSIONS,
        )
        meta_extensions = acl_data.metadata.extensions if acl_data.metadata else None
        self_write_to_write_enabled = (
            bool(meta_extensions.get("self_write_to_write"))
            if meta_extensions
            else False
        )
        if (
            self_write_to_write_enabled
            and (FlextLdifServersOudConstants.PERMISSION_SELF_WRITE in ops)
            and ("write" not in filtered_ops)
        ):
            filtered_ops.append("write")
        if not filtered_ops:
            return r[str].fail(
                f"ACL model has no OUD-supported permissions (all were unsupported vendor-specific permissions like {FlextLdifServersOudConstants.PERMISSION_SELF_WRITE}, stored in metadata)",
            )
        ops_str = ",".join(filtered_ops)
        return r[str].ok(f"{FlextLdifServersOudConstants.ACL_ALLOW_PREFIX}{ops_str})")

    def _build_aci_subject(self, acl_data: m.Ldif.Acl) -> str:
        """Build ACI bind rules (subject) clause from ACL model."""
        base_dn, subject_type, subject_value = self._extract_and_resolve_acl_subject(
            acl_data,
        )
        if not subject_type or subject_type == "self":
            return f'userdn="{FlextLdifServersOudConstants.ACL_SELF_SUBJECT}";)'
        attr_suffix_map = {
            "dn_attr": "LDAPURL",
            "guid_attr": "USERDN",
            "group_attr": "GROUPDN",
        }
        if subject_type in attr_suffix_map:
            suffix = attr_suffix_map[subject_type]
            return f'userattr="{subject_value}#{suffix}";)'
        filtered_value = (
            subject_value[: -len(base_dn)].rstrip(",")
            if base_dn and subject_value.endswith(base_dn)
            else subject_value
        )
        bind_operator = {"user": "userdn", "group": "groupdn", "role": "roledn"}.get(
            subject_type,
            "userdn",
        )
        formatted: str = u.Ldif.format_aci_subject(
            subject_type,
            filtered_value,
            bind_operator,
        )
        return formatted

    def _build_aci_target(self, acl_data: m.Ldif.Acl) -> str:
        """Build ACI target clause from ACL model."""
        target = acl_data.target
        if not target and acl_data.metadata:
            extensions = acl_data.metadata.extensions
            target_dict = extensions.get("acl_target_target") if extensions else None
            target_data: t.Ldif.MutableMetadataMapping = {}
            target_value: t.JsonPayload | None = target_dict
            if isinstance(target_value, Mapping):
                for raw_key, raw_value in target_value.items():
                    json_value: t.JsonPayload | None = raw_value
                    if isinstance(json_value, Mapping):
                        continue
                    if FlextLdifServersOudAcl._scalar_or_list_value(json_value):
                        target_data[raw_key] = u.normalize_to_metadata(json_value)
            if target_data:
                attrs_raw = target_data.get("attributes")
                dn_raw = target_data.get("target_dn")
                attrs: t.MutableSequenceOf[str] = (
                    [item for item in attrs_raw if isinstance(item, str)]
                    if isinstance(attrs_raw, list)
                    else []
                )
                dn: str = dn_raw if isinstance(dn_raw, str) else "*"
                target = m.Ldif.AclTarget.model_validate({
                    "target_dn": dn,
                    "attributes": attrs,
                })
        clause: str = u.Ldif.build_aci_target_clause(
            target_attributes=target.attributes if target else None,
            target_dn=target.target_dn if target else None,
            separator=" || ",
        )
        return clause

    def _extract_and_resolve_acl_subject(
        self,
        acl_data: m.Ldif.Acl,
    ) -> tuple[str | None, str, str]:
        """Extract metadata and resolve subject type and value in one pass."""
        ext = acl_data.metadata.extensions if acl_data.metadata else None
        base_dn = self._extension_get_str(ext, "base_dn")
        source_subject_type = self._extension_get_str(ext, "acl_source_subject_type")
        subject = acl_data.subject
        attr_subject_types = {"dn_attr", "guid_attr", "group_attr"}
        subject_type = (
            source_subject_type
            if source_subject_type in attr_subject_types
            else (subject.subject_type if subject else source_subject_type)
        ) or "self"
        if subject_type == FlextLdifServersOudConstants.ACL_SUBJECT_TYPE_BIND_RULES:
            subject_value_lower = (
                (subject.subject_value or "").lower() if subject else ""
            )
            source_subject_type_normalized = source_subject_type or ""
            match source_subject_type_normalized:
                case "dn_attr" | "guid_attr" | "group_attr":
                    subject_type = source_subject_type_normalized
                case "group_dn":
                    subject_type = "group"
                case _ if (
                    "group=" in subject_value_lower
                    or FlextLdifServersOudConstants.ACL_BIND_RULE_TYPE_GROUPDN
                    in subject_value_lower
                ):
                    subject_type = "group"
                case _:
                    pass
        subject_value = (
            subject.subject_value if subject else None
        ) or self._extension_get_str(
            ext,
            "acl_original_subject_value",
        )
        if not subject_value:
            subject_value = (
                FlextLdifServersOudConstants.ACL_SELF_SUBJECT
                if subject_type == "self"
                else ""
            )
        return (base_dn, subject_type, subject_value)

    def _finalize_aci(
        self,
        current_aci: t.MutableSequenceOf[str],
        # NOTE (multi-agent, mro-0ftd.3.7.2): receiving collection carries the
        # protocol objects parse_server yields; model is built at .ok() only.
        acls: t.MutableSequenceOf[p.Ldif.Acl],
    ) -> None:
        """Parse and add accumulated ACI to ACL list."""
        if current_aci:
            aci_text = "\n".join(current_aci)
            result = self.parse_server(aci_text)
            if result.success:
                acls.append(result.value)

    def _parse_aci_format(self, acl_line: str) -> p.Result[p.Ldif.Acl]:
        """Parse RFC 4876 ACI format using utility with OUD-specific settings."""
        settings = FlextLdifServersOudUtilities.get_parser_config()
        result: p.Result[p.Ldif.Acl] = u.Ldif.parse_aci(acl_line, settings)
        if not result.success:
            return result
        acl = result.value
        aci_content = acl_line.split(":", 1)[1].strip() if ":" in acl_line else ""
        extensions: t.MutableJsonMapping = {}
        if acl.metadata and acl.metadata.extensions:
            extensions.update(acl.metadata.extensions)
        timeofday_match = FlextLdifServersOudConstants.ACL_TIMEOFDAY_RE.search(
            aci_content,
        )
        if timeofday_match:
            extensions[c.Ldif.ACL_BIND_TIMEOFDAY] = (
                f"{timeofday_match.group(1)}{timeofday_match.group(2)}"
            )
        ssf_match = FlextLdifServersOudConstants.ACL_SSF_RE.search(aci_content)
        if ssf_match:
            extensions[c.Ldif.ACL_SSF] = f"{ssf_match.group(1)}{ssf_match.group(2)}"
        server_type_value = settings.server_type if settings else "oud"
        new_metadata = u.Ldif.server_metadata_for(
            server_type_value,
            extensions=extensions,
        )
        update_dict: MutableMapping[str, m.Ldif.ServerMetadata] = {
            "metadata": new_metadata,
        }
        acl_updated = acl.model_copy(update=update_dict)
        acl_result: m.Ldif.Acl = acl_updated
        return r[p.Ldif.Acl].ok(acl_result)

    @override
    def _parse_acl(self, acl_line: str) -> p.Result[p.Ldif.Acl]:
        """Parse Oracle OUD ACL string to RFC-compliant internal model."""
        normalized = acl_line.strip()
        if normalized.startswith(FlextLdifServersOudConstants.ACL_ACI_PREFIX):
            return self._parse_aci_format(acl_line)
        rfc_result = super()._parse_acl(acl_line)
        if rfc_result.success:
            acl_model = rfc_result.value
            if acl_model.name or normalized.startswith("aci:"):
                return rfc_result
        return self._parse_ds_privilege_name(normalized)

    def _parse_ds_privilege_name(self, privilege_name: str) -> p.Result[p.Ldif.Acl]:
        """Parse OUD ds-privilege-name format (simple privilege names)."""
        try:
            server_type_oud: c.Ldif.ServerTypes = c.Ldif.ServerTypes.OUD
            acl_model = m.Ldif.Acl(
                name=privilege_name,
                target=None,
                subject=None,
                permissions=None,
                server_type=server_type_oud,
                raw_line=privilege_name,
                raw_acl=privilege_name,
                validation_violations=[],
                metadata=m.Ldif.ServerMetadata(
                    server_type=c.Ldif.ServerTypes.OUD,
                    extensions={
                        FlextLdifServersOudConstants.DS_PRIVILEGE_NAME_KEY: privilege_name,
                        FlextLdifServersOudConstants.FORMAT_TYPE_KEY: FlextLdifServersOudConstants.FORMAT_TYPE_DS_PRIVILEGE,
                    },
                ),
            )
            return r[p.Ldif.Acl].ok(acl_model)
        except c.Ldif.EXC_LDIF_PARSE as e:
            FlextLdifServersOudAcl._module_logger.exception(
                "Failed to parse OUD ds-privilege-name",
            )
            return r[p.Ldif.Acl].fail(f"Failed to parse OUD ds-privilege-name: {e}")

    def _should_use_raw_acl(self, acl_data: m.Ldif.Acl) -> bool:
        """Check if raw_acl should be used as-is."""
        if not acl_data.raw_acl:
            return False
        raw_acl_str: str = acl_data.raw_acl
        acl_aci_prefix: str = FlextLdifServersOudConstants.ACL_ACI_PREFIX
        return raw_acl_str.startswith(acl_aci_prefix)

    @override
    def _write_acl(self, acl_data: m.Ldif.Acl) -> p.Result[str]:
        """Write RFC-compliant ACL model to OUD ACI string format (protected internal method)."""
        try:
            return self._write_oud_aci(acl_data)
        except c.Ldif.EXC_LDIF_PARSE as e:
            FlextLdifServersOudAcl._module_logger.exception(
                "Failed to write ACL to OUD ACI format",
            )
            return r[str].fail(f"Failed to write ACL to OUD ACI format: {e}")

    def _write_oud_aci(self, acl_data: m.Ldif.Acl) -> p.Result[str]:
        """Build an OUD ACI string from the canonical ACL model."""
        sc = FlextLdifServersOudConstants
        extensions: t.Ldif.MutableMetadataMapping | None = (
            acl_data.metadata.extensions
            if acl_data.metadata and acl_data.metadata.extensions
            else None
        )
        aci_output_lines = u.Ldif.format_conversion_comments(
            extensions,
            "converted_from_server",
            "conversion_comments",
        )
        if self._should_use_raw_acl(acl_data):
            aci_output_lines.append(acl_data.raw_acl)
            return r[str].ok("\n".join(aci_output_lines))
        aci_parts = [self._build_aci_target(acl_data)]
        aci_parts.extend(
            u.Ldif.extract_target_extensions(
                extensions,
                sc.ACL_TARGET_EXTENSIONS_CONFIG,
            ),
        )
        acl_name = acl_data.name or sc.ACL_DEFAULT_NAME
        aci_parts.append(f'({sc.ACL_DEFAULT_VERSION}; acl "{acl_name}";')
        perms_result = self._build_aci_permissions(acl_data)
        if perms_result.failure:
            return r[str].fail(perms_result.error or "Unknown error")
        subject_str = self._build_aci_subject(acl_data)
        if not subject_str:
            return r[str].fail("ACL subject DN was filtered out")
        bind_rules = u.Ldif.extract_bind_rules_from_extensions(
            extensions,
            sc.ACL_BIND_RULES_CONFIG,
            tuple_length=sc.ACL_BIND_RULE_TUPLE_LENGTH,
        )
        if bind_rules:
            subject_str = subject_str.rstrip(";)")
            subject_str = f"{subject_str} and {' and '.join(bind_rules)};)"
        aci_parts.extend([perms_result.value, subject_str])
        aci_string = f"{sc.ACL_ACI_PREFIX} {' '.join(aci_parts)}"
        aci_output_lines.append(aci_string)
        return r[str].ok("\n".join(aci_output_lines))
