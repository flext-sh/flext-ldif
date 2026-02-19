"""Oracle Unified Directory (OUD) Quirks."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import ClassVar

from flext_core import FlextLogger, FlextResult

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif._utilities.acl import FlextLdifUtilitiesACL
from flext_ldif._utilities.schema import FlextLdifUtilitiesSchema
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.servers._base.acl import FlextLdifServersBaseSchemaAcl
from flext_ldif.servers._oud.constants import FlextLdifServersOudConstants
from flext_ldif.servers._oud.utilities import FlextLdifServersOudUtilities
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.typings import t

logger = FlextLogger(__name__)


class FlextLdifServersOudAcl(FlextLdifServersRfc.Acl):
    """Oracle OUD ACL Implementation (RFC 4876 ACI Format)."""

    RFC_ACL_ATTRIBUTES: ClassVar[list[str]] = [
        "aci",
        "acl",
        "olcAccess",
        "aclRights",
        "aclEntry",
    ]

    OUD_ACL_ATTRIBUTES: ClassVar[list[str]] = [
        "ds-privilege-name",
    ]

    def get_acl_attributes(self) -> list[str]:
        """Get RFC + OUD extensions."""
        return self.RFC_ACL_ATTRIBUTES + self.OUD_ACL_ATTRIBUTES

    def __init__(
        self,
        acl_service: object | None = None,
        _parent_quirk: object | None = None,
        **kwargs: str | float | bool | None,
    ) -> None:
        """Initialize OUD ACL quirk."""
        filtered_kwargs: dict[str, str | float | bool | None] = {
            k: v
            for k, v in kwargs.items()
            if k != "_parent_quirk" and isinstance(v, (str, float, bool, type(None)))
        }

        acl_service_typed: object | None = (
            acl_service if acl_service is not None else None
        )

        parent_quirk_typed: object | None = (
            _parent_quirk if _parent_quirk is not None else None
        )
        FlextLdifServersBaseSchemaAcl.__init__(
            self,
            acl_service=acl_service_typed,
            _parent_quirk=parent_quirk_typed,
            **filtered_kwargs,
        )

    def can_handle(self, acl_line: str | m.Ldif.Acl) -> bool:
        """Check if this is an Oracle OUD ACL (public method)."""
        if isinstance(acl_line, str):
            return self.can_handle_acl(acl_line)
        if isinstance(acl_line, m.Ldif.Acl):
            return self.can_handle_acl(acl_line)

        return False

    def can_handle_acl(self, acl_line: str | m.Ldif.Acl) -> bool:
        """Check if this is an Oracle OUD ACL line (implements abstract method from base.py)."""
        if not isinstance(acl_line, str):
            if isinstance(acl_line, m.Ldif.Acl):
                if (
                    acl_line.metadata
                    and hasattr(acl_line.metadata, "quirk_type")
                    and acl_line.metadata.quirk_type
                ):
                    return str(acl_line.metadata.quirk_type) == self._get_server_type()

                if hasattr(acl_line, "name") and acl_line.name:
                    return FlextLdifUtilitiesSchema.normalize_attribute_name(
                        acl_line.name,
                    ) == FlextLdifUtilitiesSchema.normalize_attribute_name(
                        FlextLdifServersOudConstants.ACL_ATTRIBUTE_NAME,
                    )
            return False

        if not isinstance(acl_line, str) or not (normalized := acl_line.strip()):
            return False

        normalized_lower = normalized.lower()
        oud_prefixes = [
            FlextLdifServersOudConstants.ACL_ACI_PREFIX,
            FlextLdifServersOudConstants.ACL_TARGETATTR_PREFIX,
            FlextLdifServersOudConstants.ACL_TARGETSCOPE_PREFIX,
            FlextLdifServersOudConstants.ACL_DEFAULT_VERSION,
        ]

        if (
            any(normalized.startswith(prefix) for prefix in oud_prefixes)
            or "ds-cfg-" in normalized_lower
        ):
            return True

        return not any(
            pattern in normalized_lower for pattern in ["access to", "(", ")", "=", ":"]
        )

    def _parse_acl(self, acl_line: str) -> FlextResult[m.Ldif.Acl]:
        """Parse Oracle OUD ACL string to RFC-compliant internal model."""
        if not isinstance(acl_line, str):
            return FlextResult[m.Ldif.Acl].fail(
                f"ACL line must be a string, got {type(acl_line).__name__}",
            )
        normalized = acl_line.strip()

        if normalized.startswith(FlextLdifServersOudConstants.ACL_ACI_PREFIX):
            return self._parse_aci_format(acl_line)

        rfc_result = super()._parse_acl(acl_line)
        if rfc_result.is_success:
            acl_model = rfc_result.value
            if acl_model.name or normalized.startswith("aci:"):
                return rfc_result

        return self._parse_ds_privilege_name(normalized)

    def _parse_aci_format(self, acl_line: str) -> FlextResult[m.Ldif.Acl]:
        """Parse RFC 4876 ACI format using utility with OUD-specific config."""
        config_raw = FlextLdifServersOudUtilities.get_parser_config()

        config_dict = config_raw.model_dump()
        config = m.Ldif.AciParserConfig.model_validate(config_dict)
        result = FlextLdifUtilitiesACL.parse_aci(acl_line, config)

        if not result.is_success:
            return result

        acl = result.value
        aci_content = acl_line.split(":", 1)[1].strip() if ":" in acl_line else ""

        extensions = m.Ldif.DynamicMetadata()
        if acl.metadata and acl.metadata.extensions:
            extensions.update(acl.metadata.extensions.to_dict())

        timeofday_match = re.search(
            FlextLdifServersOudConstants.ACL_TIMEOFDAY_PATTERN,
            aci_content,
        )
        if timeofday_match:
            extensions["acl_bind_timeofday"] = (
                f"{timeofday_match.group(1)}{timeofday_match.group(2)}"
            )

        ssf_match = re.search(
            FlextLdifServersOudConstants.ACL_SSF_PATTERN,
            aci_content,
        )
        if ssf_match:
            extensions["acl_ssf"] = f"{ssf_match.group(1)}{ssf_match.group(2)}"

        server_type_value = config.server_type if config else "oud"

        new_metadata = m.Ldif.QuirkMetadata.create_for(
            server_type_value,
            extensions=extensions,
        )

        update_dict: dict[str, m.Ldif.QuirkMetadata] = {"metadata": new_metadata}
        acl_updated = acl.model_copy(update=update_dict)

        acl_result: m.Ldif.Acl = acl_updated

        return FlextResult[m.Ldif.Acl].ok(acl_result)

    def _parse_ds_privilege_name(
        self,
        privilege_name: str,
    ) -> FlextResult[m.Ldif.Acl]:
        """Parse OUD ds-privilege-name format (simple privilege names)."""
        try:
            server_type_oud: c.Ldif.LiteralTypes.ServerTypeLiteral = "oud"
            acl_model = m.Ldif.Acl(
                name=privilege_name,
                target=None,
                subject=None,
                permissions=None,
                server_type=server_type_oud,
                raw_line=privilege_name,
                raw_acl=privilege_name,
                validation_violations=[],
                metadata=m.Ldif.QuirkMetadata(
                    quirk_type=c.Ldif.ServerTypes.OUD,
                    extensions=FlextLdifModelsMetadata.DynamicMetadata.from_dict({
                        FlextLdifServersOudConstants.DS_PRIVILEGE_NAME_KEY: privilege_name,
                        FlextLdifServersOudConstants.FORMAT_TYPE_KEY: (
                            FlextLdifServersOudConstants.FORMAT_TYPE_DS_PRIVILEGE
                        ),
                    }),
                ),
            )

            return FlextResult[m.Ldif.Acl].ok(acl_model)

        except Exception as e:
            logger.exception(
                "Failed to parse OUD ds-privilege-name",
            )
            return FlextResult[m.Ldif.Acl].fail(
                f"Failed to parse OUD ds-privilege-name: {e}",
            )

    def _should_use_raw_acl(self, acl_data: FlextLdifModelsDomains.Acl) -> bool:
        """Check if raw_acl should be used as-is."""
        if not acl_data.raw_acl:
            return False

        raw_acl_str = acl_data.raw_acl if isinstance(acl_data.raw_acl, str) else ""
        return raw_acl_str.startswith(
            FlextLdifServersOudConstants.ACL_ACI_PREFIX,
        )

    def _build_aci_target(self, acl_data: FlextLdifModelsDomains.Acl) -> str:
        """Build ACI target clause from ACL model."""
        target = acl_data.target
        if not target and acl_data.metadata:
            extensions = acl_data.metadata.extensions
            target_dict = (
                extensions.get("acl_target_target")
                if extensions and hasattr(extensions, "get")
                else None
            )

            target_data: dict[str, t.MetadataAttributeValue] = {}
            if isinstance(target_dict, dict):
                target_data = {
                    k: v
                    for k, v in target_dict.items()
                    if not isinstance(v, Mapping)
                    and isinstance(v, (str, int, float, bool, type(None), list))
                }

            if target_data:
                attrs_raw = target_data.get("attributes")
                dn_raw = target_data.get("target_dn")

                attrs: list[str] = (
                    [item for item in attrs_raw if isinstance(item, str)]
                    if isinstance(attrs_raw, list)
                    else []
                )
                dn: str = str(dn_raw) if isinstance(dn_raw, str) else "*"
                target = m.Ldif.AclTarget(
                    target_dn=dn,
                    attributes=attrs,
                )

        return FlextLdifUtilitiesACL.build_aci_target_clause(
            target_attributes=target.attributes if target else None,
            target_dn=target.target_dn if target else None,
            separator=" || ",
        )

    def _build_aci_permissions(
        self,
        acl_data: FlextLdifModelsDomains.Acl,
    ) -> FlextResult[str]:
        """Build ACI permissions clause from ACL model."""
        perms = acl_data.permissions
        target_perms_dict = None

        if not perms and acl_data.metadata:
            extensions = acl_data.metadata.extensions
            target_perms_dict_raw = (
                extensions.get("acl_target_permissions")
                if extensions and hasattr(extensions, "get")
                else None
            )
            if not target_perms_dict_raw:
                target_perms_dict_raw = (
                    extensions.get("target_permissions")
                    if extensions and hasattr(extensions, "get")
                    else None
                )
            target_perms_dict = target_perms_dict_raw

        if target_perms_dict and isinstance(target_perms_dict, dict):
            target_perms_dict_typed: Mapping[str, t.MetadataAttributeValue] = (
                target_perms_dict
            )
            perms_data: dict[str, object] = {}

            for key, val in target_perms_dict_typed.items():
                if not isinstance(key, str):
                    continue
                k = str(key)

                if isinstance(val, Mapping):
                    continue

                if isinstance(val, (str, bool, int, float)) or val is None:
                    perms_data[k] = val
                elif isinstance(val, list):
                    str_list = [str(item) for item in val if isinstance(item, str)]
                    perms_data[k] = str_list

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
            return FlextResult[str].fail("ACL model has no permissions object")

        ops: list[str] = [
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

        permission_normalization = {
            "self_write": "selfwrite",
        }
        normalized_ops = [permission_normalization.get(op, op) for op in ops]

        filtered_ops = FlextLdifUtilitiesACL.filter_supported_permissions(
            normalized_ops,
            FlextLdifServersOudConstants.SUPPORTED_PERMISSIONS,
        )

        meta_extensions = acl_data.metadata.extensions if acl_data.metadata else None
        if (
            meta_extensions
            and hasattr(meta_extensions, "get")
            and meta_extensions.get("self_write_to_write")
            and FlextLdifServersOudConstants.PERMISSION_SELF_WRITE in ops
            and "write" not in filtered_ops
        ):
            filtered_ops.append("write")

        if not filtered_ops:
            return FlextResult[str].fail(
                f"ACL model has no OUD-supported permissions (all were unsupported vendor-specific permissions like {FlextLdifServersOudConstants.PERMISSION_SELF_WRITE}, stored in metadata)",
            )

        ops_str = ",".join(filtered_ops)
        return FlextResult[str].ok(
            f"{FlextLdifServersOudConstants.ACL_ALLOW_PREFIX}{ops_str})",
        )

    def _extract_and_resolve_acl_subject(
        self,
        acl_data: FlextLdifModelsDomains.Acl,
    ) -> tuple[str | None, str, str]:
        """Extract metadata and resolve subject type and value in one pass."""
        ext = acl_data.metadata.extensions if acl_data.metadata else None
        if ext:
            base_dn_raw = ext.get("base_dn")
            base_dn = base_dn_raw if isinstance(base_dn_raw, str) else None
        else:
            base_dn = None
        source_subject_type = (
            (
                sst
                if isinstance(
                    sst := ext.get(
                        "acl_source_subject_type",
                    ),
                    str,
                )
                else None
            )
            if ext
            else None
        )

        if source_subject_type in {"dn_attr", "guid_attr", "group_attr"}:
            subject_type = source_subject_type
        else:
            subject_type = (
                acl_data.subject.subject_type
                if acl_data.subject
                else source_subject_type
            ) or "self"

        if subject_type == "bind_rules":
            if source_subject_type in {"dn_attr", "guid_attr", "group_attr"}:
                subject_type = source_subject_type
            elif source_subject_type == "group_dn" or (
                acl_data.subject
                and acl_data.subject.subject_value
                and any(
                    kw in acl_data.subject.subject_value.lower()
                    for kw in ("group=", "groupdn")
                )
            ):
                subject_type = "group"

        subject_value = (
            acl_data.subject.subject_value if acl_data.subject else None
        ) or (
            sv
            if ext
            and isinstance(
                sv := ext.get(
                    "acl_original_subject_value",
                ),
                str,
            )
            else None
        )

        if not subject_value and subject_type == "self":
            subject_value = FlextLdifServersOudConstants.ACL_SELF_SUBJECT
        if not subject_value:
            subject_value = ""

        return base_dn, subject_type, subject_value

    def _build_aci_subject(self, acl_data: FlextLdifModelsDomains.Acl) -> str:
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
            if (base_dn and subject_value.endswith(base_dn))
            else subject_value
        )

        bind_operator = {
            "user": "userdn",
            "group": "groupdn",
            "role": "roledn",
        }.get(
            subject_type,
            "userdn",
        )
        return FlextLdifUtilitiesACL.format_aci_subject(
            subject_type,
            filtered_value,
            bind_operator,
        )

    def _write_acl(self, acl_data: FlextLdifModelsDomains.Acl) -> FlextResult[str]:
        """Write RFC-compliant ACL model to OUD ACI string format (protected internal method)."""
        try:
            sc = FlextLdifServersOudConstants
            extensions: dict[str, t.MetadataAttributeValue] | None = (
                acl_data.metadata.extensions.model_dump()
                if acl_data.metadata and acl_data.metadata.extensions
                else None
            )

            aci_output_lines = FlextLdifUtilitiesACL.format_conversion_comments(
                extensions,
                "converted_from_server",
                "conversion_comments",
            )

            if self._should_use_raw_acl(acl_data):
                aci_output_lines.append(acl_data.raw_acl)
                return FlextResult[str].ok("\n".join(aci_output_lines))

            aci_parts = [self._build_aci_target(acl_data)]

            aci_parts.extend(
                FlextLdifUtilitiesACL.extract_target_extensions(
                    extensions,
                    sc.ACL_TARGET_EXTENSIONS_CONFIG,
                ),
            )

            acl_name = acl_data.name or sc.ACL_DEFAULT_NAME
            aci_parts.append(f'({sc.ACL_DEFAULT_VERSION}; acl "{acl_name}";')

            perms_result = self._build_aci_permissions(acl_data)
            if perms_result.is_failure:
                return FlextResult[str].fail(perms_result.error or "Unknown error")

            subject_str = self._build_aci_subject(acl_data)
            if not subject_str:
                return FlextResult[str].fail("ACL subject DN was filtered out")

            bind_rules = FlextLdifUtilitiesACL.extract_bind_rules_from_extensions(
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

            return FlextResult[str].ok("\n".join(aci_output_lines))

        except Exception as e:
            logger.exception(
                "Failed to write ACL to OUD ACI format",
            )
            return FlextResult[str].fail(
                f"Failed to write ACL to OUD ACI format: {e}",
            )

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

    def _finalize_aci(
        self,
        current_aci: list[str],
        acls: list[m.Ldif.Acl],
    ) -> None:
        """Parse and add accumulated ACI to ACL list."""
        if current_aci:
            aci_text = "\n".join(current_aci)
            result = self.parse(aci_text)
            if result.is_success:
                acls.append(result.value)
