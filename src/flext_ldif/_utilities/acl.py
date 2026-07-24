"""Extracted nested class from FlextLdifUtilities."""

from __future__ import annotations

from types import MappingProxyType
from typing import ClassVar, TypeIs

from flext_cli import u
from flext_ldif import c, m, p, r, t
from flext_ldif._utilities.metadata import FlextLdifUtilitiesMetadata as um


class FlextLdifUtilitiesACL:
    """Generic ACL parsing and writing utilities."""

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)
    _OPERATOR_PLACEHOLDER: str = "{operator}"
    _ACL_SUBJECT_TYPE_VALUES: frozenset[str] = frozenset(
        subject_type.value for subject_type in c.Ldif.AclSubjectType
    )

    @staticmethod
    def _is_acl_subject_type(value: str) -> TypeIs[c.Ldif.AclSubjectType]:
        """Type guard to check if a string is a valid ACL subject enum value."""
        return value in FlextLdifUtilitiesACL._ACL_SUBJECT_TYPE_VALUES

    _RFC_ACL_ATTRIBUTES: t.StrSequence = (
        "aci",
        "acl",
        "olcAccess",
        "aclRights",
        "aclEntry",
    )
    _GENERIC_ACL_ATTRIBUTES: t.StrSequence = ("aci", "acl")
    _OID_ACL_ATTRIBUTES: t.StrSequence = (*c.Ldif.ACL_ATTR_NAMES, "acl")
    _OUD_ACL_ATTRIBUTES: t.StrSequence = tuple(c.Ldif.ACL_ATTR_NAMES)
    _AD_ACL_ATTRIBUTES: t.StrSequence = ("nTSecurityDescriptor", "aci")
    _ACL_ATTRIBUTES_BY_SERVER_TYPE: t.MappingKV[c.Ldif.ServerTypes, t.StrSequence] = (
        MappingProxyType({
            c.Ldif.ServerTypes.RFC: _RFC_ACL_ATTRIBUTES,
            c.Ldif.ServerTypes.OID: _OID_ACL_ATTRIBUTES,
            c.Ldif.ServerTypes.OUD: _OUD_ACL_ATTRIBUTES,
            c.Ldif.ServerTypes.AD: _AD_ACL_ATTRIBUTES,
        })
    )

    @staticmethod
    def _build_extensions(
        aci_content: str,
        version: str,
        acl_line: str,
        extra_patterns: t.MappingKV[str, str],
    ) -> t.Ldif.MutableMetadataInputMapping:
        """Build metadata extensions dict."""
        extensions: t.Ldif.MutableMetadataInputMapping = {
            "version": version,
            "original_format": acl_line,
        }

        def extract_extra(_pattern_name: str, pattern: str) -> str | None:
            """Extract extra field from pattern."""
            return FlextLdifUtilitiesACL.extract_component(
                aci_content, pattern, group=1
            )

        extra_dict: t.MutableOptionalStrMapping = {}
        for k, v in extra_patterns.items():
            if bool(v):
                result = extract_extra(k, v)
                if result is not None:
                    extra_dict[k] = result
        if extra_dict:
            filtered_extensions: t.MutableStrMapping = {
                k: v for k, v in extra_dict.items() if isinstance(v, str)
            }
            if filtered_extensions:
                extensions = dict(extensions, **filtered_extensions)
        return extensions

    @staticmethod
    def _build_subject_and_permissions(
        aci_content: str, settings: p.Ldif.AciParserConfig
    ) -> tuple[str, str, t.MutableBoolMapping]:
        """Build subject and permissions from ACI content."""
        permissions_list = FlextLdifUtilitiesACL.extract_permissions(
            aci_content,
            settings.allow_deny_pattern,
            settings.ops_separator,
            settings.action_filter,
        )
        bind_rules_data = FlextLdifUtilitiesACL.extract_bind_rules(
            aci_content, settings.bind_patterns
        )
        subject_type_map = {"userdn": "user", "groupdn": "group", "roledn": "role"}
        subject_type, subject_value = FlextLdifUtilitiesACL.build_aci_subject(
            bind_rules_data, subject_type_map, settings.special_subjects
        )
        permissions_dict_raw = FlextLdifUtilitiesACL.build_permissions_dict(
            permissions_list, settings.permission_map
        )
        permissions_dict: t.MutableBoolMapping = dict(
            dict(permissions_dict_raw).items()
        )
        return (subject_type, subject_value, permissions_dict)

    @staticmethod
    def _check_special_value(
        rule_value: str, special_values: t.MappingKV[str, t.StrPair]
    ) -> t.StrPair | None:
        """Check if rule value matches any special value."""
        for key, value_tuple in dict(special_values).items():
            if (
                rule_value.lower() == key.lower()
                and len(value_tuple) == c.Ldif.TUPLE_LENGTH_PAIR
            ):
                return value_tuple
        return None

    @staticmethod
    def _extract_from_match(match: t.Ldif.RegexMatch, group: int) -> p.Result[str]:
        """Extract group from regex match, propagating the group-index failure."""
        if match.lastindex is None:
            full_match: str = match.group(0)
            return r[str].ok(full_match)
        if group > match.lastindex:
            return r[str].fail(f"Regex group {group} exceeds last index")
        try:
            extracted: str = match.group(group)
        except IndexError as exc:
            return r[str].fail(str(exc), exception=exc)
        return r[str].ok(extracted)

    @staticmethod
    def _extract_target_info(
        aci_content: str, settings: p.Ldif.AciParserConfig
    ) -> tuple[t.MutableSequenceOf[str], str]:
        """Extract target attributes and DN from ACI content."""
        targetattr_extracted = FlextLdifUtilitiesACL.extract_component(
            aci_content, settings.targetattr_pattern, group=2
        )
        targetattr: str = targetattr_extracted or settings.default_targetattr
        target_attributes, target_dn = FlextLdifUtilitiesACL.parse_targetattr(
            targetattr
        )
        return (target_attributes, target_dn)

    @staticmethod
    def _extract_version_and_name(
        aci_content: str, version_pattern: str, default_name: str
    ) -> t.StrPair:
        """Extract version and ACL name from content."""
        version_match = c.Ldif.compile_pattern(version_pattern).search(aci_content)
        version: str = (
            version_match.group(1)
            if version_match
            and version_match.lastindex
            and (version_match.lastindex >= 1)
            else None
        ) or "3.0"
        acl_name: str = (
            version_match.group(c.Ldif.TUPLE_LENGTH_PAIR)
            if version_match
            and version_match.lastindex
            and (version_match.lastindex >= c.Ldif.TUPLE_LENGTH_PAIR)
            else None
        ) or default_name
        return (version, acl_name)

    @staticmethod
    def _normalize_permission(
        perm: str, permission_map: t.MappingKV[str, str] | None
    ) -> str:
        """Normalize permission name using map if available."""
        if not permission_map:
            return perm
        normalized_permission: str = permission_map.get(perm, perm)
        return normalized_permission

    @staticmethod
    def _process_permission_list(
        perm_list: t.SequenceOf[str],
        permission_map: t.MappingKV[str, str] | None,
        *,
        is_allow: bool,
    ) -> t.MutableBoolMapping:
        """Process permission list into dictionary."""
        result: t.MutableBoolMapping = {}
        for perm in perm_list:
            if perm:
                normalized = FlextLdifUtilitiesACL._normalize_permission(
                    perm, permission_map
                )
                result[normalized] = is_allow
        return result

    @staticmethod
    def build_aci_subject(
        bind_rules_data: t.SequenceOf[t.MutableStrMapping],
        subject_type_map: t.MappingKV[str, str],
        special_values: t.MappingKV[str, t.StrPair],
    ) -> t.StrPair:
        """Build ACL subject from bind rules using configurable maps."""
        if not bind_rules_data:
            return ("self", "ldap:///self")
        for rule in bind_rules_data:
            rule_type_raw = rule.get("type", "")
            rule_type = rule_type_raw.lower()
            rule_value_raw = rule.get("value", "")
            rule_value = rule_value_raw
            special_match = FlextLdifUtilitiesACL._check_special_value(
                rule_value, special_values
            )
            if special_match:
                return special_match
            mapped_type_raw = subject_type_map.get(rule_type)
            mapped_type: str | None = (
                mapped_type_raw if isinstance(mapped_type_raw, str) else None
            )
            if mapped_type:
                return (mapped_type, rule_value)
        if bind_rules_data:
            default_value_raw = bind_rules_data[0].get("value", "")
            default_value = default_value_raw
        else:
            default_value = ""
        return ("user", default_value)

    @staticmethod
    def build_aci_target_clause(
        target_attributes: t.MutableSequenceOf[str] | None,
        target_dn: str | None = None,
        separator: str = " || ",
    ) -> str:
        """Build ACI targetattr clause."""
        if target_attributes:
            return f'(targetattr="{separator.join(target_attributes)}")'
        if target_dn and target_dn != "*":
            return f'(targetattr="{target_dn}")'
        return '(targetattr="*")'

    @staticmethod
    def build_metadata_extensions(
        settings: p.Ldif.AclMetadataConfig,
    ) -> t.Ldif.MutableMetadataMapping:
        """Build ServerMetadata extensions for ACL."""
        result: t.Ldif.MutableMetadataMapping = {}
        if settings.line_breaks is not None:
            result["line_breaks"] = settings.line_breaks
        if settings.dn_spaces is not None:
            result["dn_spaces"] = settings.dn_spaces
        if settings.targetscope is not None:
            result["targetscope"] = settings.targetscope
        if settings.version is not None:
            result["version"] = settings.version
        if settings.action_type is not None:
            result["action_type"] = settings.action_type
        return result

    @staticmethod
    def build_permissions_dict(
        allow_permissions: t.SequenceOf[str],
        permission_map: t.MappingKV[str, str] | None = None,
        deny_permissions: t.SequenceOf[str] | None = None,
    ) -> t.MutableBoolMapping:
        """Build permissions dictionary from allow/deny lists."""
        allow_dict: t.MutableBoolMapping = {}
        if allow_permissions:
            allow_dict = FlextLdifUtilitiesACL._process_permission_list(
                allow_permissions, permission_map, is_allow=True
            )
        deny_dict: t.MutableBoolMapping = {}
        if deny_permissions:
            deny_dict = FlextLdifUtilitiesACL._process_permission_list(
                deny_permissions, permission_map, is_allow=False
            )
        return {**allow_dict, **deny_dict}

    @staticmethod
    def extract_bind_rules(
        content: str, bind_patterns: t.MappingKV[str, str] | None = None
    ) -> t.MutableSequenceOf[t.MutableStrMapping]:
        """Extract bind rules from ACL content.

        Finds userdn, groupdn, or other bind rule specifications.

        Args:
            content: ACL content string
            bind_patterns: Optional dict mapping bind type names to regex patterns.
                          Each pattern MUST have a capturing group for the value.
                          If None, uses default RFC patterns.

        Returns:
            List of dicts with 'type' and 'value' keys.

        """
        if not content:
            return []
        default_patterns: t.MutableStrMapping = {
            "userdn": 'userdn\\s*=\\s*"([^"]*)"',
            "groupdn": 'groupdn\\s*=\\s*"([^"]*)"',
            "roledn": 'roledn\\s*=\\s*"([^"]*)"',
        }
        patterns = bind_patterns or default_patterns
        all_bind_rules: t.MutableSequenceOf[t.MutableStrMapping] = []
        for bind_type, pattern in dict(patterns).items():
            matches = c.Ldif.compile_pattern(pattern, ignorecase=True).findall(content)
            all_bind_rules.extend([
                {"type": bind_type, "value": match} for match in matches
            ])
        return all_bind_rules

    @staticmethod
    def extract_bind_rules_from_extensions(
        extensions: t.Ldif.MutableMetadataMapping | None,
        rule_config: t.SequenceOf[tuple[str, str, str | None]],
        *,
        tuple_length: int = 2,
    ) -> t.MutableSequenceOf[str]:
        """Extract and format bind rules from metadata extensions."""
        if not extensions:
            return []

        result: t.MutableSequenceOf[str] = []
        for ext_key, format_template, operator_default in rule_config:
            try:
                value_raw = extensions.get(ext_key)
                if value_raw is None:
                    continue
                formatted_rule = FlextLdifUtilitiesACL._format_bind_rule_from_extension(
                    value_raw, format_template, operator_default, tuple_length
                )
                result.append(formatted_rule)
            except c.Ldif.EXC_LDIF_PARSE as e:
                FlextLdifUtilitiesACL._module_logger.debug(
                    "Skipping ACL rule processing due to error", error=str(e)
                )
                continue
        return result

    @staticmethod
    def _format_bind_rule_from_extension(
        value_raw: t.JsonValue | t.StrPair,
        format_template: str,
        operator_default: str | None,
        tuple_length: int,
    ) -> str:
        """Format one ACL bind rule from metadata extension payload."""
        has_operator_placeholder = (
            FlextLdifUtilitiesACL._OPERATOR_PLACEHOLDER in format_template
        )
        match value_raw:
            case tuple() as tuple_items if (
                len(tuple_items) == tuple_length
                and len(tuple_items) >= c.Ldif.TUPLE_LENGTH_PAIR
            ):
                operator_val = tuple_items[0]
                value_val = tuple_items[1]
                if has_operator_placeholder:
                    return format_template.format(
                        operator=operator_val, value=value_val
                    )
                return format_template.format(value=value_val)
            case _ if has_operator_placeholder and operator_default is not None:
                return format_template.format(
                    operator=operator_default, value=str(value_raw)
                )
            case _:
                return format_template.format(value=str(value_raw))

    @staticmethod
    def extract_component(content: str, pattern: str, group: int = 1) -> str | None:
        r"""Extract single ACL component using regex pattern.

        Args:
            content: ACL content string to parse
            pattern: Regex pattern to match
            group: Regex group number to extract (default: 1)

        Returns:
            Extracted component value or None if not found

        Example:
            >>> pattern = r"targetattr\\\\s*=\\\\s*\\"([^\\"]+)\\""
            >>> extract_component(aci_content, pattern, group=1)
            "cn,mail,telephoneNumber"

        """
        if not content or not pattern:
            return None
        match = c.Ldif.compile_pattern(pattern).search(content)
        if not match:
            return None
        extraction = FlextLdifUtilitiesACL._extract_from_match(match, group)
        if extraction.success:
            extracted_value: str = extraction.value
            return extracted_value
        return None

    @staticmethod
    def extract_permissions(
        content: str,
        allow_deny_pattern: str,
        ops_separator: str = ",",
        action_filter: str | None = None,
    ) -> t.MutableSequenceOf[str]:
        """Extract permissions from ACL content using configurable patterns.

        Args:
            content: ACL content string
            allow_deny_pattern: Regex pattern to match allow/deny rules
            ops_separator: Separator for operations list (default: ",")
            action_filter: Only include permissions for this action (e.g., "allow")

        Returns:
            List of permission strings

        """
        if not content or not allow_deny_pattern:
            return []
        permissions: t.MutableSequenceOf[str] = []
        matches = c.Ldif.compile_pattern(allow_deny_pattern, ignorecase=True).finditer(
            content
        )
        min_groups_for_action = 1
        min_groups_for_ops = 2
        for match in matches:
            action = (
                match.group(1)
                if match.lastindex and match.lastindex >= min_groups_for_action
                else ""
            )
            ops = (
                match.group(2)
                if match.lastindex and match.lastindex >= min_groups_for_ops
                else ""
            )
            if action_filter and action.lower() != action_filter.lower():
                continue
            if ops:
                split_ops = ops.split(ops_separator)
                permissions.extend(s for op in split_ops if (s := op.strip()))
        return permissions

    @staticmethod
    def extract_target_extensions(
        extensions: t.Ldif.MetadataInputMapping | None, target_config: t.StrPairSequence
    ) -> t.MutableSequenceOf[str]:
        """Extract and format target extensions from metadata extensions."""
        if not extensions:
            return []

        result: t.MutableSequenceOf[str] = []
        for ext_key, format_template in target_config:
            try:
                value_raw = extensions.get(ext_key)
                if not value_raw:
                    continue
                result.append(format_template.format(value=str(value_raw)))
            except c.Ldif.EXC_LDIF_PARSE as e:
                FlextLdifUtilitiesACL._module_logger.debug(
                    "Skipping ACL rule processing due to error", error=str(e)
                )
        return result

    @staticmethod
    def filter_supported_permissions(
        permissions: t.MutableSequenceOf[str], supported: set[str] | frozenset[str]
    ) -> t.MutableSequenceOf[str]:
        """Filter permissions to only include supported ones."""
        supported_lower = {s.lower() for s in supported}
        return [p.lower() for p in permissions if p.lower() in supported_lower]

    @staticmethod
    def format_aci_line(settings: p.Ldif.AciLineFormatConfig) -> str:
        r"""Format complete ACI line from components.

        Args:
            settings: AciLineFormatConfig with all formatting parameters

        Returns:
            Formatted ACI line string

        Example:
            settings = m.Ldif.AciLineFormatConfig(
                name="test-acl",
                target_clause="(targetattr=\\"cn\\")",
                permissions_clause="allow (read,write)",
                bind_rule="userdn=\\"ldap:///self\\"",
            )
            aci_line = FlextLdifUtilitiesACL.format_aci_line(settings)

        """
        sanitized_name, _ = FlextLdifUtilitiesACL.sanitize_acl_name(settings.name)
        return f'{settings.aci_prefix}{settings.target_clause}(version {settings.version}; acl "{sanitized_name}"; {settings.permissions_clause} {settings.bind_rule};)'

    @staticmethod
    def format_aci_subject(
        _subject_type: str, subject_value: str, bind_operator: str = "userdn"
    ) -> str:
        """Format ACL subject into ACI bind rule format."""
        cleaned_value = subject_value.replace(", ", ",")
        default_value = f'by dn="{cleaned_value}"'
        bind_rules: t.MutableStrMapping = {
            "userdn": f'userdn="ldap:///{cleaned_value}"',
            "groupdn": f'groupdn="ldap:///{cleaned_value}"',
            "roledn": f'roledn="ldap:///{cleaned_value}"',
        }
        result: str = bind_rules.get(bind_operator, default_value)
        return result

    @staticmethod
    def format_conversion_comments(
        extensions: t.Ldif.MetadataInputMapping | None,
        converted_from_key: str,
        comments_key: str,
    ) -> t.MutableSequenceOf[str]:
        """Extract conversion comments from metadata extensions."""
        if not extensions:
            return []
        converted_from_value = (
            extensions.get(converted_from_key) if extensions else None
        )
        if not converted_from_value:
            return []
        comments_value: t.Ldif.MetadataCarrierValue | None = (
            extensions.get(comments_key) if extensions else None
        )
        if comments_value is None:
            return []
        normalized: t.MutableSequenceOf[str]
        if isinstance(comments_value, str):
            normalized = [comments_value]
        elif isinstance(comments_value, list):
            normalized = [str(item) for item in comments_value]
        else:
            normalized = [str(comments_value)]
        return [*normalized, ""]

    @staticmethod
    def get_acl_attributes(
        server_type: c.Ldif.ServerTypes | str | None = None,
    ) -> t.MutableSequenceOf[str]:
        """Get ACL attributes for a server type."""
        if server_type is None:
            normalized_server_type: c.Ldif.ServerTypes | None = c.Ldif.ServerTypes.RFC
        elif isinstance(server_type, c.Ldif.ServerTypes):
            normalized_server_type = server_type
        else:
            key = server_type.lower().strip()
            normalized_server_type = next(
                (st for st in c.Ldif.ServerTypes if st.value == key),
                c.Ldif.SERVER_TYPE_ALIASES.get(key),
            )
        attributes = (
            FlextLdifUtilitiesACL._GENERIC_ACL_ATTRIBUTES
            if normalized_server_type is None
            else FlextLdifUtilitiesACL._ACL_ATTRIBUTES_BY_SERVER_TYPE.get(
                normalized_server_type, FlextLdifUtilitiesACL._GENERIC_ACL_ATTRIBUTES
            )
        )
        return list(attributes)

    @staticmethod
    def is_acl_attribute(attribute_name: str, server_type: str | None = None) -> bool:
        """Check if attribute is an ACL attribute (case-insensitive)."""
        all_attrs = FlextLdifUtilitiesACL.get_acl_attributes(server_type)
        all_attrs_lower = {a.lower() for a in all_attrs}
        return attribute_name.lower() in all_attrs_lower

    @staticmethod
    def normalize_permission_key(key: str) -> str:
        """Normalize permission key for cross-server ACL mapping."""
        return {"self_write": "selfwrite"}.get(key, key)

    @staticmethod
    def map_oid_to_oud_permissions(
        orig_perms_dict: t.MutableBoolMapping,
    ) -> t.MutableBoolMapping:
        """Map OID permission names to OUD permission names."""
        normalized_orig_perms: t.MutableBoolMapping = {
            FlextLdifUtilitiesACL.normalize_permission_key(key): value
            for key, value in orig_perms_dict.items()
        }
        mapping_values = {
            FlextLdifUtilitiesACL.normalize_permission_key(key)
            for key in c.Ldif.ACL_PERMISSION_KEYS
        }
        pass_through_perms = {
            key for key in mapping_values if key not in {"browse", "selfwrite"}
        }
        mapped_perms: t.MutableBoolMapping = {}
        for perm_name, perm_value in normalized_orig_perms.items():
            if perm_name == "browse":
                mapped_perms["read"] = mapped_perms.get("read", False) or perm_value
                mapped_perms["search"] = mapped_perms.get("search", False) or perm_value
                continue
            if perm_name == "selfwrite":
                mapped_perms["write"] = mapped_perms.get("write", False) or perm_value
                continue
            if perm_name in pass_through_perms:
                mapped_perms[perm_name] = (
                    mapped_perms.get(perm_name, False) or perm_value
                )
        return mapped_perms

    @staticmethod
    def map_oud_to_oid_permissions(
        orig_perms_dict: t.MutableBoolMapping,
    ) -> t.MutableBoolMapping:
        """Map OUD permission names to OID permission names."""
        normalized_orig_perms: t.MutableBoolMapping = {
            FlextLdifUtilitiesACL.normalize_permission_key(key): value
            for key, value in orig_perms_dict.items()
        }
        mapping_values = {
            FlextLdifUtilitiesACL.normalize_permission_key(key)
            for key in c.Ldif.ACL_PERMISSION_KEYS
        }
        pass_through_perms = {
            key for key in mapping_values if key not in {"read", "search", "browse"}
        }
        has_read = normalized_orig_perms.get("read", False)
        has_search = normalized_orig_perms.get("search", False)
        mapped_perms: t.MutableBoolMapping = {}
        if has_read or has_search:
            mapped_perms["browse"] = has_read and has_search
        for perm_name, perm_value in normalized_orig_perms.items():
            if perm_name in pass_through_perms:
                mapped_perms[perm_name] = perm_value
        return mapped_perms

    @staticmethod
    def build_mapped_permissions_dict(
        mapped_perms: t.MutableBoolMapping, mapping: t.MutableStrMapping
    ) -> t.MutableOptionalBoolMapping:
        """Build permissions dict from a source->mapped key table."""
        result: t.MutableOptionalBoolMapping = {}
        for source_key, mapped_key in mapping.items():
            result[source_key] = mapped_perms.get(mapped_key)
        return result

    @staticmethod
    def parse_aci(
        acl_line: str, settings: p.Ldif.AciParserConfig
    ) -> p.Result[p.Ldif.Acl]:
        """Parse ACI line using server-specific settings Model."""
        valid, aci_content = FlextLdifUtilitiesACL.validate_aci_format(
            acl_line, settings.aci_prefix
        )
        if not valid:
            return r[p.Ldif.Acl].fail(f"Not a valid ACI format: {settings.aci_prefix}")
        version, acl_name = FlextLdifUtilitiesACL._extract_version_and_name(
            aci_content, settings.version_acl_pattern, settings.default_name
        )
        target_attributes, target_dn = FlextLdifUtilitiesACL._extract_target_info(
            aci_content, settings
        )
        subject_type, subject_value, permissions_dict = (
            FlextLdifUtilitiesACL._build_subject_and_permissions(aci_content, settings)
        )
        extensions = FlextLdifUtilitiesACL._build_extensions(
            aci_content, version, acl_line, settings.extra_patterns
        )
        acl_model = m.Ldif.Acl(
            name=acl_name,
            target=m.Ldif.AclTarget.model_validate({
                "target_dn": target_dn,
                "attributes": target_attributes,
            }),
            subject=m.Ldif.AclSubject(
                subject_type=subject_type
                if FlextLdifUtilitiesACL._is_acl_subject_type(subject_type)
                else c.Ldif.AclSubjectType.USER,
                subject_value=subject_value,
            ),
            permissions=m.Ldif.AclPermissions(**permissions_dict),
            server_type=settings.server_type,
            raw_acl=acl_line,
            metadata=um.server_metadata_for(
                settings.server_type, extensions=extensions or None
            ),
        )
        return r[p.Ldif.Acl].ok(acl_model)

    @staticmethod
    def parse_targetattr(
        targetattr_str: str | None, separator: str = "||"
    ) -> tuple[t.MutableSequenceOf[str], str]:
        """Parse targetattr string to attributes list and target DN."""
        if not targetattr_str:
            return ([], "*")
        if separator in targetattr_str:
            attrs = [a.strip() for a in targetattr_str.split(separator) if a.strip()]
            return (attrs, "*")
        if targetattr_str != "*":
            return ([targetattr_str.strip()], "*")
        return ([], "*")

    @staticmethod
    def sanitize_acl_name(raw_name: str, max_length: int = 128) -> tuple[str, bool]:
        """Sanitize ACL name for ACI format."""
        if not raw_name or not raw_name.strip():
            return ("", False)

        def sanitize_char(char: str) -> str:
            """Sanitize single character."""
            char_ord = ord(char)
            rfc_format = c.Ldif
            ascii_min = rfc_format.ASCII_PRINTABLE_MIN
            ascii_max = rfc_format.ASCII_PRINTABLE_MAX
            if char_ord < ascii_min or char_ord > ascii_max or char == '"':
                return " "
            return char

        sanitized_chars: t.MutableSequenceOf[str] = [sanitize_char(c) for c in raw_name]
        sanitized_chars_list: t.MutableSequenceOf[str] = sanitized_chars
        was_sanitized = sanitized_chars_list != list(raw_name)
        result_chars: t.MutableSequenceOf[str] = []
        prev_char = ""
        for char in sanitized_chars_list:
            if not (char == " " and prev_char == " "):
                result_chars.append(char)
            else:
                was_sanitized = True
            prev_char = char
        sanitized = " ".join("".join(result_chars).split())
        if len(sanitized) > max_length:
            sanitized = sanitized[: max_length - 3] + "..."
            was_sanitized = True
        return (sanitized, was_sanitized)

    @staticmethod
    def split_acl_line(acl_line: str) -> t.StrPair:
        r"""Split an ACL line into attribute name and payload.

        Generic utility for splitting ACL lines at the colon separator,
        used by multiple server implementations (RFC, OUD, OID, etc.).

        Args:
            acl_line: The raw ACL line string.

        Returns:
            Tuple of (attribute_name, payload).

        Example:
            >>> split_acl_line('aci: (version 3.0; acl "test"; ...)')
            ("aci", "(version 3.0; acl \\"test\\"; ...)")

        """
        attr_name, _, remainder = acl_line.partition(":")
        return (attr_name.strip(), remainder.strip())

    @staticmethod
    def validate_aci_format(
        acl_line: str, aci_prefix: str = "aci:"
    ) -> tuple[bool, str]:
        """Validate and extract ACI content from line."""
        if not acl_line or not acl_line.strip():
            return (False, "")
        first_line = acl_line.split("\n", maxsplit=1)[0].strip()
        if not first_line.startswith(aci_prefix):
            return (False, "")
        if "\n" in acl_line:
            lines = acl_line.split("\n")
            aci_content: str = (
                lines[0].split(":", 1)[1].strip() + "\n" + "\n".join(lines[1:])
            )
        else:
            aci_content = acl_line.split(":", 1)[1].strip()
        return (True, aci_content)


__all__: list[str] = ["FlextLdifUtilitiesACL"]
