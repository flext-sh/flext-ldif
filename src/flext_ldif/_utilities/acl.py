"""Extracted nested class from FlextLdifUtilities."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence

from flext_core import FlextLogger, r, u
from flext_core.runtime import FlextRuntime

from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif._models.settings import FlextLdifModelsSettings
from flext_ldif._utilities.functional import FlextFunctional
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.typings import t

f = FlextFunctional  # Pure functional utilities (no circular import)

logger = FlextLogger(__name__)

TUPLE_LENGTH_PAIR = 2


class FlextLdifUtilitiesACL:
    """Generic ACL parsing and writing utilities."""

    @staticmethod
    def get_acl_attributes(server_type: str | None) -> list[str]:
        """Get ACL attributes for a server type."""
        attrs = list(c.Ldif.AclAttributeRegistry.RFC_FOUNDATION)

        if server_type:
            server_key = server_type.lower()
            server_quirks = c.Ldif.AclAttributeRegistry.SERVER_QUIRKS.get(
                server_key,
                [],
            )
            attrs.extend(server_quirks)

        return attrs

    @staticmethod
    def is_acl_attribute(
        attribute_name: str,
        server_type: str | None = None,
    ) -> bool:
        """Check if attribute is an ACL attribute (case-insensitive)."""
        all_attrs = FlextLdifUtilitiesACL.get_acl_attributes(server_type)
        all_attrs_lower = {a.lower() for a in all_attrs}
        return attribute_name.lower() in all_attrs_lower

    @staticmethod
    def split_acl_line(acl_line: str) -> tuple[str, str]:
        r"""Split an ACL line into attribute name and payload.

        Generic utility for splitting ACL lines at the colon separator,
        used by multiple server implementations (RFC, OUD, OID, etc.).

        Args:
            acl_line: The raw ACL line string.

        Returns:
            Tuple of (attribute_name, payload).

        Example:
            >>> split_acl_line('aci: (version 3.0; acl "test"; ...)')
            ("aci", "(version 3.0; acl \"test\"; ...)")

        """
        attr_name, _, remainder = acl_line.partition(":")
        return attr_name.strip(), remainder.strip()

    @staticmethod
    def _extract_from_match(match: re.Match[str], group: int) -> str | None:
        """Extract group from regex match."""
        if match.lastindex is None:
            return match.group(0)
        if group > match.lastindex:
            return None
        try:
            return match.group(group)
        except IndexError:
            return None

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
            >>> pattern = r"targetattr\\s*=\\s*\"([^\"]+)\""
            >>> extract_component(aci_content, pattern, group=1)
            "cn,mail,telephoneNumber"

        """
        if not content or not pattern:
            return None
        match = re.search(pattern, content)
        return (
            FlextLdifUtilitiesACL._extract_from_match(match, group) if match else None
        )

    @staticmethod
    def extract_permissions(
        content: str,
        allow_deny_pattern: str,
        ops_separator: str = ",",
        action_filter: str | None = None,
    ) -> list[str]:
        r"""Extract permissions from ACL content using configurable patterns.

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

        permissions: list[str] = []
        matches = re.finditer(allow_deny_pattern, content, re.IGNORECASE)

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
                filtered_perms_list = f.map_filter(
                    split_ops,
                    mapper=str.strip,
                    predicate=bool,
                )
                permissions.extend(filtered_perms_list)

        return permissions

    @staticmethod
    def extract_bind_rules(
        content: str,
        bind_patterns: dict[str, str] | None = None,
    ) -> list[dict[str, str]]:
        r"""Extract bind rules from ACL content.

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

        default_patterns: dict[str, str] = {
            "userdn": r'userdn\s*=\s*"([^"]*)"',
            "groupdn": r'groupdn\s*=\s*"([^"]*)"',
            "roledn": r'roledn\s*=\s*"([^"]*)"',
        }

        patterns = bind_patterns or default_patterns

        all_bind_rules: list[dict[str, str]] = []
        for bind_type, pattern in u.mapper().to_dict(patterns).items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            all_bind_rules.extend([
                {"type": bind_type, "value": match} for match in matches
            ])
        return all_bind_rules

    @staticmethod
    def _normalize_permission(
        perm: str,
        permission_map: dict[str, str] | None,
    ) -> str:
        """Normalize permission name using map if available."""
        if not permission_map:
            return perm
        return u.mapper().get(permission_map, perm, default=perm)

    @staticmethod
    def _process_permission_list(
        perm_list: list[str],
        permission_map: dict[str, str] | None,
        *,
        is_allow: bool,
    ) -> dict[str, bool]:
        """Process permission list into dictionary."""
        result: dict[str, bool] = {}
        for perm in perm_list:
            if perm:
                normalized = FlextLdifUtilitiesACL._normalize_permission(
                    perm,
                    permission_map,
                )
                result[normalized] = is_allow
        return result

    @staticmethod
    def build_permissions_dict(
        allow_permissions: list[str],
        permission_map: dict[str, str] | None = None,
        deny_permissions: list[str] | None = None,
    ) -> dict[str, bool]:
        """Build permissions dictionary from allow/deny lists."""
        allow_dict: dict[str, bool] = (
            f.when(
                condition=bool(allow_permissions),
                then=lambda: FlextLdifUtilitiesACL._process_permission_list(
                    allow_permissions,
                    permission_map,
                    is_allow=True,
                ),
                else_={},
            )
            or {}
        )
        deny_dict: dict[str, bool] = (
            f.when(
                condition=bool(deny_permissions),
                then=lambda: FlextLdifUtilitiesACL._process_permission_list(
                    deny_permissions or [],
                    permission_map,
                    is_allow=False,
                ),
                else_={},
            )
            or {}
        )
        return f.merge(allow_dict, deny_dict)

    @staticmethod
    def format_aci_subject(
        _subject_type: str,
        subject_value: str,
        bind_operator: str = "userdn",
    ) -> str:
        """Format ACL subject into ACI bind rule format."""
        cleaned_value = subject_value.replace(", ", ",")
        default_value = f'by dn="{cleaned_value}"'
        result: str = (
            f.switch(
                bind_operator,
                {
                    "userdn": f'userdn="ldap:///{cleaned_value}"',
                    "groupdn": f'groupdn="ldap:///{cleaned_value}"',
                    "roledn": f'roledn="ldap:///{cleaned_value}"',
                },
                default=default_value,
            )
            or default_value
        )
        return result

    @staticmethod
    def build_metadata_extensions(
        config: FlextLdifModelsSettings.AclMetadataConfig,
    ) -> dict[str, t.MetadataAttributeValue]:
        """Build QuirkMetadata extensions for ACL."""
        result: dict[str, t.MetadataAttributeValue] = {}

        extension_items: list[tuple[str, object]] = [
            ("line_breaks", config.line_breaks),
            ("dn_spaces", config.dn_spaces),
            ("targetscope", config.targetscope),
            ("version", config.version),
            ("action_type", config.action_type),
        ]

        result.update({
            key: value
            for key, value in extension_items
            if value is not None
            and isinstance(value, (str, int, float, bool, list, dict, type(None)))
        })

        return result

    @staticmethod
    def sanitize_acl_name(raw_name: str, max_length: int = 128) -> tuple[str, bool]:
        """Sanitize ACL name for ACI format."""
        if not raw_name or not raw_name.strip():
            return "", False

        def sanitize_char(char: str) -> str:
            """Sanitize single character."""
            char_ord = ord(char)
            rfc_format = c.Ldif.Format
            ascii_min = rfc_format.ASCII_PRINTABLE_MIN
            ascii_max = rfc_format.ASCII_PRINTABLE_MAX
            if char_ord < ascii_min or char_ord > ascii_max or char == '"':
                return " "
            return char

        sanitized_chars: list[str] = [sanitize_char(c) for c in raw_name]

        sanitized_chars_list: list[str] = sanitized_chars
        was_sanitized = sanitized_chars_list != list(raw_name)

        result_chars: list[str] = []
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

        return sanitized, was_sanitized

    @staticmethod
    def validate_aci_format(
        acl_line: str,
        aci_prefix: str = "aci:",
    ) -> tuple[bool, str]:
        """Validate and extract ACI content from line."""
        if not acl_line or not acl_line.strip():
            return False, ""
        first_line = acl_line.split("\n", maxsplit=1)[0].strip()
        if not first_line.startswith(aci_prefix):
            return False, ""
        if "\n" in acl_line:
            lines = acl_line.split("\n")
            aci_content: str = (
                lines[0].split(":", 1)[1].strip() + "\n" + "\n".join(lines[1:])
            )
        else:
            aci_content = acl_line.split(":", 1)[1].strip()
        return True, aci_content

    @staticmethod
    def parse_targetattr(
        targetattr_str: str | None,
        separator: str = "||",
    ) -> tuple[list[str], str]:
        """Parse targetattr string to attributes list and target DN."""
        if not targetattr_str:
            return [], "*"

        if separator in targetattr_str:
            attrs = [a.strip() for a in targetattr_str.split(separator) if a.strip()]
            return attrs, "*"
        if targetattr_str != "*":
            return [targetattr_str.strip()], "*"
        return [], "*"

    @staticmethod
    def _check_special_value(
        rule_value: str,
        special_values: dict[str, tuple[str, str]],
    ) -> tuple[str, str] | None:
        """Check if rule value matches any special value."""
        for key, value_tuple in u.mapper().to_dict(special_values).items():
            if (
                rule_value.lower() == key.lower()
                and isinstance(value_tuple, tuple)
                and len(value_tuple) == TUPLE_LENGTH_PAIR
                and isinstance(value_tuple[0], str)
                and isinstance(value_tuple[1], str)
            ):
                return value_tuple
        return None

    @staticmethod
    def build_aci_subject(
        bind_rules_data: list[dict[str, str]],
        subject_type_map: dict[str, str],
        special_values: dict[str, tuple[str, str]],
    ) -> tuple[str, str]:
        """Build ACL subject from bind rules using configurable maps."""
        if not bind_rules_data:
            return "self", "ldap:///self"

        for rule in bind_rules_data:
            rule_type_raw = u.mapper().get(rule, "type", default="")
            rule_type = rule_type_raw.lower() if isinstance(rule_type_raw, str) else ""
            rule_value = u.mapper().get(rule, "value", default="")
            rule_value = rule_value if isinstance(rule_value, str) else ""

            special_match = FlextLdifUtilitiesACL._check_special_value(
                rule_value,
                special_values,
            )
            if special_match:
                return special_match

            mapped_type_raw = u.mapper().get(subject_type_map, rule_type)
            mapped_type: str | None = None
            if isinstance(mapped_type_raw, FlextRuntime.RuntimeResult):
                if mapped_type_raw.is_success:
                    value = mapped_type_raw.value
                    mapped_type = value if isinstance(value, str) else None
            else:
                mapped_type = (
                    mapped_type_raw if isinstance(mapped_type_raw, str) else None
                )
            if mapped_type:
                return mapped_type, rule_value

        if bind_rules_data:
            default_value = u.mapper().get(bind_rules_data[0], "value", default="")
            default_value = default_value if isinstance(default_value, str) else ""
        else:
            default_value = ""
        return "user", default_value

    @staticmethod
    def filter_supported_permissions(
        permissions: list[str],
        supported: set[str] | frozenset[str],
    ) -> list[str]:
        """Filter permissions to only include supported ones."""
        supported_lower = {s.lower() for s in supported}
        return [p.lower() for p in permissions if p.lower() in supported_lower]

    @staticmethod
    def build_aci_target_clause(
        target_attributes: list[str] | None,
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
    def build_aci_permissions_clause(
        permissions: list[str],
        allow_prefix: str = "(allow (",
        supported_permissions: set[str] | frozenset[str] | None = None,
    ) -> str | None:
        """Build ACI permissions clause."""
        if supported_permissions:
            filtered: list[str] = FlextLdifUtilitiesACL.filter_supported_permissions(
                permissions,
                supported_permissions,
            )
        else:
            filtered = permissions

        if filtered:
            return f"{allow_prefix}{','.join(filtered)})"
        return None

    @staticmethod
    def build_aci_bind_rule(
        subject_type: str,
        subject_value: str,
        bind_operators: dict[str, str] | None = None,
        self_value: str = "ldap:///self",
        anonymous_value: str = "ldap:///anyone",
    ) -> str:
        """Build ACI bind rule (subject) clause."""
        default_operators = {
            "user": "userdn",
            "group": "groupdn",
            "role": "roledn",
            "self": "userdn",
            "anonymous": "userdn",
        }
        operators = bind_operators or default_operators

        if subject_type == "self":
            op = u.mapper().get(operators, "self", default="userdn")
            op = op if isinstance(op, str) else "userdn"
            return f'{op}="{self_value}"'
        if subject_type == "anonymous":
            op = u.mapper().get(operators, "anonymous", default="userdn")
            op = op if isinstance(op, str) else "userdn"
            return f'{op}="{anonymous_value}"'
        op = u.mapper().get(operators, subject_type, default="userdn")
        op = op if isinstance(op, str) else "userdn"
        value = subject_value.replace(", ", ",")
        if not value.startswith("ldap:///"):
            value = f"ldap:///{value}"
        return f'{op}="{value}"'

    @staticmethod
    def format_aci_line(
        config: FlextLdifModelsSettings.AciLineFormatConfig,
    ) -> str:
        r"""Format complete ACI line from components.

        Args:
            config: AciLineFormatConfig with all formatting parameters

        Returns:
            Formatted ACI line string

        Example:
            config = FlextLdifModelsSettings.AciLineFormatConfig(
                name="test-acl",
                target_clause="(targetattr=\"cn\")",
                permissions_clause="allow (read,write)",
                bind_rule="userdn=\"ldap:///self\"",
            )
            aci_line = FlextLdifUtilitiesACL.format_aci_line(config)

        """
        sanitized_name, _ = FlextLdifUtilitiesACL.sanitize_acl_name(config.name)
        return (
            f"{config.aci_prefix}{config.target_clause}"
            f'(version {config.version}; acl "{sanitized_name}"; '
            f"{config.permissions_clause} {config.bind_rule};)"
        )

    @staticmethod
    def _extract_version_and_name(
        aci_content: str,
        version_pattern: str,
        default_name: str,
    ) -> tuple[str, str]:
        """Extract version and ACL name from content."""
        version_match = re.search(version_pattern, aci_content)
        version: str = (
            version_match.group(1)
            if version_match
            and version_match.lastindex
            and version_match.lastindex >= 1
            else None
        ) or "3.0"
        acl_name: str = (
            version_match.group(TUPLE_LENGTH_PAIR)
            if version_match
            and version_match.lastindex
            and version_match.lastindex >= TUPLE_LENGTH_PAIR
            else None
        ) or default_name
        return version, acl_name

    @staticmethod
    def _extract_target_info(
        aci_content: str,
        config: FlextLdifModelsSettings.AciParserConfig,
    ) -> tuple[list[str], str]:
        """Extract target attributes and DN from ACI content."""
        targetattr_extracted = FlextLdifUtilitiesACL.extract_component(
            aci_content,
            config.targetattr_pattern,
            group=2,
        )
        targetattr: str = targetattr_extracted or config.default_targetattr
        target_attributes, target_dn = FlextLdifUtilitiesACL.parse_targetattr(
            targetattr,
        )
        return target_attributes, target_dn

    @staticmethod
    def _build_subject_and_permissions(
        aci_content: str,
        config: FlextLdifModelsSettings.AciParserConfig,
    ) -> tuple[str, str, dict[str, bool]]:
        """Build subject and permissions from ACI content."""
        permissions_list = FlextLdifUtilitiesACL.extract_permissions(
            aci_content,
            config.allow_deny_pattern,
            config.ops_separator,
            config.action_filter,
        )
        bind_rules_data = FlextLdifUtilitiesACL.extract_bind_rules(
            aci_content,
            config.bind_patterns,
        )

        subject_type_map = {"userdn": "user", "groupdn": "group", "roledn": "role"}
        subject_type, subject_value = FlextLdifUtilitiesACL.build_aci_subject(
            bind_rules_data,
            subject_type_map,
            config.special_subjects,
        )
        permissions_dict_raw = FlextLdifUtilitiesACL.build_permissions_dict(
            permissions_list,
            config.permission_map,
        )
        permissions_dict: dict[str, bool] = {
            k: bool(v) if isinstance(v, (bool, int, str)) else False
            for k, v in u.mapper().to_dict(permissions_dict_raw).items()
        }
        return subject_type, subject_value, permissions_dict

    @staticmethod
    def _build_extensions(
        aci_content: str,
        version: str,
        acl_line: str,
        extra_patterns: dict[str, str],
    ) -> dict[str, t.MetadataAttributeValue]:
        """Build metadata extensions dict."""
        extensions: dict[str, t.MetadataAttributeValue] = {
            "version": version,
            "original_format": acl_line,
        }

        def extract_extra(_pattern_name: str, pattern: str) -> str | None:
            """Extract extra field from pattern."""
            return FlextLdifUtilitiesACL.extract_component(
                aci_content,
                pattern,
                group=1,
            )

        extra_dict: dict[str, str | None] = {}
        for k, v in extra_patterns.items():
            if bool(v):  # Apply predicate
                result = extract_extra(k, v)
                if result is not None:
                    extra_dict[k] = result

        if extra_dict:
            filtered_extensions: dict[str, str] = {
                k: v for k, v in extra_dict.items() if isinstance(v, str)
            }
            if filtered_extensions:
                extensions = dict(extensions, **filtered_extensions)
        return extensions

    @staticmethod
    def parse_aci(
        acl_line: str,
        config: FlextLdifModelsSettings.AciParserConfig,
    ) -> r[m.Ldif.Acl]:
        """Parse ACI line using server-specific config Model."""
        is_valid, aci_content = FlextLdifUtilitiesACL.validate_aci_format(
            acl_line,
            config.aci_prefix,
        )
        if not is_valid:
            return r[m.Ldif.Acl].fail(
                f"Not a valid ACI format: {config.aci_prefix}",
            )

        version, acl_name = FlextLdifUtilitiesACL._extract_version_and_name(
            aci_content,
            config.version_acl_pattern,
            config.default_name,
        )

        target_attributes, target_dn = FlextLdifUtilitiesACL._extract_target_info(
            aci_content,
            config,
        )

        subject_type, subject_value, permissions_dict = (
            FlextLdifUtilitiesACL._build_subject_and_permissions(
                aci_content,
                config,
            )
        )

        extensions = FlextLdifUtilitiesACL._build_extensions(
            aci_content,
            version,
            acl_line,
            config.extra_patterns,
        )

        acl_model = m.Ldif.Acl(
            name=acl_name,
            target=m.Ldif.AclTarget(
                target_dn=target_dn,
                attributes=target_attributes,
            ),
            subject=m.Ldif.AclSubject.model_validate({
                "subject_type": subject_type,
                "subject_value": subject_value,
            }),
            permissions=m.Ldif.AclPermissions(**permissions_dict),
            server_type=config.server_type,
            raw_acl=acl_line,
            metadata=m.Ldif.QuirkMetadata.create_for(
                config.server_type,
                extensions=(
                    FlextLdifModelsMetadata.DynamicMetadata.from_dict(extensions)
                    if extensions
                    else None
                ),
            ),
        )
        return r[str].ok(acl_model)

    @staticmethod
    def extract_bind_rules_from_extensions(
        extensions: dict[str, t.MetadataAttributeValue] | None,
        rule_config: list[tuple[str, str, str | None]],
        *,
        tuple_length: int = 2,
    ) -> list[str]:
        """Extract and format bind rules from metadata extensions."""
        if not extensions:
            return []

        def process_rule_config(rule_item: tuple[str, str, str | None]) -> str | None:
            """Process single rule config item."""
            ext_key, format_template, operator_default = rule_item
            value_raw: t.MetadataAttributeValue | None = (
                extensions.get(ext_key) if extensions else None
            )
            if not value_raw:
                return None

            operator_placeholder = "{" + "operator" + "}"
            expected_tuple_length = tuple_length

            if isinstance(value_raw, tuple) and len(value_raw) == expected_tuple_length:
                tuple_items = list(value_raw) if value_raw else []
                if len(tuple_items) >= TUPLE_LENGTH_PAIR:
                    operator_val = str(tuple_items[0])
                    value_val = str(tuple_items[1])
                    if operator_placeholder in format_template:
                        return format_template.format(
                            operator=operator_val,
                            value=value_val,
                        )
                    return format_template.format(value=value_val)

            if operator_placeholder in format_template and operator_default is not None:
                return format_template.format(
                    operator=operator_default,
                    value=str(value_raw),
                )

            return format_template.format(value=str(value_raw))

        def rule_predicate(item: tuple[str, str, str | None]) -> bool:
            """Filter rule config items based on extensions."""
            return bool(extensions.get(item[0]) if extensions else None)

        result: list[str] = []
        for item in rule_config:
            try:
                if rule_predicate(item):  # Apply predicate
                    processed = process_rule_config(item)
                    if processed is not None:
                        result.append(processed)
            except Exception as e:
                logger.debug("Skipping ACL rule processing due to error", error=str(e))
                continue
        return result

    @staticmethod
    def extract_target_extensions(
        extensions: FlextLdifModelsMetadata.DynamicMetadata
        | dict[str, t.MetadataAttributeValue]
        | None,
        target_config: list[tuple[str, str]],
    ) -> list[str]:
        """Extract and format target extensions from metadata extensions."""
        if not extensions:
            return []

        def process_target_config(target_item: tuple[str, str]) -> str | None:
            """Process single target config item."""
            ext_key, format_template = target_item
            value: t.MetadataAttributeValue | None = (
                extensions.get(ext_key) if extensions else None
            )
            if value is None:
                return None
            return format_template.format(value=value)

        def predicate_func(item: str | tuple[str, str]) -> bool:
            """Predicate function for Collection.process."""
            if isinstance(item, tuple) and len(item) >= 1:
                return bool(extensions.get(item[0]) if extensions else None)
            return False

        result: list[str] = []
        for item in target_config:
            try:
                if predicate_func(item):  # Apply predicate
                    processed = process_target_config(item)
                    if processed is not None:
                        result.append(processed)
            except Exception as e:
                logger.debug("Skipping ACL rule processing due to error", error=str(e))
                continue
        return result

    @staticmethod
    def format_conversion_comments(
        extensions: FlextLdifModelsMetadata.DynamicMetadata
        | dict[str, t.MetadataAttributeValue]
        | None,
        converted_from_key: str,
        comments_key: str,
    ) -> list[str]:
        """Extract conversion comments from metadata extensions."""
        if not extensions:
            return []

        converted_from_value = (
            extensions.get(converted_from_key) if extensions else None
        )
        if not converted_from_value:
            return []

        comments_value = extensions.get(comments_key) if extensions else None
        if comments_value is None:
            return []
        normalized: list[str]
        if isinstance(comments_value, str):
            normalized = [comments_value]
        elif isinstance(comments_value, (list, tuple)):
            normalized = [str(item) for item in comments_value]
        else:
            normalized = [str(comments_value)]
        return normalized + [""]  # Empty line after comments

    @staticmethod
    def parser(acl_string: str) -> dict[str, str] | None:
        """Detect ACL format and return format information."""
        if not acl_string or not acl_string.strip():
            return None

        first_line = acl_string.split("\n", maxsplit=1)[0].strip()

        if first_line.startswith(("orclaci:", "orclentrylevelaci:")):
            return {"format": "oid"}
        if first_line.startswith("aci:"):
            return {"format": "oud"}
        return None

    @staticmethod
    def map_oid_to_oud_permissions(
        oid_permissions: dict[str, bool],
    ) -> dict[str, bool]:
        """Map OID-specific permissions to OUD-equivalent permissions."""
        pass_through_perms = {
            "read",
            "write",
            "add",
            "delete",
            "search",
            "compare",
            "all",
        }

        def map_perm(perm_name: str, *, perm_value: bool) -> dict[str, bool]:
            """Map single permission."""
            if perm_name == "browse":
                return {"read": perm_value, "search": perm_value}
            if perm_name == "selfwrite":
                return {"write": perm_value}
            if perm_name in pass_through_perms:
                return {perm_name: perm_value}
            return {}

        mapped_dicts: list[dict[str, bool]] = [
            map_perm(perm_name, perm_value=perm_value)
            for perm_name, perm_value in oid_permissions.items()
        ]

        filtered_dicts: list[dict[str, bool]] = [
            d for d in mapped_dicts if isinstance(d, dict) and d
        ]

        result: dict[str, bool] = {}
        for d in filtered_dicts:
            for k, v in d.items():
                result[k] = result.get(k, False) or v
        return result

    @staticmethod
    def map_oud_to_oid_permissions(
        oud_permissions: dict[str, bool],
    ) -> dict[str, bool]:
        """Map OUD-specific permissions to OID-equivalent permissions."""
        pass_through_perms = {
            "read",
            "write",
            "add",
            "delete",
            "search",
            "compare",
            "all",
        }

        has_read = oud_permissions.get("read", False)
        has_search = oud_permissions.get("search", False)
        browse_dict: dict[str, bool] = (
            {"browse": has_read and has_search} if (has_read or has_search) else {}
        )

        pass_through: dict[str, bool] = {
            k: v
            for k, v in oud_permissions.items()
            if k in pass_through_perms and k not in {"read", "search"}
        }

        result: dict[str, bool] = {**browse_dict, **pass_through}
        return result

    @staticmethod
    def extract_components_batch(
        content: str,
        patterns: Mapping[str, str | tuple[str, int]],
        *,
        defaults: Mapping[str, object] | None = None,
    ) -> dict[str, t.GeneralValueType]:
        r"""Extract multiple ACL components in one call.

        Replaces repetitive extract_component() calls with a single batch call.

        Example - BEFORE (9 calls in oid.py):
            bindmode = extract_component(acl, r'bindmode=([^,;]+)', None)
            filter = extract_component(acl, r'filter="([^"]*)"', None)
            constraint = extract_component(acl, r'constraint="([^"]*)"', None)

        AFTER (1 call):
            components = extract_components_batch(
                acl_string,
                {
                    'bindmode': r'bindmode=([^,;]+)',
                    'filter': r'filter="([^"]*)"',
                    'constraint': r'constraint="([^"]*)"',
                },
                defaults={'bindmode': None, 'filter': None, 'constraint': None}
            )

        Args:
            content: ACL content string to extract from
            patterns: Mapping of component names to regex patterns.
                      Pattern can be str or (pattern, group_index) tuple.
            defaults: Default values for components not found

        Returns:
            Dictionary of extracted component values

        Examples:
            >>> components = FlextLdifUtilitiesACL.extract_components_batch(
            ...     "target=ldap:///dc=example;bindmode=all;filter=(*)",
            ...     {
            ...         "target": r"target=([^;]+)",
            ...         "bindmode": r"bindmode=([^;]+)",
            ...         "filter": r"filter=\\(([^)]*)\\)",
            ...     },
            ...     defaults={"filter": "*"},
            ... )
            >>> components["target"]
            'ldap:///dc=example'

        """
        effective_defaults = defaults or {}

        def extract_component_batch(
            name: str,
            pattern_spec: str | tuple[str, int],
        ) -> tuple[str, t.GeneralValueType]:
            """Extract component from pattern spec."""
            if isinstance(pattern_spec, tuple):
                pattern, group_idx = pattern_spec
            else:
                pattern = pattern_spec
                group_idx = 1
            value = FlextLdifUtilitiesACL.extract_component(content, pattern, group_idx)
            raw_default = effective_defaults.get(name) if effective_defaults else None
            default_value: t.GeneralValueType | None = (
                raw_default
                if isinstance(raw_default, str | int | float | bool | type(None))
                else str(raw_default)
                if raw_default is not None
                else None
            )
            final_value: t.GeneralValueType = (
                value if value is not None else default_value
            )
            return name, final_value

        result_dict: dict[str, tuple[str, t.GeneralValueType]] = {}
        for key, pattern in patterns.items():
            try:
                result = extract_component_batch(key, pattern)
                if result is not None:
                    result_dict[key] = result
            except (ValueError, TypeError, AttributeError):
                continue

        final_result: dict[str, t.GeneralValueType] = {}
        for key, value_item in result_dict.items():
            if isinstance(value_item, tuple) and len(value_item) == TUPLE_LENGTH_PAIR:
                final_result[key] = value_item[1]

        return final_result

    @staticmethod
    def _parse_single_acl_with_config(
        acl_line: str,
        config: FlextLdifModelsSettings.AciParserConfig,
        *,
        fail_fast: bool = False,
    ) -> m.Ldif.Acl | None:
        """Parse single ACL line, return None on error."""
        try:
            result = FlextLdifUtilitiesACL.parse_aci(acl_line, config)
        except Exception:
            return None
        if not result.is_success:
            if fail_fast:
                error_msg = f"ACL parse failed: {result.error}"
                raise ValueError(error_msg)
            return None
        return result.value

    @staticmethod
    def _format_batch_errors(errors: list[tuple[int, str]]) -> list[str]:
        """Format batch error tuples to strings."""
        return [f"ACL {idx}: {msg}" for idx, msg in errors]

    @staticmethod
    def validate_batch(
        acl_lines: Sequence[str],
        *,
        collect_errors: bool = True,
    ) -> r[list[tuple[str, bool, str | None]]]:
        """Validate multiple ACL lines."""

        def validate_single_acl(acl_line: str) -> tuple[str, bool, str | None]:
            """Validate single ACL line."""
            is_valid, aci_content = FlextLdifUtilitiesACL.validate_aci_format(acl_line)
            if is_valid:
                return (acl_line, True, None)
            error_msg = aci_content or "Invalid ACI format"
            return (acl_line, False, error_msg)

        results: list[tuple[str, bool, str | None]] = []

        if collect_errors:
            for acl_line in acl_lines:
                result_tuple = validate_single_acl(acl_line)
                results.append(result_tuple)
        else:
            for acl_line in acl_lines:
                result_tuple = validate_single_acl(acl_line)
                results.append(result_tuple)
                if not result_tuple[1]:  # is_valid is False
                    break

        return r[str].ok(results)


__all__ = [
    "FlextLdifUtilitiesACL",
]
