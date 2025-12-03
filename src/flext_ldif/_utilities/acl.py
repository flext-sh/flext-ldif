"""Extracted nested class from FlextLdifUtilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Literal

from flext_core import (
    FlextLogger,
    FlextResult,
)
from flext_core.typings import t as FlextTypes  # noqa: N812
from flext_core.utilities import FlextUtilities

from flext_ldif._models.config import FlextLdifModelsConfig
from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels

# Aliases for simplified usage - after all imports
u = FlextUtilities  # Utilities
t = FlextTypes  # Types
r = FlextResult  # Result

logger = FlextLogger(__name__)

# Type for parsed ACL components (using MetadataValue for nested structures)
AclComponent = dict[str, str | t.MetadataAttributeValue]


class FlextLdifUtilitiesACL:
    """Generic ACL parsing and writing utilities."""

    # ASCII control character boundaries for sanitization (use constants from FlextLdifConstants.Rfc)
    # Note: Cannot use class attribute assignment with constants due to import order
    # Use constants directly in methods instead

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

            # Filter by action if specified
            if action_filter and action.lower() != action_filter.lower():
                continue

            if ops:
                perms = [op.strip() for op in ops.split(ops_separator)]
                filtered_perms = [p for p in perms if p]
                permissions.extend(filtered_perms)

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

        # Default patterns with capturing groups for values
        default_patterns: dict[str, str] = {
            "userdn": r'userdn\s*=\s*"([^"]*)"',
            "groupdn": r'groupdn\s*=\s*"([^"]*)"',
            "roledn": r'roledn\s*=\s*"([^"]*)"',
        }

        patterns = bind_patterns or default_patterns

        def extract_bind_rule(bind_type: str, pattern: str) -> list[dict[str, str]]:
            """Extract bind rules for single bind type."""
            matches = re.findall(pattern, content, re.IGNORECASE)
            return [{"type": bind_type, "value": m} for m in matches]

        bind_rules_result = u.process(
            list(patterns.items()),
            processor=lambda item: extract_bind_rule(item[0], item[1]),
            on_error="skip",
        )
        bind_rules: list[dict[str, str]] = []
        if bind_rules_result.is_success:
            bind_rules_list = bind_rules_result.value
            if isinstance(bind_rules_list, list):
                flattened_result = u.process(
                    bind_rules_list,
                    processor=lambda rule_list: rule_list
                    if isinstance(rule_list, list)
                    else [],
                    on_error="skip",
                )
                if flattened_result.is_success and isinstance(
                    flattened_result.value, list
                ):
                    bind_rules = u.ensure(
                        [
                            item
                            for sublist in flattened_result.value
                            for item in sublist
                        ],
                        target_type="list",
                        default=[],
                    )

        return bind_rules

    @staticmethod
    def build_permissions_dict(
        allow_permissions: list[str],
        permission_map: dict[str, str] | None = None,
        deny_permissions: list[str] | None = None,
    ) -> dict[str, bool]:
        """Build permissions dictionary from allow/deny lists.

        Args:
            allow_permissions: List of allowed permission names
            permission_map: Optional dict to normalize permission names.
                           Maps server-specific names to canonical names.
            deny_permissions: Optional list of denied permission names

        Returns:
            Dictionary mapping permission names to True (allow) or False (deny)

        """
        permissions: dict[str, bool] = {}

        def normalize(perm: str) -> str:
            """Normalize permission name using map if available."""
            return permission_map.get(perm, perm) if permission_map else perm

        def build_from_list(perm_list: list[str], *, is_allow: bool) -> dict[str, bool]:
            """Build dict from permission list."""

            def process_perm(p: str) -> tuple[str, bool] | None:
                """Process single permission."""
                return (normalize(p), is_allow) if p else None

            def is_valid_perm(p: str) -> bool:
                """Check if permission is valid."""
                return bool(p)

            process_result = u.process(
                perm_list,
                processor=process_perm,
                predicate=is_valid_perm,
                on_error="skip",
            )
            if not process_result.is_success or not isinstance(
                process_result.value, list
            ):
                return {}
            tuple_length = 2
            filtered_tuples = u.filter(
                process_result.value,
                predicate=lambda t: isinstance(t, tuple) and len(t) == tuple_length,
            )
            if isinstance(filtered_tuples, list):
                result_dict = {
                    perm_tuple[0]: perm_tuple[1]
                    for perm_tuple in filtered_tuples
                    if isinstance(perm_tuple, tuple) and len(perm_tuple) == tuple_length
                }
            else:
                result_dict = {}
            return result_dict

        if allow_permissions:
            permissions.update(build_from_list(allow_permissions, is_allow=True))
        if deny_permissions:
            permissions.update(build_from_list(deny_permissions, is_allow=False))

        return permissions

    # NOTE: OID-specific methods (extract_oid_target, detect_oid_subject, parse_oid_permissions,
    # format_oid_target, format_oid_subject, format_oid_permissions) were REMOVED from here.
    # They are now in FlextLdifServersOid.Acl class where OID knowledge belongs.
    # Servers must encapsulate their own knowledge - utilities should be generic/parametrized.

    @staticmethod
    def format_aci_subject(
        _subject_type: str,
        subject_value: str,
        bind_operator: str = "userdn",
    ) -> str:
        """Format ACL subject into ACI bind rule format.

        Supports both RFC (userdn/groupdn with ldap:///) and OID (by DN=) formats.

        Args:
            _subject_type: "user", "group", "role" (reserved for future use)
            subject_value: Subject DN or value
            bind_operator: "userdn", "groupdn", "roledn"

        Returns:
            Formatted ACI bind rule

        """
        # Clean up subject value if it contains spaces
        cleaned_value = subject_value.replace(", ", ",")

        # OUD ACI format: userdn="ldap:///..." or groupdn="ldap:///..."
        if bind_operator in {"userdn", "groupdn", "roledn"}:
            return f'{bind_operator}="ldap:///{cleaned_value}"'

        # OID format: by dn="..."
        return f'by dn="{cleaned_value}"'

    @staticmethod
    def build_acl_subject(
        bind_rules_data: list[dict[str, str]],
        subject_type_map: dict[str, str],
        special_values: dict[str, tuple[str, str]],
    ) -> tuple[str, str]:
        """Build ACL subject from bind rules - generic implementation.

        Args:
            bind_rules_data: List of dicts with 'type' and 'value' keys
            subject_type_map: Maps bind rule types to subject types
            special_values: Maps special values to (type, value) tuples

        Returns:
            Tuple of (subject_type, subject_value)

        """
        if not bind_rules_data:
            return ("", "")

        first_rule = bind_rules_data[0]
        rule_type = first_rule.get("type", "")
        rule_value = first_rule.get("value", "")

        # Check for special values first
        if rule_value in special_values:
            return special_values[rule_value]

        # Map the type
        subject_type = subject_type_map.get(rule_type, rule_type)

        return (subject_type, rule_value)

    @staticmethod
    def build_metadata_extensions(
        config: FlextLdifModelsConfig.AclMetadataConfig,
    ) -> dict[str, t.MetadataAttributeValue]:
        """Build QuirkMetadata extensions for ACL.

        Args:
            config: ACL metadata configuration

        Returns:
            Metadata extensions dictionary

        """
        extensions: dict[str, t.MetadataAttributeValue] = {}

        if config.line_breaks:
            # config.line_breaks is list[int] | None, compatible with MetadataAttributeValue
            extensions["line_breaks"] = config.line_breaks
        if config.dn_spaces:
            # config.dn_spaces is bool, compatible with MetadataAttributeValue
            extensions["dn_spaces"] = config.dn_spaces
        if config.targetscope:
            extensions["targetscope"] = config.targetscope
        if config.version:
            extensions["version"] = config.version
        if config.action_type:
            extensions["action_type"] = config.action_type

        return extensions

    @staticmethod
    def sanitize_acl_name(raw_name: str, max_length: int = 128) -> tuple[str, bool]:
        """Sanitize ACL name for ACI format."""
        if not raw_name or not raw_name.strip():
            return "", False

        def sanitize_char(char: str) -> str:
            """Sanitize single character."""
            char_ord = ord(char)
            if (
                char_ord < FlextLdifConstants.Rfc.ASCII_PRINTABLE_MIN
                or char_ord > FlextLdifConstants.Rfc.ASCII_PRINTABLE_MAX
                or char == '"'
            ):
                return " "
            return char

        sanitized_chars_result = u.map(list(raw_name), mapper=sanitize_char)
        sanitized_chars = (
            sanitized_chars_result
            if isinstance(sanitized_chars_result, list)
            else list(raw_name)
        )

        def should_keep_char(char: str, prev_char: str) -> bool:
            """Check if character should be kept."""
            return not (char == " " and prev_char == " ")

        result: list[str] = []
        was_sanitized = False
        prev_char = ""
        for char in sanitized_chars:
            if should_keep_char(char, prev_char):
                result.append(char)
                if char == " ":
                    was_sanitized = True
                prev_char = char

        sanitized = " ".join("".join(result).split())

        if len(sanitized) > max_length:
            sanitized = sanitized[: max_length - 3] + "..."
            was_sanitized = True

        return sanitized, was_sanitized

    # =========================================================================
    # GENERIC ACI PARSING - Parametrized for OUD/RFC/OID
    # =========================================================================

    @staticmethod
    def validate_aci_format(
        acl_line: str,
        aci_prefix: str = "aci:",
    ) -> tuple[bool, str]:
        """Validate and extract ACI content from line.

        Args:
            acl_line: Raw ACL line
            aci_prefix: Expected prefix (default: "aci:")

        Returns:
            Tuple of (is_valid, aci_content)

        """
        if not acl_line or not acl_line.strip():
            return False, ""
        first_line = acl_line.split("\n", maxsplit=1)[0].strip()
        if not first_line.startswith(aci_prefix):
            return False, ""
        has_newline = "\n" in acl_line
        if has_newline:
            lines = acl_line.split("\n")
            first_line_content = lines[0].split(":", 1)[1].strip()
            aci_content = first_line_content + "\n" + "\n".join(lines[1:])
        else:
            aci_content = acl_line.split(":", 1)[1].strip()
        return True, aci_content

    @staticmethod
    def extract_aci_components(
        aci_content: str,
        patterns: dict[str, tuple[str, int]],
        defaults: dict[str, str | None] | None = None,
    ) -> dict[str, str | None]:
        """Extract all ACI components using configurable patterns.

        Args:
            aci_content: ACI content string (without prefix)
            patterns: Dict mapping component name to (pattern, group) tuple
            defaults: Default values for components

        Returns:
            Context dict with extracted components

        """
        context: dict[str, str | None] = dict(defaults or {})
        context["aci_content"] = aci_content

        def extract_pattern(
            name: str, pattern_spec: str | tuple[str, int]
        ) -> tuple[str, str | None]:
            """Extract component from pattern spec."""
            if isinstance(pattern_spec, tuple):
                pattern, group = pattern_spec
            else:
                pattern = pattern_spec
                group = 1
            if not pattern:
                return name, None
            value = FlextLdifUtilitiesACL.extract_component(aci_content, pattern, group)
            return name, value

        def has_pattern(pattern_spec: str | tuple[str, int]) -> bool:
            """Check if pattern spec is valid."""
            if isinstance(pattern_spec, tuple):
                return bool(pattern_spec[0])
            return bool(pattern_spec)

        process_result = u.process(
            patterns,
            processor=extract_pattern,
            predicate=lambda _k, v: has_pattern(v),
            on_error="skip",
        )
        if process_result.is_success and isinstance(process_result.value, dict):
            filtered_dict = u.filter(
                process_result.value,
                predicate=lambda _k, v: isinstance(v, str),
            )
            if isinstance(filtered_dict, dict):
                context.update(filtered_dict)

        return context

    @staticmethod
    def parse_targetattr(
        targetattr_str: str | None,
        separator: str = "||",
    ) -> tuple[list[str], str]:
        """Parse targetattr string to attributes list and target DN.

        Args:
            targetattr_str: Target attribute string
            separator: Separator for multiple attributes (default: "||")

        Returns:
            Tuple of (target_attributes, target_dn)

        """
        if not targetattr_str:
            return [], "*"
        if separator in targetattr_str:
            parts = targetattr_str.split(separator)
            filtered = u.filter(parts, predicate=lambda a: bool(a.strip()))
            if isinstance(filtered, list):
                mapped = u.map(filtered, mapper=lambda a: a.strip())
                return mapped if isinstance(mapped, list) else [], "*"
            return [], "*"
        if targetattr_str != "*":
            return [targetattr_str.strip()], "*"
        return [], "*"

    @staticmethod
    def _check_special_value(
        rule_value: str,
        special_values: dict[str, tuple[str, str]],
    ) -> tuple[str, str] | None:
        """Check if rule value matches any special value."""
        tuple_length = 2

        def matches_special(_k: str, _unused_value_tuple: tuple[str, str]) -> bool:
            """Check if rule value matches special key."""
            return bool(u.normalize(rule_value, _k))

        found = u.find(
            special_values,
            predicate=matches_special,
            return_key=True,
        )
        if found and isinstance(found, tuple) and len(found) == tuple_length:
            key, value_tuple = found
            if u.normalize(rule_value, key):
                return value_tuple
        return None

    @staticmethod
    def build_aci_subject(
        bind_rules_data: list[dict[str, str]],
        subject_type_map: dict[str, str],
        special_values: dict[str, tuple[str, str]],
    ) -> tuple[str, str]:
        """Build ACL subject from bind rules using configurable maps.

        Args:
            bind_rules_data: List of bind rule dicts with 'type' and 'value'
            subject_type_map: Mapping of bind type to subject type
            special_values: Special subject values (self, anonymous, etc.)

        Returns:
            Tuple of (subject_type, subject_value)

        """
        if not bind_rules_data:
            return "self", "ldap:///self"

        def process_rule(rule: dict[str, str]) -> tuple[str, str] | None:
            """Process single bind rule."""
            rule_type = rule.get("type", "").lower()
            rule_value = rule.get("value", "")
            special_match = FlextLdifUtilitiesACL._check_special_value(
                rule_value, special_values
            )
            if special_match:
                return special_match
            if rule_type in subject_type_map:
                return subject_type_map[rule_type], rule_value
            return None

        process_result = u.process(
            bind_rules_data,
            processor=process_rule,
            on_error="skip",
        )
        if process_result.is_success and isinstance(process_result.value, list):
            found = u.find(process_result.value, predicate=lambda r: r is not None)
            if found is not None:
                return found

        return "user", bind_rules_data[0].get("value", "") if bind_rules_data else ""

    @staticmethod
    def filter_supported_permissions(
        permissions: list[str],
        supported: set[str] | frozenset[str],
    ) -> list[str]:
        """Filter permissions to only include supported ones.

        Args:
            permissions: List of permission names
            supported: Set of supported permission names

        Returns:
            Filtered list of supported permissions

        """
        supported_lower = {u.normalize(s, case="lower") for s in supported}
        filtered = u.filter(
            permissions,
            predicate=lambda p: u.normalize(p, case="lower") in supported_lower,
        )
        return filtered if isinstance(filtered, list) else []

    @staticmethod
    def build_aci_target_clause(
        target_attributes: list[str] | None,
        target_dn: str | None = None,
        separator: str = " || ",
    ) -> str:
        """Build ACI targetattr clause.

        Args:
            target_attributes: List of target attributes
            target_dn: Target DN (used if no attributes)
            separator: Separator for multiple attributes

        Returns:
            Formatted targetattr clause

        """
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
        """Build ACI permissions clause.

        Args:
            permissions: List of permission names
            allow_prefix: Prefix for allow clause
            supported_permissions: Optional set of supported permissions to filter

        Returns:
            Formatted permissions clause or None if empty

        """
        filtered = permissions
        if supported_permissions:
            filtered = FlextLdifUtilitiesACL.filter_supported_permissions(
                permissions,
                supported_permissions,
            )
        if not filtered:
            return None
        return f"{allow_prefix}{','.join(filtered)})"

    @staticmethod
    def build_aci_bind_rule(
        subject_type: str,
        subject_value: str,
        bind_operators: dict[str, str] | None = None,
        self_value: str = "ldap:///self",
        anonymous_value: str = "ldap:///anyone",
    ) -> str:
        """Build ACI bind rule (subject) clause.

        Args:
            subject_type: Subject type (user, group, self, anonymous, etc.)
            subject_value: Subject value (DN or special value)
            bind_operators: Mapping of subject type to bind operator
            self_value: Value for self subject
            anonymous_value: Value for anonymous subject

        Returns:
            Formatted bind rule string

        """
        default_operators = {
            "user": "userdn",
            "group": "groupdn",
            "role": "roledn",
            "self": "userdn",
            "anonymous": "userdn",
        }
        operators = bind_operators or default_operators

        if subject_type == "self":
            return f'{operators.get("self", "userdn")}="{self_value}"'
        if subject_type == "anonymous":
            return f'{operators.get("anonymous", "userdn")}="{anonymous_value}"'

        operator = operators.get(subject_type, "userdn")
        clean_value = subject_value.replace(", ", ",")
        if not clean_value.startswith("ldap:///"):
            clean_value = f"ldap:///{clean_value}"
        return f'{operator}="{clean_value}"'

    @staticmethod
    def format_aci_line(
        config: FlextLdifModelsConfig.AciLineFormatConfig,
    ) -> str:
        r"""Format complete ACI line from components.

        Args:
            config: AciLineFormatConfig with all formatting parameters

        Returns:
            Formatted ACI line string

        Example:
            config = FlextLdifModelsConfig.AciLineFormatConfig(
                name="test-acl",
                target_clause="(targetattr=\"cn\")",
                permissions_clause="allow (read,write)",
                bind_rule="userdn=\"ldap:///self\"",
            )
            aci_line = FlextLdifUtilities.ACL.format_aci_line(config)

        """
        sanitized_name, _ = FlextLdifUtilitiesACL.sanitize_acl_name(config.name)
        return (
            f"{config.aci_prefix}{config.target_clause}"
            f'(version {config.version}; acl "{sanitized_name}"; '
            f"{config.permissions_clause} {config.bind_rule};)"
        )

    # =========================================================================
    # HIGH-LEVEL PARSE/WRITE - Uses Models for server-specific config
    # =========================================================================

    @staticmethod
    def _extract_version_and_name(
        aci_content: str,
        version_pattern: str,
        default_name: str,
    ) -> tuple[str, str]:
        """Extract version and ACL name from content."""
        version = "3.0"
        acl_name = default_name
        version_match = re.search(version_pattern, aci_content)
        if version_match:
            version = version_match.group(1)
            acl_name = version_match.group(2)
        return version, acl_name

    @staticmethod
    def _extract_target_info(
        aci_content: str,
        config: FlextLdifModelsConfig.AciParserConfig,
    ) -> tuple[list[str], str]:
        """Extract target attributes and DN from ACI content.

        Args:
            aci_content: ACI content string
            config: AciParserConfig with targetattr_pattern and default_targetattr

        Returns:
            Tuple of (target_attributes, target_dn)

        """
        # Extract targetattr
        targetattr = config.default_targetattr
        targetattr_extracted = FlextLdifUtilitiesACL.extract_component(
            aci_content,
            config.targetattr_pattern,
            group=2,
        )
        if targetattr_extracted:
            targetattr = targetattr_extracted
        target_attributes, target_dn = FlextLdifUtilitiesACL.parse_targetattr(
            targetattr,
        )
        return target_attributes, target_dn

    @staticmethod
    def _build_subject_and_permissions(
        aci_content: str,
        config: FlextLdifModelsConfig.AciParserConfig,
    ) -> tuple[str, str, dict[str, bool]]:
        """Build subject and permissions from ACI content.

        Args:
            aci_content: ACI content string
            config: AciParserConfig with patterns and maps

        Returns:
            Tuple of (subject_type, subject_value, permissions_dict)

        """
        # Extract permissions and bind rules
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

        # Build subject and permissions
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
            for k, v in permissions_dict_raw.items()
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

        extra_result = u.process(
            extra_patterns,
            processor=extract_extra,
            predicate=lambda _k, v: bool(v),
            on_error="skip",
        )
        if extra_result.is_success and isinstance(extra_result.value, dict):
            filtered_extensions = u.filter(
                extra_result.value,
                predicate=lambda _k, v: isinstance(v, str),
            )
            if isinstance(filtered_extensions, dict):
                extensions.update(filtered_extensions)
        return extensions

    @staticmethod
    def parse_aci(
        acl_line: str,
        config: FlextLdifModelsConfig.AciParserConfig,
    ) -> FlextResult[FlextLdifModelsDomains.Acl]:
        """Parse ACI line using server-specific config Model.

        Args:
            acl_line: Raw ACL line string
            config: AciParserConfig with server-specific patterns

        Returns:
            FlextResult with parsed Acl model

        Example:
            config = FlextLdifModelsConfig.AciParserConfig(
                server_type=FlextLdifConstants.ServerTypes.OUD,
                version_acl_pattern=OudConstants.ACL_VERSION_ACL_PATTERN,
                targetattr_pattern=OudConstants.ACL_TARGETATTR_PATTERN,
                allow_deny_pattern=OudConstants.ACL_ALLOW_DENY_PATTERN,
                bind_patterns=dict(OudConstants.ACL_BIND_PATTERNS),
            )
            result = FlextLdifUtilities.ACL.parse_aci(acl_line, config)

        """
        # Validate and extract ACI content
        is_valid, aci_content = FlextLdifUtilitiesACL.validate_aci_format(
            acl_line,
            config.aci_prefix,
        )
        if not is_valid:
            return r.fail(
                f"Not a valid ACI format: {config.aci_prefix}",
            )

        # Extract version and name
        version, acl_name = FlextLdifUtilitiesACL._extract_version_and_name(
            aci_content,
            config.version_acl_pattern,
            config.default_name,
        )

        # Extract target info
        target_attributes, target_dn = FlextLdifUtilitiesACL._extract_target_info(
            aci_content,
            config,
        )

        # Build subject and permissions
        subject_type, subject_value, permissions_dict = (
            FlextLdifUtilitiesACL._build_subject_and_permissions(
                aci_content,
                config,
            )
        )

        # Build extensions
        extensions = FlextLdifUtilitiesACL._build_extensions(
            aci_content,
            version,
            acl_line,
            config.extra_patterns,
        )

        # Create Acl model
        acl_model = FlextLdifModelsDomains.Acl(
            name=acl_name,
            target=FlextLdifModelsDomains.AclTarget(
                target_dn=target_dn,
                attributes=target_attributes,
            ),
            subject=FlextLdifModelsDomains.AclSubject.model_validate({
                "subject_type": subject_type,
                "subject_value": subject_value,
            }),
            permissions=FlextLdifModelsDomains.AclPermissions(**permissions_dict),
            server_type=config.server_type,
            raw_acl=acl_line,
            metadata=FlextLdifModels.QuirkMetadata.create_for(
                config.server_type,
                extensions=FlextLdifModelsMetadata.DynamicMetadata(**extensions)
                if isinstance(extensions, dict)
                else extensions,
            ),
        )
        return r.ok(acl_model)

    @staticmethod
    def write_aci(
        acl_data: FlextLdifModelsDomains.Acl,
        config: FlextLdifModelsConfig.AciWriterConfig,
    ) -> FlextResult[str]:
        """Write Acl model to ACI string using server-specific config Model.

        Args:
            acl_data: Acl model to write
            config: AciWriterConfig with server-specific settings

        Returns:
            FlextResult with formatted ACI string

        Example:
            config = FlextLdifModelsConfig.AciWriterConfig(
                aci_prefix="aci: ",
                version="3.0",
                supported_permissions=OudConstants.SUPPORTED_PERMISSIONS,
            )
            result = FlextLdifUtilities.ACL.write_aci(acl, config)

        """
        # Build target clause
        # Type narrowed: acl_data is concrete Acl model with target object
        target_attributes = acl_data.target.attributes if acl_data.target else None
        target_dn = acl_data.target.target_dn if acl_data.target else None
        target_clause = FlextLdifUtilitiesACL.build_aci_target_clause(
            target_attributes,
            target_dn,
            config.attr_separator,
        )

        # Build permissions clause
        # Type narrowed: acl_data is concrete Acl model with permissions object
        if not acl_data.permissions:
            return r.fail("ACL has no permissions")
        perm_names = [
            name
            for name in [
                "read",
                "write",
                "add",
                "delete",
                "search",
                "compare",
                "self_write",
                "proxy",
            ]
            if getattr(acl_data.permissions, name, False)
        ]
        permissions_clause = FlextLdifUtilitiesACL.build_aci_permissions_clause(
            perm_names,
            f"({config.allow_prefix}",
            config.supported_permissions,
        )
        if not permissions_clause:
            return r.fail("No supported permissions")

        # Build bind rule
        # Type narrowed: acl_data is concrete Acl model with subject object
        subject_type = acl_data.subject.subject_type if acl_data.subject else "self"
        subject_value = (
            acl_data.subject.subject_value if acl_data.subject else config.self_subject
        )
        bind_rule = FlextLdifUtilitiesACL.build_aci_bind_rule(
            subject_type,
            subject_value,
            bind_operators=config.bind_operators,
            self_value=config.self_subject,
            anonymous_value=config.anonymous_subject,
        )

        # Format complete ACI
        acl_name = acl_data.name or "ACL"
        format_config = FlextLdifModelsConfig.AciLineFormatConfig(
            name=acl_name,
            target_clause=target_clause,
            permissions_clause=permissions_clause,
            bind_rule=bind_rule,
            version=config.version,
            aci_prefix=config.aci_prefix,
        )
        aci_line = FlextLdifUtilitiesACL.format_aci_line(format_config)
        return r.ok(aci_line)

    @staticmethod
    def extract_bind_rules_from_extensions(
        extensions: dict[str, t.MetadataAttributeValue] | None,
        rule_config: list[tuple[str, str, str | None]],
        *,
        tuple_length: int = 2,
    ) -> list[str]:
        """Extract and format bind rules from metadata extensions.

        Generic utility for extracting bind rules like ip, dns, dayofweek, etc.
        from ACL metadata extensions with consistent formatting.

        Args:
            extensions: Metadata extensions dict (may be None)
            rule_config: List of (extension_key, format_template, operator_default) tuples.
                        format_template can use {value} or {operator}/{value} placeholders.
                        operator_default is used for tuple values that need operator.
            tuple_length: Expected length for tuple values (default: 2 for (operator, value))

        Returns:
            List of formatted bind rule strings

        Example:
            >>> rule_config = [
            ...     ("ACL_BIND_IP", 'ip="{value}"', None),
            ...     ("ACL_BIND_DNS", 'dns="{value}"', None),
            ...     ("ACL_BIND_TIMEOFDAY", 'timeofday {operator} "{value}"', "="),
            ... ]
            >>> extract_bind_rules_from_extensions(extensions, rule_config)
            ['ip="192.168.1.0/24"', 'timeofday >= "0800"']

        """
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
                operator, val = value_raw
                if operator_placeholder in format_template:
                    return format_template.format(
                        operator=str(operator), value=str(val)
                    )
                return format_template.format(value=str(val))
            if operator_placeholder in format_template and operator_default:
                return format_template.format(
                    operator=operator_default, value=str(value_raw)
                )
            return format_template.format(value=str(value_raw))

        process_result = u.process(
            rule_config,
            processor=process_rule_config,
            predicate=lambda item: bool(
                extensions.get(item[0]) if extensions else None
            ),
            on_error="skip",
        )
        if process_result.is_success and isinstance(process_result.value, list):
            return [rule for rule in process_result.value if rule is not None]
        return []

    @staticmethod
    def extract_target_extensions(
        extensions: FlextLdifModelsMetadata.DynamicMetadata
        | dict[str, t.MetadataAttributeValue]
        | None,
        target_config: list[tuple[str, str]],
    ) -> list[str]:
        """Extract and format target extensions from metadata extensions.

        Generic utility for extracting target extensions like targattrfilters,
        targetcontrol, extop, etc. from ACL metadata extensions.

        Args:
            extensions: Metadata extensions dict (may be None)
            target_config: List of (extension_key, format_template) tuples.
                          format_template uses {value} placeholder.

        Returns:
            List of formatted target extension strings

        Example:
            >>> target_config = [
            ...     ("ACL_TARGETATTR_FILTERS", '(targattrfilters="{value}")'),
            ...     ("ACL_TARGET_CONTROL", '(targetcontrol="{value}")'),
            ...     ("ACL_EXTOP", '(extop="{value}")'),
            ... ]
            >>> extract_target_extensions(extensions, target_config)
            ['(targetcontrol="1.2.840.113556.1.4.805")']

        """
        if not extensions:
            return []

        def process_target_config(target_item: tuple[str, str]) -> str | None:
            """Process single target config item."""
            ext_key, format_template = target_item
            value = extensions.get(ext_key)
            return format_template.format(value=value) if value else None

        process_result = u.process(
            target_config,
            processor=process_target_config,
            predicate=lambda item: bool(
                extensions.get(item[0]) if extensions else None
            ),
            on_error="skip",
        )
        if process_result.is_success and isinstance(process_result.value, list):
            return [part for part in process_result.value if part is not None]
        return []

    @staticmethod
    def format_conversion_comments(
        extensions: FlextLdifModelsMetadata.DynamicMetadata
        | dict[str, t.MetadataAttributeValue]
        | None,
        converted_from_key: str,
        comments_key: str,
    ) -> list[str]:
        """Extract conversion comments from metadata extensions.

        Args:
            extensions: Metadata extensions dict (may be None)
            converted_from_key: Key for checking if conversion occurred
            comments_key: Key for the list of comment strings

        Returns:
            List of comment strings (with empty string at end if comments exist)

        """
        if not extensions:
            return []

        if not extensions.get(converted_from_key):
            return []

        comments = extensions.get(comments_key, [])
        if not comments or not isinstance(comments, list):
            return []

        mapped = u.map(comments, mapper=str)
        result = mapped if isinstance(mapped, list) else []
        result.append("")  # Empty line after comments
        return result

    @staticmethod
    def parser(acl_string: str) -> dict[str, str] | None:
        """Detect ACL format and return format information.

        Generic utility for detecting ACL format from raw string,
        used to determine which server-specific quirk to apply.

        Args:
            acl_string: Raw ACL string to analyze

        Returns:
            Dict with "format" key ("oid", "oud", "rfc") or None if unrecognized

        Example:
            >>> parser("orclaci: access to entry by * (browse)")
            {"format": "oid"}
            >>> parser('aci: (version 3.0; acl "test"; ...)')
            {"format": "oud"}

        """
        if not acl_string or not acl_string.strip():
            return None

        first_line = acl_string.split("\n", maxsplit=1)[0].strip()

        # Check OID format (orclaci: or orclentrylevelaci:)
        if first_line.startswith(("orclaci:", "orclentrylevelaci:")):
            return {"format": "oid"}

        # Check OUD/RFC ACI format (aci:)
        if first_line.startswith("aci:"):
            return {"format": "oud"}  # OUD uses RFC ACI format

        return None

    @staticmethod
    def map_oid_to_oud_permissions(
        oid_permissions: dict[str, bool],
    ) -> dict[str, bool]:
        """Map OID-specific permissions to OUD-equivalent permissions.

        Handles OID → OUD permission conversion:
        - browse → read + search (OID browse allows listing, OUD requires read+search)
        - selfwrite → write (OID-specific self-write becomes OUD write)
        - Other permissions (read, write, add, delete, search, compare, all) pass through

        Args:
            oid_permissions: Dict with OID permission names as keys (e.g., browse, selfwrite)

        Returns:
            Dict with OUD-compatible permission names mapped correctly

        Example:
            >>> oid_perms = {"browse": True, "write": False}
            >>> oud_perms = FlextLdifUtilitiesACL.map_oid_to_oud_permissions(oid_perms)
            >>> print(oud_perms)  # {"read": True, "search": True, "write": False}

        """
        oud_permissions: dict[str, bool] = {}

        # Direct pass-through permissions (exist in both OID and OUD)
        pass_through_perms = {
            "read",
            "write",
            "add",
            "delete",
            "search",
            "compare",
            "all",
        }

        # Process each OID permission
        for perm_name, perm_value in oid_permissions.items():
            if perm_name in pass_through_perms:
                # Standard permission - use as-is
                oud_permissions[perm_name] = perm_value
            elif perm_name == "browse":
                # OID browse → OUD read + search
                oud_permissions["read"] = (
                    oud_permissions.get("read", False) or perm_value
                )
                oud_permissions["search"] = (
                    oud_permissions.get("search", False) or perm_value
                )
            elif perm_name == "selfwrite":
                # OID selfwrite → OUD write
                oud_permissions["write"] = (
                    oud_permissions.get("write", False) or perm_value
                )
            elif perm_name == "proxy":
                # OID proxy has no direct OUD equivalent - skip for now
                # Could be preserved in metadata for potential future OUD extensions
                pass
            # Skip unknown OID-specific permissions

        return oud_permissions

    @staticmethod
    def map_oud_to_oid_permissions(
        oud_permissions: dict[str, bool],
    ) -> dict[str, bool]:
        """Map OUD-specific permissions to OID-equivalent permissions.

        Handles OUD → OID permission conversion (reverse mapping):
        - read + search → browse (OUD read+search becomes OID browse)
        - write → write (standard mapping, no special handling needed)
        - Other permissions (add, delete, compare, all) pass through

        Args:
            oud_permissions: Dict with OUD permission names as keys

        Returns:
            Dict with OID-compatible permission names mapped correctly

        Example:
            >>> oud_perms = {"read": True, "search": True, "write": False}
            >>> oid_perms = FlextLdifUtilitiesACL.map_oud_to_oid_permissions(oud_perms)
            >>> print(oid_perms)  # {"browse": True, "write": False}

        """
        oid_permissions: dict[str, bool] = {}

        # Direct pass-through permissions (exist in both OUD and OID)
        pass_through_perms = {
            "read",
            "write",
            "add",
            "delete",
            "search",
            "compare",
            "all",
        }

        # Track which permissions we've processed
        processed = set()

        # Handle read + search → browse conversion
        has_read = oud_permissions.get("read", False)
        has_search = oud_permissions.get("search", False)
        if has_read or has_search:
            # Set browse if both read and search are present
            oid_permissions["browse"] = has_read and has_search
            processed.add("read")
            processed.add("search")

        # Pass through standard permissions (except read/search already processed)
        for perm_name in pass_through_perms:
            if (
                perm_name not in processed
                and perm_name not in {"read", "search"}
                and perm_name in oud_permissions
            ):
                oid_permissions[perm_name] = oud_permissions[perm_name]

        return oid_permissions

    # =========================================================================
    # BATCH METHODS - Power Method Support
    # =========================================================================

    @staticmethod
    def extract_components_batch(
        content: str,
        patterns: Mapping[str, str | tuple[str, int]],
        *,
        defaults: Mapping[str, object] | None = None,
    ) -> dict[str, object]:
        r"""Extract multiple ACL components in one call.

        Replaces repetitive extract_component() calls with a single batch call.

        Example - BEFORE (9 calls in oid.py):
            bindmode = extract_component(acl, r'bindmode=([^,;]+)', None)
            filter = extract_component(acl, r'filter="([^"]*)"', None)
            constraint = extract_component(acl, r'constraint="([^"]*)"', None)
            # ... 6 more calls

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
            name: str, pattern_spec: str | tuple[str, int]
        ) -> tuple[str, object]:
            """Extract component from pattern spec."""
            if isinstance(pattern_spec, tuple):
                pattern, group_idx = pattern_spec
            else:
                pattern = pattern_spec
                group_idx = 1
            value = FlextLdifUtilitiesACL.extract_component(content, pattern, group_idx)
            default_value = effective_defaults.get(name)
            return name, value if value is not None else default_value

        process_result = u.process(
            patterns,
            processor=extract_component_batch,
            on_error="skip",
        )
        if process_result.is_success and isinstance(process_result.value, dict):
            results: dict[str, object] = {}
            tuple_length = 2
            for name, value_tuple in process_result.value.items():
                if isinstance(value_tuple, tuple) and len(value_tuple) == tuple_length:
                    _, value = value_tuple
                    results[name] = value
            return results
        return {}

    @staticmethod
    def parse_batch(
        acl_lines: Sequence[str],
        config: FlextLdifModelsConfig.AciParserConfig,
        *,
        fail_fast: bool = False,
        skip_invalid: bool = True,
    ) -> FlextResult[list[FlextLdifModelsDomains.Acl]]:
        """Parse multiple ACL lines in one call.

        Args:
            acl_lines: Sequence of ACL line strings to parse
            config: Parser configuration
            fail_fast: If True, return error on first parse failure
            skip_invalid: If True, skip invalid ACLs (when fail_fast=False)

        Returns:
            FlextResult containing list of parsed ACL objects

        Examples:
            >>> config = FlextLdifModelsConfig.AciParserConfig(
            ...     strict_mode=False,
            ...     preserve_comments=True,
            ... )
            >>> result = FlextLdifUtilitiesACL.parse_batch(
            ...     acl_lines,
            ...     config,
            ...     fail_fast=False,
            ... )
            >>> if result.is_success:
            ...     acls = result.unwrap()

        """
        results: list[FlextLdifModelsDomains.Acl] = []
        errors: list[str] = []

        def parse_single_acl(acl_line: str) -> FlextLdifModelsDomains.Acl | None:
            """Parse single ACL line, return None on error."""
            try:
                result = FlextLdifUtilitiesACL.parse_aci(acl_line, config)
                if result.is_success:
                    return result.unwrap()
                error_msg = f"ACL parse failed: {result.error}"
                if fail_fast:
                    raise ValueError(error_msg)
                if not skip_invalid:
                    errors.append(error_msg)
                return None
            except Exception as e:
                if fail_fast:
                    raise
                if not skip_invalid:
                    errors.append(f"ACL exception: {e}")
                return None

        batch_result = u.batch(
            list(acl_lines),
            operation=parse_single_acl,
            on_error="collect" if not fail_fast else "fail",
            post_validate=lambda r: r is not None,
        )
        if batch_result.is_failure:
            return batch_result
        batch_data = batch_result.value
        results = [
            r
            for r in batch_data["results"]
            if isinstance(r, FlextLdifModelsDomains.Acl)
        ]
        if batch_data["error_count"] > 0 and not skip_invalid:
            error_msgs = [f"ACL {idx}: {err}" for idx, err in batch_data["errors"]]
            return r.fail(f"Parse errors: {'; '.join(error_msgs)}")
        return r.ok(results)

    @staticmethod
    def convert_permissions_batch(
        permissions_list: Sequence[dict[str, bool]],
        direction: Literal["oid_to_oud", "oud_to_oid"],
    ) -> FlextResult[list[dict[str, bool]]]:
        """Convert multiple permission sets between OID and OUD formats.

        Args:
            permissions_list: Sequence of permission dictionaries
            direction: Conversion direction ("oid_to_oud" or "oud_to_oid")

        Returns:
            FlextResult containing list of converted permission dictionaries

        Examples:
            >>> oid_perms = [{"read": True, "search": True}, {"write": True}]
            >>> result = FlextLdifUtilitiesACL.convert_permissions_batch(
            ...     oid_perms,
            ...     direction="oid_to_oud",
            ... )

        """

        def convert_single_permissions(permissions: dict[str, bool]) -> dict[str, bool]:
            """Convert single permission set."""
            if direction == "oid_to_oud":
                return FlextLdifUtilitiesACL.map_oid_to_oud_permissions(permissions)
            return FlextLdifUtilitiesACL.map_oud_to_oid_permissions(permissions)

        batch_result = u.batch(
            list(permissions_list),
            operation=convert_single_permissions,
            on_error="fail",
        )
        if batch_result.is_failure:
            return batch_result
        batch_data = batch_result.value
        results = [r for r in batch_data["results"] if isinstance(r, dict)]
        return r.ok(results)

    @staticmethod
    def validate_batch(
        acl_lines: Sequence[str],
        *,
        collect_errors: bool = True,
    ) -> FlextResult[list[tuple[str, bool, str | None]]]:
        """Validate multiple ACL lines.

        Business Rule:
        - Validates ACI format for each ACL line using RFC 2849/4512 standards
        - Returns tuple (is_valid, aci_content) where is_valid indicates format correctness
        - When collect_errors=False, stops at first invalid ACL (fail-fast pattern)
        - Error messages are extracted from validation tuple for audit trail

        Args:
            acl_lines: Sequence of ACL line strings to validate
            collect_errors: If True, continue after failures (default: True)

        Returns:
            FlextResult containing list of (acl_line, is_valid, error_message) tuples
            - is_valid: True if ACL format is valid, False otherwise
            - error_message: None if valid, error description if invalid

        Examples:
            >>> result = FlextLdifUtilitiesACL.validate_batch([
            ...     "(target=ldap:///...)(version 3.0;acl...)",
            ...     "invalid-acl",
            ... ])
            >>> if result.is_success:
            ...     for line, is_valid, error in result.unwrap():
            ...         print(f"Valid: {is_valid}")

        """
        results: list[tuple[str, bool, str | None]] = []

        for acl_line in acl_lines:
            # validate_aci_format returns tuple[bool, str] where:
            # - bool: is_valid (True if format is valid)
            # - str: aci_content (empty string if invalid)
            is_valid, aci_content = FlextLdifUtilitiesACL.validate_aci_format(acl_line)

            if is_valid:
                # Valid ACL: no error message
                results.append((acl_line, True, None))
            else:
                # Invalid ACL: extract error message from content or use default
                error_msg = aci_content or "Invalid ACI format"
                results.append((acl_line, False, error_msg))

            if not collect_errors and results[-1][1] is False:
                break

        return r.ok(results)


__all__ = [
    "FlextLdifUtilitiesACL",
]
