"""Extracted nested class from FlextLdifUtilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Literal, cast

from flext_core import r
from flext_core.loggings import FlextLogger as l_core
from flext_core.typings import t
from flext_core.utilities import FlextUtilities as u_core

from flext_ldif._models.config import FlextLdifModelsConfig
from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif._utilities.functional import FlextFunctional
from flext_ldif.constants import c
from flext_ldif.models import FlextLdifModels

# Aliases for simplified usage - after all imports
u = u_core  # Utilities (from flext-core)
f = FlextFunctional  # Pure functional utilities (no circular import)
# t is already imported from flext_core.typings
# r is already imported from flext_core

logger = l_core(__name__)

# Constants for tuple length validation
TUPLE_LENGTH_PAIR = 2

# Type for parsed ACL components (using MetadataValue for nested structures)
AclComponent = dict[str, str | t.MetadataAttributeValue]


class FlextLdifUtilitiesACL:
    """Generic ACL parsing and writing utilities."""

    # ASCII control character boundaries for sanitization
    # (use constants from c.Ldif.Rfc)
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

        # Default patterns with capturing groups for values
        default_patterns: dict[str, str] = {
            "userdn": r'userdn\s*=\s*"([^"]*)"',
            "groupdn": r'groupdn\s*=\s*"([^"]*)"',
            "roledn": r'roledn\s*=\s*"([^"]*)"',
        }

        patterns = bind_patterns or default_patterns

        # Simple native extraction with perfect type inference
        all_bind_rules: list[dict[str, str]] = []
        for bind_type, pattern in patterns.items():
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
        # Use native dict.get for simpler type inference
        return permission_map.get(perm, perm)

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
                    perm, permission_map
                )
                result[normalized] = is_allow
        return result

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

    # NOTE: OID-specific methods (extract_oid_target, detect_oid_subject,
    # parse_oid_permissions, format_oid_target, format_oid_subject,
    # format_oid_permissions) were REMOVED from here.
    # They are now in FlextLdifServersOid.Acl class where OID knowledge belongs.
    # Servers must encapsulate their own knowledge -
    # utilities should be generic/parametrized.

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
        rule_type: str = first_rule.get("type", "")
        rule_value: str = first_rule.get("value", "")

        # Check for special values first
        special_match: tuple[str, str] | None = special_values.get(rule_value)
        if special_match:
            return special_match

        # Map the type
        subject_type: str = subject_type_map.get(rule_type, rule_type)

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
        result: dict[str, t.MetadataAttributeValue] = {}

        extension_items: list[tuple[str, object]] = [
            ("line_breaks", config.line_breaks),
            ("dn_spaces", config.dn_spaces),
            ("targetscope", config.targetscope),
            ("version", config.version),
            ("action_type", config.action_type),
        ]

        for key, value in extension_items:
            if value is not None:
                result[key] = cast("t.MetadataAttributeValue", value)

        return result

    @staticmethod
    def sanitize_acl_name(raw_name: str, max_length: int = 128) -> tuple[str, bool]:
        """Sanitize ACL name for ACI format."""
        if not raw_name or not raw_name.strip():
            return "", False

        def sanitize_char(char: str) -> str:
            """Sanitize single character."""
            char_ord = ord(char)
            if (
                char_ord < c.Ldif.Format.Rfc.ASCII_PRINTABLE_MIN
                or char_ord > c.Ldif.Format.Rfc.ASCII_PRINTABLE_MAX
                or char == '"'
            ):
                return " "
            return char

        sanitized_chars: list[str] = f.normalize_list(
            list(raw_name),
            mapper=sanitize_char,
        )

        # Check if any characters were modified during sanitization
        sanitized_chars_list: list[str] = (
            sanitized_chars
            if isinstance(sanitized_chars, list)
            else list(sanitized_chars)
        )
        was_sanitized = sanitized_chars_list != list(raw_name)

        # Remove consecutive spaces
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
        # Handle multiline vs single-line ACI content
        if "\n" in acl_line:
            lines = acl_line.split("\n")
            aci_content: str = (
                lines[0].split(":", 1)[1].strip() + "\n" + "\n".join(lines[1:])
            )
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

        # Native Python iteration - proper type narrowing for isinstance
        for name, pattern_spec in patterns.items():
            # Native isinstance provides proper type narrowing
            if isinstance(pattern_spec, tuple):
                pattern, group = pattern_spec
            else:
                pattern = pattern_spec
                group = 1
            if not pattern:
                continue
            value = FlextLdifUtilitiesACL.extract_component(aci_content, pattern, group)
            if isinstance(value, str):
                context[name] = value

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

        # Simplify using native Python for clearer type inference
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
        # Simple native iteration - no complex FlextFunctional chains
        for key, value_tuple in special_values.items():
            if (
                u.normalize(rule_value, key)
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

        # Process each rule with native Python - clear type inference
        for rule in bind_rules_data:
            rule_type = rule.get("type", "").lower()
            rule_value = rule.get("value", "")

            # Check for special values first
            special_match = FlextLdifUtilitiesACL._check_special_value(
                rule_value,
                special_values,
            )
            if special_match:
                return special_match

            # Check for mapped type
            mapped_type = subject_type_map.get(rule_type)
            if mapped_type:
                return mapped_type, rule_value

        # Default fallback using first rule's value
        default_value = bind_rules_data[0].get("value", "") if bind_rules_data else ""
        return "user", default_value

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
        supported_lower = {s.lower() for s in supported}
        # Native Python: list comprehension with filter and transform
        return [p.lower() for p in permissions if p.lower() in supported_lower]

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
        # Filter permissions if supported set is provided
        if supported_permissions:
            filtered: list[str] = FlextLdifUtilitiesACL.filter_supported_permissions(
                permissions,
                supported_permissions,
            )
        else:
            filtered = permissions

        # Build permissions clause if filtered list is non-empty
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

        # Native Python: direct if-elif instead of f.switch()
        if subject_type == "self":
            op = operators.get("self", "userdn")
            return f'{op}="{self_value}"'
        if subject_type == "anonymous":
            op = operators.get("anonymous", "userdn")
            return f'{op}="{anonymous_value}"'
        # Default case: format subject_value
        op = operators.get(subject_type, "userdn")
        value = subject_value.replace(", ", ",")
        if not value.startswith("ldap:///"):
            value = f"ldap:///{value}"
        return f'{op}="{value}"'

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
        version_match = re.search(version_pattern, aci_content)
        # Native Python: or operator for type narrowing (f.or_ returns Optional)
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
        targetattr_extracted = FlextLdifUtilitiesACL.extract_component(
            aci_content,
            config.targetattr_pattern,
            group=2,
        )
        # Native Python: or operator for type narrowing (f.or_ returns Optional)
        targetattr: str = targetattr_extracted or config.default_targetattr
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
        # Native Python: dict comprehension instead of f.map_dict()
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

        extra_result = u.Collection.process(
            extra_patterns,
            processor=extract_extra,
            predicate=lambda _k, v: bool(v),
            on_error="skip",
        )
        if extra_result.is_success and extra_result.value:
            # Type guard: ensure value is dict before accessing .items()
            extra_value = extra_result.value
            if isinstance(extra_value, dict):
                # Native Python: dict comprehension with isinstance check
                filtered_extensions: dict[str, str] = {
                    k: v for k, v in extra_value.items() if isinstance(v, str)
                }
                if filtered_extensions:
                    extensions = dict(extensions, **filtered_extensions)
        return extensions

    @staticmethod
    def parse_aci(
        acl_line: str,
        config: FlextLdifModelsConfig.AciParserConfig,
    ) -> r[FlextLdifModelsDomains.Acl]:
        """Parse ACI line using server-specific config Model.

        Args:
            acl_line: Raw ACL line string
            config: AciParserConfig with server-specific patterns

        Returns:
            r with parsed Acl model

        Example:
            config = FlextLdifModelsConfig.AciParserConfig(
                server_type=c.Ldif.ServerTypes.OUD,
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
                extensions=(
                    FlextLdifModelsMetadata.DynamicMetadata(**extensions)
                    if extensions
                    else None
                ),
            ),
        )
        return r.ok(acl_model)

    @staticmethod
    def write_aci(
        acl_data: FlextLdifModelsDomains.Acl,
        config: FlextLdifModelsConfig.AciWriterConfig,
    ) -> r[str]:
        """Write Acl model to ACI string using server-specific config Model.

        Args:
            acl_data: Acl model to write
            config: AciWriterConfig with server-specific settings

        Returns:
            r with formatted ACI string

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
        perm_candidates = [
            "read",
            "write",
            "add",
            "delete",
            "search",
            "compare",
            "self_write",
            "proxy",
        ]
        # Native Python: list comprehension instead of f.map_filter()
        # getattr on permissions object with type narrowing
        perm_names: list[str] = [
            name
            for name in perm_candidates
            if acl_data.permissions and getattr(acl_data.permissions, name, False)
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
            rule_config: List of (extension_key, format_template, operator_default)
                        tuples. format_template can use {value} or {operator}/{value}
                        placeholders. operator_default is used for tuple values that
                        need operator.
            tuple_length: Expected length for tuple values
                         (default: 2 for (operator, value))

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

            # Native Python: if-elif-else instead of f.match()
            # Match case 1: tuple with expected length
            if isinstance(value_raw, tuple) and len(value_raw) == expected_tuple_length:
                if operator_placeholder in format_template:
                    return format_template.format(
                        operator=str(value_raw[0]),
                        value=str(value_raw[1]),
                    )
                return format_template.format(value=str(value_raw[1]))

            # Match case 2: has operator placeholder and default operator
            if operator_placeholder in format_template and operator_default is not None:
                return format_template.format(
                    operator=operator_default,
                    value=str(value_raw),
                )

            # Default case
            return format_template.format(value=str(value_raw))

        # Predicate for rule_config: list[tuple[str, str, str | None]]
        def rule_predicate(item: tuple[str, str, str | None]) -> bool:
            """Filter rule config items based on extensions."""
            return bool(extensions.get(item[0]) if extensions else None)

        process_result = u.Collection.process(
            rule_config,
            processor=process_rule_config,
            predicate=rule_predicate,
            on_error="skip",
        )
        if not process_result.is_success or process_result.value is None:
            return []
        raw_value = process_result.value
        if not isinstance(raw_value, list):
            return []
        result: list[str] = [rule for rule in raw_value if rule is not None]
        return result

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
            value: t.MetadataAttributeValue | None = (
                extensions.get(ext_key) if extensions else None
            )
            if value is None:
                return None
            return format_template.format(value=value)

        process_result = u.Collection.process(
            target_config,
            processor=process_target_config,
            predicate=lambda item: bool(
                extensions.get(item[0]) if extensions else None,
            )
            if isinstance(item, tuple) and len(item) >= 1
            else False,
            on_error="skip",
        )
        if not process_result.is_success or process_result.value is None:
            return []
        raw_value = process_result.value
        if not isinstance(raw_value, list):
            return []
        result: list[str] = [part for part in raw_value if part is not None]
        return result

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

        converted_from_value = (
            extensions.get(converted_from_key) if extensions else None
        )
        if not converted_from_value:
            return []

        comments_value = extensions.get(comments_key) if extensions else None
        if comments_value is None:
            return []
        # Native list conversion (Fix #18: replaces f.normalize_list + f.as_type)
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

        # Native conditional (Fix #19: replaces f.cond for type clarity)
        if first_line.startswith(("orclaci:", "orclentrylevelaci:")):
            return {"format": "oid"}
        if first_line.startswith("aci:"):
            return {"format": "oud"}
        return None

    @staticmethod
    def map_oid_to_oud_permissions(
        oid_permissions: dict[str, bool],
    ) -> dict[str, bool]:
        """Map OID-specific permissions to OUD-equivalent permissions.

        Handles OID → OUD permission conversion:
        - browse → read + search (OID browse allows listing, OUD requires
          read+search)
        - selfwrite → write (OID-specific self-write becomes OUD write)
        - Other permissions (read, write, add, delete, search, compare, all)
          pass through

        Args:
            oid_permissions: Dict with OID permission names as keys
                           (e.g., browse, selfwrite)

        Returns:
            Dict with OUD-compatible permission names mapped correctly

        Example:
            >>> oid_perms = {"browse": True, "write": False}
            >>> oud_perms = FlextLdifUtilitiesACL.map_oid_to_oud_permissions(oid_perms)
            >>> print(oud_perms)  # {"read": True, "search": True, "write": False}

        """
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

        # Map all permissions through map_perm
        mapped_dicts: list[dict[str, bool]] = [
            map_perm(perm_name, perm_value=perm_value)
            for perm_name, perm_value in oid_permissions.items()
        ]

        # Filter to only include dict results (skip empty results)
        filtered_dicts: list[dict[str, bool]] = [
            d for d in mapped_dicts if isinstance(d, dict) and d
        ]

        # Merge with OR combiner for boolean values
        result: dict[str, bool] = {}
        for d in filtered_dicts:
            for k, v in d.items():
                result[k] = result.get(k, False) or v
        return result

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
        pass_through_perms = {
            "read",
            "write",
            "add",
            "delete",
            "search",
            "compare",
            "all",
        }

        # Handle read + search → browse conversion
        has_read = oud_permissions.get("read", False)
        has_search = oud_permissions.get("search", False)
        browse_dict: dict[str, bool] = (
            {"browse": has_read and has_search} if (has_read or has_search) else {}
        )

        # Pass through standard permissions (except read/search)
        pass_through: dict[str, bool] = {
            k: v
            for k, v in oud_permissions.items()
            if k in pass_through_perms and k not in {"read", "search"}
        }

        # Merge browse_dict with pass_through
        result: dict[str, bool] = {**browse_dict, **pass_through}
        return result

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
            name: str,
            pattern_spec: str | tuple[str, int],
        ) -> tuple[str, object]:
            """Extract component from pattern spec."""
            if isinstance(pattern_spec, tuple):
                pattern, group_idx = pattern_spec
            else:
                pattern = pattern_spec
                group_idx = 1
            value = FlextLdifUtilitiesACL.extract_component(content, pattern, group_idx)
            default_value = effective_defaults.get(name) if effective_defaults else None
            final_value = value if value is not None else default_value
            return name, final_value

        process_result = u.Collection.process(
            patterns,
            processor=extract_component_batch,
            on_error="skip",
        )
        if not process_result.is_success or not isinstance(process_result.value, dict):
            return {}

        # Extract pairs from the process result
        result_dict = process_result.value

        # Build result dict from pairs - extract second element from tuple values
        final_result: dict[str, object] = {}
        for key, value_item in result_dict.items():
            if isinstance(value_item, tuple) and len(value_item) == TUPLE_LENGTH_PAIR:
                final_result[key] = value_item[1]

        return final_result

    @staticmethod
    def _parse_single_acl_with_config(
        acl_line: str,
        config: FlextLdifModelsConfig.AciParserConfig,
        *,
        fail_fast: bool = False,
    ) -> FlextLdifModelsDomains.Acl | None:
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
        return result.unwrap()

    @staticmethod
    def _format_batch_errors(errors: list[tuple[int, str]]) -> list[str]:
        """Format batch error tuples to strings."""
        # Native Python: simple list comprehension
        return [f"ACL {idx}: {msg}" for idx, msg in errors]

    @staticmethod
    def _process_batch_results(
        batch_data: dict[str, object],
        *,
        skip_invalid: bool = True,
    ) -> r[list[FlextLdifModelsDomains.Acl]]:
        """Process batch results and return r."""
        # Native Python: extract and filter results
        results_typed: list[FlextLdifModelsDomains.Acl] = []
        raw_results = batch_data.get("results")
        if isinstance(raw_results, list):
            results_typed.extend([
                item
                for item in raw_results
                if isinstance(item, FlextLdifModelsDomains.Acl)
            ])

        # Native Python: extract error_count safely
        raw_error_count = batch_data.get("error_count", 0)
        error_count = raw_error_count if isinstance(raw_error_count, int) else 0

        if error_count > 0 and not skip_invalid:
            # Native Python: extract and filter errors
            raw_errors = batch_data.get("errors")
            errors_typed: list[tuple[int, str]] = []
            if isinstance(raw_errors, list):
                errors_typed.extend([
                    cast("tuple[int, str]", err)
                    for err in raw_errors
                    if isinstance(err, tuple) and len(err) == TUPLE_LENGTH_PAIR
                ])
            if errors_typed:
                error_msgs = FlextLdifUtilitiesACL._format_batch_errors(
                    errors_typed,
                )
                return r.fail(f"Parse errors: {'; '.join(error_msgs)}")
        return r.ok(results_typed)

    @staticmethod
    def parse_batch(
        acl_lines: Sequence[str],
        config: FlextLdifModelsConfig.AciParserConfig,
        *,
        fail_fast: bool = False,
        skip_invalid: bool = True,
    ) -> r[list[FlextLdifModelsDomains.Acl]]:
        """Parse multiple ACL lines in one call.

        Args:
            acl_lines: Sequence of ACL line strings to parse
            config: Parser configuration
            fail_fast: If True, return error on first parse failure
            skip_invalid: If True, skip invalid ACLs (when fail_fast=False)

        Returns:
            r containing list of parsed ACL objects

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

        def parse_single_acl(acl_line: str) -> FlextLdifModelsDomains.Acl | None:
            """Parse single ACL line wrapper."""
            return FlextLdifUtilitiesACL._parse_single_acl_with_config(
                acl_line,
                config,
                fail_fast=fail_fast,
            )

        batch_result: r[t.Types.BatchResultDict] = u.batch(
            list(acl_lines),
            operation=parse_single_acl,
            on_error="collect" if not fail_fast else "fail",
            pre_validate=lambda r: r
            is not None,  # Changed from post_validate to pre_validate
        )
        if batch_result.is_failure:
            return cast("r[list[FlextLdifModelsDomains.Acl]]", batch_result)

        # Native Python: extract needed fields directly (avoids f.pick type issues)
        batch_value = batch_result.value
        batch_data_dict: dict[str, object] = {
            "results": batch_value.get("results") if batch_value else None,
            "errors": batch_value.get("errors") if batch_value else None,
            "error_count": batch_value.get("error_count") if batch_value else 0,
        }
        return FlextLdifUtilitiesACL._process_batch_results(
            batch_data_dict,
            skip_invalid=skip_invalid,
        )

    @staticmethod
    def convert_permissions_batch(
        permissions_list: Sequence[dict[str, bool]],
        direction: Literal["oid_to_oud", "oud_to_oid"],
    ) -> r[list[dict[str, bool]]]:
        """Convert multiple permission sets between OID and OUD formats.

        Args:
            permissions_list: Sequence of permission dictionaries
            direction: Conversion direction ("oid_to_oud" or "oud_to_oid")

        Returns:
            r containing list of converted permission dictionaries

        Examples:
            >>> oid_perms = [{"read": True, "search": True}, {"write": True}]
            >>> result = FlextLdifUtilitiesACL.convert_permissions_batch(
            ...     oid_perms,
            ...     direction="oid_to_oud",
            ... )

        """

        def convert_single_permissions(permissions: dict[str, bool]) -> dict[str, bool]:
            """Convert single permission set."""
            # Native Python: simple if-else instead of f.switch
            if direction == "oid_to_oud":
                return FlextLdifUtilitiesACL.map_oid_to_oud_permissions(permissions)
            if direction == "oud_to_oid":
                return FlextLdifUtilitiesACL.map_oud_to_oid_permissions(permissions)
            return permissions

        batch_result: r[t.Types.BatchResultDict] = u.batch(
            list(permissions_list),
            operation=convert_single_permissions,
            on_error="fail",
        )
        if batch_result.is_failure:
            return cast("r[list[dict[str, bool]]]", batch_result)

        # Native Python: extract and filter results
        results_typed: list[dict[str, bool]] = []
        raw_results = batch_result.value.get("results") if batch_result.value else None
        if isinstance(raw_results, list):
            results_typed.extend(
                cast("dict[str, bool]", item)
                for item in raw_results
                if isinstance(item, dict)
            )
        return r.ok(results_typed)

    @staticmethod
    def validate_batch(
        acl_lines: Sequence[str],
        *,
        collect_errors: bool = True,
    ) -> r[list[tuple[str, bool, str | None]]]:
        """Validate multiple ACL lines.

        Business Rule:
        - Validates ACI format for each ACL line using RFC 2849/4512 standards
        - Returns tuple (is_valid, aci_content) where is_valid indicates
          format correctness
        - When collect_errors=False, stops at first invalid ACL
          (fail-fast pattern)
        - Error messages are extracted from validation tuple for audit trail

        Args:
            acl_lines: Sequence of ACL line strings to validate
            collect_errors: If True, continue after failures (default: True)

        Returns:
            r containing list of (acl_line, is_valid, error_message) tuples
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

        def validate_single_acl(acl_line: str) -> tuple[str, bool, str | None]:
            """Validate single ACL line."""
            is_valid, aci_content = FlextLdifUtilitiesACL.validate_aci_format(acl_line)
            if is_valid:
                return (acl_line, True, None)
            error_msg = aci_content or "Invalid ACI format"
            return (acl_line, False, error_msg)

        # Native Python: simple for loop instead of FlextFunctional chains
        results: list[tuple[str, bool, str | None]] = []

        if collect_errors:
            # Collect all results, continue on errors
            for acl_line in acl_lines:
                result_tuple = validate_single_acl(acl_line)
                results.append(result_tuple)
        else:
            # Fail-fast: stop at first invalid
            for acl_line in acl_lines:
                result_tuple = validate_single_acl(acl_line)
                results.append(result_tuple)
                if not result_tuple[1]:  # is_valid is False
                    break

        return r.ok(results)


__all__ = [
    "FlextLdifUtilitiesACL",
]
